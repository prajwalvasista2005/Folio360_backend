"""End-to-end Phase 2 Stage 5 API, quarantine, malware scanning, token, and linking tests."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.security import create_access_token, hash_password
from app.db.session import build_sessionmaker
from app.main import create_app
from app.models.document import Document
from app.models.user import User
from app.services import document_service
from app.services.malware_scanner import EICAR_TEST_SIGNATURE, MockMalwareScanner
from app.services.storage_service import LocalFilesystemStorage, generate_local_content_token

VALID_PDF = b"%PDF-1.7\n%Folio360-stage5\n1 0 obj\n<<>>\nendobj\n%%EOF\n"
INFECTED_PDF = b"%PDF-1.7\n1 0 obj\n<<" + EICAR_TEST_SIGNATURE + b">>\nendobj\n%%EOF\n"


def _build_test_app(
    test_database_url: str,
    *,
    storage_dir: Path,
    processing_mode: str = "inline",
    retention_policy: str = "delete",
    max_retries: int = 3,
    stale_seconds: int = 300,
) -> tuple[Settings, object]:
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL=test_database_url,
        JWT_SECRET_KEY="stage5-doc-integration-jwt-secret-key-at-least-32-chars",
        JWT_ISSUER="folio360",
        JWT_AUDIENCE="folio360-api",
        JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15,
        REFRESH_TOKEN_EXPIRE_DAYS=14,
        REFRESH_TOKEN_ABSOLUTE_EXPIRE_DAYS=30,
        FRONTEND_BASE_URL="http://localhost:5173",
        BACKEND_BASE_URL="http://localhost:8000",
        CORS_ORIGINS=["http://localhost:5173"],
        RESEND_API_KEY="re_stage5_mock_key",
        EMAIL_FROM_ADDRESS="no-reply@folio360.com",
        RATE_LIMIT_ENABLED=False,
        STORAGE_BACKEND="local",
        DOCUMENT_LOCAL_STORAGE_DIR=str(storage_dir),
        DOCUMENT_SIGNING_SECRET="stage5-signing-secret-at-least-32-chars",
        MALWARE_SCANNER_BACKEND="mock",
        DOCUMENT_SCAN_PROCESSING_MODE=processing_mode,  # type: ignore[arg-type]
        DOCUMENT_REJECTED_RETENTION_POLICY=retention_policy,  # type: ignore[arg-type]
        DOCUMENT_SCAN_MAX_RETRIES=max_retries,
        DOCUMENT_SCAN_STALE_SECONDS=stale_seconds,
    )
    return settings, create_app(settings=settings)


@pytest.fixture
def clean_stage5_db(db_engine: Engine):
    """Clean users (and cascaded documents/educations) before and after each test."""
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))
    yield
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))


def _create_db_user(db_engine: Engine, *, email: str) -> User:
    session_factory = build_sessionmaker(db_engine)
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password("StrongPassword!2026"),
        is_active=True,
        is_email_verified=True,
        email_verified_at=datetime.now(timezone.utc),
        auth_version=0,
    )
    with session_factory() as session:
        session.add(user)
        session.commit()
        session.refresh(user)
    return user


def _auth_headers(user: User, settings: Settings) -> dict[str, str]:
    token, _ = create_access_token(
        user_id=user.id,
        auth_version=user.auth_version,
        settings=settings,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.db
def test_quarantine_promotion_ready_and_malicious_rejection_policies(
    test_database_url: str,
    db_engine: Engine,
    clean_stage5_db: None,
    tmp_path: Path,
) -> None:
    """Clean uploads promote quarantine->trusted->ready; EICAR uploads reject and respect retention."""
    settings, app = _build_test_app(
        test_database_url,
        storage_dir=tmp_path,
        retention_policy="delete",
    )
    user = _create_db_user(db_engine, email="stage5.clean@example.com")
    headers = _auth_headers(user, settings)
    session_factory = build_sessionmaker(db_engine)

    with TestClient(app) as client:  # type: ignore[arg-type]
        clean_resp = client.post(
            "/api/v1/documents",
            headers=headers,
            files={"file": ("clean.pdf", VALID_PDF, "application/pdf")},
            data={"category": "marksheet", "title": "Clean Transcript"},
        )
        assert clean_resp.status_code == 201
        clean_doc = clean_resp.json()["document"]
        assert clean_doc["processing_status"] == "ready"
        assert clean_doc["failure_reason"] is None

        with session_factory() as s:
            row = s.execute(
                select(Document).where(Document.id == uuid.UUID(clean_doc["id"]))
            ).scalar_one()
            assert row.storage_state == "trusted"
            assert row.storage_key == f"trusted/{user.id}/{clean_doc['id']}"
            assert row.scan_attempts == 1
            assert row.scanned_at is not None
            assert (tmp_path / row.storage_key).exists()
            assert not (tmp_path / f"quarantine/{user.id}/{clean_doc['id']}").exists()

        # Infected upload (retention=delete) -> rejected + deleted from quarantine + never leak signature
        inf_resp = client.post(
            "/api/v1/documents",
            headers=headers,
            files={"file": ("virus.pdf", INFECTED_PDF, "application/pdf")},
            data={"category": "other", "title": "Suspicious Upload"},
        )
        assert inf_resp.status_code == 201
        inf_doc = inf_resp.json()["document"]
        assert inf_doc["processing_status"] == "rejected"
        assert inf_doc["failure_reason"] == "malware_detected"
        assert "Eicar" not in inf_resp.text

        with session_factory() as s:
            inf_row = s.execute(
                select(Document).where(Document.id == uuid.UUID(inf_doc["id"]))
            ).scalar_one()
            assert inf_row.storage_state == "deleted"
            assert not (tmp_path / inf_row.storage_key).exists()

        # Preview / Download denied with 403 DOCUMENT_REJECTED; cannot rescan rejected doc
        assert client.get(f"/api/v1/documents/{inf_doc['id']}/preview", headers=headers).status_code == 403
        assert client.get(f"/api/v1/documents/{inf_doc['id']}/download", headers=headers).status_code == 403
        assert client.post(f"/api/v1/documents/{inf_doc['id']}/rescan", headers=headers).status_code == 409

    # Test retain_quarantine retention policy keeps object isolated in quarantine only
    _, app_retain = _build_test_app(
        test_database_url,
        storage_dir=tmp_path / "retain",
        retention_policy="retain_quarantine",
    )
    with TestClient(app_retain) as client:  # type: ignore[arg-type]
        retained = client.post(
            "/api/v1/documents",
            headers=headers,
            files={"file": ("eicar.pdf", INFECTED_PDF, "application/pdf")},
        )
        assert retained.status_code == 201
        ret_id = retained.json()["document"]["id"]
        with session_factory() as s:
            ret_row = s.execute(select(Document).where(Document.id == uuid.UUID(ret_id))).scalar_one()
            assert ret_row.processing_status == "rejected"
            assert ret_row.storage_state == "quarantine"
            assert (tmp_path / "retain" / ret_row.storage_key).exists()


@pytest.mark.db
def test_scanner_unavailable_timeout_retries_and_recovery(
    test_database_url: str,
    db_engine: Engine,
    clean_stage5_db: None,
    tmp_path: Path,
) -> None:
    """Scanner unavailable/timeout transitions to scan_failed, preserves quarantine, and supports bounded rescan."""
    settings, app = _build_test_app(
        test_database_url,
        storage_dir=tmp_path,
        max_retries=2,
    )
    user = _create_db_user(db_engine, email="stage5.retry@example.com")
    headers = _auth_headers(user, settings)

    with TestClient(app) as client:  # type: ignore[arg-type]
        with patch(
            "app.services.document_service.build_malware_scanner",
            return_value=MockMalwareScanner(mode="unavailable"),
        ):
            up = client.post(
                "/api/v1/documents",
                headers=headers,
                files={"file": ("doc.pdf", VALID_PDF, "application/pdf")},
            )
            assert up.status_code == 201
            doc = up.json()["document"]
            doc_id = doc["id"]
            assert doc["processing_status"] == "scan_failed"
            assert doc["failure_reason"] == "scanner_unavailable"

        # Pending/failed cannot be previewed or downloaded (409)
        assert client.get(f"/api/v1/documents/{doc_id}/preview", headers=headers).status_code == 409
        assert client.get(f"/api/v1/documents/{doc_id}/download", headers=headers).status_code == 409

        # Rescan attempt #2 succeeds once scanner recovers
        with patch(
            "app.services.document_service.build_malware_scanner",
            return_value=MockMalwareScanner(mode="eicar"),
        ):
            rescanned = client.post(f"/api/v1/documents/{doc_id}/rescan", headers=headers)
            assert rescanned.status_code == 200
            assert rescanned.json()["processing_status"] == "ready"
            assert rescanned.json()["failure_reason"] is None

        # Timeout exhausts max_retries=2 and blocks further rescan with 409
        with patch(
            "app.services.document_service.build_malware_scanner",
            return_value=MockMalwareScanner(mode="timeout"),
        ):
            up_timeout = client.post(
                "/api/v1/documents",
                headers=headers,
                files={"file": ("slow.pdf", VALID_PDF, "application/pdf")},
            )
            assert up_timeout.status_code == 201
            t_id = up_timeout.json()["document"]["id"]
            assert up_timeout.json()["document"]["failure_reason"] == "scanner_timeout"

            retry2 = client.post(f"/api/v1/documents/{t_id}/rescan", headers=headers)
            assert retry2.status_code == 200
            assert retry2.json()["processing_status"] == "scan_failed"

        retry3 = client.post(f"/api/v1/documents/{t_id}/rescan", headers=headers)
        assert retry3.status_code == 409
        assert retry3.json()["error"]["code"] == "DOCUMENT_SCAN_RETRIES_EXHAUSTED"


@pytest.mark.db
def test_deferred_token_bypass_defense_malformed_files_and_education_linking(
    test_database_url: str,
    db_engine: Engine,
    clean_stage5_db: None,
    tmp_path: Path,
) -> None:
    """Verify deferred mode, forged/valid token status checks, malformed rejection, and education gate."""
    settings, app = _build_test_app(
        test_database_url,
        storage_dir=tmp_path,
        processing_mode="deferred",
    )
    owner = _create_db_user(db_engine, email="stage5.owner@example.com")
    other = _create_db_user(db_engine, email="stage5.other@example.com")
    owner_headers = _auth_headers(owner, settings)
    other_headers = _auth_headers(other, settings)
    session_factory = build_sessionmaker(db_engine)

    with TestClient(app) as client:  # type: ignore[arg-type]
        # Truncated PDF fails structurally with 422 MALFORMED_FILE before quarantine storage/DB insert
        bad_pdf = client.post(
            "/api/v1/documents",
            headers=owner_headers,
            files={"file": ("trunc.pdf", b"%PDF-1.7\n1 0 obj\n", "application/pdf")},
        )
        assert bad_pdf.status_code == 422
        assert bad_pdf.json()["error"]["code"] == "MALFORMED_FILE"
        assert [p for p in tmp_path.rglob("*") if p.is_file()] == []

        # Upload valid PDF in deferred mode -> stays pending_scan in quarantine
        pending_resp = client.post(
            "/api/v1/documents",
            headers=owner_headers,
            files={"file": ("pending.pdf", VALID_PDF, "application/pdf")},
            data={"category": "marksheet", "title": "Pending Transcript"},
        )
        assert pending_resp.status_code == 201
        pending_doc = pending_resp.json()["document"]
        doc_id = pending_doc["id"]
        assert pending_doc["processing_status"] == "pending_scan"

        # Preview/download denied with 409 DOCUMENT_NOT_READY
        assert client.get(f"/api/v1/documents/{doc_id}/preview", headers=owner_headers).status_code == 409
        assert client.get(f"/api/v1/documents/{doc_id}/download", headers=owner_headers).status_code == 409

        # Even a cryptographically valid, unexpired HMAC content token cannot bypass pending_scan status
        exp_ts = int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp())
        token = generate_local_content_token(
            document_id=uuid.UUID(doc_id),
            disposition="inline",
            expires_at_ts=exp_ts,
            settings=settings,
        )
        bypass_attempt = client.get(
            f"/api/v1/documents/{doc_id}/content?token={token}&disposition=inline"
        )
        assert bypass_attempt.status_code == 403
        assert bypass_attempt.json()["error"]["code"] == "DOCUMENT_NOT_READY"

        # Cross-user access including /rescan returns 404 DOCUMENT_NOT_FOUND
        assert (
            client.post(f"/api/v1/documents/{doc_id}/rescan", headers=other_headers).status_code == 404
        )

        # Education linking must reject pending_scan documents with 422 DOCUMENT_NOT_READY
        link_pending = client.post(
            "/api/v1/education",
            headers=owner_headers,
            json={
                "institution": "RVCE",
                "degree": "B.E.",
                "document_ids": [doc_id],
            },
        )
        assert link_pending.status_code == 422
        assert link_pending.json()["error"]["code"] == "DOCUMENT_NOT_READY"

        # Rescan -> promotes to ready -> valid token & education linking now succeed
        rescan = client.post(f"/api/v1/documents/{doc_id}/rescan", headers=owner_headers)
        assert rescan.status_code == 200
        assert rescan.json()["processing_status"] == "ready"

        stream_ok = client.get(
            f"/api/v1/documents/{doc_id}/content?token={token}&disposition=inline"
        )
        assert stream_ok.status_code == 200
        assert stream_ok.content == VALID_PDF

        link_ready = client.post(
            "/api/v1/education",
            headers=owner_headers,
            json={
                "institution": "RVCE",
                "degree": "B.E.",
                "document_ids": [doc_id],
            },
        )
        assert link_ready.status_code == 201
        assert link_ready.json()["document_ids"] == [doc_id]

        # Idempotent duplicate scan call leaves ready document unchanged with same scan_attempts
        with session_factory() as s:
            dup = document_service.process_document_scan(
                s,
                document_id=uuid.UUID(doc_id),
                settings=settings,
            )
            assert dup.processing_status == "ready"
            assert dup.scan_attempts == 1


@pytest.mark.db
def test_promotion_failure_commit_failure_and_stale_scan_recovery(
    test_database_url: str,
    db_engine: Engine,
    clean_stage5_db: None,
    tmp_path: Path,
) -> None:
    """Verify promotion failure, post-promotion commit failure cleanup, and stale scan recovery."""
    settings, app = _build_test_app(
        test_database_url,
        storage_dir=tmp_path,
        processing_mode="deferred",
        stale_seconds=60,
    )
    user = _create_db_user(db_engine, email="stage5.fail@example.com")
    headers = _auth_headers(user, settings)
    session_factory = build_sessionmaker(db_engine)

    with TestClient(app) as client:  # type: ignore[arg-type]
        up1 = client.post(
            "/api/v1/documents",
            headers=headers,
            files={"file": ("promo.pdf", VALID_PDF, "application/pdf")},
        )
        doc1_id = uuid.UUID(up1.json()["document"]["id"])

        # 1. Storage promotion failure leaves DB at scan_failed ('promotion_failed'), never ready
        with patch.object(
            LocalFilesystemStorage,
            "promote_object",
            side_effect=RuntimeError("disk full"),
        ):
            with session_factory() as s:
                res1 = document_service.process_document_scan(
                    s, document_id=doc1_id, settings=settings
                )
                assert res1.processing_status == "scan_failed"
                assert res1.failure_reason == "promotion_failed"
                assert res1.storage_state == "quarantine"
                assert res1.storage_key.startswith("quarantine/")

        # 2. DB commit failure right after promotion cleans up trusted object and recovers to scan_failed
        up2 = client.post(
            "/api/v1/documents",
            headers=headers,
            files={"file": ("commit_fail.pdf", VALID_PDF, "application/pdf")},
        )
        doc2_id = uuid.UUID(up2.json()["document"]["id"])
        real_commit = Session.commit
        call_count = 0

        def _fail_second_commit(self: Session) -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise RuntimeError("commit lost after promotion")
            return real_commit(self)

        with patch.object(Session, "commit", new=_fail_second_commit):
            with session_factory() as s:
                res2 = document_service.process_document_scan(
                    s, document_id=doc2_id, settings=settings
                )
                assert res2.processing_status == "scan_failed"
                assert res2.failure_reason == "promotion_failed"
                assert res2.storage_state == "quarantine"
                assert not (tmp_path / f"trusted/{user.id}/{doc2_id}").exists()

        # 3. Stale 'scanning' recovery moves abandoned jobs back to scan_failed
        up3 = client.post(
            "/api/v1/documents",
            headers=headers,
            files={"file": ("stale.pdf", VALID_PDF, "application/pdf")},
        )
        doc3_id = uuid.UUID(up3.json()["document"]["id"])
        with session_factory() as s:
            row3 = s.execute(select(Document).where(Document.id == doc3_id)).scalar_one()
            row3.processing_status = "scanning"
            row3.scan_started_at = datetime.now(timezone.utc) - timedelta(minutes=15)
            s.commit()

        with session_factory() as s:
            recovered = document_service.recover_stale_scans(s, settings=settings)
            assert recovered == 1
            refreshed = s.execute(select(Document).where(Document.id == doc3_id)).scalar_one()
            assert refreshed.processing_status == "scan_failed"
            assert refreshed.failure_reason == "scanner_timeout"
