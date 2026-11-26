"""End-to-end Phase 2 Stage 6 AI Analyzer API, security gate, retry, and DB persistence tests."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import Engine, select, text

from app.core.config import Settings
from app.core.security import create_access_token, hash_password
from app.db.session import build_sessionmaker
from app.main import create_app
from app.models.document import Document
from app.models.document_analysis import DocumentAnalysis
from app.models.user import User
from app.services import document_analysis_service
from app.services.ai_analyzer_provider import MockDocumentAnalyzer
from app.services.malware_scanner import EICAR_TEST_SIGNATURE

VALID_PDF = b"%PDF-1.7\n%Folio360-stage6\n1 0 obj\n<<>>\nendobj\n%%EOF\n"
INFECTED_PDF = b"%PDF-1.7\n1 0 obj\n<<" + EICAR_TEST_SIGNATURE + b">>\nendobj\n%%EOF\n"


def _build_test_app(
    test_database_url: str,
    *,
    storage_dir: Path,
    scan_mode: str = "inline",
    ai_provider: str = "mock",
    ai_mode: str = "inline",
    max_retries: int = 3,
    max_input_bytes: int = 10 * 1024 * 1024,
) -> tuple[Settings, object]:
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL=test_database_url,
        JWT_SECRET_KEY="stage6-ai-integration-jwt-secret-key-at-least-32-chars",
        JWT_ISSUER="folio360",
        JWT_AUDIENCE="folio360-api",
        JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15,
        REFRESH_TOKEN_EXPIRE_DAYS=14,
        REFRESH_TOKEN_ABSOLUTE_EXPIRE_DAYS=30,
        FRONTEND_BASE_URL="http://localhost:5173",
        BACKEND_BASE_URL="http://localhost:8000",
        CORS_ORIGINS=["http://localhost:5173"],
        RESEND_API_KEY="re_stage6_mock_key",
        EMAIL_FROM_ADDRESS="no-reply@folio360.com",
        RATE_LIMIT_ENABLED=False,
        STORAGE_BACKEND="local",
        DOCUMENT_LOCAL_STORAGE_DIR=str(storage_dir),
        MALWARE_SCANNER_BACKEND="mock",
        DOCUMENT_SCAN_PROCESSING_MODE=scan_mode,  # type: ignore[arg-type]
        AI_ANALYZER_PROVIDER=ai_provider,  # type: ignore[arg-type]
        AI_ANALYZER_PROCESSING_MODE=ai_mode,  # type: ignore[arg-type]
        AI_ANALYZER_MAX_RETRIES=max_retries,
        AI_ANALYZER_MAX_INPUT_BYTES=max_input_bytes,
    )
    return settings, create_app(settings=settings)


@pytest.fixture
def clean_stage6_db(db_engine: Engine):
    """Clean users (cascading documents and analyses) before and after each test."""
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))
    yield
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))


def _create_db_user(
    db_engine: Engine,
    *,
    email: str,
    is_email_verified: bool = True,
) -> User:
    session_factory = build_sessionmaker(db_engine)
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password("StrongPassword!2026"),
        is_active=True,
        is_email_verified=is_email_verified,
        email_verified_at=datetime.now(timezone.utc) if is_email_verified else None,
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
def test_ai_analysis_marksheet_certificate_duplicate_and_delete_cascade(
    test_database_url: str,
    db_engine: Engine,
    clean_stage6_db: None,
    tmp_path: Path,
) -> None:
    """Ready/trusted marksheets & certificates analyze cleanly, block duplicates, and cascade on delete."""
    settings, app = _build_test_app(test_database_url, storage_dir=tmp_path)
    owner = _create_db_user(db_engine, email="ai.owner@example.com")
    other = _create_db_user(db_engine, email="ai.other@example.com")
    unverified = _create_db_user(db_engine, email="ai.unver@example.com", is_email_verified=False)

    owner_headers = _auth_headers(owner, settings)
    other_headers = _auth_headers(other, settings)
    unver_headers = _auth_headers(unverified, settings)
    session_factory = build_sessionmaker(db_engine)

    with TestClient(app) as client:  # type: ignore[arg-type]
        up_ms = client.post(
            "/api/v1/documents",
            headers=owner_headers,
            files={"file": ("sem5.pdf", VALID_PDF, "application/pdf")},
            data={"category": "marksheet", "title": "Sem 5 Marksheet"},
        )
        assert up_ms.status_code == 201
        doc_id = up_ms.json()["document"]["id"]

        # Unauthenticated / unverified / cross-user denied
        assert client.post(f"/api/v1/documents/{doc_id}/analysis").status_code == 401
        assert client.post(f"/api/v1/documents/{doc_id}/analysis", headers=unver_headers).status_code == 403
        assert client.post(f"/api/v1/documents/{doc_id}/analysis", headers=other_headers).status_code == 404
        assert client.get(f"/api/v1/documents/{doc_id}/analysis", headers=other_headers).status_code == 404

        # Analyze marksheet
        an_resp = client.post(f"/api/v1/documents/{doc_id}/analysis", headers=owner_headers)
        assert an_resp.status_code == 201
        an_body = an_resp.json()
        assert an_body["status"] == "completed"
        assert an_body["document_type"] == "marksheet"
        assert an_body["is_verified"] is False
        assert an_body["provider_name"] == "mock"
        assert an_body["attempts"] == 1
        assert an_body["extracted_data"]["marksheet"]["institution_name"] == "RV College of Engineering"
        assert len(an_body["extracted_data"]["marksheet"]["subjects"]) == 2
        assert an_body["failure_reason"] is None

        # GET /analysis returns completed output
        get_an = client.get(f"/api/v1/documents/{doc_id}/analysis", headers=owner_headers)
        assert get_an.status_code == 200
        assert get_an.json()["id"] == an_body["id"]

        # Duplicate analysis request rejected with 409 ANALYSIS_ALREADY_COMPLETED
        dup_an = client.post(f"/api/v1/documents/{doc_id}/analysis", headers=owner_headers)
        assert dup_an.status_code == 409
        assert dup_an.json()["error"]["code"] == "ANALYSIS_ALREADY_COMPLETED"

        # Original document stays ready/trusted and unchanged
        doc_after = client.get(f"/api/v1/documents/{doc_id}", headers=owner_headers).json()
        assert doc_after["processing_status"] == "ready"
        assert doc_after["failure_reason"] is None

        # Delete source document cascades to document_analyses
        del_resp = client.delete(f"/api/v1/documents/{doc_id}", headers=owner_headers)
        assert del_resp.status_code == 204
        with session_factory() as s:
            assert (
                s.execute(
                    select(DocumentAnalysis).where(DocumentAnalysis.document_id == uuid.UUID(doc_id))
                ).scalar_one_or_none()
                is None
            )

        # Certificate extraction
        up_cert = client.post(
            "/api/v1/documents",
            headers=owner_headers,
            files={"file": ("cert.pdf", VALID_PDF, "application/pdf")},
            data={"category": "certificate", "title": "Merit Certificate"},
        )
        cert_id = up_cert.json()["document"]["id"]
        cert_an = client.post(f"/api/v1/documents/{cert_id}/analysis", headers=owner_headers)
        assert cert_an.status_code == 201
        assert cert_an.json()["document_type"] == "certificate"
        assert cert_an.json()["extracted_data"]["certificate"]["issuing_institution"] == "RV College of Engineering"


@pytest.mark.db
def test_stage5_security_boundary_blocks_quarantined_pending_rejected_and_failed_docs(
    test_database_url: str,
    db_engine: Engine,
    clean_stage6_db: None,
    tmp_path: Path,
) -> None:
    """AI Analyzer strictly rejects pending_scan, scanning, scan_failed, rejected, and quarantined docs."""
    settings, app = _build_test_app(
        test_database_url,
        storage_dir=tmp_path,
        scan_mode="deferred",
    )
    user = _create_db_user(db_engine, email="ai.gate@example.com")
    headers = _auth_headers(user, settings)
    session_factory = build_sessionmaker(db_engine)

    with TestClient(app) as client:  # type: ignore[arg-type]
        up_pending = client.post(
            "/api/v1/documents",
            headers=headers,
            files={"file": ("pending.pdf", VALID_PDF, "application/pdf")},
        )
        doc_id = up_pending.json()["document"]["id"]

        # 1. pending_scan blocked (409 DOCUMENT_NOT_READY) & no quarantine read happens
        r_pending = client.post(f"/api/v1/documents/{doc_id}/analysis", headers=headers)
        assert r_pending.status_code == 409
        assert r_pending.json()["error"]["code"] == "DOCUMENT_NOT_READY"

        # 2. scanning blocked (409 DOCUMENT_NOT_READY)
        with session_factory() as s:
            row = s.execute(select(Document).where(Document.id == uuid.UUID(doc_id))).scalar_one()
            row.processing_status = "scanning"
            s.commit()
        r_scanning = client.post(f"/api/v1/documents/{doc_id}/analysis", headers=headers)
        assert r_scanning.status_code == 409
        assert r_scanning.json()["error"]["code"] == "DOCUMENT_NOT_READY"

        # 3. scan_failed blocked (409 DOCUMENT_SCAN_FAILED)
        with session_factory() as s:
            row = s.execute(select(Document).where(Document.id == uuid.UUID(doc_id))).scalar_one()
            row.processing_status = "scan_failed"
            row.failure_reason = "scanner_timeout"
            s.commit()
        r_failed = client.post(f"/api/v1/documents/{doc_id}/analysis", headers=headers)
        assert r_failed.status_code == 409
        assert r_failed.json()["error"]["code"] == "DOCUMENT_SCAN_FAILED"

        # 4. rejected blocked (403 DOCUMENT_REJECTED)
        with session_factory() as s:
            row = s.execute(select(Document).where(Document.id == uuid.UUID(doc_id))).scalar_one()
            row.processing_status = "rejected"
            row.failure_reason = "malware_detected"
            s.commit()
        r_rejected = client.post(f"/api/v1/documents/{doc_id}/analysis", headers=headers)
        assert r_rejected.status_code == 403
        assert r_rejected.json()["error"]["code"] == "DOCUMENT_REJECTED"

        # 5. Tampered ready row still pointing to quarantine key blocked (409 DOCUMENT_NOT_READY)
        with session_factory() as s:
            row = s.execute(select(Document).where(Document.id == uuid.UUID(doc_id))).scalar_one()
            row.processing_status = "ready"
            row.storage_state = "trusted"
            # storage_key still starts with quarantine/
            s.commit()
        r_quarantine_key = client.post(f"/api/v1/documents/{doc_id}/analysis", headers=headers)
        assert r_quarantine_key.status_code == 409
        assert r_quarantine_key.json()["error"]["code"] == "DOCUMENT_NOT_READY"


@pytest.mark.db
def test_provider_outages_malformed_output_retry_limits_and_unconfigured_provider(
    test_database_url: str,
    db_engine: Engine,
    clean_stage6_db: None,
    tmp_path: Path,
) -> None:
    """Verify unconfigured 503, provider outage/bad output recovery, retry limits, and stale recovery."""
    # Unconfigured provider fails safely with 503 AI_ANALYZER_NOT_CONFIGURED
    settings_none, app_none = _build_test_app(
        test_database_url,
        storage_dir=tmp_path / "none",
        ai_provider="none",
    )
    user = _create_db_user(db_engine, email="ai.fail@example.com")
    headers_none = _auth_headers(user, settings_none)

    with TestClient(app_none) as client:  # type: ignore[arg-type]
        up = client.post(
            "/api/v1/documents",
            headers=headers_none,
            files={"file": ("doc.pdf", VALID_PDF, "application/pdf")},
        )
        doc_id = up.json()["document"]["id"]
        unconf = client.post(f"/api/v1/documents/{doc_id}/analysis", headers=headers_none)
        assert unconf.status_code == 503
        assert "code" not in unconf.json()["error"]
        with build_sessionmaker(db_engine)() as s:
            assert (
                s.execute(
                    select(DocumentAnalysis).where(DocumentAnalysis.document_id == uuid.UUID(doc_id))
                ).scalar_one_or_none()
                is None
            )

    # Configured provider outages -> failed record, Document stays ready/trusted, retry recovers
    settings, app = _build_test_app(
        test_database_url,
        storage_dir=tmp_path / "retry",
        max_retries=2,
    )
    headers = _auth_headers(user, settings)
    session_factory = build_sessionmaker(db_engine)

    with TestClient(app) as client:  # type: ignore[arg-type]
        up_ok = client.post(
            "/api/v1/documents",
            headers=headers,
            files={"file": ("retry.pdf", VALID_PDF, "application/pdf")},
        )
        doc2_id = up_ok.json()["document"]["id"]

        with patch(
            "app.services.document_analysis_service.build_ai_analyzer_provider",
            return_value=MockDocumentAnalyzer(mode="timeout"),
        ):
            r1 = client.post(f"/api/v1/documents/{doc2_id}/analysis", headers=headers)
            assert r1.status_code == 201
            assert r1.json()["status"] == "failed"
            assert r1.json()["failure_reason"] == "provider_timeout"

        # Original document remains ready & trusted
        doc2_meta = client.get(f"/api/v1/documents/{doc2_id}", headers=headers).json()
        assert doc2_meta["processing_status"] == "ready"

        # Duplicate POST /analysis blocked with 409 ANALYSIS_ALREADY_EXISTS
        assert client.post(f"/api/v1/documents/{doc2_id}/analysis", headers=headers).status_code == 409

        # Retry succeeds when provider returns partial valid extraction
        with patch(
            "app.services.document_analysis_service.build_ai_analyzer_provider",
            return_value=MockDocumentAnalyzer(mode="partial"),
        ):
            r2 = client.post(f"/api/v1/documents/{doc2_id}/analysis/retry", headers=headers)
            assert r2.status_code == 200
            assert r2.json()["status"] == "completed"
            assert r2.json()["attempts"] == 2
            assert r2.json()["extracted_data"]["marksheet"]["total_marks_obtained"] is None
            assert len(r2.json()["uncertain_fields"]) == 2

        # Malformed output exhausts max_retries=2 and blocks further retries with 409
        up_bad = client.post(
            "/api/v1/documents",
            headers=headers,
            files={"file": ("bad_out.pdf", VALID_PDF, "application/pdf")},
        )
        doc3_id = up_bad.json()["document"]["id"]
        with patch(
            "app.services.document_analysis_service.build_ai_analyzer_provider",
            return_value=MockDocumentAnalyzer(mode="malformed_json"),
        ):
            fail1 = client.post(f"/api/v1/documents/{doc3_id}/analysis", headers=headers)
            assert fail1.json()["status"] == "failed"
            assert fail1.json()["failure_reason"] == "invalid_provider_output"

            fail2 = client.post(f"/api/v1/documents/{doc3_id}/analysis/retry", headers=headers)
            assert fail2.json()["status"] == "failed"

        exhausted = client.post(f"/api/v1/documents/{doc3_id}/analysis/retry", headers=headers)
        assert exhausted.status_code == 409
        assert exhausted.json()["error"]["code"] == "ANALYSIS_RETRIES_EXHAUSTED"

        # Stale 'processing' recovery
        up_stale = client.post(
            "/api/v1/documents",
            headers=headers,
            files={"file": ("stale_ai.pdf", VALID_PDF, "application/pdf")},
        )
        doc4_id = uuid.UUID(up_stale.json()["document"]["id"])
        with session_factory() as s:
            stale_row = DocumentAnalysis(
                id=uuid.uuid4(),
                document_id=doc4_id,
                user_id=user.id,
                status="processing",
                provider_name="mock",
                model_name="mock-academic-v1",
                analyzer_version="stage6-v1",
                attempts=1,
                started_at=datetime.now(timezone.utc) - timedelta(minutes=20),
                uncertain_fields=[],
            )
            s.add(stale_row)
            s.commit()
            stale_id = stale_row.id

        with session_factory() as s:
            assert document_analysis_service.recover_stale_analyses(s, settings=settings) == 1
            recovered = s.execute(
                select(DocumentAnalysis).where(DocumentAnalysis.id == stale_id)
            ).scalar_one()
            assert recovered.status == "failed"
            assert recovered.failure_reason == "provider_timeout"
