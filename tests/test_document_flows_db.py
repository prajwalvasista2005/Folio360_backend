"""End-to-end Phase 2 Stage 4 Document Vault upload, metadata, signed URL, security, and linking tests."""

from datetime import datetime, timezone
from pathlib import Path
import struct
from unittest.mock import patch
import uuid
import zlib

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import Engine, select, text

from app.core.config import Settings
from app.core.security import create_access_token, hash_password
from app.db.session import build_sessionmaker
from app.main import create_app
from app.models.document import Document
from app.models.user import User


def _build_minimal_png() -> bytes:
    def _chunk(chunk_type: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack("!I", len(data)) + chunk_type + data + struct.pack("!I", crc)

    ihdr_data = struct.pack("!IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat_data = zlib.compress(b"\x00\xff\x00\x00")
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr_data) + _chunk(b"IDAT", idat_data) + _chunk(b"IEND", b"")


PDF_BYTES = b"%PDF-1.7\n%Folio360-test-pdf\n1 0 obj\n<<>>\nendobj\n%%EOF\n"
PNG_BYTES = _build_minimal_png()
JPEG_BYTES = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00\x00\xff\xd9"
)


def _build_test_app(
    test_database_url: str,
    *,
    storage_dir: Path,
    max_size_bytes: int = 10 * 1024 * 1024,
) -> tuple[Settings, object]:
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL=test_database_url,
        JWT_SECRET_KEY="document-integration-jwt-secret-key-at-least-32-chars",
        JWT_ISSUER="folio360",
        JWT_AUDIENCE="folio360-api",
        JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15,
        REFRESH_TOKEN_EXPIRE_DAYS=14,
        REFRESH_TOKEN_ABSOLUTE_EXPIRE_DAYS=30,
        FRONTEND_BASE_URL="http://localhost:5173",
        BACKEND_BASE_URL="http://localhost:8000",
        CORS_ORIGINS=["http://localhost:5173"],
        RESEND_API_KEY="re_document_integration_mock_key",
        EMAIL_FROM_ADDRESS="no-reply@folio360.com",
        RATE_LIMIT_ENABLED=False,
        STORAGE_BACKEND="local",
        DOCUMENT_LOCAL_STORAGE_DIR=str(storage_dir),
        DOCUMENT_MAX_SIZE_BYTES=max_size_bytes,
        DOCUMENT_SIGNED_URL_TTL_SECONDS=300,
        MALWARE_SCANNER_BACKEND="mock",
    )
    return settings, create_app(settings=settings)


@pytest.fixture
def clean_document_db(db_engine: Engine):
    """Clean users (and cascaded documents/educations) before and after each test."""
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))
    yield
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))


def _create_db_user(
    db_engine: Engine,
    *,
    email: str,
    is_active: bool = True,
    is_email_verified: bool = True,
) -> User:
    session_factory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password("StrongPassword!2026"),
        is_active=is_active,
        is_email_verified=is_email_verified,
        email_verified_at=now if is_email_verified else None,
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
def test_document_upload_list_update_signed_preview_download_and_delete(
    test_database_url: str,
    db_engine: Engine,
    clean_document_db: None,
    tmp_path: Path,
) -> None:
    """Verify full Document Vault lifecycle with local storage and security headers."""
    settings, app = _build_test_app(test_database_url, storage_dir=tmp_path)
    user = _create_db_user(db_engine, email="doc.owner@example.com")
    headers = _auth_headers(user, settings)

    with TestClient(app) as client:  # type: ignore[arg-type]
        # Categories endpoint
        cats = client.get("/api/v1/documents/categories", headers=headers)
        assert cats.status_code == 200
        assert any(item["key"] == "marksheet" for item in cats.json()["items"])

        # Upload PDF with misleading filename & client MIME; magic bytes dictate stored MIME
        up_resp = client.post(
            "/api/v1/documents",
            headers=headers,
            files={"file": ("../../evil/sem5.pdf", PDF_BYTES, "application/octet-stream")},
            data={
                "category": "marksheet",
                "title": "Semester 5 Marksheet",
                "notes": "VTU 2021 scheme",
                "show_in_education": "true",
            },
        )
        assert up_resp.status_code == 201
        up_body = up_resp.json()
        assert up_body["processing_job"] is None
        doc = up_body["document"]
        doc_id = doc["id"]
        assert doc["title"] == "Semester 5 Marksheet"
        assert doc["original_filename"] == "sem5.pdf"
        assert doc["category"] == "marksheet"
        assert doc["mime_type"] == "application/pdf"
        assert doc["size_bytes"] == len(PDF_BYTES)
        assert len(doc["sha256"]) == 64
        assert doc["processing_status"] == "ready"
        assert doc["failure_reason"] is None
        assert doc["show_in_education"] is True
        assert doc["attached_to"] == []
        # Ensure internal storage path is never exposed
        assert "storage_key" not in doc
        assert str(tmp_path) not in str(doc)

        # Upload PNG as well to verify filter by category/search
        up_png = client.post(
            "/api/v1/documents",
            headers=headers,
            files={"file": ("cert.png", PNG_BYTES, "image/png")},
            data={"category": "certificate", "title": "AWS Certificate"},
        )
        assert up_png.status_code == 201

        # List + search + category filter
        list_all = client.get("/api/v1/documents", headers=headers).json()
        assert list_all["total"] == 2
        list_filtered = client.get(
            "/api/v1/documents?category=marksheet&q=VTU", headers=headers
        ).json()
        assert list_filtered["total"] == 1
        assert list_filtered["items"][0]["id"] == doc_id

        # Metadata-only PATCH
        patch_resp = client.patch(
            f"/api/v1/documents/{doc_id}",
            headers=headers,
            json={"title": "Sem 5 Official Marksheet", "show_in_education": False},
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["title"] == "Sem 5 Official Marksheet"
        assert patch_resp.json()["show_in_education"] is False

        # Preview & Download signed URLs -> stream local content with security headers
        prev_resp = client.get(f"/api/v1/documents/{doc_id}/preview", headers=headers)
        assert prev_resp.status_code == 200
        prev_data = prev_resp.json()
        assert prev_data["mime_type"] == "application/pdf"
        prev_path = prev_data["url"].replace("http://localhost:8000", "")
        stream_prev = client.get(prev_path)
        assert stream_prev.status_code == 200
        assert stream_prev.content == PDF_BYTES
        assert stream_prev.headers["x-content-type-options"] == "nosniff"
        assert "private" in stream_prev.headers["cache-control"]
        assert stream_prev.headers["content-disposition"].startswith("inline;")

        dl_resp = client.get(f"/api/v1/documents/{doc_id}/download", headers=headers)
        assert dl_resp.status_code == 200
        dl_path = dl_resp.json()["url"].replace("http://localhost:8000", "")
        stream_dl = client.get(dl_path)
        assert stream_dl.status_code == 200
        assert stream_dl.headers["content-disposition"].startswith("attachment;")

        # Wrong disposition or tampered HMAC token rejected with 403
        wrong_disp = prev_path.replace("disposition=inline", "disposition=attachment")
        assert client.get(wrong_disp).status_code == 403
        tampered_token = prev_path.replace("&disposition=inline", "X&disposition=inline")
        assert client.get(tampered_token).status_code == 403

        # Delete unattached document removes DB row and local file
        session_factory = build_sessionmaker(db_engine)
        with session_factory() as s:
            storage_key = s.execute(
                select(Document.storage_key).where(Document.id == uuid.UUID(doc_id))
            ).scalar_one()
        assert (tmp_path / storage_key).exists()

        del_resp = client.delete(f"/api/v1/documents/{doc_id}", headers=headers)
        assert del_resp.status_code == 204
        assert not (tmp_path / storage_key).exists()
        assert client.get(f"/api/v1/documents/{doc_id}", headers=headers).status_code == 404


@pytest.mark.db
def test_document_upload_validation_errors_and_storage_cleanup_on_db_failure(
    test_database_url: str,
    db_engine: Engine,
    clean_document_db: None,
    tmp_path: Path,
) -> None:
    """Verify 415/413/422 upload rejections and storage cleanup when DB commit fails."""
    settings, app = _build_test_app(
        test_database_url, storage_dir=tmp_path, max_size_bytes=1024
    )
    user = _create_db_user(db_engine, email="doc.validation@example.com")
    headers = _auth_headers(user, settings)

    with TestClient(app) as client:  # type: ignore[arg-type]
        # Disguised executable with .pdf extension -> 415 UNSUPPORTED_FILE_TYPE
        bad_magic = client.post(
            "/api/v1/documents",
            headers=headers,
            files={"file": ("fake.pdf", b"MZ\x90\x00not-a-pdf", "application/pdf")},
        )
        assert bad_magic.status_code == 415
        assert bad_magic.json()["error"]["code"] == "UNSUPPORTED_FILE_TYPE"

        # Oversized PDF -> 413 FILE_TOO_LARGE
        too_big = client.post(
            "/api/v1/documents",
            headers=headers,
            files={"file": ("big.pdf", b"%PDF-1.4\n" + b"a" * 2048, "application/pdf")},
        )
        assert too_big.status_code == 413
        assert too_big.json()["error"]["code"] == "FILE_TOO_LARGE"

        # Empty file -> 422
        empty = client.post(
            "/api/v1/documents",
            headers=headers,
            files={"file": ("empty.pdf", b"", "application/pdf")},
        )
        assert empty.status_code == 422

        # DB failure after put_object cleans up the orphaned file
        with patch("sqlalchemy.orm.Session.commit", side_effect=RuntimeError("db down")):
            failed = client.post(
                "/api/v1/documents",
                headers=headers,
                files={"file": ("ok.jpg", JPEG_BYTES, "image/jpeg")},
            )
            assert failed.status_code == 500
        leftover_files = [p for p in tmp_path.rglob("*") if p.is_file()]
        assert leftover_files == []


@pytest.mark.db
def test_document_ownership_and_education_in_use_delete_guard(
    test_database_url: str,
    db_engine: Engine,
    clean_document_db: None,
    tmp_path: Path,
) -> None:
    """Verify cross-user isolation, 409 DOCUMENT_IN_USE guard, and force=true deletion."""
    settings, app = _build_test_app(test_database_url, storage_dir=tmp_path)
    owner = _create_db_user(db_engine, email="doc.sec.owner@example.com")
    other = _create_db_user(db_engine, email="doc.sec.other@example.com")
    unverified = _create_db_user(
        db_engine, email="doc.sec.unver@example.com", is_email_verified=False
    )

    owner_headers = _auth_headers(owner, settings)
    other_headers = _auth_headers(other, settings)
    unverified_headers = _auth_headers(unverified, settings)

    with TestClient(app) as client:  # type: ignore[arg-type]
        assert client.get("/api/v1/documents").status_code == 401
        assert client.get("/api/v1/documents", headers=unverified_headers).status_code == 403

        up = client.post(
            "/api/v1/documents",
            headers=owner_headers,
            files={"file": ("deg.pdf", PDF_BYTES, "application/pdf")},
            data={"category": "certificate", "title": "Degree Certificate"},
        )
        assert up.status_code == 201
        doc_id = up.json()["document"]["id"]

        # Cross-user cannot list, get, patch, preview, download, delete, or link
        assert client.get("/api/v1/documents", headers=other_headers).json()["total"] == 0
        for resp in (
            client.get(f"/api/v1/documents/{doc_id}", headers=other_headers),
            client.patch(
                f"/api/v1/documents/{doc_id}",
                headers=other_headers,
                json={"title": "Hijacked"},
            ),
            client.get(f"/api/v1/documents/{doc_id}/preview", headers=other_headers),
            client.get(f"/api/v1/documents/{doc_id}/download", headers=other_headers),
            client.delete(f"/api/v1/documents/{doc_id}", headers=other_headers),
        ):
            assert resp.status_code == 404
            assert resp.json()["error"]["code"] == "DOCUMENT_NOT_FOUND"

        cross_link = client.post(
            "/api/v1/education",
            headers=other_headers,
            json={
                "institution": "Other Univ",
                "degree": "B.S.",
                "document_ids": [doc_id],
            },
        )
        assert cross_link.status_code == 422
        assert cross_link.json()["error"]["code"] == "INVALID_REFERENCE"

        # Owner links document to an Education record
        edu_resp = client.post(
            "/api/v1/education",
            headers=owner_headers,
            json={
                "institution": "RVCE",
                "degree": "B.E.",
                "document_ids": [doc_id],
            },
        )
        assert edu_resp.status_code == 201
        edu_id = edu_resp.json()["id"]
        assert edu_resp.json()["document_ids"] == [doc_id]
        assert edu_resp.json()["documents"] == [
            {
                "id": doc_id,
                "title": "Degree Certificate",
                "category": "certificate",
                "mime_type": "application/pdf",
            }
        ]

        # Document attached_to reflects the education link
        doc_meta = client.get(f"/api/v1/documents/{doc_id}", headers=owner_headers).json()
        assert len(doc_meta["attached_to"]) == 1
        assert doc_meta["attached_to"][0]["entity_type"] == "education"
        assert doc_meta["attached_to"][0]["entity_id"] == edu_id

        # Non-forced delete returns 409 DOCUMENT_IN_USE
        in_use_del = client.delete(f"/api/v1/documents/{doc_id}", headers=owner_headers)
        assert in_use_del.status_code == 409
        assert in_use_del.json()["error"]["code"] == "DOCUMENT_IN_USE"

        # Forced delete unlinks and deletes the document, leaving Education intact
        forced_del = client.delete(
            f"/api/v1/documents/{doc_id}?force=true", headers=owner_headers
        )
        assert forced_del.status_code == 204
        edu_after = client.get(f"/api/v1/education/{edu_id}", headers=owner_headers).json()
        assert edu_after["document_ids"] == []
        assert edu_after["documents"] == []
