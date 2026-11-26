"""Unit tests for Phase 2 Stage 4 Document Vault schemas, storage, validation, and migration DDL."""

from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock
import uuid

from alembic.config import Config
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from fastapi import UploadFile
from pydantic import ValidationError
import pytest
from sqlalchemy import create_mock_engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex, CreateTable

from app.core.config import Settings
from app.core.exceptions import AppException, ValidationAppError
from app.db.base import Base
from app.models.document import Document, EducationDocument
from app.schemas.document import DocumentUpdateRequest
from app.services.document_service import (
    read_bounded_upload,
    sanitize_original_filename,
    sniff_mime_type,
)
from app.services.storage_service import (
    LocalFilesystemStorage,
    S3CompatibleStorage,
    generate_local_content_token,
    safe_content_disposition,
    verify_local_content_token,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_magic_byte_mime_sniffing() -> None:
    """Only PDF, JPEG, and PNG magic bytes are accepted regardless of filename or headers."""
    assert sniff_mime_type(b"%PDF-1.7\n...") == "application/pdf"
    assert sniff_mime_type(b"\xff\xd8\xff\xe0\x00\x10JFIF") == "image/jpeg"
    assert sniff_mime_type(b"\x89PNG\r\n\x1a\n\x00\x00") == "image/png"

    for fake_bytes in (
        b"MZ\x90\x00",
        b"<svg><script>alert(1)</script></svg>",
        b"#!/bin/sh\nrm -rf /",
        b"PK\x03\x04",
        b"plain text disguised as pdf",
    ):
        with pytest.raises(AppException) as exc_info:
            sniff_mime_type(fake_bytes)
        assert exc_info.value.status_code == 415
        assert exc_info.value.error_code == "UNSUPPORTED_FILE_TYPE"


def test_bounded_upload_streaming_size_limits() -> None:
    """Streaming upload rejects empty files (422) and oversized files (413) cleanly."""
    empty_upload = UploadFile(filename="empty.pdf", file=BytesIO(b""))
    with pytest.raises(ValidationAppError):
        read_bounded_upload(empty_upload, max_bytes=1024)

    oversized_upload = UploadFile(filename="big.pdf", file=BytesIO(b"%PDF-1.4\n" + b"x" * 2048))
    with pytest.raises(AppException) as exc_info:
        read_bounded_upload(oversized_upload, max_bytes=1024)
    assert exc_info.value.status_code == 413
    assert exc_info.value.error_code == "FILE_TOO_LARGE"

    valid_data = b"%PDF-1.4\n" + b"x" * 100
    valid_upload = UploadFile(filename="ok.pdf", file=BytesIO(valid_data))
    assert read_bounded_upload(valid_upload, max_bytes=1024) == valid_data


def test_filename_and_content_disposition_sanitization() -> None:
    """Path traversal, null bytes, and header injection characters are stripped."""
    assert (
        sanitize_original_filename("../../etc/passwd\x00.pdf", detected_mime="application/pdf")
        == "passwd.pdf"
    )
    assert (
        sanitize_original_filename("C:\\Users\\evil\\marksheet.png", detected_mime="image/png")
        == "marksheet.png"
    )
    assert sanitize_original_filename("...", detected_mime="image/jpeg") == "..."
    assert sanitize_original_filename("..", detected_mime="image/jpeg") == "document.jpg"

    disp = safe_content_disposition("attachment", 'bad"\r\n;name.pdf')
    assert "\r" not in disp and "\n" not in disp
    assert disp.startswith("attachment; filename=")
    assert "filename*=UTF-8''" in disp


def test_local_storage_put_read_delete_traversal_guard_and_hmac(tmp_path: Path) -> None:
    """LocalFilesystemStorage enforces UUID storage keys, atomic writes, and HMAC tokens."""
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        STORAGE_BACKEND="local",
        DOCUMENT_LOCAL_STORAGE_DIR=str(tmp_path),
        DOCUMENT_SIGNING_SECRET="unit-test-document-signing-secret-32chars",
        BACKEND_BASE_URL="http://localhost:8000",
    )
    storage = LocalFilesystemStorage(root_dir=str(tmp_path), settings=settings)

    user_id = uuid.uuid4()
    doc_id = uuid.uuid4()
    key = f"{user_id}/{doc_id}"
    payload = b"%PDF-1.7\nhello world"

    storage.put_object(storage_key=key, data=payload, content_type="application/pdf")
    assert storage.read_bytes(storage_key=key) == payload

    for bad_key in ("../escape", f"{user_id}/../other", "not-a-uuid/file.pdf"):
        with pytest.raises(AppException):
            storage.put_object(storage_key=bad_key, data=payload, content_type="application/pdf")

    url, expires_at = storage.generate_signed_url(
        document_id=doc_id,
        storage_key=key,
        filename="transcript.pdf",
        content_type="application/pdf",
        disposition="inline",
        ttl_seconds=300,
    )
    assert expires_at > datetime.now(timezone.utc)
    assert f"/api/v1/documents/{doc_id}/content" in url
    assert "disposition=inline" in url

    token = generate_local_content_token(
        document_id=doc_id,
        disposition="inline",
        expires_at_ts=int(expires_at.timestamp()),
        settings=settings,
    )
    assert verify_local_content_token(
        token, document_id=doc_id, disposition="inline", settings=settings
    )
    # Wrong disposition or wrong doc_id fails verification
    assert not verify_local_content_token(
        token, document_id=doc_id, disposition="attachment", settings=settings
    )
    assert not verify_local_content_token(
        token, document_id=uuid.uuid4(), disposition="inline", settings=settings
    )
    # Expired token fails verification
    expired = generate_local_content_token(
        document_id=doc_id,
        disposition="inline",
        expires_at_ts=100,
        settings=settings,
    )
    assert not verify_local_content_token(
        expired, document_id=doc_id, disposition="inline", settings=settings
    )

    storage.delete_object(storage_key=key)
    assert not (tmp_path / key).exists()


def test_s3_compatible_storage_adapter_with_mocked_boto3() -> None:
    """S3CompatibleStorage supports AWS S3 and Cloudflare R2 via boto3 without ACL exposure."""
    mock_client = MagicMock()
    mock_client.generate_presigned_url.return_value = "https://r2.example.com/bucket/signed"

    settings = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        STORAGE_BACKEND="s3",
        S3_ENDPOINT_URL="https://acct.r2.cloudflarestorage.com",
        S3_BUCKET_NAME="folio360-private-vault",
        S3_REGION="auto",
        S3_ACCESS_KEY_ID="test-access-key",
        S3_SECRET_ACCESS_KEY="test-secret-key",
    )
    storage = S3CompatibleStorage(settings=settings, client=mock_client)

    doc_id = uuid.uuid4()
    key = f"{uuid.uuid4()}/{doc_id}"
    storage.put_object(storage_key=key, data=b"%PDF-1.5\n", content_type="application/pdf")
    mock_client.put_object.assert_called_once_with(
        Bucket="folio360-private-vault",
        Key=key,
        Body=b"%PDF-1.5\n",
        ContentType="application/pdf",
    )

    url, _expires = storage.generate_signed_url(
        document_id=doc_id,
        storage_key=key,
        filename="sem5.pdf",
        content_type="application/pdf",
        disposition="attachment",
        ttl_seconds=180,
    )
    assert url == "https://r2.example.com/bucket/signed"
    mock_client.generate_presigned_url.assert_called_once()
    call_kwargs = mock_client.generate_presigned_url.call_args.kwargs
    assert call_kwargs["ExpiresIn"] == 180
    assert call_kwargs["Params"]["Bucket"] == "folio360-private-vault"
    assert call_kwargs["Params"]["ResponseContentType"] == "application/pdf"
    assert "attachment" in call_kwargs["Params"]["ResponseContentDisposition"]

    storage.delete_object(storage_key=key)
    mock_client.delete_object.assert_called_once_with(
        Bucket="folio360-private-vault",
        Key=key,
    )


def test_document_update_request_metadata_only_and_validation() -> None:
    """DocumentUpdateRequest forbids empty patches, extra fields, and invalid nulls."""
    with pytest.raises(ValidationError):
        DocumentUpdateRequest()

    with pytest.raises(ValidationError):
        DocumentUpdateRequest(title="OK", file_size=123)  # type: ignore[call-arg]

    for non_null in ("title", "category", "show_in_education"):
        with pytest.raises(ValidationError):
            DocumentUpdateRequest(**{non_null: None})

    valid = DocumentUpdateRequest(
        title="  Updated Marksheet  ",
        category="MARKSHEET",  # type: ignore[arg-type]
        notes=None,
        show_in_education=False,
    )
    assert valid.title == "Updated Marksheet"
    assert valid.category == "marksheet"
    assert valid.notes is None
    assert valid.show_in_education is False


def _compile_pg(ddl_element: object) -> str:
    return str(ddl_element.compile(dialect=postgresql.dialect())).strip()  # type: ignore[attr-defined]


def _normalize_create_table(ddl: str) -> tuple[str, list[str], set[str]]:
    lines = [line.strip().rstrip(",") for line in ddl.splitlines() if line.strip()]
    header = lines[0]
    body = lines[1:-1]
    col_lines = [line for line in body if not line.startswith("CONSTRAINT ")]
    constraint_lines = {line for line in body if line.startswith("CONSTRAINT ")}
    return header, col_lines, constraint_lines


def test_alembic_0007_and_0008_documents_migration_chain() -> None:
    """Verify migrations 0007 -> 0008 apply and downgrade cleanly with Stage 5 metadata."""
    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "alembic"))
    script = ScriptDirectory.from_config(cfg)

    rev_0007 = script.get_revision("0007_add_documents")
    rev_0008 = script.get_revision("0008_document_quarantine_scan")
    assert rev_0007 is not None and rev_0007.module is not None
    assert rev_0007.down_revision == "0006_add_educations"
    assert rev_0008 is not None and rev_0008.module is not None
    assert rev_0008.down_revision == "0007_add_documents"

    upgrade_0008_sql: list[str] = []
    upgrade_engine = create_mock_engine(
        "postgresql+psycopg://",
        lambda sql, *a, **kw: upgrade_0008_sql.append(_compile_pg(sql)),
    )
    mc_up = MigrationContext.configure(
        connection=upgrade_engine.connect(),
        opts={"target_metadata": Base.metadata},
    )
    with Operations.context(mc_up):
        rev_0008.module.upgrade()

    joined_up = "\n".join(upgrade_0008_sql)
    for col in ("storage_state", "scan_attempts", "scan_started_at", "scanned_at", "failure_reason"):
        assert f"ADD COLUMN {col}" in joined_up
    assert "ck_documents_status_storage_consistency" in joined_up
    assert "ix_documents_processing_status" in joined_up

    downgrade_0008_sql: list[str] = []
    downgrade_engine = create_mock_engine(
        "postgresql+psycopg://",
        lambda sql, *a, **kw: downgrade_0008_sql.append(_compile_pg(sql)),
    )
    mc_down = MigrationContext.configure(
        connection=downgrade_engine.connect(),
        opts={"target_metadata": Base.metadata},
    )
    with Operations.context(mc_down):
        rev_0008.module.downgrade()

    joined_down = "\n".join(downgrade_0008_sql)
    assert "DROP INDEX ix_documents_processing_status" in joined_down
    assert "DROP COLUMN storage_state" in joined_down
    assert "DROP COLUMN failure_reason" in joined_down
