"""Phase 2 Stage 4/5 Document Vault validation, quarantine, malware scan, and storage workflow."""

from datetime import datetime, timedelta, timezone
import hashlib
import logging
import math
from pathlib import Path
from typing import Literal
import uuid

from fastapi import UploadFile, status
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core.config import Settings
from app.core.exceptions import (
    AppException,
    ResourceNotFoundError,
    ValidationAppError,
)
from app.models.certificate import AchievementDocument, Certificate
from app.models.document import DOCUMENT_CATEGORIES, Document, EducationDocument
from app.models.experience import ExperienceDocument
from app.schemas.document import (
    DocumentCategory,
    DocumentMimeType,
    DocumentUpdateRequest,
    clean_document_notes,
    clean_document_title,
)
from app.services.auth_service import get_constraint_name
from app.services.file_validation import (
    sniff_and_validate_document_bytes,
    sniff_mime_type,
)
from app.services.malware_scanner import (
    MalwareScanner,
    MalwareScannerError,
    ScannerProtocolError,
    ScannerTimeoutError,
    ScannerUnavailableError,
    build_malware_scanner,
)
from app.services.storage_service import (
    LocalFilesystemStorage,
    StorageBackend,
    build_quarantine_storage_key,
    build_storage_backend,
    build_trusted_storage_key,
    is_trusted_storage_key,
    verify_local_content_token,
)

logger = logging.getLogger("folio360.document.service")

_NOT_FOUND_MESSAGE = "Document not found"
_NOT_FOUND_PUBLIC = "Document not found."
_NOT_FOUND_CODE = "DOCUMENT_NOT_FOUND"
_UPLOAD_CHUNK_SIZE = 65536

_MIME_DEFAULT_EXTENSIONS: dict[DocumentMimeType, str] = {
    "application/pdf": ".pdf",
    "image/jpeg": ".jpg",
    "image/png": ".png",
}

ALLOWED_DOCUMENT_STATUS_TRANSITIONS: dict[str, frozenset[str]] = {
    "pending_scan": frozenset({"scanning", "rejected"}),
    "scanning": frozenset({"ready", "rejected", "scan_failed"}),
    "scan_failed": frozenset({"pending_scan", "scanning"}),
    "ready": frozenset(),
    "rejected": frozenset(),
}


class InvalidDocumentStateTransitionError(AppException):
    """Raised when an invalid document processing_status transition is attempted."""

    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=f"Invalid document transition from {current_status!r} to {target_status!r}",
            status_code=status.HTTP_409_CONFLICT,
            public_message="Requested document state transition is not permitted.",
            error_code="INVALID_STATE_TRANSITION",
        )


def transition_document_status(doc: Document, target_status: str) -> None:
    """Validate and apply a state transition on doc.processing_status."""
    allowed = ALLOWED_DOCUMENT_STATUS_TRANSITIONS.get(doc.processing_status, frozenset())
    if target_status not in allowed:
        raise InvalidDocumentStateTransitionError(doc.processing_status, target_status)
    doc.processing_status = target_status


def sanitize_original_filename(
    raw_filename: str | None,
    *,
    detected_mime: DocumentMimeType,
) -> str:
    """Sanitize client filename to a safe basename without path traversal or control chars."""
    default_ext = _MIME_DEFAULT_EXTENSIONS[detected_mime]
    if not raw_filename:
        return f"document{default_ext}"
    normalized = raw_filename.replace("\\", "/")
    basename = Path(normalized).name
    cleaned = "".join(
        ch for ch in basename if ord(ch) >= 0x20 and ord(ch) != 0x7F and ch != "\x00"
    ).strip()
    if not cleaned or cleaned in {".", ".."}:
        return f"document{default_ext}"
    if len(cleaned) > 255:
        stem = Path(cleaned).stem[: 255 - len(default_ext)] or "document"
        return f"{stem}{default_ext}"
    return cleaned


def read_bounded_upload(upload_file: UploadFile, *, max_bytes: int) -> bytes:
    """Stream upload in bounded chunks, rejecting empty and oversized payloads."""
    chunks: list[bytes] = []
    total_read = 0
    while True:
        chunk = upload_file.file.read(_UPLOAD_CHUNK_SIZE)
        if not chunk:
            break
        total_read += len(chunk)
        if total_read > max_bytes:
            raise AppException(
                message="Uploaded document exceeds size limit",
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                public_message=f"File exceeds the maximum allowed limit of {max_bytes // (1024 * 1024)} MB.",
                error_code="FILE_TOO_LARGE",
            )
        chunks.append(chunk)

    if total_read == 0:
        raise ValidationAppError(
            message="Uploaded document is empty",
            public_message="Uploaded file must not be empty.",
            error_code="VALIDATION_ERROR",
        )
    return b"".join(chunks)


def _normalize_category(raw_category: str | None) -> DocumentCategory:
    if raw_category is None:
        return "other"
    cleaned = raw_category.strip().lower()
    if not cleaned:
        return "other"
    if cleaned not in DOCUMENT_CATEGORIES:
        raise ValidationAppError(
            message="Invalid document category",
            public_message=f"Category must be one of: {', '.join(DOCUMENT_CATEGORIES)}.",
            details={"field": "category"},
            error_code="VALIDATION_ERROR",
        )
    return cleaned  # type: ignore[return-value]


def _derive_title(raw_title: str | None, *, safe_filename: str) -> str:
    if raw_title is not None and raw_title.strip():
        try:
            return clean_document_title(raw_title)
        except ValueError as exc:
            raise ValidationAppError(
                message="Invalid document title",
                public_message=str(exc),
                details={"field": "title"},
                error_code="VALIDATION_ERROR",
            ) from None

    stem = Path(safe_filename).stem.strip() or safe_filename
    return stem[:255]


def _load_document_with_links(
    db: Session,
    *,
    document_id: uuid.UUID,
    user_id: uuid.UUID | None = None,
) -> Document | None:
    conditions = [Document.id == document_id]
    if user_id is not None:
        conditions.append(Document.user_id == user_id)
    stmt = (
        select(Document)
        .options(
            selectinload(Document.education_links).selectinload(
                EducationDocument.education
            ),
            selectinload(Document.certificates),
            selectinload(Document.achievement_links).selectinload(
                AchievementDocument.achievement
            ),
            selectinload(Document.experience_links).selectinload(
                ExperienceDocument.experience
            ),
        )
        .where(*conditions)
    )
    return db.execute(stmt).scalar_one_or_none()


def _mark_scan_failed(
    db: Session,
    *,
    document_id: uuid.UUID,
    failure_reason: str,
) -> None:
    doc = db.execute(
        select(Document).where(Document.id == document_id).with_for_update()
    ).scalar_one_or_none()
    if doc is None:
        db.rollback()
        return
    if doc.processing_status == "scanning":
        transition_document_status(doc, "scan_failed")
    doc.storage_state = "quarantine"
    doc.failure_reason = failure_reason
    doc.scanned_at = datetime.now(timezone.utc)
    db.commit()


def _mark_rejected(
    db: Session,
    *,
    document_id: uuid.UUID,
    failure_reason: str,
    settings: Settings,
    backend: StorageBackend,
) -> None:
    doc = db.execute(
        select(Document).where(Document.id == document_id).with_for_update()
    ).scalar_one_or_none()
    if doc is None:
        db.rollback()
        return
    quarantine_key = doc.storage_key
    if doc.processing_status != "rejected":
        transition_document_status(doc, "rejected")
    doc.failure_reason = failure_reason
    doc.scanned_at = datetime.now(timezone.utc)
    should_delete = settings.DOCUMENT_REJECTED_RETENTION_POLICY == "delete"
    doc.storage_state = "deleted" if should_delete else "quarantine"
    db.commit()

    if should_delete:
        backend.delete_object(storage_key=quarantine_key)


def process_document_scan(
    db: Session,
    *,
    document_id: uuid.UUID,
    settings: Settings,
    storage: StorageBackend | None = None,
    scanner: MalwareScanner | None = None,
    allow_retry: bool = False,
) -> Document:
    """
    Execute the atomic quarantine validation + malware-scan + promotion workflow.

    Concurrency & idempotency:
      - Uses FOR UPDATE SKIP LOCKED so concurrent callers do not duplicate-scan.
      - Terminal states ('ready', 'rejected') and active ('scanning') are safe no-ops.
      - Never leaves a document marked 'ready' unless storage promotion and DB commit succeed.
    """
    locked_doc = db.execute(
        select(Document)
        .where(Document.id == document_id)
        .with_for_update(skip_locked=True)
    ).scalar_one_or_none()
    if locked_doc is None:
        existing = _load_document_with_links(db, document_id=document_id)
        if existing is None:
            raise ResourceNotFoundError(
                message=_NOT_FOUND_MESSAGE,
                public_message=_NOT_FOUND_PUBLIC,
                error_code=_NOT_FOUND_CODE,
            )
        return existing

    if locked_doc.processing_status in {"ready", "rejected", "scanning"}:
        db.rollback()
        loaded = _load_document_with_links(db, document_id=document_id)
        if loaded is None:
            raise ResourceNotFoundError(
                message=_NOT_FOUND_MESSAGE,
                public_message=_NOT_FOUND_PUBLIC,
                error_code=_NOT_FOUND_CODE,
            )
        return loaded

    if locked_doc.processing_status == "scan_failed" and (
        not allow_retry or locked_doc.scan_attempts >= settings.DOCUMENT_SCAN_MAX_RETRIES
    ):
        db.rollback()
        loaded = _load_document_with_links(db, document_id=document_id)
        if loaded is None:
            raise ResourceNotFoundError(
                message=_NOT_FOUND_MESSAGE,
                public_message=_NOT_FOUND_PUBLIC,
                error_code=_NOT_FOUND_CODE,
            )
        return loaded

    transition_document_status(locked_doc, "scanning")
    locked_doc.scan_attempts += 1
    locked_doc.scan_started_at = datetime.now(timezone.utc)
    locked_doc.failure_reason = None
    locked_doc.storage_state = "quarantine"
    quarantine_key = locked_doc.storage_key
    expected_sha256 = locked_doc.sha256
    expected_mime = locked_doc.mime_type
    doc_user_id = locked_doc.user_id
    db.commit()

    backend = storage or build_storage_backend(settings)
    active_scanner = scanner or build_malware_scanner(settings)

    try:
        quarantine_bytes = backend.read_bytes(storage_key=quarantine_key)
        actual_sha256 = hashlib.sha256(quarantine_bytes).hexdigest()
        detected_mime = sniff_and_validate_document_bytes(quarantine_bytes)
        if actual_sha256 != expected_sha256 or detected_mime != expected_mime:
            raise ValidationAppError(
                message="Quarantined payload checksum or MIME mismatch",
                public_message="Uploaded file failed integrity verification.",
                error_code="MALFORMED_FILE",
            )
    except (AppException, ValidationAppError, OSError) as exc:
        logger.warning(
            "Document validation during scan failed: document_id=%s exception=%s",
            document_id,
            type(exc).__name__,
        )
        _mark_rejected(
            db,
            document_id=document_id,
            failure_reason="validation_failed",
            settings=settings,
            backend=backend,
        )
        loaded = _load_document_with_links(db, document_id=document_id)
        assert loaded is not None
        return loaded

    try:
        scan_result = active_scanner.scan_bytes(quarantine_bytes)
    except ScannerTimeoutError:
        logger.warning("Document malware scan timed out: document_id=%s", document_id)
        _mark_scan_failed(db, document_id=document_id, failure_reason="scanner_timeout")
        loaded = _load_document_with_links(db, document_id=document_id)
        assert loaded is not None
        return loaded
    except ScannerUnavailableError:
        logger.warning("Malware scanner unavailable: document_id=%s", document_id)
        _mark_scan_failed(db, document_id=document_id, failure_reason="scanner_unavailable")
        loaded = _load_document_with_links(db, document_id=document_id)
        assert loaded is not None
        return loaded
    except (ScannerProtocolError, MalwareScannerError, Exception) as exc:
        logger.error(
            "Malware scan failed unexpectedly: document_id=%s exception=%s",
            document_id,
            type(exc).__name__,
        )
        _mark_scan_failed(db, document_id=document_id, failure_reason="scanner_error")
        loaded = _load_document_with_links(db, document_id=document_id)
        assert loaded is not None
        return loaded

    if scan_result.verdict == "infected":
        logger.warning(
            "Malware detected in quarantined document: document_id=%s signature=%s",
            document_id,
            scan_result.signature or "unknown",
        )
        _mark_rejected(
            db,
            document_id=document_id,
            failure_reason="malware_detected",
            settings=settings,
            backend=backend,
        )
        loaded = _load_document_with_links(db, document_id=document_id)
        assert loaded is not None
        return loaded

    trusted_key = build_trusted_storage_key(
        doc_user_id,
        document_id,
        namespace=settings.DOCUMENT_TRUSTED_NAMESPACE,
    )
    try:
        backend.promote_object(
            source_key=quarantine_key,
            destination_key=trusted_key,
            content_type=expected_mime,
        )
    except Exception as exc:
        logger.error(
            "Quarantine-to-trusted promotion failed: document_id=%s exception=%s",
            document_id,
            type(exc).__name__,
        )
        _mark_scan_failed(db, document_id=document_id, failure_reason="promotion_failed")
        loaded = _load_document_with_links(db, document_id=document_id)
        assert loaded is not None
        return loaded

    try:
        ready_doc = db.execute(
            select(Document).where(Document.id == document_id).with_for_update()
        ).scalar_one_or_none()
        if ready_doc is None:
            db.rollback()
            backend.delete_object(storage_key=trusted_key)
            raise ResourceNotFoundError(
                message=_NOT_FOUND_MESSAGE,
                public_message=_NOT_FOUND_PUBLIC,
                error_code=_NOT_FOUND_CODE,
            )
        transition_document_status(ready_doc, "ready")
        ready_doc.storage_state = "trusted"
        ready_doc.storage_key = trusted_key
        ready_doc.scanned_at = datetime.now(timezone.utc)
        ready_doc.failure_reason = None
        db.commit()
    except ResourceNotFoundError:
        raise
    except Exception as exc:
        db.rollback()
        backend.delete_object(storage_key=trusted_key)
        logger.error(
            "Failed committing ready state after promotion: document_id=%s exception=%s",
            document_id,
            type(exc).__name__,
        )
        _mark_scan_failed(db, document_id=document_id, failure_reason="promotion_failed")

    loaded = _load_document_with_links(db, document_id=document_id)
    assert loaded is not None
    return loaded


def recover_stale_scans(db: Session, *, settings: Settings) -> int:
    """Reset stalled 'scanning' rows older than DOCUMENT_SCAN_STALE_SECONDS to 'scan_failed'."""
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=settings.DOCUMENT_SCAN_STALE_SECONDS
    )
    stale_docs = list(
        db.execute(
            select(Document)
            .where(
                Document.processing_status == "scanning",
                or_(
                    Document.scan_started_at.is_(None),
                    Document.scan_started_at < cutoff,
                ),
            )
            .with_for_update(skip_locked=True)
        )
        .scalars()
        .all()
    )
    if not stale_docs:
        db.rollback()
        return 0
    now = datetime.now(timezone.utc)
    for doc in stale_docs:
        transition_document_status(doc, "scan_failed")
        doc.storage_state = "quarantine"
        doc.failure_reason = "scanner_timeout"
        doc.scanned_at = now
    db.commit()
    return len(stale_docs)


def upload_document(
    db: Session,
    *,
    user_id: uuid.UUID,
    upload_file: UploadFile,
    category: str | None,
    title: str | None,
    notes: str | None,
    show_in_education: bool,
    settings: Settings,
    storage: StorageBackend | None = None,
    scanner: MalwareScanner | None = None,
) -> Document:
    """Validate, quarantine privately, persist pending metadata, and scan inline when configured."""
    data = read_bounded_upload(upload_file, max_bytes=settings.DOCUMENT_MAX_SIZE_BYTES)
    detected_mime = sniff_and_validate_document_bytes(data)
    safe_filename = sanitize_original_filename(
        upload_file.filename,
        detected_mime=detected_mime,
    )
    resolved_category = _normalize_category(category)
    resolved_title = _derive_title(title, safe_filename=safe_filename)

    try:
        resolved_notes = clean_document_notes(notes)
    except ValueError as exc:
        raise ValidationAppError(
            message="Invalid document notes",
            public_message=str(exc),
            details={"field": "notes"},
            error_code="VALIDATION_ERROR",
        ) from None

    sha256_hex = hashlib.sha256(data).hexdigest()
    doc_id = uuid.uuid4()
    quarantine_key = build_quarantine_storage_key(
        user_id,
        doc_id,
        namespace=settings.DOCUMENT_QUARANTINE_NAMESPACE,
    )
    backend = storage or build_storage_backend(settings)

    backend.put_object(
        storage_key=quarantine_key,
        data=data,
        content_type=detected_mime,
    )

    doc = Document(
        id=doc_id,
        user_id=user_id,
        title=resolved_title,
        original_filename=safe_filename,
        category=resolved_category,
        mime_type=detected_mime,
        size_bytes=len(data),
        page_count=None,
        sha256=sha256_hex,
        storage_backend=backend.backend_name,
        storage_key=quarantine_key,
        storage_state="quarantine",
        notes=resolved_notes,
        processing_status="pending_scan",
        scan_attempts=0,
        scan_started_at=None,
        scanned_at=None,
        failure_reason=None,
        show_in_education=show_in_education,
    )
    db.add(doc)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        backend.delete_object(storage_key=quarantine_key)
        constraint = get_constraint_name(exc)
        logger.error(
            "Document metadata persistence integrity error: constraint=%s",
            constraint or "unknown",
        )
        raise AppException(
            message=f"Document creation integrity failure: {constraint}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        ) from None
    except Exception as exc:
        db.rollback()
        backend.delete_object(storage_key=quarantine_key)
        logger.error(
            "Document metadata persistence failed; quarantine object cleaned up: exception=%s",
            type(exc).__name__,
        )
        raise AppException(
            message="Failed to persist document metadata",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        ) from None

    if settings.DOCUMENT_SCAN_PROCESSING_MODE == "inline":
        return process_document_scan(
            db,
            document_id=doc_id,
            settings=settings,
            storage=backend,
            scanner=scanner,
        )

    loaded = _load_document_with_links(db, document_id=doc_id, user_id=user_id)
    if loaded is None:
        raise AppException(
            message="Document disappeared immediately after commit",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    return loaded


def rescan_document(
    db: Session,
    *,
    user_id: uuid.UUID,
    document_id: uuid.UUID,
    settings: Settings,
    storage: StorageBackend | None = None,
    scanner: MalwareScanner | None = None,
) -> Document:
    """Retry scanning for an owned pending_scan or scan_failed document within retry bounds."""
    doc = get_document_by_id(db, user_id=user_id, document_id=document_id)
    if doc.processing_status not in {"pending_scan", "scan_failed"}:
        raise AppException(
            message="Document is not eligible for rescanning",
            status_code=status.HTTP_409_CONFLICT,
            public_message="Only pending or failed documents can be rescanned.",
            error_code="DOCUMENT_RESCAN_NOT_ALLOWED",
        )
    if doc.scan_attempts >= settings.DOCUMENT_SCAN_MAX_RETRIES:
        raise AppException(
            message="Document scan retry limit reached",
            status_code=status.HTTP_409_CONFLICT,
            public_message="Maximum scan retry limit reached. Please re-upload the document.",
            error_code="DOCUMENT_SCAN_RETRIES_EXHAUSTED",
        )
    if doc.storage_state != "quarantine":
        raise AppException(
            message="Document object is not in quarantine",
            status_code=status.HTTP_409_CONFLICT,
            public_message="Quarantined file is no longer available. Please re-upload the document.",
            error_code="DOCUMENT_NOT_READY",
        )
    return process_document_scan(
        db,
        document_id=document_id,
        settings=settings,
        storage=storage,
        scanner=scanner,
        allow_retry=True,
    )


def list_documents(
    db: Session,
    *,
    user_id: uuid.UUID,
    page: int,
    page_size: int,
    q: str | None = None,
    category: DocumentCategory | None = None,
    uploaded_from: datetime | None = None,
    uploaded_to: datetime | None = None,
) -> tuple[list[Document], int, int]:
    """List paginated documents owned by user_id with optional search/category/date filters."""
    conditions = [Document.user_id == user_id]
    if category is not None:
        conditions.append(Document.category == category)
    if uploaded_from is not None:
        conditions.append(Document.created_at >= uploaded_from)
    if uploaded_to is not None:
        conditions.append(Document.created_at <= uploaded_to)
    if q is not None and q.strip():
        pattern = f"%{q.strip()}%"
        conditions.append(
            or_(
                Document.title.ilike(pattern),
                Document.original_filename.ilike(pattern),
                Document.notes.ilike(pattern),
            )
        )

    total = int(
        db.execute(select(func.count(Document.id)).where(*conditions)).scalar_one()
    )
    total_pages = math.ceil(total / page_size) if total > 0 else 0
    offset = (page - 1) * page_size
    if total == 0 or offset >= total:
        return [], total, total_pages

    stmt = (
        select(Document)
        .options(
            selectinload(Document.education_links).selectinload(
                EducationDocument.education
            ),
            selectinload(Document.certificates),
            selectinload(Document.achievement_links).selectinload(
                AchievementDocument.achievement
            ),
            selectinload(Document.experience_links).selectinload(
                ExperienceDocument.experience
            ),
        )
        .where(*conditions)
        .order_by(Document.created_at.desc(), Document.id.desc())
        .offset(offset)
        .limit(page_size)
    )
    items = list(db.execute(stmt).scalars().all())
    return items, total, total_pages


def get_document_by_id(
    db: Session,
    *,
    user_id: uuid.UUID,
    document_id: uuid.UUID,
) -> Document:
    """Fetch a single document owned by user_id or raise 404 DOCUMENT_NOT_FOUND."""
    doc = _load_document_with_links(db, document_id=document_id, user_id=user_id)
    if doc is None:
        raise ResourceNotFoundError(
            message=_NOT_FOUND_MESSAGE,
            public_message=_NOT_FOUND_PUBLIC,
            error_code=_NOT_FOUND_CODE,
        )
    return doc


def update_document(
    db: Session,
    *,
    user_id: uuid.UUID,
    document_id: uuid.UUID,
    payload: DocumentUpdateRequest,
) -> Document:
    """Partially update metadata for an owned document (file replacement is disallowed)."""
    doc = db.execute(
        select(Document)
        .where(Document.id == document_id, Document.user_id == user_id)
        .with_for_update()
    ).scalar_one_or_none()
    if doc is None:
        raise ResourceNotFoundError(
            message=_NOT_FOUND_MESSAGE,
            public_message=_NOT_FOUND_PUBLIC,
            error_code=_NOT_FOUND_CODE,
        )

    fields = payload.model_fields_set
    if "title" in fields and payload.title is not None:
        doc.title = payload.title
    if "category" in fields and payload.category is not None:
        doc.category = payload.category
    if "notes" in fields:
        doc.notes = payload.notes
    if "show_in_education" in fields and payload.show_in_education is not None:
        doc.show_in_education = payload.show_in_education

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        constraint = get_constraint_name(exc)
        logger.error(
            "Unexpected constraint violation during document update: constraint=%s",
            constraint or "unknown",
        )
        raise AppException(
            message=f"Document update integrity failure: {constraint}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        ) from None

    loaded = _load_document_with_links(db, document_id=document_id, user_id=user_id)
    if loaded is None:
        raise ResourceNotFoundError(
            message=_NOT_FOUND_MESSAGE,
            public_message=_NOT_FOUND_PUBLIC,
            error_code=_NOT_FOUND_CODE,
        )
    return loaded


def _assert_document_accessible(
    doc: Document,
    *,
    trusted_namespace: str,
    for_content_stream: bool = False,
) -> None:
    """Fail-closed check ensuring only scanned/promoted trusted documents can be accessed."""
    if doc.processing_status == "rejected":
        raise AppException(
            message="Access blocked for rejected document",
            status_code=status.HTTP_403_FORBIDDEN,
            public_message="This document was rejected during security scanning and cannot be accessed.",
            error_code="DOCUMENT_REJECTED",
        )
    if doc.processing_status == "scan_failed":
        raise AppException(
            message="Access blocked for document with failed scan",
            status_code=(
                status.HTTP_403_FORBIDDEN
                if for_content_stream
                else status.HTTP_409_CONFLICT
            ),
            public_message="Security scanning failed for this document. Please rescan or re-upload.",
            error_code="DOCUMENT_NOT_READY" if for_content_stream else "DOCUMENT_SCAN_FAILED",
        )
    if (
        doc.processing_status != "ready"
        or doc.storage_state != "trusted"
        or not is_trusted_storage_key(
            doc.storage_key,
            trusted_namespace=trusted_namespace,
        )
    ):
        raise AppException(
            message="Access blocked until document security scan completes",
            status_code=(
                status.HTTP_403_FORBIDDEN
                if for_content_stream
                else status.HTTP_409_CONFLICT
            ),
            public_message="Document is still undergoing security validation and is not yet available.",
            error_code="DOCUMENT_NOT_READY",
        )


def get_document_signed_url(
    db: Session,
    *,
    user_id: uuid.UUID,
    document_id: uuid.UUID,
    disposition: Literal["inline", "attachment"],
    settings: Settings,
    storage: StorageBackend | None = None,
) -> tuple[Document, str, datetime]:
    """Authorize ownership + ready/trusted state and generate an expiring URL."""
    doc = get_document_by_id(db, user_id=user_id, document_id=document_id)
    _assert_document_accessible(
        doc,
        trusted_namespace=settings.DOCUMENT_TRUSTED_NAMESPACE,
    )
    backend = storage or build_storage_backend(settings)
    url, expires_at = backend.generate_signed_url(
        document_id=doc.id,
        storage_key=doc.storage_key,
        filename=doc.original_filename,
        content_type=doc.mime_type,
        disposition=disposition,
        ttl_seconds=settings.DOCUMENT_SIGNED_URL_TTL_SECONDS,
    )
    return doc, url, expires_at


def get_local_document_content(
    db: Session,
    *,
    document_id: uuid.UUID,
    token: str,
    disposition: Literal["inline", "attachment"],
    settings: Settings,
    storage: StorageBackend | None = None,
) -> tuple[Document, bytes]:
    """Validate HMAC token AND live ready/trusted status before serving local bytes."""
    if not verify_local_content_token(
        token,
        document_id=document_id,
        disposition=disposition,
        settings=settings,
    ):
        raise AppException(
            message="Invalid or expired document access token",
            status_code=status.HTTP_403_FORBIDDEN,
            public_message="Document access link is invalid or has expired.",
            error_code="FORBIDDEN",
        )

    doc = db.execute(
        select(Document).where(Document.id == document_id)
    ).scalar_one_or_none()
    if doc is None or doc.storage_backend != "local":
        raise ResourceNotFoundError(
            message=_NOT_FOUND_MESSAGE,
            public_message=_NOT_FOUND_PUBLIC,
            error_code=_NOT_FOUND_CODE,
        )

    _assert_document_accessible(
        doc,
        trusted_namespace=settings.DOCUMENT_TRUSTED_NAMESPACE,
        for_content_stream=True,
    )

    backend = storage or build_storage_backend(settings)
    if not isinstance(backend, LocalFilesystemStorage):
        raise ResourceNotFoundError(
            message="Local content route disabled when STORAGE_BACKEND is not local",
            public_message=_NOT_FOUND_PUBLIC,
            error_code=_NOT_FOUND_CODE,
        )

    content = backend.read_bytes(storage_key=doc.storage_key)
    return doc, content


def delete_document(
    db: Session,
    *,
    user_id: uuid.UUID,
    document_id: uuid.UUID,
    force: bool,
    settings: Settings,
    storage: StorageBackend | None = None,
) -> None:
    """Delete an owned document, blocking with 409 DOCUMENT_IN_USE unless force=True."""
    doc = db.execute(
        select(Document)
        .where(Document.id == document_id, Document.user_id == user_id)
        .with_for_update()
    ).scalar_one_or_none()
    if doc is None:
        raise ResourceNotFoundError(
            message=_NOT_FOUND_MESSAGE,
            public_message=_NOT_FOUND_PUBLIC,
            error_code=_NOT_FOUND_CODE,
        )

    edu_link_count = int(
        db.execute(
            select(func.count(EducationDocument.education_id)).where(
                EducationDocument.document_id == document_id
            )
        ).scalar_one()
    )
    cert_link_count = int(
        db.execute(
            select(func.count(Certificate.id)).where(
                Certificate.document_id == document_id
            )
        ).scalar_one()
    )
    ach_link_count = int(
        db.execute(
            select(func.count(AchievementDocument.achievement_id)).where(
                AchievementDocument.document_id == document_id
            )
        ).scalar_one()
    )
    exp_link_count = int(
        db.execute(
            select(func.count(ExperienceDocument.experience_id)).where(
                ExperienceDocument.document_id == document_id
            )
        ).scalar_one()
    )
    link_count = edu_link_count + cert_link_count + ach_link_count + exp_link_count
    if link_count > 0 and not force:
        raise AppException(
            message="Document is attached to one or more records",
            status_code=status.HTTP_409_CONFLICT,
            public_message="Document is attached to an education, certificate, achievement, or experience record. Unlink it or confirm forced deletion.",
            details={"linked_count": link_count},
            error_code="DOCUMENT_IN_USE",
        )

    storage_key = doc.storage_key
    storage_backend = doc.storage_backend
    storage_state = doc.storage_state
    db.delete(doc)
    db.commit()

    if storage_state != "deleted":
        if storage is not None:
            storage.delete_object(storage_key=storage_key)
        elif storage_backend == settings.STORAGE_BACKEND:
            build_storage_backend(settings).delete_object(storage_key=storage_key)


__all__ = [
    "ALLOWED_DOCUMENT_STATUS_TRANSITIONS",
    "InvalidDocumentStateTransitionError",
    "delete_document",
    "get_document_by_id",
    "get_document_signed_url",
    "get_local_document_content",
    "list_documents",
    "process_document_scan",
    "read_bounded_upload",
    "recover_stale_scans",
    "rescan_document",
    "sanitize_original_filename",
    "sniff_and_validate_document_bytes",
    "sniff_mime_type",
    "transition_document_status",
    "update_document",
    "upload_document",
]
