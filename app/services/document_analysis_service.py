"""Phase 2 Stage 6 AI Document Analysis lifecycle, Stage 5 boundary checks, and retry orchestration."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import logging
import uuid

from fastapi import status
from pydantic import ValidationError
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import AppException, ResourceNotFoundError
from app.models.document import Document
from app.models.document_analysis import DocumentAnalysis
from app.schemas.document_analysis import DocumentExtractionPayload
from app.services.ai_analyzer_provider import (
    AIAnalyzerConfigError,
    AIAnalyzerError,
    AIAnalyzerProvider,
    AIProviderOutputError,
    AIProviderRateLimitError,
    AIProviderTimeoutError,
    AIProviderUnavailableError,
    build_ai_analyzer_provider,
)
from app.services.file_validation import SUPPORTED_DOCUMENT_MIME_TYPES
from app.services.storage_service import (
    StorageBackend,
    build_storage_backend,
    is_trusted_storage_key,
)

logger = logging.getLogger("folio360.document_analysis.service")

ANALYZER_VERSION = "stage6-v1"

ALLOWED_ANALYSIS_STATUS_TRANSITIONS: dict[str, frozenset[str]] = {
    "pending": frozenset({"processing", "failed"}),
    "processing": frozenset({"completed", "failed"}),
    "failed": frozenset({"pending", "processing"}),
    "completed": frozenset(),
}


class InvalidAnalysisStateTransitionError(AppException):
    """Raised when an invalid analysis status transition is attempted."""

    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=f"Invalid analysis transition from {current_status!r} to {target_status!r}",
            status_code=status.HTTP_409_CONFLICT,
            public_message="Requested analysis state transition is not permitted.",
            error_code="INVALID_STATE_TRANSITION",
        )


def transition_analysis_status(analysis: DocumentAnalysis, target_status: str) -> None:
    """Validate and apply an allowed status transition on a DocumentAnalysis record."""
    allowed = ALLOWED_ANALYSIS_STATUS_TRANSITIONS.get(analysis.status, frozenset())
    if target_status not in allowed:
        raise InvalidAnalysisStateTransitionError(analysis.status, target_status)
    analysis.status = target_status


def _get_owned_document(
    db: Session,
    *,
    user_id: uuid.UUID,
    document_id: uuid.UUID,
) -> Document:
    doc = db.execute(
        select(Document).where(
            Document.id == document_id,
            Document.user_id == user_id,
        )
    ).scalar_one_or_none()
    if doc is None:
        raise ResourceNotFoundError(
            message="Document not found",
            public_message="Document not found.",
            error_code="DOCUMENT_NOT_FOUND",
        )
    return doc


def _assert_document_eligible_for_analysis(
    doc: Document,
    *,
    settings: Settings,
) -> None:
    """Enforce strict Stage 5 trusted-storage boundary before any AI analysis."""
    if doc.processing_status == "rejected":
        raise AppException(
            message="Rejected document cannot be analyzed",
            status_code=status.HTTP_403_FORBIDDEN,
            public_message="Rejected documents cannot be analyzed.",
            error_code="DOCUMENT_REJECTED",
        )
    if doc.processing_status == "scan_failed":
        raise AppException(
            message="Scan-failed document cannot be analyzed",
            status_code=status.HTTP_409_CONFLICT,
            public_message="Document security scanning failed. Please rescan before analysis.",
            error_code="DOCUMENT_SCAN_FAILED",
        )
    if (
        doc.processing_status != "ready"
        or doc.storage_state != "trusted"
        or not is_trusted_storage_key(
            doc.storage_key,
            trusted_namespace=settings.DOCUMENT_TRUSTED_NAMESPACE,
        )
    ):
        raise AppException(
            message="Unscanned or quarantined document cannot be analyzed",
            status_code=status.HTTP_409_CONFLICT,
            public_message="Only scanned and trusted documents can be analyzed.",
            error_code="DOCUMENT_NOT_READY",
        )
    if doc.mime_type not in SUPPORTED_DOCUMENT_MIME_TYPES:
        raise AppException(
            message="Unsupported MIME type for AI analysis",
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            public_message="This document format is not supported for AI analysis.",
            error_code="UNSUPPORTED_FILE_TYPE",
        )
    if doc.size_bytes > settings.AI_ANALYZER_MAX_INPUT_BYTES:
        raise AppException(
            message="Document exceeds AI_ANALYZER_MAX_INPUT_BYTES limit",
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            public_message="Document exceeds the maximum size supported for AI analysis.",
            error_code="ANALYSIS_INPUT_TOO_LARGE",
        )


def _mark_analysis_failed(
    db: Session,
    *,
    analysis_id: uuid.UUID,
    failure_reason: str,
) -> None:
    analysis = db.execute(
        select(DocumentAnalysis)
        .where(DocumentAnalysis.id == analysis_id)
        .with_for_update()
    ).scalar_one_or_none()
    if analysis is None:
        db.rollback()
        return
    if analysis.status in {"pending", "processing"}:
        transition_analysis_status(analysis, "failed")
    analysis.failure_reason = failure_reason
    analysis.completed_at = datetime.now(timezone.utc)
    db.commit()


def process_document_analysis(
    db: Session,
    *,
    analysis_id: uuid.UUID,
    settings: Settings,
    storage: StorageBackend | None = None,
    provider: AIAnalyzerProvider | None = None,
    allow_retry: bool = False,
) -> DocumentAnalysis:
    """Claim an analysis row atomically, read trusted bytes, invoke AI provider, and persist result."""
    locked = db.execute(
        select(DocumentAnalysis)
        .where(DocumentAnalysis.id == analysis_id)
        .with_for_update(skip_locked=True)
    ).scalar_one_or_none()
    if locked is None:
        existing = db.execute(
            select(DocumentAnalysis).where(DocumentAnalysis.id == analysis_id)
        ).scalar_one_or_none()
        if existing is None:
            raise ResourceNotFoundError(
                message="Document analysis record not found",
                public_message="Document analysis not found.",
                error_code="ANALYSIS_NOT_FOUND",
            )
        return existing

    if locked.status in {"completed", "processing"}:
        db.rollback()
        return locked

    if locked.status == "failed" and (
        not allow_retry or locked.attempts >= settings.AI_ANALYZER_MAX_RETRIES
    ):
        db.rollback()
        return locked

    doc = db.execute(
        select(Document).where(Document.id == locked.document_id)
    ).scalar_one_or_none()
    if doc is None:
        db.rollback()
        raise ResourceNotFoundError(
            message="Source document not found",
            public_message="Document not found.",
            error_code="DOCUMENT_NOT_FOUND",
        )

    try:
        _assert_document_eligible_for_analysis(doc, settings=settings)
    except AppException:
        transition_analysis_status(locked, "failed")
        locked.failure_reason = "unsupported_content"
        locked.completed_at = datetime.now(timezone.utc)
        db.commit()
        return locked

    transition_analysis_status(locked, "processing")
    locked.attempts += 1
    locked.started_at = datetime.now(timezone.utc)
    locked.failure_reason = None
    doc_storage_key = doc.storage_key
    doc_sha256 = doc.sha256
    doc_mime_type = doc.mime_type
    doc_category = doc.category
    db.commit()

    backend = storage or build_storage_backend(settings)

    try:
        active_provider = provider or build_ai_analyzer_provider(settings)
    except AIAnalyzerConfigError:
        _mark_analysis_failed(
            db,
            analysis_id=analysis_id,
            failure_reason="provider_not_configured",
        )
        return db.execute(
            select(DocumentAnalysis).where(DocumentAnalysis.id == analysis_id)
        ).scalar_one()

    try:
        trusted_bytes = backend.read_bytes(storage_key=doc_storage_key)
        if hashlib.sha256(trusted_bytes).hexdigest() != doc_sha256:
            raise ValueError("Trusted document checksum mismatch")
    except Exception as exc:
        logger.warning(
            "Trusted document read/integrity check failed before AI analysis: analysis_id=%s exception=%s",
            analysis_id,
            type(exc).__name__,
        )
        _mark_analysis_failed(
            db,
            analysis_id=analysis_id,
            failure_reason="unsupported_content",
        )
        return db.execute(
            select(DocumentAnalysis).where(DocumentAnalysis.id == analysis_id)
        ).scalar_one()

    try:
        extraction = active_provider.analyze_document(
            data=trusted_bytes,
            mime_type=doc_mime_type,  # type: ignore[arg-type]
            category_hint=doc_category,
        )
        validated = DocumentExtractionPayload.model_validate(extraction)
    except AIAnalyzerConfigError:
        _mark_analysis_failed(
            db,
            analysis_id=analysis_id,
            failure_reason="provider_not_configured",
        )
    except AIProviderTimeoutError:
        logger.warning("AI analysis timed out: analysis_id=%s", analysis_id)
        _mark_analysis_failed(
            db,
            analysis_id=analysis_id,
            failure_reason="provider_timeout",
        )
    except AIProviderRateLimitError:
        logger.warning("AI provider rate limited analysis: analysis_id=%s", analysis_id)
        _mark_analysis_failed(
            db,
            analysis_id=analysis_id,
            failure_reason="provider_rate_limited",
        )
    except AIProviderUnavailableError:
        logger.warning("AI provider unavailable during analysis: analysis_id=%s", analysis_id)
        _mark_analysis_failed(
            db,
            analysis_id=analysis_id,
            failure_reason="provider_unavailable",
        )
    except (AIProviderOutputError, ValidationError):
        logger.warning("Invalid AI provider output for analysis_id=%s", analysis_id)
        _mark_analysis_failed(
            db,
            analysis_id=analysis_id,
            failure_reason="invalid_provider_output",
        )
    except (AIAnalyzerError, Exception) as exc:
        logger.error(
            "Unexpected AI analysis failure: analysis_id=%s exception=%s",
            analysis_id,
            type(exc).__name__,
        )
        _mark_analysis_failed(
            db,
            analysis_id=analysis_id,
            failure_reason="analysis_error",
        )
    else:
        completed = db.execute(
            select(DocumentAnalysis)
            .where(DocumentAnalysis.id == analysis_id)
            .with_for_update()
        ).scalar_one_or_none()
        if completed is None:
            db.rollback()
            raise ResourceNotFoundError(
                message="Document analysis record disappeared",
                public_message="Document analysis not found.",
                error_code="ANALYSIS_NOT_FOUND",
            )
        transition_analysis_status(completed, "completed")
        completed.document_type = validated.document_type
        completed.provider_name = active_provider.provider_name
        completed.model_name = active_provider.model_name
        completed.summary = validated.summary
        completed.extracted_data = validated.model_dump(mode="json")
        completed.confidence = (
            Decimal(f"{validated.confidence:.3f}")
            if validated.confidence is not None
            else None
        )
        completed.uncertain_fields = list(validated.uncertain_fields)
        completed.failure_reason = None
        completed.completed_at = datetime.now(timezone.utc)
        db.commit()

    refreshed = db.execute(
        select(DocumentAnalysis).where(DocumentAnalysis.id == analysis_id)
    ).scalar_one_or_none()
    if refreshed is None:
        raise ResourceNotFoundError(
            message="Document analysis not found after processing",
            public_message="Document analysis not found.",
            error_code="ANALYSIS_NOT_FOUND",
        )
    return refreshed


def request_document_analysis(
    db: Session,
    *,
    user_id: uuid.UUID,
    document_id: uuid.UUID,
    settings: Settings,
    storage: StorageBackend | None = None,
    provider: AIAnalyzerProvider | None = None,
) -> DocumentAnalysis:
    """Validate ownership + Stage 5 trusted state, create analysis record, and run or enqueue it."""
    doc = _get_owned_document(db, user_id=user_id, document_id=document_id)
    _assert_document_eligible_for_analysis(doc, settings=settings)

    try:
        active_provider = provider or build_ai_analyzer_provider(settings)
    except AIAnalyzerConfigError:
        raise AppException(
            message="AI analyzer provider is not configured",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            public_message="AI document analysis is not configured.",
            error_code="AI_ANALYZER_NOT_CONFIGURED",
        ) from None

    existing = db.execute(
        select(DocumentAnalysis).where(DocumentAnalysis.document_id == document_id)
    ).scalar_one_or_none()
    if existing is not None:
        if existing.status == "processing":
            raise AppException(
                message="Document analysis is already in progress",
                status_code=status.HTTP_409_CONFLICT,
                public_message="Document analysis is currently in progress.",
                error_code="ANALYSIS_IN_PROGRESS",
            )
        if existing.status == "completed":
            raise AppException(
                message="Document analysis already completed",
                status_code=status.HTTP_409_CONFLICT,
                public_message="Document analysis has already completed.",
                error_code="ANALYSIS_ALREADY_COMPLETED",
            )
        raise AppException(
            message="Document analysis already exists",
            status_code=status.HTTP_409_CONFLICT,
            public_message="An analysis record already exists for this document. Use retry to re-run it.",
            error_code="ANALYSIS_ALREADY_EXISTS",
        )

    analysis = DocumentAnalysis(
        id=uuid.uuid4(),
        document_id=doc.id,
        user_id=user_id,
        status="pending",
        provider_name=active_provider.provider_name,
        model_name=active_provider.model_name,
        analyzer_version=ANALYZER_VERSION,
        attempts=0,
        uncertain_fields=[],
    )
    db.add(analysis)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise AppException(
            message="Duplicate document analysis request blocked",
            status_code=status.HTTP_409_CONFLICT,
            public_message="An analysis record already exists for this document.",
            error_code="ANALYSIS_ALREADY_EXISTS",
        ) from None

    if settings.AI_ANALYZER_PROCESSING_MODE == "inline":
        return process_document_analysis(
            db,
            analysis_id=analysis.id,
            settings=settings,
            storage=storage,
            provider=active_provider,
        )

    db.refresh(analysis)
    return analysis


def get_document_analysis(
    db: Session,
    *,
    user_id: uuid.UUID,
    document_id: uuid.UUID,
) -> DocumentAnalysis:
    """Return owner-scoped AI analysis record for an owned document."""
    _get_owned_document(db, user_id=user_id, document_id=document_id)
    analysis = db.execute(
        select(DocumentAnalysis).where(
            DocumentAnalysis.document_id == document_id,
            DocumentAnalysis.user_id == user_id,
        )
    ).scalar_one_or_none()
    if analysis is None:
        raise ResourceNotFoundError(
            message="Document analysis not found",
            public_message="No analysis record found for this document.",
            error_code="ANALYSIS_NOT_FOUND",
        )
    return analysis


def retry_document_analysis(
    db: Session,
    *,
    user_id: uuid.UUID,
    document_id: uuid.UUID,
    settings: Settings,
    storage: StorageBackend | None = None,
    provider: AIAnalyzerProvider | None = None,
) -> DocumentAnalysis:
    """Retry a pending or failed AI analysis within configured retry limits."""
    doc = _get_owned_document(db, user_id=user_id, document_id=document_id)
    _assert_document_eligible_for_analysis(doc, settings=settings)

    try:
        active_provider = provider or build_ai_analyzer_provider(settings)
    except AIAnalyzerConfigError:
        raise AppException(
            message="AI analyzer provider is not configured",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            public_message="AI document analysis is not configured.",
            error_code="AI_ANALYZER_NOT_CONFIGURED",
        ) from None

    analysis = get_document_analysis(db, user_id=user_id, document_id=document_id)
    if analysis.status not in {"pending", "failed"}:
        raise AppException(
            message="Document analysis is not eligible for retry",
            status_code=status.HTTP_409_CONFLICT,
            public_message="Only pending or failed document analyses can be retried.",
            error_code="ANALYSIS_RETRY_NOT_ALLOWED",
        )
    if analysis.attempts >= settings.AI_ANALYZER_MAX_RETRIES:
        raise AppException(
            message="Document analysis retry limit exhausted",
            status_code=status.HTTP_409_CONFLICT,
            public_message="Maximum AI analysis retry attempts reached for this document.",
            error_code="ANALYSIS_RETRIES_EXHAUSTED",
        )

    return process_document_analysis(
        db,
        analysis_id=analysis.id,
        settings=settings,
        storage=storage,
        provider=active_provider,
        allow_retry=True,
    )


def recover_stale_analyses(db: Session, *, settings: Settings) -> int:
    """Transition stalled 'processing' analyses older than AI_ANALYZER_STALE_SECONDS to 'failed'."""
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=settings.AI_ANALYZER_STALE_SECONDS
    )
    stale_rows = list(
        db.execute(
            select(DocumentAnalysis)
            .where(
                DocumentAnalysis.status == "processing",
                or_(
                    DocumentAnalysis.started_at.is_(None),
                    DocumentAnalysis.started_at < cutoff,
                ),
            )
            .with_for_update(skip_locked=True)
        )
        .scalars()
        .all()
    )
    if not stale_rows:
        db.rollback()
        return 0
    now = datetime.now(timezone.utc)
    for row in stale_rows:
        transition_analysis_status(row, "failed")
        row.failure_reason = "provider_timeout"
        row.completed_at = now
    db.commit()
    return len(stale_rows)
