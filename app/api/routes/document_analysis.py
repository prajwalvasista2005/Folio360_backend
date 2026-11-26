"""Phase 2 Stage 6 synchronous Document AI Analysis routes under /api/v1/documents."""

import uuid

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps.auth import (
    get_current_settings,
    get_current_verified_user,
    rate_limit_dependency,
)
from app.core.config import Settings
from app.db.session import get_db
from app.models.document_analysis import DocumentAnalysis
from app.models.user import User
from app.schemas.document_analysis import (
    DocumentAnalysisResponse,
    DocumentExtractionPayload,
)
from app.services import document_analysis_service

router = APIRouter(prefix="/documents", tags=["Document Analysis"])


def _to_analysis_response(record: DocumentAnalysis) -> DocumentAnalysisResponse:
    extracted_payload = (
        DocumentExtractionPayload.model_validate(record.extracted_data)
        if record.extracted_data is not None
        else None
    )
    return DocumentAnalysisResponse(
        id=record.id,
        document_id=record.document_id,
        status=record.status,  # type: ignore[arg-type]
        document_type=record.document_type,  # type: ignore[arg-type]
        is_verified=False,
        provider_name=record.provider_name,
        model_name=record.model_name,
        analyzer_version=record.analyzer_version,
        attempts=record.attempts,
        summary=record.summary,
        extracted_data=extracted_payload,
        confidence=float(record.confidence) if record.confidence is not None else None,
        uncertain_fields=list(record.uncertain_fields or []),
        failure_reason=record.failure_reason,  # type: ignore[arg-type]
        started_at=record.started_at,
        completed_at=record.completed_at,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.post(
    "/{document_id}/analysis",
    response_model=DocumentAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            rate_limit_dependency(
                "documents:analysis_create",
                limit=10,
                window_seconds=900,
            )
        )
    ],
    summary="Request AI structured analysis for a scanned, trusted document",
)
def request_document_analysis(
    document_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> DocumentAnalysisResponse:
    """Run or enqueue AI structured analysis on an owned, ready, trusted document."""
    record = document_analysis_service.request_document_analysis(
        db,
        user_id=current_user.id,
        document_id=document_id,
        settings=settings,
    )
    return _to_analysis_response(record)


@router.get(
    "/{document_id}/analysis",
    response_model=DocumentAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve AI analysis status and unverified extraction results for a document",
)
def get_document_analysis(
    document_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> DocumentAnalysisResponse:
    """Return owner-scoped AI analysis status and unverified extraction payload."""
    record = document_analysis_service.get_document_analysis(
        db,
        user_id=current_user.id,
        document_id=document_id,
    )
    return _to_analysis_response(record)


@router.post(
    "/{document_id}/analysis/retry",
    response_model=DocumentAnalysisResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            rate_limit_dependency(
                "documents:analysis_retry",
                limit=10,
                window_seconds=900,
            )
        )
    ],
    summary="Retry a pending or failed AI document analysis",
)
def retry_document_analysis(
    document_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> DocumentAnalysisResponse:
    """Retry AI document analysis within configured retry limits."""
    record = document_analysis_service.retry_document_analysis(
        db,
        user_id=current_user.id,
        document_id=document_id,
        settings=settings,
    )
    return _to_analysis_response(record)
