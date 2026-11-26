"""Phase 2 Stage 4 synchronous Document Vault routes under /api/v1/documents."""

from datetime import datetime
from typing import Literal
import uuid

from fastapi import APIRouter, Depends, File, Form, Query, Response, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps.auth import (
    get_current_settings,
    get_current_verified_user,
    rate_limit_dependency,
)
from app.core.config import Settings
from app.db.session import get_db
from app.models.document import Document
from app.models.user import User
from app.schemas.document import (
    DOCUMENT_CATEGORY_LABELS,
    DocumentAttachedToItem,
    DocumentCategoriesResponse,
    DocumentCategory,
    DocumentCategoryInfo,
    DocumentDownloadUrlResponse,
    DocumentListResponse,
    DocumentPreviewUrlResponse,
    DocumentResponse,
    DocumentUpdateRequest,
    DocumentUploadResponse,
)
from app.services import document_service
from app.services.storage_service import safe_content_disposition

router = APIRouter(prefix="/documents", tags=["Documents"])


def _to_document_response(doc: Document) -> DocumentResponse:
    attached_to: list[DocumentAttachedToItem] = []
    for link in doc.education_links:
        edu = link.education
        if edu is not None:
            label = f"{edu.degree} · {edu.institution}"
            attached_to.append(
                DocumentAttachedToItem(
                    entity_type="education",
                    entity_id=edu.id,
                    label=label,
                )
            )
    return DocumentResponse(
        id=doc.id,
        user_id=doc.user_id,
        title=doc.title,
        original_filename=doc.original_filename,
        category=doc.category,  # type: ignore[arg-type]
        mime_type=doc.mime_type,  # type: ignore[arg-type]
        size_bytes=doc.size_bytes,
        page_count=doc.page_count,
        sha256=doc.sha256,
        notes=doc.notes,
        processing_status=doc.processing_status,  # type: ignore[arg-type]
        failure_reason=doc.failure_reason,  # type: ignore[arg-type]
        show_in_education=doc.show_in_education,
        attached_to=attached_to,
        uploaded_at=doc.created_at,
        updated_at=doc.updated_at,
    )


@router.get(
    "/categories",
    response_model=DocumentCategoriesResponse,
    status_code=status.HTTP_200_OK,
    summary="List supported document categories",
)
def list_document_categories(
    current_user: User = Depends(get_current_verified_user),
) -> DocumentCategoriesResponse:
    """Return canonical Document Vault categories."""
    del current_user
    return DocumentCategoriesResponse(
        items=[
            DocumentCategoryInfo(key=key, label=label)
            for key, label in DOCUMENT_CATEGORY_LABELS.items()
        ]
    )


@router.post(
    "",
    response_model=DocumentUploadResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            rate_limit_dependency(
                "documents:upload",
                limit=20,
                window_seconds=900,
            )
        )
    ],
    summary="Upload a private document into the authenticated user's Document Vault",
)
def upload_document(
    file: UploadFile = File(...),
    category: str | None = Form(default="other"),
    title: str | None = Form(default=None),
    notes: str | None = Form(default=None),
    show_in_education: bool = Form(default=True),
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> DocumentUploadResponse:
    """Validate magic bytes and size, store privately, and persist metadata."""
    doc = document_service.upload_document(
        db,
        user_id=current_user.id,
        upload_file=file,
        category=category,
        title=title,
        notes=notes,
        show_in_education=show_in_education,
        settings=settings,
    )
    return DocumentUploadResponse(
        document=_to_document_response(doc),
        processing_job=None,
    )


@router.get(
    "",
    response_model=DocumentListResponse,
    status_code=status.HTTP_200_OK,
    summary="List the authenticated user's uploaded documents",
)
def list_my_documents(
    page: int = Query(default=1, ge=1, description="1-based page number."),
    page_size: int = Query(default=100, ge=1, le=200, description="Items per page."),
    q: str | None = Query(default=None, max_length=200),
    category: DocumentCategory | None = Query(default=None),
    uploaded_from: datetime | None = Query(default=None),
    uploaded_to: datetime | None = Query(default=None),
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> DocumentListResponse:
    """List paginated documents owned by the authenticated user."""
    items, total, total_pages = document_service.list_documents(
        db,
        user_id=current_user.id,
        page=page,
        page_size=page_size,
        q=q,
        category=category,
        uploaded_from=uploaded_from,
        uploaded_to=uploaded_to,
    )
    return DocumentListResponse(
        items=[_to_document_response(doc) for doc in items],
        page=page,
        page_size=page_size,
        total=total,
        total_pages=total_pages,
    )


@router.get(
    "/{document_id}",
    response_model=DocumentResponse,
    status_code=status.HTTP_200_OK,
    summary="Get metadata for one document owned by the authenticated user",
)
def get_my_document(
    document_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> DocumentResponse:
    """Return metadata for a single document owned by the authenticated user."""
    doc = document_service.get_document_by_id(
        db,
        user_id=current_user.id,
        document_id=document_id,
    )
    return _to_document_response(doc)


@router.patch(
    "/{document_id}",
    response_model=DocumentResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            rate_limit_dependency(
                "documents:update",
                limit=60,
                window_seconds=900,
            )
        )
    ],
    summary="Update metadata for a document owned by the authenticated user",
)
def update_my_document(
    document_id: uuid.UUID,
    payload: DocumentUpdateRequest,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> DocumentResponse:
    """Update document metadata only; file replacement uses delete and re-upload."""
    doc = document_service.update_document(
        db,
        user_id=current_user.id,
        document_id=document_id,
        payload=payload,
    )
    return _to_document_response(doc)


@router.post(
    "/{document_id}/rescan",
    response_model=DocumentResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            rate_limit_dependency(
                "documents:rescan",
                limit=10,
                window_seconds=900,
            )
        )
    ],
    summary="Retry malware scanning for an owned pending or scan-failed document",
)
def rescan_my_document(
    document_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> DocumentResponse:
    """Trigger malware rescan for a quarantined pending or failed document."""
    doc = document_service.rescan_document(
        db,
        user_id=current_user.id,
        document_id=document_id,
        settings=settings,
    )
    return _to_document_response(doc)


@router.get(
    "/{document_id}/preview",
    response_model=DocumentPreviewUrlResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate an expiring inline preview URL for an owned document",
)
def get_my_document_preview_url(
    document_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> DocumentPreviewUrlResponse:
    """Return a short-lived signed preview URL and MIME type."""
    doc, url, expires_at = document_service.get_document_signed_url(
        db,
        user_id=current_user.id,
        document_id=document_id,
        disposition="inline",
        settings=settings,
    )
    return DocumentPreviewUrlResponse(
        url=url,
        expires_at=expires_at,
        mime_type=doc.mime_type,  # type: ignore[arg-type]
    )


@router.get(
    "/{document_id}/download",
    response_model=DocumentDownloadUrlResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate an expiring attachment download URL for an owned document",
)
def get_my_document_download_url(
    document_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> DocumentDownloadUrlResponse:
    """Return a short-lived signed download URL."""
    _doc, url, expires_at = document_service.get_document_signed_url(
        db,
        user_id=current_user.id,
        document_id=document_id,
        disposition="attachment",
        settings=settings,
    )
    return DocumentDownloadUrlResponse(url=url, expires_at=expires_at)


@router.get(
    "/{document_id}/content",
    status_code=status.HTTP_200_OK,
    summary="Serve local-storage document bytes via short-lived HMAC-signed token",
)
def stream_local_document_content(
    document_id: uuid.UUID,
    token: str = Query(..., min_length=10, max_length=256),
    disposition: Literal["inline", "attachment"] = Query(default="inline"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> Response:
    """Serve private document bytes only when the short-lived HMAC token verifies."""
    doc, content = document_service.get_local_document_content(
        db,
        document_id=document_id,
        token=token,
        disposition=disposition,
        settings=settings,
    )
    return Response(
        content=content,
        media_type=doc.mime_type,
        headers={
            "Content-Disposition": safe_content_disposition(
                disposition,
                doc.original_filename,
            ),
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-store",
        },
    )


@router.delete(
    "/{document_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(
            rate_limit_dependency(
                "documents:delete",
                limit=30,
                window_seconds=900,
            )
        )
    ],
    summary="Delete an owned document and its stored object",
)
def delete_my_document(
    document_id: uuid.UUID,
    force: bool = Query(default=False),
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> Response:
    """Delete an owned document (409 DOCUMENT_IN_USE when attached unless force=true)."""
    document_service.delete_document(
        db,
        user_id=current_user.id,
        document_id=document_id,
        force=force,
        settings=settings,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
