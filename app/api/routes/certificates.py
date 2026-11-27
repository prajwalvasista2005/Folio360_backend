"""Certificates CRUD routes under /api/v1/certificates."""

import uuid

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.orm import Session

from app.api.deps.auth import get_current_verified_user, rate_limit_dependency
from app.db.session import get_db
from app.models.certificate import Certificate
from app.models.user import User
from app.schemas.certificate import (
    CertificateCreate,
    CertificateListResponse,
    CertificateResponse,
    CertificateSkillRef,
    CertificateUpdate,
    CredentialVisibility,
)
from app.schemas.document import DocumentRef
from app.services import certificate_service

router = APIRouter(prefix="/certificates", tags=["Certificates"])


def to_certificate_response(record: Certificate) -> CertificateResponse:
    """Serialize a Certificate ORM record to CertificateResponse."""
    doc_ref = (
        DocumentRef(
            id=record.document.id,
            title=record.document.title,
            category=record.document.category,  # type: ignore[arg-type]
            mime_type=record.document.mime_type,  # type: ignore[arg-type]
        )
        if record.document is not None
        else None
    )
    skills = [
        CertificateSkillRef(id=link.skill.id, name=link.skill.name)
        for link in record.skill_links
        if link.skill is not None
    ]
    return CertificateResponse(
        id=record.id,
        name=record.name,
        issuer=record.issuer,
        category=record.category,  # type: ignore[arg-type]
        issue_date=record.issue_date,
        expiry_date=record.expiry_date,
        credential_id=record.credential_id,
        verification_url=record.verification_url,
        verification_status=record.verification_status,  # type: ignore[arg-type]
        document=doc_ref,
        skills=skills,
        featured=record.featured,
        order=record.display_order,
        visibility=record.visibility,  # type: ignore[arg-type]
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.get(
    "",
    response_model=CertificateListResponse,
    status_code=status.HTTP_200_OK,
    summary="List certificates owned by the authenticated user",
)
def list_my_certificates(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=200),
    q: str | None = Query(default=None, max_length=120),
    category: str | None = Query(default=None, max_length=40),
    visibility: CredentialVisibility | None = Query(default=None),
    featured: bool | None = Query(default=None),
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> CertificateListResponse:
    """List paginated certificates owned by the authenticated user."""
    items, total, total_pages = certificate_service.list_certificates(
        db,
        user_id=current_user.id,
        page=page,
        page_size=page_size,
        q=q,
        category=category,
        visibility=visibility,
        featured=featured,
    )
    return CertificateListResponse(
        items=[to_certificate_response(item) for item in items],
        page=page,
        page_size=page_size,
        total=total,
        total_pages=total_pages,
    )


@router.post(
    "",
    response_model=CertificateResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(rate_limit_dependency("certificates:create", limit=30, window_seconds=900))
    ],
    summary="Create a new certificate",
)
def create_my_certificate(
    payload: CertificateCreate,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> CertificateResponse:
    """Create a certificate owned by the authenticated user."""
    record = certificate_service.create_certificate(
        db,
        user_id=current_user.id,
        payload=payload,
    )
    return to_certificate_response(record)


@router.get(
    "/{certificate_id}",
    response_model=CertificateResponse,
    status_code=status.HTTP_200_OK,
    summary="Get one certificate owned by the authenticated user",
)
def get_my_certificate(
    certificate_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> CertificateResponse:
    """Return a single certificate owned by the authenticated user."""
    record = certificate_service.get_certificate_by_id(
        db,
        user_id=current_user.id,
        certificate_id=certificate_id,
    )
    return to_certificate_response(record)


@router.patch(
    "/{certificate_id}",
    response_model=CertificateResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(rate_limit_dependency("certificates:update", limit=60, window_seconds=900))
    ],
    summary="Partially update an owned certificate",
)
def update_my_certificate(
    certificate_id: uuid.UUID,
    payload: CertificateUpdate,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> CertificateResponse:
    """Partially update an owned certificate."""
    record = certificate_service.update_certificate(
        db,
        user_id=current_user.id,
        certificate_id=certificate_id,
        payload=payload,
    )
    return to_certificate_response(record)


@router.delete(
    "/{certificate_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(rate_limit_dependency("certificates:delete", limit=30, window_seconds=900))
    ],
    summary="Delete an owned certificate",
)
def delete_my_certificate(
    certificate_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> Response:
    """Delete an owned certificate (preserving Vault evidence documents)."""
    certificate_service.delete_certificate(
        db,
        user_id=current_user.id,
        certificate_id=certificate_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
