"""Experience CRUD routes under /api/v1/experience."""

import uuid

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.orm import Session

from app.api.deps.auth import get_current_verified_user, rate_limit_dependency
from app.db.session import get_db
from app.models.experience import Experience
from app.models.user import User
from app.schemas.document import DocumentRef
from app.schemas.experience import (
    ExperienceCreate,
    ExperienceListResponse,
    ExperienceResponse,
    ExperienceSkillRef,
    ExperienceType,
    ExperienceUpdate,
    ExperienceVisibility,
)
from app.services import experience_service

router = APIRouter(prefix="/experience", tags=["Experience"])


def to_experience_response(record: Experience) -> ExperienceResponse:
    """Serialize an Experience ORM record to ExperienceResponse."""
    skills = [
        ExperienceSkillRef(id=link.skill.id, name=link.skill.name)
        for link in record.skill_links
        if link.skill is not None
    ]
    documents = [
        DocumentRef(
            id=link.document.id,
            title=link.document.title,
            category=link.document.category,  # type: ignore[arg-type]
            mime_type=link.document.mime_type,  # type: ignore[arg-type]
        )
        for link in record.document_links
        if link.document is not None
    ]
    return ExperienceResponse(
        id=record.id,
        type=record.type,  # type: ignore[arg-type]
        organization=record.organization,
        role=record.role,
        location=record.location,
        is_remote=record.is_remote,
        organization_url=record.organization_url,
        start_date=record.start_date,
        end_date=record.end_date,
        is_current=record.is_current,
        description=record.description,
        highlights=list(record.highlights or []),
        skills=skills,
        documents=documents,
        featured=record.featured,
        order=record.display_order,
        visibility=record.visibility,  # type: ignore[arg-type]
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.get(
    "",
    response_model=ExperienceListResponse,
    status_code=status.HTTP_200_OK,
    summary="List experience records owned by the authenticated user",
)
def list_my_experiences(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=200),
    q: str | None = Query(default=None, max_length=120),
    type: ExperienceType | None = Query(default=None),
    visibility: ExperienceVisibility | None = Query(default=None),
    featured: bool | None = Query(default=None),
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> ExperienceListResponse:
    """List paginated experience records owned by the authenticated user."""
    items, total, total_pages = experience_service.list_experiences(
        db,
        user_id=current_user.id,
        experience_type=type,
        visibility=visibility,
        featured=featured,
        query_text=q,
        page=page,
        page_size=page_size,
    )
    return ExperienceListResponse(
        items=[to_experience_response(item) for item in items],
        page=page,
        page_size=page_size,
        total=total,
        total_pages=total_pages,
    )


@router.post(
    "",
    response_model=ExperienceResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(rate_limit_dependency("experience:create", limit=30, window_seconds=900))
    ],
    summary="Create a new experience record",
)
def create_my_experience(
    payload: ExperienceCreate,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> ExperienceResponse:
    """Create an experience record owned by the authenticated user."""
    record = experience_service.create_experience(
        db,
        user_id=current_user.id,
        payload=payload,
    )
    return to_experience_response(record)


@router.get(
    "/{experience_id}",
    response_model=ExperienceResponse,
    status_code=status.HTTP_200_OK,
    summary="Get one experience record owned by the authenticated user",
)
def get_my_experience(
    experience_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> ExperienceResponse:
    """Return a single experience record owned by the authenticated user."""
    record = experience_service.get_owned_experience(
        db,
        experience_id=experience_id,
        user_id=current_user.id,
    )
    return to_experience_response(record)


@router.patch(
    "/{experience_id}",
    response_model=ExperienceResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(rate_limit_dependency("experience:update", limit=60, window_seconds=900))
    ],
    summary="Partially update an owned experience record",
)
def update_my_experience(
    experience_id: uuid.UUID,
    payload: ExperienceUpdate,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> ExperienceResponse:
    """Partially update an owned experience record."""
    record = experience_service.update_experience(
        db,
        experience_id=experience_id,
        user_id=current_user.id,
        payload=payload,
    )
    return to_experience_response(record)


@router.delete(
    "/{experience_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(rate_limit_dependency("experience:delete", limit=30, window_seconds=900))
    ],
    summary="Delete an owned experience record",
)
def delete_my_experience(
    experience_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> Response:
    """Delete an owned experience record without deleting linked Vault documents."""
    experience_service.delete_experience(
        db,
        experience_id=experience_id,
        user_id=current_user.id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
