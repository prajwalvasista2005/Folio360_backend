"""Achievements CRUD routes under /api/v1/achievements."""

import uuid

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.orm import Session

from app.api.deps.auth import get_current_verified_user, rate_limit_dependency
from app.db.session import get_db
from app.models.certificate import Achievement
from app.models.user import User
from app.schemas.certificate import (
    AchievementCreate,
    AchievementListResponse,
    AchievementResponse,
    AchievementUpdate,
    CredentialVisibility,
)
from app.schemas.document import DocumentRef
from app.services import certificate_service

router = APIRouter(prefix="/achievements", tags=["Achievements"])


def to_achievement_response(record: Achievement) -> AchievementResponse:
    """Serialize an Achievement ORM record to AchievementResponse."""
    docs = [
        DocumentRef(
            id=link.document.id,
            title=link.document.title,
            category=link.document.category,  # type: ignore[arg-type]
            mime_type=link.document.mime_type,  # type: ignore[arg-type]
        )
        for link in record.document_links
        if link.document is not None
    ]
    return AchievementResponse(
        id=record.id,
        title=record.title,
        category=record.category,  # type: ignore[arg-type]
        organization=record.organization,
        date=record.date,
        description=record.description,
        documents=docs,
        featured=record.featured,
        order=record.display_order,
        visibility=record.visibility,  # type: ignore[arg-type]
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.get(
    "",
    response_model=AchievementListResponse,
    status_code=status.HTTP_200_OK,
    summary="List achievements owned by the authenticated user",
)
def list_my_achievements(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=200),
    q: str | None = Query(default=None, max_length=120),
    category: str | None = Query(default=None, max_length=40),
    visibility: CredentialVisibility | None = Query(default=None),
    featured: bool | None = Query(default=None),
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> AchievementListResponse:
    """List paginated achievements owned by the authenticated user."""
    items, total, total_pages = certificate_service.list_achievements(
        db,
        user_id=current_user.id,
        page=page,
        page_size=page_size,
        q=q,
        category=category,
        visibility=visibility,
        featured=featured,
    )
    return AchievementListResponse(
        items=[to_achievement_response(item) for item in items],
        page=page,
        page_size=page_size,
        total=total,
        total_pages=total_pages,
    )


@router.post(
    "",
    response_model=AchievementResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(rate_limit_dependency("achievements:create", limit=30, window_seconds=900))
    ],
    summary="Create a new achievement",
)
def create_my_achievement(
    payload: AchievementCreate,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> AchievementResponse:
    """Create an achievement owned by the authenticated user."""
    record = certificate_service.create_achievement(
        db,
        user_id=current_user.id,
        payload=payload,
    )
    return to_achievement_response(record)


@router.get(
    "/{achievement_id}",
    response_model=AchievementResponse,
    status_code=status.HTTP_200_OK,
    summary="Get one achievement owned by the authenticated user",
)
def get_my_achievement(
    achievement_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> AchievementResponse:
    """Return a single achievement owned by the authenticated user."""
    record = certificate_service.get_achievement_by_id(
        db,
        user_id=current_user.id,
        achievement_id=achievement_id,
    )
    return to_achievement_response(record)


@router.patch(
    "/{achievement_id}",
    response_model=AchievementResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(rate_limit_dependency("achievements:update", limit=60, window_seconds=900))
    ],
    summary="Partially update an owned achievement",
)
def update_my_achievement(
    achievement_id: uuid.UUID,
    payload: AchievementUpdate,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> AchievementResponse:
    """Partially update an owned achievement."""
    record = certificate_service.update_achievement(
        db,
        user_id=current_user.id,
        achievement_id=achievement_id,
        payload=payload,
    )
    return to_achievement_response(record)


@router.delete(
    "/{achievement_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(rate_limit_dependency("achievements:delete", limit=30, window_seconds=900))
    ],
    summary="Delete an owned achievement",
)
def delete_my_achievement(
    achievement_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> Response:
    """Delete an owned achievement (preserving Vault evidence documents)."""
    certificate_service.delete_achievement(
        db,
        user_id=current_user.id,
        achievement_id=achievement_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
