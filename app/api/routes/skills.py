"""Skills CRUD routes and gap-analysis placeholder under /api/v1/skills."""

import math
import uuid

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps.auth import get_current_settings, get_current_verified_user
from app.core.config import Settings
from app.core.exceptions import ResourceNotFoundError
from app.db.session import get_db
from app.models.skill import Skill
from app.models.user import User
from app.schemas.skill import (
    GapAnalysisRequest,
    GapAnalysisResponse,
    SkillBulkCreateRequest,
    SkillBulkCreateResponse,
    SkillCreate,
    SkillImportPreviewRequest,
    SkillImportPreviewResponse,
    SkillListResponse,
    SkillResponse,
    SkillUpdate,
)
from app.services.ai_analyzer_provider import (
    AIAnalyzerConfigError,
    AIProviderOutputError,
    AIProviderRateLimitError,
    AIProviderTimeoutError,
    AIProviderUnavailableError,
)
from app.services.skill_analysis_service import analyze_skill_gaps
from app.services.skill_import_service import bulk_create_skills, preview_skill_imports

router = APIRouter(prefix="/skills", tags=["Skills"])


def _get_owned_skill(
    db: Session,
    *,
    user_id: uuid.UUID,
    skill_id: uuid.UUID,
) -> Skill:
    skill = db.execute(
        select(Skill).where(Skill.id == skill_id, Skill.user_id == user_id)
    ).scalar_one_or_none()
    if skill is None:
        raise ResourceNotFoundError(
            message="Skill not found",
            public_message="Skill not found.",
            error_code="SKILL_NOT_FOUND",
        )
    return skill


def _create_skill_record(
    db: Session,
    *,
    user_id: uuid.UUID,
    payload: SkillCreate,
) -> Skill:
    skill = Skill(
        user_id=user_id,
        name=payload.name,
        category=payload.category,
        proficiency=payload.proficiency,
    )
    db.add(skill)
    db.commit()
    db.refresh(skill)
    return skill


def _update_skill_record(
    db: Session,
    *,
    user_id: uuid.UUID,
    skill_id: uuid.UUID,
    payload: SkillUpdate,
) -> Skill:
    skill = _get_owned_skill(db, user_id=user_id, skill_id=skill_id)
    updates = payload.model_dump(exclude_unset=True)
    for field, value in updates.items():
        if field in {"name", "category"} and value is None:
            continue
        setattr(skill, field, value)
    db.commit()
    db.refresh(skill)
    return skill


def _delete_skill_record(
    db: Session,
    *,
    user_id: uuid.UUID,
    skill_id: uuid.UUID,
) -> None:
    skill = _get_owned_skill(db, user_id=user_id, skill_id=skill_id)
    db.delete(skill)
    db.commit()


def _run_gap_analysis(
    db: Session,
    *,
    user_id: uuid.UUID,
    payload: GapAnalysisRequest,
) -> GapAnalysisResponse:
    skills = list(
        db.execute(
            select(Skill)
            .where(Skill.user_id == user_id)
            .order_by(Skill.created_at.desc())
        )
        .scalars()
        .all()
    )
    try:
        return analyze_skill_gaps(
            current_skills=skills,
            target_role=payload.target_role,
        )
    except AIAnalyzerConfigError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except AIProviderTimeoutError as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=str(exc),
        ) from exc
    except AIProviderRateLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
        ) from exc
    except (AIProviderUnavailableError, AIProviderOutputError) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc


@router.get(
    "",
    response_model=list[SkillResponse],
    status_code=status.HTTP_200_OK,
    summary="List all skills for the authenticated user",
)
def list_skills(
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> list[Skill]:
    """Return all skills owned by the authenticated user."""
    return list(
        db.execute(
            select(Skill)
            .where(Skill.user_id == current_user.id)
            .order_by(Skill.created_at.desc())
        )
        .scalars()
        .all()
    )


@router.get(
    "/me",
    response_model=SkillListResponse,
    status_code=status.HTTP_200_OK,
    summary="List paginated skills for the authenticated user",
)
def list_my_skills(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=200),
    category: str | None = Query(default=None),
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> SkillListResponse:
    """Return paginated skills owned by the authenticated user."""
    filters = [Skill.user_id == current_user.id]
    if category is not None and category.strip():
        filters.append(Skill.category == category.strip())

    total = db.execute(select(func.count()).select_from(Skill).where(*filters)).scalar_one()
    total_pages = max(1, math.ceil(total / page_size)) if total > 0 else 1
    offset = (page - 1) * page_size
    items = list(
        db.execute(
            select(Skill)
            .where(*filters)
            .order_by(Skill.created_at.desc())
            .offset(offset)
            .limit(page_size)
        )
        .scalars()
        .all()
    )
    return SkillListResponse(
        items=[SkillResponse.model_validate(item) for item in items],
        page=page,
        page_size=page_size,
        total=total,
        total_pages=total_pages,
    )


@router.post(
    "",
    response_model=SkillResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new skill for the authenticated user",
)
def create_skill(
    payload: SkillCreate,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> Skill:
    """Create a new skill owned by the authenticated user."""
    return _create_skill_record(db, user_id=current_user.id, payload=payload)


@router.post(
    "/me",
    response_model=SkillResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new skill for the authenticated user (/me alias)",
)
def create_my_skill(
    payload: SkillCreate,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> Skill:
    """Create a new skill owned by the authenticated user."""
    return _create_skill_record(db, user_id=current_user.id, payload=payload)


@router.post(
    "/analyze-gaps",
    response_model=GapAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze skill gaps against a target role",
)
def analyze_skill_gaps_endpoint(
    payload: GapAnalysisRequest,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> GapAnalysisResponse:
    """Compare authenticated user's skills against a target role via Gemini."""
    return _run_gap_analysis(db, user_id=current_user.id, payload=payload)


@router.post(
    "/me/analyze-gaps",
    response_model=GapAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze skill gaps against a target role (/me alias)",
)
def analyze_my_skill_gaps_endpoint(
    payload: GapAnalysisRequest,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> GapAnalysisResponse:
    """Compare authenticated user's skills against a target role via Gemini."""
    return _run_gap_analysis(db, user_id=current_user.id, payload=payload)


@router.post(
    "/import-preview",
    response_model=SkillImportPreviewResponse,
    status_code=status.HTTP_200_OK,
    summary="Extract candidate skills from projects and uploaded resumes",
)
def preview_skill_import_endpoint(
    payload: SkillImportPreviewRequest = Body(default_factory=SkillImportPreviewRequest),
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> SkillImportPreviewResponse:
    """Extract deduplicated skill candidates from the user's projects and uploaded resumes."""
    return preview_skill_imports(
        db,
        user_id=current_user.id,
        payload=payload,
        settings=settings,
    )


@router.post(
    "/me/import-preview",
    response_model=SkillImportPreviewResponse,
    status_code=status.HTTP_200_OK,
    summary="Extract candidate skills from projects and uploaded resumes (/me alias)",
)
def preview_my_skill_import_endpoint(
    payload: SkillImportPreviewRequest = Body(default_factory=SkillImportPreviewRequest),
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> SkillImportPreviewResponse:
    """Extract deduplicated skill candidates from the user's projects and uploaded resumes."""
    return preview_skill_imports(
        db,
        user_id=current_user.id,
        payload=payload,
        settings=settings,
    )


@router.post(
    "/bulk",
    response_model=SkillBulkCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Bulk-create skills with case-insensitive deduplication",
)
def bulk_create_skills_endpoint(
    payload: SkillBulkCreateRequest,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> SkillBulkCreateResponse:
    """Create multiple skills for the authenticated user, skipping duplicates."""
    return bulk_create_skills(db, user_id=current_user.id, payload=payload)


@router.post(
    "/me/bulk",
    response_model=SkillBulkCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Bulk-create skills with case-insensitive deduplication (/me alias)",
)
def bulk_create_my_skills_endpoint(
    payload: SkillBulkCreateRequest,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> SkillBulkCreateResponse:
    """Create multiple skills for the authenticated user, skipping duplicates."""
    return bulk_create_skills(db, user_id=current_user.id, payload=payload)


@router.put(
    "/{skill_id}",
    response_model=SkillResponse,
    status_code=status.HTTP_200_OK,
    summary="Update a skill owned by the authenticated user",
)
def update_skill(
    skill_id: uuid.UUID,
    payload: SkillUpdate,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> Skill:
    """Update a skill owned by the authenticated user."""
    return _update_skill_record(
        db, user_id=current_user.id, skill_id=skill_id, payload=payload
    )


@router.patch(
    "/me/{skill_id}",
    response_model=SkillResponse,
    status_code=status.HTTP_200_OK,
    summary="Partially update a skill owned by the authenticated user",
)
def patch_my_skill(
    skill_id: uuid.UUID,
    payload: SkillUpdate,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> Skill:
    """Partially update a skill owned by the authenticated user."""
    return _update_skill_record(
        db, user_id=current_user.id, skill_id=skill_id, payload=payload
    )


@router.delete(
    "/{skill_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a skill owned by the authenticated user",
)
def delete_skill(
    skill_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> Response:
    """Delete a skill owned by the authenticated user."""
    _delete_skill_record(db, user_id=current_user.id, skill_id=skill_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete(
    "/me/{skill_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a skill owned by the authenticated user (/me alias)",
)
def delete_my_skill(
    skill_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> Response:
    """Delete a skill owned by the authenticated user."""
    _delete_skill_record(db, user_id=current_user.id, skill_id=skill_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
