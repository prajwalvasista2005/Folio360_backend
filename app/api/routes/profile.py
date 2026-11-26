"""Phase 1 synchronous profile creation and management routes under /api/v1/profile/*."""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.deps.auth import (
    get_current_settings,
    get_current_verified_user,
    rate_limit_dependency,
)
from app.core.config import Settings
from app.db.session import get_db
from app.models.profile import UserProfile
from app.models.user import User
from app.schemas.profile import (
    PrivateProfileResponse,
    ProfileActivityResponse,
    ProfileUpdateRequest,
    SlugAvailabilityResponse,
    SlugUpdateRequest,
)
from app.services import profile_service

router = APIRouter(prefix="/profile", tags=["Profile"])


def _to_private_profile(profile: UserProfile) -> PrivateProfileResponse:
    return PrivateProfileResponse(
        id=profile.id,
        user_id=profile.user_id,
        slug=profile.slug,
        full_name=profile.full_name,
        date_of_birth=profile.date_of_birth,
        bio=profile.bio,
        avatar_url=profile.profile_picture_url,
        interests=list(profile.interests or []),
        current_activities=[
            ProfileActivityResponse(
                key=activity.activity_key,  # type: ignore[arg-type]
                label=activity.custom_label,
                description=activity.description,
            )
            for activity in profile.activities
        ],
        profile_completed=profile.profile_completed,
        profile_completed_at=profile.profile_completed_at,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


@router.get(
    "/slug-availability",
    response_model=SlugAvailabilityResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            rate_limit_dependency(
                "profile:slug-availability",
                limit=60,
                window_seconds=900,
            )
        )
    ],
    summary="Check username/slug format and availability",
)
def check_slug_availability(
    slug: str = Query(..., description="Candidate username/slug to check."),
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> SlugAvailabilityResponse:
    """Validate slug format (422 if malformed) and check reserved/ownership availability."""
    normalized, available, reason = profile_service.check_slug_availability(
        db,
        raw_slug=slug,
        current_user_id=current_user.id,
    )
    return SlugAvailabilityResponse(
        slug=normalized,
        available=available,
        reason=reason,
    )


@router.patch(
    "/me/slug",
    response_model=PrivateProfileResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            rate_limit_dependency(
                "profile:update-slug",
                limit=20,
                window_seconds=900,
            )
        )
    ],
    summary="Set or update the authenticated user's unique profile slug",
)
def update_my_slug(
    payload: SlugUpdateRequest,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> PrivateProfileResponse:
    """Persist or update the authenticated user's unique slug."""
    profile = profile_service.update_profile_slug(
        db,
        user_id=current_user.id,
        slug=payload.slug,
    )
    return _to_private_profile(profile)


@router.get(
    "/me",
    response_model=PrivateProfileResponse,
    status_code=status.HTTP_200_OK,
    summary="Get the authenticated user's private profile",
)
def get_my_profile(
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> PrivateProfileResponse:
    """Return the authenticated user's private profile or 404 PROFILE_NOT_FOUND."""
    profile = profile_service.get_profile_by_user_id(
        db,
        user_id=current_user.id,
    )
    return _to_private_profile(profile)


@router.patch(
    "/me",
    response_model=PrivateProfileResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            rate_limit_dependency(
                "profile:update",
                limit=30,
                window_seconds=900,
            )
        )
    ],
    summary="Create draft or update the authenticated user's profile",
)
def update_my_profile(
    payload: ProfileUpdateRequest,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> PrivateProfileResponse:
    """Update Phase 1 private profile fields and optionally mark onboarding complete."""
    profile = profile_service.update_profile(
        db,
        user_id=current_user.id,
        payload=payload,
        settings=settings,
    )
    return _to_private_profile(profile)
