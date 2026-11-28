"""Phase 1 synchronous profile creation and management routes under /api/v1/profile/*."""

import uuid

from fastapi import APIRouter, Depends, File, Query, Response, UploadFile, status
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
    AvatarUploadResponse,
    PreferencesResponse,
    PreferencesUpdateRequest,
    PrivateProfileResponse,
    ProfileActivityResponse,
    ProfileLinkItem,
    ProfileLinksResponse,
    ProfileUpdateRequest,
    PublicSettingsResponse,
    PublicSettingsUpdateRequest,
    SlugAvailabilityResponse,
    SlugUpdateRequest,
)
from app.services import profile_service

router = APIRouter(prefix="/profile", tags=["Profile"])


def _to_private_profile(profile: UserProfile) -> PrivateProfileResponse:
    links_data = profile_service.resolve_profile_links(profile.links)
    return PrivateProfileResponse(
        id=profile.id,
        user_id=profile.user_id,
        slug=profile.slug,
        public_url=f"/@{profile.slug}" if profile.slug else None,
        full_name=profile.full_name,
        date_of_birth=profile.date_of_birth,
        headline=profile.headline,
        bio=profile.bio,
        location=profile.location,
        contact_email=profile.contact_email,
        phone=profile.phone,
        website=profile.website,
        links=ProfileLinksResponse(
            linkedin=links_data["linkedin"],
            github=links_data["github"],
            other=[ProfileLinkItem(**item) for item in links_data["other"]],
        ),
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
    """Update private profile fields and optionally mark onboarding complete."""
    profile = profile_service.update_profile(
        db,
        user_id=current_user.id,
        payload=payload,
        settings=settings,
    )
    return _to_private_profile(profile)


@router.post(
    "/me/avatar",
    response_model=AvatarUploadResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            rate_limit_dependency(
                "profile:upload-avatar",
                limit=20,
                window_seconds=900,
            )
        )
    ],
    summary="Upload or replace the authenticated user's profile picture",
)
def upload_my_avatar(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> AvatarUploadResponse:
    """Validate, store, and set the authenticated user's profile picture."""
    avatar_url = profile_service.upload_profile_avatar(
        db,
        user_id=current_user.id,
        upload_file=file,
        settings=settings,
    )
    return AvatarUploadResponse(avatar_url=avatar_url)


@router.delete(
    "/me/avatar",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(
            rate_limit_dependency(
                "profile:delete-avatar",
                limit=20,
                window_seconds=900,
            )
        )
    ],
    summary="Remove the authenticated user's profile picture",
)
def delete_my_avatar(
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> Response:
    """Clear the profile picture and remove its stored asset."""
    profile_service.remove_profile_avatar(
        db,
        user_id=current_user.id,
        settings=settings,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/avatars/{profile_id}",
    status_code=status.HTTP_200_OK,
    summary="Serve a user's uploaded profile picture",
)
def serve_profile_avatar(
    profile_id: uuid.UUID,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> Response:
    """Stream stored profile picture bytes with safe content headers."""
    mime_type, content = profile_service.get_profile_avatar_content(
        db,
        profile_id=profile_id,
        settings=settings,
    )
    return Response(
        content=content,
        media_type=mime_type,
        headers={
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "public, max-age=300",
        },
    )


@router.get(
    "/me/visibility",
    response_model=PublicSettingsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get the authenticated user's public profile visibility settings",
)
def get_my_visibility(
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> PublicSettingsResponse:
    """Return persisted public profile visibility settings for the authenticated user."""
    settings_data = profile_service.get_profile_visibility(db, user_id=current_user.id)
    return PublicSettingsResponse(**settings_data)


@router.patch(
    "/me/visibility",
    response_model=PublicSettingsResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            rate_limit_dependency(
                "profile:update-visibility",
                limit=30,
                window_seconds=900,
            )
        )
    ],
    summary="Update the authenticated user's public profile visibility settings",
)
def update_my_visibility(
    payload: PublicSettingsUpdateRequest,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> PublicSettingsResponse:
    """Persist partial updates to public profile visibility settings."""
    settings_data = profile_service.update_profile_visibility(
        db,
        user_id=current_user.id,
        payload=payload,
    )
    return PublicSettingsResponse(**settings_data)


@router.get(
    "/me/preferences",
    response_model=PreferencesResponse,
    status_code=status.HTTP_200_OK,
    summary="Get the authenticated user's interface preferences",
)
def get_my_preferences(
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> PreferencesResponse:
    """Return persisted interface preferences for the authenticated user."""
    theme = profile_service.get_profile_preferences(db, user_id=current_user.id)
    return PreferencesResponse(theme=theme)  # type: ignore[arg-type]


@router.patch(
    "/me/preferences",
    response_model=PreferencesResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            rate_limit_dependency(
                "profile:update-preferences",
                limit=30,
                window_seconds=900,
            )
        )
    ],
    summary="Update the authenticated user's interface preferences",
)
def update_my_preferences(
    payload: PreferencesUpdateRequest,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> PreferencesResponse:
    """Persist interface preferences for the authenticated user."""
    theme = profile_service.update_profile_preferences(
        db,
        user_id=current_user.id,
        theme=payload.theme,
    )
    return PreferencesResponse(theme=theme)  # type: ignore[arg-type]
