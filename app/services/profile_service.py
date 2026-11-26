"""Phase 1 synchronous profile creation, slug availability, and update service."""

from datetime import datetime, timezone
import logging
from typing import Literal
import uuid

from fastapi import status
from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core.config import Settings
from app.core.exceptions import (
    AppException,
    ResourceNotFoundError,
    ValidationAppError,
)
from app.core.username import (
    is_reserved_slug,
    validate_assignable_slug,
    validate_safe_avatar_url,
    validate_slug_format,
)
from app.models.profile import UserProfile, UserProfileActivity
from app.schemas.profile import ProfileUpdateRequest
from app.services.auth_service import get_constraint_name

logger = logging.getLogger("folio360.profile.service")


def is_profile_completed(db: Session, *, user_id: uuid.UUID) -> bool:
    """Return True if the user has a completed profile record."""
    stmt = select(
        exists().where(
            UserProfile.user_id == user_id,
            UserProfile.profile_completed.is_(True),
        )
    )
    return bool(db.execute(stmt).scalar_one())


def check_slug_availability(
    db: Session,
    *,
    raw_slug: str,
    current_user_id: uuid.UUID,
) -> tuple[str, bool, Literal["taken", "reserved"] | None]:
    """
    Validate slug format and check reserved/database availability.

    Malformed slugs raise ValidationAppError (HTTP 422).
    Slugs already owned by current_user_id return available=True.
    """
    try:
        normalized = validate_slug_format(raw_slug)
    except ValueError as exc:
        raise ValidationAppError(
            message="Malformed slug query parameter",
            public_message=str(exc),
            error_code="VALIDATION_ERROR",
        ) from None

    if is_reserved_slug(normalized):
        return normalized, False, "reserved"

    owner_id = db.execute(
        select(UserProfile.user_id).where(UserProfile.slug == normalized)
    ).scalar_one_or_none()
    if owner_id is None or owner_id == current_user_id:
        return normalized, True, None

    return normalized, False, "taken"


def _load_profile_with_activities(
    db: Session,
    *,
    user_id: uuid.UUID,
) -> UserProfile | None:
    stmt = (
        select(UserProfile)
        .options(selectinload(UserProfile.activities))
        .where(UserProfile.user_id == user_id)
    )
    return db.execute(stmt).scalar_one_or_none()


def get_profile_by_user_id(db: Session, *, user_id: uuid.UUID) -> UserProfile:
    """Retrieve the authenticated user's profile or raise 404 PROFILE_NOT_FOUND."""
    profile = _load_profile_with_activities(db, user_id=user_id)
    if profile is None:
        raise ResourceNotFoundError(
            message="User profile not found",
            public_message="Profile not found.",
            error_code="PROFILE_NOT_FOUND",
        )
    return profile


def _lock_or_init_profile(
    db: Session,
    *,
    user_id: uuid.UUID,
) -> tuple[UserProfile, bool]:
    profile = db.execute(
        select(UserProfile)
        .where(UserProfile.user_id == user_id)
        .with_for_update()
    ).scalar_one_or_none()
    if profile is not None:
        return profile, False

    profile = UserProfile(
        id=uuid.uuid4(),
        user_id=user_id,
        interests=[],
        profile_completed=False,
        profile_completed_at=None,
    )
    db.add(profile)
    return profile, True


def update_profile_slug(
    db: Session,
    *,
    user_id: uuid.UUID,
    slug: str,
) -> UserProfile:
    """Create or update the authenticated user's unique profile slug."""
    try:
        normalized = validate_assignable_slug(slug)
    except ValueError as exc:
        raise ValidationAppError(
            message="Invalid slug",
            public_message=str(exc),
            error_code="VALIDATION_ERROR",
        ) from None

    for attempt in range(2):
        profile, _created = _lock_or_init_profile(db, user_id=user_id)
        if profile.slug != normalized:
            profile.slug = normalized

        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            constraint = get_constraint_name(exc)
            if constraint == "uq_user_profiles_slug":
                raise AppException(
                    message="Profile slug already in use",
                    status_code=status.HTTP_409_CONFLICT,
                    public_message="This username is already taken.",
                    error_code="SLUG_TAKEN",
                ) from None
            if constraint == "uq_user_profiles_user_id" and attempt == 0:
                continue
            logger.error(
                "Unexpected database constraint violation during slug update: constraint=%s",
                constraint or "unknown",
            )
            raise AppException(
                message=f"Profile slug update integrity failure: {constraint}",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            ) from None

        loaded = _load_profile_with_activities(db, user_id=user_id)
        if loaded is None:
            raise AppException(
                message="Profile disappeared immediately after commit",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        return loaded

    raise AppException(
        message="Profile slug update failed after concurrent initialization retry",
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )


def _apply_profile_fields(
    db: Session,
    *,
    profile: UserProfile,
    payload: ProfileUpdateRequest,
    settings: Settings,
) -> None:
    fields = payload.model_fields_set

    if profile.profile_completed:
        if "profile_completed" in fields and payload.profile_completed is False:
            raise ValidationAppError(
                message="Cannot revert completed profile",
                public_message="A completed profile cannot be marked incomplete.",
                error_code="VALIDATION_ERROR",
            )
        if "full_name" in fields and payload.full_name is None:
            raise ValidationAppError(
                message="Cannot clear full_name on completed profile",
                public_message="Full name is required on a completed profile.",
                error_code="VALIDATION_ERROR",
            )
        if "date_of_birth" in fields and payload.date_of_birth is None:
            raise ValidationAppError(
                message="Cannot clear date_of_birth on completed profile",
                public_message="Date of birth is required on a completed profile.",
                error_code="VALIDATION_ERROR",
            )

    if "full_name" in fields:
        profile.full_name = payload.full_name

    if "date_of_birth" in fields:
        if payload.date_of_birth is not None:
            today_utc = datetime.now(timezone.utc).date()
            if payload.date_of_birth > today_utc:
                raise ValidationAppError(
                    message="Future date_of_birth rejected",
                    public_message="Date of birth cannot be in the future.",
                    error_code="VALIDATION_ERROR",
                )
        profile.date_of_birth = payload.date_of_birth

    if "bio" in fields:
        profile.bio = payload.bio

    if "avatar_url" in fields:
        try:
            validated_avatar = validate_safe_avatar_url(
                payload.avatar_url,
                allow_localhost_http=(settings.ENVIRONMENT != "production"),
            )
        except ValueError as exc:
            raise ValidationAppError(
                message="Invalid avatar URL",
                public_message=str(exc),
                error_code="VALIDATION_ERROR",
            ) from None
        profile.profile_picture_url = validated_avatar

    if "interests" in fields and payload.interests is not None:
        profile.interests = list(payload.interests)

    if "current_activities" in fields and payload.current_activities is not None:
        profile.activities.clear()
        db.flush()
        for idx, item in enumerate(payload.current_activities):
            profile.activities.append(
                UserProfileActivity(
                    id=uuid.uuid4(),
                    activity_key=item.key,
                    custom_label=item.label if item.key == "other" else None,
                    description=item.description,
                    display_order=idx,
                )
            )

    if payload.profile_completed is True and not profile.profile_completed:
        missing_fields: list[str] = []
        if not profile.slug:
            missing_fields.append("username")
        if not profile.full_name:
            missing_fields.append("full name")
        if profile.date_of_birth is None:
            missing_fields.append("date of birth")
        if missing_fields:
            raise ValidationAppError(
                message="Missing required fields for profile completion",
                public_message=(
                    "Full name, username, and date of birth are required to complete your profile."
                ),
                details={"missing_fields": missing_fields},
                error_code="VALIDATION_ERROR",
            )
        profile.profile_completed = True
        profile.profile_completed_at = datetime.now(timezone.utc)


def update_profile(
    db: Session,
    *,
    user_id: uuid.UUID,
    payload: ProfileUpdateRequest,
    settings: Settings,
) -> UserProfile:
    """Create or update the authenticated user's private profile fields atomically."""
    for attempt in range(2):
        profile, _created = _lock_or_init_profile(db, user_id=user_id)
        try:
            _apply_profile_fields(
                db,
                profile=profile,
                payload=payload,
                settings=settings,
            )
            db.commit()
        except ValidationAppError:
            db.rollback()
            raise
        except IntegrityError as exc:
            db.rollback()
            constraint = get_constraint_name(exc)
            if constraint == "uq_user_profiles_user_id" and attempt == 0:
                continue
            logger.error(
                "Unexpected database constraint violation during profile update: constraint=%s",
                constraint or "unknown",
            )
            raise AppException(
                message=f"Profile update integrity failure: {constraint}",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            ) from None

        loaded = _load_profile_with_activities(db, user_id=user_id)
        if loaded is None:
            raise AppException(
                message="Profile disappeared immediately after commit",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        return loaded

    raise AppException(
        message="Profile update failed after concurrent initialization retry",
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )
