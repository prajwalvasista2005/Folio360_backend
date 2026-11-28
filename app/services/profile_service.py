"""Phase 1 synchronous profile creation, slug availability, and update service."""

from datetime import datetime, timezone
import logging
from typing import Any, Literal
import uuid

from fastapi import UploadFile, status
from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core.config import Settings, normalize_api_v1_prefix
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
from app.models.profile import THEME_PREFERENCES, UserProfile, UserProfileActivity
from app.schemas.profile import (
    ProfileUpdateRequest,
    PublicSettingsUpdateRequest,
)
from app.services.auth_service import get_constraint_name
from app.services.file_validation import sniff_and_validate_project_image_bytes
from app.services.storage_service import build_storage_backend

logger = logging.getLogger("folio360.profile.service")

AVATAR_NAMESPACE = "profile_avatars"
AVATAR_MAX_SIZE_BYTES = 5 * 1024 * 1024


def resolve_profile_links(raw: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize persisted JSONB links into {linkedin, github, other}."""
    data = raw if isinstance(raw, dict) else {}
    linkedin = data.get("linkedin") if isinstance(data.get("linkedin"), str) else None
    github = data.get("github") if isinstance(data.get("github"), str) else None
    raw_other = data.get("other") if isinstance(data.get("other"), list) else []
    other = [
        {"label": item["label"], "url": item["url"]}
        for item in raw_other
        if isinstance(item, dict)
        and isinstance(item.get("label"), str)
        and isinstance(item.get("url"), str)
    ]
    return {
        "linkedin": linkedin or None,
        "github": github or None,
        "other": other,
    }


def get_profile_identity_summary(db: Session, *, user_id: uuid.UUID) -> dict[str, Any]:
    """Return lightweight profile fields needed by /auth/me without loading relationships."""
    row = db.execute(
        select(
            UserProfile.profile_completed,
            UserProfile.full_name,
            UserProfile.slug,
            UserProfile.profile_picture_url,
        ).where(UserProfile.user_id == user_id)
    ).first()
    if row is None:
        return {
            "profile_completed": False,
            "full_name": None,
            "slug": None,
            "avatar_url": None,
        }
    return {
        "profile_completed": bool(row[0]),
        "full_name": row[1],
        "slug": row[2],
        "avatar_url": row[3],
    }


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


def _delete_stored_object_best_effort(settings: Settings, storage_key: str | None) -> None:
    if not storage_key:
        return
    try:
        build_storage_backend(settings).delete_object(storage_key=storage_key)
    except Exception as exc:
        logger.warning(
            "Best-effort avatar storage cleanup failed: exception=%s",
            type(exc).__name__,
        )


def _apply_profile_fields(
    db: Session,
    *,
    profile: UserProfile,
    payload: ProfileUpdateRequest,
    settings: Settings,
) -> str | None:
    fields = payload.model_fields_set
    stale_avatar_key: str | None = None

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

    if "headline" in fields:
        profile.headline = payload.headline

    if "bio" in fields:
        profile.bio = payload.bio

    if "location" in fields:
        profile.location = payload.location

    if "contact_email" in fields:
        profile.contact_email = payload.contact_email

    if "phone" in fields:
        profile.phone = payload.phone

    if "website" in fields:
        profile.website = payload.website

    if "links" in fields:
        if payload.links is None:
            profile.links = {"linkedin": None, "github": None, "other": []}
        else:
            profile.links = {
                "linkedin": payload.links.linkedin,
                "github": payload.links.github,
                "other": [
                    {"label": item.label, "url": item.url}
                    for item in payload.links.other
                ],
            }

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
        if validated_avatar != profile.profile_picture_url:
            if profile.avatar_storage_key:
                stale_avatar_key = profile.avatar_storage_key
            profile.avatar_storage_key = None
            profile.avatar_mime_type = None
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

    return stale_avatar_key


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
            stale_avatar_key = _apply_profile_fields(
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

        _delete_stored_object_best_effort(settings, stale_avatar_key)

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


def upload_profile_avatar(
    db: Session,
    *,
    user_id: uuid.UUID,
    upload_file: UploadFile,
    settings: Settings,
) -> str:
    """Validate, store, and link a square/cropped profile avatar (JPEG/PNG/WebP, max 5 MB)."""
    raw_bytes = upload_file.file.read(AVATAR_MAX_SIZE_BYTES + 1)
    if not raw_bytes:
        raise ValidationAppError(
            message="Uploaded avatar file is empty",
            public_message="Uploaded image file is empty.",
            error_code="MALFORMED_FILE",
        )
    if len(raw_bytes) > AVATAR_MAX_SIZE_BYTES:
        max_mb = max(1, AVATAR_MAX_SIZE_BYTES // (1024 * 1024))
        raise AppException(
            message="Avatar image exceeds maximum allowed size",
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            public_message=f"Profile picture must not exceed {max_mb} MB.",
            error_code="FILE_TOO_LARGE",
        )

    mime_type = sniff_and_validate_project_image_bytes(raw_bytes)
    avatar_id = uuid.uuid4()
    storage_key = f"{AVATAR_NAMESPACE}/{user_id}/{avatar_id}"

    backend = build_storage_backend(settings)
    backend.put_object(
        storage_key=storage_key,
        data=raw_bytes,
        content_type=mime_type,
    )

    prefix = normalize_api_v1_prefix(settings.API_V1_PREFIX)
    for attempt in range(2):
        profile, _created = _lock_or_init_profile(db, user_id=user_id)
        old_key = profile.avatar_storage_key
        avatar_url = f"{prefix}/profile/avatars/{profile.id}?v={avatar_id.hex[:12]}"
        profile.avatar_storage_key = storage_key
        profile.avatar_mime_type = mime_type
        profile.profile_picture_url = avatar_url

        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            constraint = get_constraint_name(exc)
            if constraint == "uq_user_profiles_user_id" and attempt == 0:
                continue
            _delete_stored_object_best_effort(settings, storage_key)
            raise AppException(
                message=f"Avatar update integrity failure: {constraint}",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            ) from None
        except Exception:
            db.rollback()
            _delete_stored_object_best_effort(settings, storage_key)
            raise

        if old_key and old_key != storage_key:
            _delete_stored_object_best_effort(settings, old_key)
        return avatar_url

    _delete_stored_object_best_effort(settings, storage_key)
    raise AppException(
        message="Avatar update failed after concurrent initialization retry",
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )


def remove_profile_avatar(
    db: Session,
    *,
    user_id: uuid.UUID,
    settings: Settings,
) -> None:
    """Clear the authenticated user's profile picture and delete any stored avatar object."""
    profile = db.execute(
        select(UserProfile)
        .where(UserProfile.user_id == user_id)
        .with_for_update()
    ).scalar_one_or_none()
    if profile is None:
        return

    old_key = profile.avatar_storage_key
    profile.profile_picture_url = None
    profile.avatar_storage_key = None
    profile.avatar_mime_type = None
    db.commit()

    _delete_stored_object_best_effort(settings, old_key)


def get_profile_avatar_content(
    db: Session,
    *,
    profile_id: uuid.UUID,
    settings: Settings,
) -> tuple[str, bytes]:
    """Read stored avatar bytes and MIME type for profile_id, or raise 404."""
    profile = db.execute(
        select(UserProfile).where(UserProfile.id == profile_id)
    ).scalar_one_or_none()
    if profile is None or not profile.avatar_storage_key:
        raise ResourceNotFoundError(
            message="Profile avatar not found",
            public_message="Profile picture not found.",
            error_code="NOT_FOUND",
        )

    backend = build_storage_backend(settings)
    content = backend.read_bytes(storage_key=profile.avatar_storage_key)
    return (profile.avatar_mime_type or "image/jpeg"), content


DEFAULT_VISIBILITY_SETTINGS: dict[str, Any] = {
    "public_enabled": True,
    "discoverable": False,
    "public_sections": {
        "education": True,
        "projects": True,
        "skills": True,
        "certificates": True,
        "experience": True,
        "achievements": True,
        "academics_cgpa": False,
    },
    "public_contact": {
        "show_email": False,
        "show_phone": False,
        "show_location": False,
    },
}


def resolve_visibility_settings(raw: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize persisted JSONB visibility settings against canonical defaults."""
    data = raw if isinstance(raw, dict) else {}
    raw_sections = data.get("public_sections")
    raw_contact = data.get("public_contact")
    sections_dict = raw_sections if isinstance(raw_sections, dict) else {}
    contact_dict = raw_contact if isinstance(raw_contact, dict) else {}

    public_enabled = bool(
        data.get("public_enabled", DEFAULT_VISIBILITY_SETTINGS["public_enabled"])
    )
    discoverable = (
        bool(data.get("discoverable", DEFAULT_VISIBILITY_SETTINGS["discoverable"]))
        if public_enabled
        else False
    )

    public_sections = {
        key: bool(sections_dict.get(key, default_val))
        for key, default_val in DEFAULT_VISIBILITY_SETTINGS["public_sections"].items()
    }
    public_contact = {
        key: bool(contact_dict.get(key, default_val))
        for key, default_val in DEFAULT_VISIBILITY_SETTINGS["public_contact"].items()
    }
    return {
        "public_enabled": public_enabled,
        "discoverable": discoverable,
        "public_sections": public_sections,
        "public_contact": public_contact,
    }


def get_profile_visibility(db: Session, *, user_id: uuid.UUID) -> dict[str, Any]:
    """Return normalized public visibility settings for user_id (or defaults if no profile yet)."""
    raw = db.execute(
        select(UserProfile.visibility_settings).where(UserProfile.user_id == user_id)
    ).scalar_one_or_none()
    return resolve_visibility_settings(raw)


def update_profile_visibility(
    db: Session,
    *,
    user_id: uuid.UUID,
    payload: PublicSettingsUpdateRequest,
) -> dict[str, Any]:
    """Atomically merge and persist public visibility settings for user_id."""
    for attempt in range(2):
        profile, _created = _lock_or_init_profile(db, user_id=user_id)
        merged = resolve_visibility_settings(profile.visibility_settings)

        if payload.public_enabled is not None:
            merged["public_enabled"] = payload.public_enabled
        if payload.discoverable is not None:
            merged["discoverable"] = payload.discoverable
        if not merged["public_enabled"]:
            merged["discoverable"] = False

        if payload.public_sections is not None:
            for key, value in payload.public_sections.model_dump(
                exclude_unset=True
            ).items():
                if value is not None:
                    merged["public_sections"][key] = bool(value)

        if payload.public_contact is not None:
            for key, value in payload.public_contact.model_dump(
                exclude_unset=True
            ).items():
                if value is not None:
                    merged["public_contact"][key] = bool(value)

        profile.visibility_settings = merged
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            constraint = get_constraint_name(exc)
            if constraint == "uq_user_profiles_user_id" and attempt == 0:
                continue
            logger.error(
                "Unexpected database constraint violation during visibility update: constraint=%s",
                constraint or "unknown",
            )
            raise AppException(
                message=f"Visibility update integrity failure: {constraint}",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            ) from None
        return merged

    raise AppException(
        message="Visibility update failed after concurrent initialization retry",
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )


def get_profile_preferences(db: Session, *, user_id: uuid.UUID) -> str:
    """Return persisted theme preference for user_id (defaults to 'light')."""
    theme = db.execute(
        select(UserProfile.theme_preference).where(UserProfile.user_id == user_id)
    ).scalar_one_or_none()
    if theme in THEME_PREFERENCES:
        return str(theme)
    return "light"


def update_profile_preferences(
    db: Session,
    *,
    user_id: uuid.UUID,
    theme: str,
) -> str:
    """Persist theme preference for user_id."""
    if theme not in THEME_PREFERENCES:
        raise ValidationAppError(
            message="Invalid theme preference",
            public_message="Theme must be one of light, dark, or system.",
            error_code="VALIDATION_ERROR",
        )

    for attempt in range(2):
        profile, _created = _lock_or_init_profile(db, user_id=user_id)
        profile.theme_preference = theme
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            constraint = get_constraint_name(exc)
            if constraint == "uq_user_profiles_user_id" and attempt == 0:
                continue
            logger.error(
                "Unexpected database constraint violation during preferences update: constraint=%s",
                constraint or "unknown",
            )
            raise AppException(
                message=f"Preferences update integrity failure: {constraint}",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            ) from None
        return theme

    raise AppException(
        message="Preferences update failed after concurrent initialization retry",
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )
