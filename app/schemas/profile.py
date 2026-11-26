"""Pydantic v2 request and response schemas for Phase 1 Profile Creation."""

from datetime import date, datetime, timezone
from typing import Any, Literal
import uuid

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from app.core.username import (
    validate_assignable_slug,
    validate_safe_avatar_url,
)

ActivityKey = Literal[
    "studying",
    "working",
    "interning",
    "freelancing",
    "job_seeking",
    "researching",
    "building_project",
    "learning_skills",
    "other",
]

FULL_NAME_MIN_LENGTH = 2
FULL_NAME_MAX_LENGTH = 150
BIO_MAX_LENGTH = 500
CUSTOM_LABEL_MIN_LENGTH = 2
CUSTOM_LABEL_MAX_LENGTH = 80
ACTIVITY_DESCRIPTION_MAX_LENGTH = 200


def _strip_optional_text(value: Any, *, field_label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_label} must be a string")
    cleaned = value.strip()
    return cleaned or None


def _reject_control_chars(value: str, *, field_label: str) -> None:
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError(f"{field_label} must not contain control characters")


def _normalize_multiline_text(value: Any, *, field_label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_label} must be a string")
    normalized = value.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not normalized:
        return None
    if any((ord(ch) < 0x20 and ch != "\n") or ord(ch) == 0x7F for ch in normalized):
        raise ValueError(f"{field_label} must not contain control characters")
    return normalized


class ProfileActivityInput(BaseModel):
    """Single current-activity entry submitted by the frontend."""

    model_config = ConfigDict(extra="forbid")

    key: ActivityKey
    label: str | None = None
    description: str | None = None

    @field_validator("label", mode="before")
    @classmethod
    def sanitize_label(cls, value: Any) -> str | None:
        cleaned = _strip_optional_text(value, field_label="Activity label")
        if cleaned is not None:
            _reject_control_chars(cleaned, field_label="Activity label")
        return cleaned

    @field_validator("description", mode="before")
    @classmethod
    def sanitize_description(cls, value: Any) -> str | None:
        cleaned = _normalize_multiline_text(value, field_label="Activity description")
        if cleaned is not None and len(cleaned) > ACTIVITY_DESCRIPTION_MAX_LENGTH:
            raise ValueError(
                f"Activity description must not exceed {ACTIVITY_DESCRIPTION_MAX_LENGTH} characters"
            )
        return cleaned

    @model_validator(mode="after")
    def validate_other_label_consistency(self) -> "ProfileActivityInput":
        if self.key == "other":
            if self.label is None:
                raise ValueError("Custom label is required when activity key is 'other'")
            if (
                len(self.label) < CUSTOM_LABEL_MIN_LENGTH
                or len(self.label) > CUSTOM_LABEL_MAX_LENGTH
            ):
                raise ValueError(
                    f"Custom label must be between {CUSTOM_LABEL_MIN_LENGTH} "
                    f"and {CUSTOM_LABEL_MAX_LENGTH} characters"
                )
        elif self.label is not None:
            raise ValueError(
                "Custom label is only allowed when activity key is 'other'"
            )
        return self


class ProfileActivityResponse(BaseModel):
    """Serialized current-activity entry returned in private profile responses."""

    key: ActivityKey
    label: str | None = None
    description: str | None = None


class SlugUpdateRequest(BaseModel):
    """Request payload for PATCH /api/v1/profile/me/slug."""

    model_config = ConfigDict(extra="forbid")

    slug: str

    @field_validator("slug", mode="before")
    @classmethod
    def validate_slug(cls, value: Any) -> str:
        return validate_assignable_slug(value)


class SlugAvailabilityResponse(BaseModel):
    """Response payload for GET /api/v1/profile/slug-availability."""

    slug: str
    available: bool
    reason: Literal["taken", "reserved"] | None = None


class ProfileUpdateRequest(BaseModel):
    """Request payload for PATCH /api/v1/profile/me."""

    model_config = ConfigDict(extra="forbid")

    full_name: str | None = None
    date_of_birth: date | None = None
    bio: str | None = None
    avatar_url: str | None = None
    interests: list[str] | None = None
    current_activities: list[ProfileActivityInput] | None = None
    profile_completed: bool | None = None

    @field_validator("full_name", mode="before")
    @classmethod
    def validate_full_name(cls, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("Full name must be a string")
        cleaned = value.strip()
        _reject_control_chars(cleaned, field_label="Full name")
        if (
            len(cleaned) < FULL_NAME_MIN_LENGTH
            or len(cleaned) > FULL_NAME_MAX_LENGTH
        ):
            raise ValueError(
                f"Full name must be between {FULL_NAME_MIN_LENGTH} "
                f"and {FULL_NAME_MAX_LENGTH} characters"
            )
        return cleaned

    @field_validator("date_of_birth", mode="before")
    @classmethod
    def reject_numeric_or_datetime_dob(cls, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, (bool, int, float, datetime)):
            raise ValueError("Date of birth must be an ISO calendar date (YYYY-MM-DD)")
        return value

    @field_validator("date_of_birth", mode="after")
    @classmethod
    def validate_dob_not_in_future(cls, value: date | None) -> date | None:
        if value is not None:
            today_utc = datetime.now(timezone.utc).date()
            if value > today_utc:
                raise ValueError("Date of birth cannot be in the future")
        return value

    @field_validator("bio", mode="before")
    @classmethod
    def validate_bio(cls, value: Any) -> str | None:
        cleaned = _normalize_multiline_text(value, field_label="Bio")
        if cleaned is not None and len(cleaned) > BIO_MAX_LENGTH:
            raise ValueError(f"Bio must not exceed {BIO_MAX_LENGTH} characters")
        return cleaned

    @field_validator("avatar_url", mode="before")
    @classmethod
    def validate_avatar_url(cls, value: Any) -> str | None:
        return validate_safe_avatar_url(value, allow_localhost_http=True)

    @field_validator("interests", mode="before")
    @classmethod
    def validate_interests(cls, value: Any) -> list[str] | None:
        if value is None:
            return None
        if not isinstance(value, list):
            raise ValueError("Interests must be a list of strings")
        deduped: list[str] = []
        seen_lower: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                raise ValueError("Each interest must be a string")
            cleaned = item.strip()
            if not cleaned:
                raise ValueError("Interests must not contain empty strings")
            _reject_control_chars(cleaned, field_label="Interest")
            lowered = cleaned.lower()
            if lowered not in seen_lower:
                seen_lower.add(lowered)
                deduped.append(cleaned)
        return deduped

    @field_validator("current_activities", mode="after")
    @classmethod
    def validate_unique_activity_keys(
        cls,
        value: list[ProfileActivityInput] | None,
    ) -> list[ProfileActivityInput] | None:
        if value is None:
            return None
        seen_keys: set[str] = set()
        for entry in value:
            if entry.key in seen_keys:
                raise ValueError(f"Duplicate activity key '{entry.key}' is not allowed")
            seen_keys.add(entry.key)
        return value

    @model_validator(mode="after")
    def validate_patch_invariants(self) -> "ProfileUpdateRequest":
        if not self.model_fields_set:
            raise ValueError("At least one profile field must be provided")
        for non_nullable_list_or_bool in (
            "interests",
            "current_activities",
            "profile_completed",
        ):
            if (
                non_nullable_list_or_bool in self.model_fields_set
                and getattr(self, non_nullable_list_or_bool) is None
            ):
                raise ValueError(f"{non_nullable_list_or_bool} cannot be null")
        return self


class PrivateProfileResponse(BaseModel):
    """Owner-only private profile response (includes private date_of_birth)."""

    id: uuid.UUID
    user_id: uuid.UUID
    slug: str | None
    full_name: str | None
    date_of_birth: date | None
    bio: str | None
    # Transitional Phase 1 URL field mapped from UserProfile.profile_picture_url.
    avatar_url: str | None
    interests: list[str]
    current_activities: list[ProfileActivityResponse]
    profile_completed: bool
    profile_completed_at: datetime | None
    created_at: datetime
    updated_at: datetime
