"""Pydantic v2 request and response schemas for Phase 1 Profile Creation."""

from datetime import date, datetime, timezone
from typing import Any, Literal
from urllib.parse import urlsplit
import uuid

from pydantic import BaseModel, ConfigDict, EmailStr, Field, TypeAdapter, field_validator, model_validator

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
BIO_MAX_LENGTH = 1000
HEADLINE_MAX_LENGTH = 120
LOCATION_MAX_LENGTH = 120
PHONE_MAX_LENGTH = 32
URL_MAX_LENGTH = 512
LINK_LABEL_MAX_LENGTH = 60
MAX_OTHER_LINKS = 20
CUSTOM_LABEL_MIN_LENGTH = 2
CUSTOM_LABEL_MAX_LENGTH = 80
ACTIVITY_DESCRIPTION_MAX_LENGTH = 200
_EMAIL_ADAPTER = TypeAdapter(EmailStr)


def _validate_safe_http_url(
    value: Any,
    *,
    field_label: str,
    max_length: int = URL_MAX_LENGTH,
) -> str | None:
    cleaned = _strip_optional_text(value, field_label=field_label)
    if cleaned is None:
        return None
    if len(cleaned) > max_length:
        raise ValueError(f"{field_label} must not exceed {max_length} characters")
    if "\\" in cleaned or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in cleaned):
        raise ValueError(f"{field_label} must not contain whitespace or control characters")
    try:
        parts = urlsplit(cleaned)
    except ValueError:
        raise ValueError(f"{field_label} is not a valid URL") from None
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError(f"{field_label} must start with http:// or https://")
    if parts.username is not None or parts.password is not None:
        raise ValueError(f"{field_label} must not contain embedded credentials")
    return cleaned


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


class ProfileLinkItem(BaseModel):
    """Single labeled external profile link."""

    model_config = ConfigDict(extra="forbid")

    label: str
    url: str

    @field_validator("label", mode="before")
    @classmethod
    def validate_label(cls, value: Any) -> str:
        cleaned = _strip_optional_text(value, field_label="Link label")
        if cleaned is None:
            raise ValueError("Link label is required")
        _reject_control_chars(cleaned, field_label="Link label")
        if len(cleaned) > LINK_LABEL_MAX_LENGTH:
            raise ValueError(f"Link label must not exceed {LINK_LABEL_MAX_LENGTH} characters")
        return cleaned

    @field_validator("url", mode="before")
    @classmethod
    def validate_url(cls, value: Any) -> str:
        validated = _validate_safe_http_url(value, field_label="Link URL")
        if validated is None:
            raise ValueError("Link URL is required")
        return validated


class ProfileLinksInput(BaseModel):
    """Structured social and external profile links update payload."""

    model_config = ConfigDict(extra="forbid")

    linkedin: str | None = None
    github: str | None = None
    other: list[ProfileLinkItem] = Field(default_factory=list)

    @field_validator("linkedin", mode="before")
    @classmethod
    def validate_linkedin(cls, value: Any) -> str | None:
        return _validate_safe_http_url(value, field_label="LinkedIn URL")

    @field_validator("github", mode="before")
    @classmethod
    def validate_github(cls, value: Any) -> str | None:
        return _validate_safe_http_url(value, field_label="GitHub URL")

    @field_validator("other", mode="after")
    @classmethod
    def validate_other_limit(cls, value: list[ProfileLinkItem]) -> list[ProfileLinkItem]:
        if len(value) > MAX_OTHER_LINKS:
            raise ValueError(f"At most {MAX_OTHER_LINKS} additional links are allowed")
        return value


class ProfileLinksResponse(BaseModel):
    """Structured social and external profile links returned on profile responses."""

    linkedin: str | None = None
    github: str | None = None
    other: list[ProfileLinkItem] = Field(default_factory=list)


class AvatarUploadResponse(BaseModel):
    """Response payload for POST /api/v1/profile/me/avatar."""

    avatar_url: str


class ProfileUpdateRequest(BaseModel):
    """Request payload for PATCH /api/v1/profile/me."""

    model_config = ConfigDict(extra="forbid")

    full_name: str | None = None
    date_of_birth: date | None = None
    headline: str | None = None
    bio: str | None = None
    location: str | None = None
    contact_email: str | None = None
    phone: str | None = None
    website: str | None = None
    links: ProfileLinksInput | None = None
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

    @field_validator("headline", mode="before")
    @classmethod
    def validate_headline(cls, value: Any) -> str | None:
        cleaned = _strip_optional_text(value, field_label="Headline")
        if cleaned is not None:
            _reject_control_chars(cleaned, field_label="Headline")
            if len(cleaned) > HEADLINE_MAX_LENGTH:
                raise ValueError(f"Headline must not exceed {HEADLINE_MAX_LENGTH} characters")
        return cleaned

    @field_validator("bio", mode="before")
    @classmethod
    def validate_bio(cls, value: Any) -> str | None:
        cleaned = _normalize_multiline_text(value, field_label="Bio")
        if cleaned is not None and len(cleaned) > BIO_MAX_LENGTH:
            raise ValueError(f"Bio must not exceed {BIO_MAX_LENGTH} characters")
        return cleaned

    @field_validator("location", mode="before")
    @classmethod
    def validate_location(cls, value: Any) -> str | None:
        cleaned = _strip_optional_text(value, field_label="Location")
        if cleaned is not None:
            _reject_control_chars(cleaned, field_label="Location")
            if len(cleaned) > LOCATION_MAX_LENGTH:
                raise ValueError(f"Location must not exceed {LOCATION_MAX_LENGTH} characters")
        return cleaned

    @field_validator("contact_email", mode="before")
    @classmethod
    def validate_contact_email(cls, value: Any) -> str | None:
        cleaned = _strip_optional_text(value, field_label="Contact email")
        if cleaned is None:
            return None
        _reject_control_chars(cleaned, field_label="Contact email")
        if len(cleaned) > 255:
            raise ValueError("Contact email must not exceed 255 characters")
        try:
            validated = _EMAIL_ADAPTER.validate_python(cleaned)
        except Exception:
            raise ValueError("Enter a valid contact email address") from None
        return str(validated).strip().lower()

    @field_validator("phone", mode="before")
    @classmethod
    def validate_phone(cls, value: Any) -> str | None:
        cleaned = _strip_optional_text(value, field_label="Phone number")
        if cleaned is not None:
            _reject_control_chars(cleaned, field_label="Phone number")
            if len(cleaned) > PHONE_MAX_LENGTH:
                raise ValueError(f"Phone number must not exceed {PHONE_MAX_LENGTH} characters")
        return cleaned

    @field_validator("website", mode="before")
    @classmethod
    def validate_website(cls, value: Any) -> str | None:
        return _validate_safe_http_url(value, field_label="Website URL")

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
    public_url: str | None = None
    full_name: str | None
    date_of_birth: date | None
    headline: str | None = None
    bio: str | None
    location: str | None = None
    contact_email: str | None = None
    phone: str | None = None
    website: str | None = None
    links: ProfileLinksResponse = Field(default_factory=ProfileLinksResponse)
    # Transitional / managed profile picture URL mapped from UserProfile.profile_picture_url.
    avatar_url: str | None
    interests: list[str]
    current_activities: list[ProfileActivityResponse]
    profile_completed: bool
    profile_completed_at: datetime | None
    created_at: datetime
    updated_at: datetime


ThemePreference = Literal["light", "dark", "system"]


class PublicSectionsSettings(BaseModel):
    """Per-section public visibility toggles."""

    education: bool = True
    projects: bool = True
    skills: bool = True
    certificates: bool = True
    experience: bool = True
    achievements: bool = True
    academics_cgpa: bool = False


class PublicContactSettings(BaseModel):
    """Public contact-field visibility toggles."""

    show_email: bool = False
    show_phone: bool = False
    show_location: bool = False


class PublicSettingsResponse(BaseModel):
    """Response payload for GET/PATCH /api/v1/profile/me/visibility."""

    public_enabled: bool = True
    discoverable: bool = False
    public_sections: PublicSectionsSettings
    public_contact: PublicContactSettings


class PublicSectionsUpdate(BaseModel):
    """Partial update payload for public_sections."""

    model_config = ConfigDict(extra="forbid")

    education: bool | None = None
    projects: bool | None = None
    skills: bool | None = None
    certificates: bool | None = None
    experience: bool | None = None
    achievements: bool | None = None
    academics_cgpa: bool | None = None


class PublicContactUpdate(BaseModel):
    """Partial update payload for public_contact."""

    model_config = ConfigDict(extra="forbid")

    show_email: bool | None = None
    show_phone: bool | None = None
    show_location: bool | None = None


class PublicSettingsUpdateRequest(BaseModel):
    """Partial update payload for PATCH /api/v1/profile/me/visibility."""

    model_config = ConfigDict(extra="forbid")

    public_enabled: bool | None = None
    discoverable: bool | None = None
    public_sections: PublicSectionsUpdate | None = None
    public_contact: PublicContactUpdate | None = None

    @model_validator(mode="after")
    def validate_non_empty(self) -> "PublicSettingsUpdateRequest":
        if not self.model_fields_set:
            raise ValueError("At least one visibility setting must be provided")
        return self


class PreferencesResponse(BaseModel):
    """Response payload for GET/PATCH /api/v1/profile/me/preferences."""

    theme: ThemePreference = "light"


class PreferencesUpdateRequest(BaseModel):
    """Partial update payload for PATCH /api/v1/profile/me/preferences."""

    model_config = ConfigDict(extra="forbid")

    theme: ThemePreference
