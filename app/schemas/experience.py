"""Pydantic v2 request and response schemas for Experience records."""

from datetime import date as date_type, datetime
from typing import Any, Literal
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.document import DocumentRef

ExperienceType = Literal[
    "internship",
    "employment",
    "freelance",
    "research",
    "volunteering",
    "mentorship",
    "leadership",
    "other",
]
ExperienceVisibility = Literal["private", "public"]

MAX_EXPERIENCE_DESCRIPTION_LEN = 5_000
MAX_EXPERIENCE_HIGHLIGHTS = 15
MAX_EXPERIENCE_HIGHLIGHT_LEN = 300
MAX_EXPERIENCE_SKILLS = 30
MAX_EXPERIENCE_DOCUMENTS = 10


def _reject_control_chars(value: str, *, field_label: str, allow_newline: bool = False) -> None:
    for ch in value:
        code = ord(ch)
        if allow_newline and ch == "\n":
            continue
        if code < 0x20 or code == 0x7F:
            raise ValueError(f"{field_label} must not contain control characters")


def _clean_required_str(value: Any, *, field_label: str, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_label} must be a string")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_label} is required and cannot be blank")
    _reject_control_chars(cleaned, field_label=field_label)
    if len(cleaned) > max_length:
        raise ValueError(f"{field_label} must not exceed {max_length} characters")
    return cleaned


def _clean_optional_str(value: Any, *, field_label: str, max_length: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_label} must be a string")
    cleaned = value.strip()
    if not cleaned:
        return None
    _reject_control_chars(cleaned, field_label=field_label)
    if len(cleaned) > max_length:
        raise ValueError(f"{field_label} must not exceed {max_length} characters")
    return cleaned


def _clean_multiline_str(
    value: Any,
    *,
    field_label: str,
    max_length: int = MAX_EXPERIENCE_DESCRIPTION_LEN,
) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_label} must be a string")
    normalized = value.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not normalized:
        return None
    _reject_control_chars(normalized, field_label=field_label, allow_newline=True)
    if len(normalized) > max_length:
        raise ValueError(f"{field_label} must not exceed {max_length} characters")
    return normalized


def _clean_http_url(value: Any, *, field_label: str) -> str | None:
    cleaned = _clean_optional_str(value, field_label=field_label, max_length=512)
    if cleaned is None:
        return None
    lower = cleaned.lower()
    if not (lower.startswith("https://") or lower.startswith("http://")):
        raise ValueError(f"{field_label} must be a valid http:// or https:// URL")
    if any(ch.isspace() for ch in cleaned):
        raise ValueError(f"{field_label} must not contain whitespace")
    return cleaned


def _normalize_enum_str(value: Any, *, field_label: str, allow_none: bool) -> Any:
    if value is None:
        if allow_none:
            return None
        raise ValueError(f"{field_label} cannot be null")
    if not isinstance(value, str):
        raise ValueError(f"{field_label} must be a string")
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"{field_label} cannot be blank")
    return cleaned


def _clean_highlights(value: Any, *, allow_none: bool) -> list[str] | None:
    if value is None:
        if allow_none:
            return None
        return []
    if not isinstance(value, list):
        raise ValueError("highlights must be a list of strings")
    cleaned_items: list[str] = []
    for raw in value:
        if not isinstance(raw, str):
            raise ValueError("Each highlight must be a string")
        cleaned = raw.strip()
        if not cleaned:
            continue
        _reject_control_chars(cleaned, field_label="highlight")
        if len(cleaned) > MAX_EXPERIENCE_HIGHLIGHT_LEN:
            raise ValueError(
                f"Each highlight must not exceed {MAX_EXPERIENCE_HIGHLIGHT_LEN} characters"
            )
        cleaned_items.append(cleaned)
    if len(cleaned_items) > MAX_EXPERIENCE_HIGHLIGHTS:
        raise ValueError(
            f"highlights must not exceed {MAX_EXPERIENCE_HIGHLIGHTS} items"
        )
    return cleaned_items


def _dedupe_uuids(
    value: Any,
    *,
    field_label: str,
    max_items: int,
    allow_none: bool,
) -> list[uuid.UUID] | None:
    if value is None:
        if allow_none:
            return None
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field_label} must be a list of UUIDs")
    if len(value) > max_items:
        raise ValueError(f"{field_label} must not exceed {max_items} items")
    deduped: list[uuid.UUID] = []
    seen: set[uuid.UUID] = set()
    for raw in value:
        parsed = raw if isinstance(raw, uuid.UUID) else uuid.UUID(str(raw))
        if parsed not in seen:
            seen.add(parsed)
            deduped.append(parsed)
    return deduped


def validate_experience_dates(
    *,
    start_date: date_type,
    end_date: date_type | None,
    is_current: bool,
) -> None:
    """Enforce chronological validity and mutual exclusion of is_current and end_date."""
    if is_current and end_date is not None:
        raise ValueError("Current experience cannot have an end_date")
    if end_date is not None and end_date < start_date:
        raise ValueError("end_date cannot be earlier than start_date")


class ExperienceSkillRef(BaseModel):
    """Skill reference associated with an experience entry."""

    id: uuid.UUID
    name: str


class ExperienceCreate(BaseModel):
    """Request payload for POST /api/v1/experience."""

    model_config = ConfigDict(extra="forbid")

    type: ExperienceType = "internship"
    organization: str
    role: str
    location: str | None = None
    is_remote: bool = False
    organization_url: str | None = None
    start_date: date_type
    end_date: date_type | None = None
    is_current: bool = False
    description: str | None = None
    highlights: list[str] = Field(default_factory=list)
    skill_ids: list[uuid.UUID] = Field(default_factory=list)
    document_ids: list[uuid.UUID] = Field(default_factory=list)
    featured: bool = False
    order: int = 0
    visibility: ExperienceVisibility = "private"

    @field_validator("type", mode="before")
    @classmethod
    def validate_type(cls, value: Any) -> Any:
        if value is None or (isinstance(value, str) and not value.strip()):
            return "internship"
        return _normalize_enum_str(value, field_label="type", allow_none=False)

    @field_validator("organization", mode="before")
    @classmethod
    def validate_organization(cls, value: Any) -> str:
        return _clean_required_str(value, field_label="organization", max_length=200)

    @field_validator("role", mode="before")
    @classmethod
    def validate_role(cls, value: Any) -> str:
        return _clean_required_str(value, field_label="role", max_length=200)

    @field_validator("location", mode="before")
    @classmethod
    def validate_location(cls, value: Any) -> str | None:
        return _clean_optional_str(value, field_label="location", max_length=200)

    @field_validator("organization_url", mode="before")
    @classmethod
    def validate_organization_url(cls, value: Any) -> str | None:
        return _clean_http_url(value, field_label="organization_url")

    @field_validator("description", mode="before")
    @classmethod
    def validate_description(cls, value: Any) -> str | None:
        return _clean_multiline_str(value, field_label="description")

    @field_validator("highlights", mode="before")
    @classmethod
    def validate_highlights(cls, value: Any) -> list[str]:
        result = _clean_highlights(value, allow_none=False)
        return result or []

    @field_validator("skill_ids", mode="before")
    @classmethod
    def validate_skill_ids(cls, value: Any) -> list[uuid.UUID]:
        result = _dedupe_uuids(
            value,
            field_label="skill_ids",
            max_items=MAX_EXPERIENCE_SKILLS,
            allow_none=False,
        )
        return result or []

    @field_validator("document_ids", mode="before")
    @classmethod
    def validate_document_ids(cls, value: Any) -> list[uuid.UUID]:
        result = _dedupe_uuids(
            value,
            field_label="document_ids",
            max_items=MAX_EXPERIENCE_DOCUMENTS,
            allow_none=False,
        )
        return result or []

    @field_validator("order")
    @classmethod
    def validate_order(cls, value: int) -> int:
        if value < 0:
            raise ValueError("order must be non-negative")
        return value

    @field_validator("visibility", mode="before")
    @classmethod
    def validate_visibility(cls, value: Any) -> Any:
        if value is None or (isinstance(value, str) and not value.strip()):
            return "private"
        return _normalize_enum_str(value, field_label="visibility", allow_none=False)

    @model_validator(mode="after")
    def validate_dates(self) -> "ExperienceCreate":
        validate_experience_dates(
            start_date=self.start_date,
            end_date=self.end_date,
            is_current=self.is_current,
        )
        return self


class ExperienceUpdate(BaseModel):
    """Partial update payload for PATCH /api/v1/experience/{experience_id}."""

    model_config = ConfigDict(extra="forbid")

    type: ExperienceType | None = None
    organization: str | None = None
    role: str | None = None
    location: str | None = None
    is_remote: bool | None = None
    organization_url: str | None = None
    start_date: date_type | None = None
    end_date: date_type | None = None
    is_current: bool | None = None
    description: str | None = None
    highlights: list[str] | None = None
    skill_ids: list[uuid.UUID] | None = None
    document_ids: list[uuid.UUID] | None = None
    featured: bool | None = None
    order: int | None = None
    visibility: ExperienceVisibility | None = None

    @field_validator("type", mode="before")
    @classmethod
    def validate_type(cls, value: Any) -> Any:
        return _normalize_enum_str(value, field_label="type", allow_none=True)

    @field_validator("organization", mode="before")
    @classmethod
    def validate_organization(cls, value: Any) -> str | None:
        if value is None:
            return None
        return _clean_required_str(value, field_label="organization", max_length=200)

    @field_validator("role", mode="before")
    @classmethod
    def validate_role(cls, value: Any) -> str | None:
        if value is None:
            return None
        return _clean_required_str(value, field_label="role", max_length=200)

    @field_validator("location", mode="before")
    @classmethod
    def validate_location(cls, value: Any) -> str | None:
        return _clean_optional_str(value, field_label="location", max_length=200)

    @field_validator("organization_url", mode="before")
    @classmethod
    def validate_organization_url(cls, value: Any) -> str | None:
        return _clean_http_url(value, field_label="organization_url")

    @field_validator("description", mode="before")
    @classmethod
    def validate_description(cls, value: Any) -> str | None:
        return _clean_multiline_str(value, field_label="description")

    @field_validator("highlights", mode="before")
    @classmethod
    def validate_highlights(cls, value: Any) -> list[str] | None:
        return _clean_highlights(value, allow_none=True)

    @field_validator("skill_ids", mode="before")
    @classmethod
    def validate_skill_ids(cls, value: Any) -> list[uuid.UUID] | None:
        return _dedupe_uuids(
            value,
            field_label="skill_ids",
            max_items=MAX_EXPERIENCE_SKILLS,
            allow_none=True,
        )

    @field_validator("document_ids", mode="before")
    @classmethod
    def validate_document_ids(cls, value: Any) -> list[uuid.UUID] | None:
        return _dedupe_uuids(
            value,
            field_label="document_ids",
            max_items=MAX_EXPERIENCE_DOCUMENTS,
            allow_none=True,
        )

    @field_validator("order")
    @classmethod
    def validate_order(cls, value: int | None) -> int | None:
        if value is not None and value < 0:
            raise ValueError("order must be non-negative")
        return value

    @field_validator("visibility", mode="before")
    @classmethod
    def validate_visibility(cls, value: Any) -> Any:
        return _normalize_enum_str(value, field_label="visibility", allow_none=True)

    @model_validator(mode="after")
    def validate_patch_invariants(self) -> "ExperienceUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one experience field must be provided")

        for non_nullable in (
            "type",
            "organization",
            "role",
            "is_remote",
            "start_date",
            "is_current",
            "highlights",
            "skill_ids",
            "document_ids",
            "featured",
            "order",
            "visibility",
        ):
            if non_nullable in self.model_fields_set and getattr(self, non_nullable) is None:
                raise ValueError(f"{non_nullable} cannot be null")

        if self.is_current is True and self.end_date is not None:
            raise ValueError("Current experience cannot have an end_date")
        if (
            self.start_date is not None
            and self.end_date is not None
            and self.end_date < self.start_date
        ):
            raise ValueError("end_date cannot be earlier than start_date")
        return self


class ExperienceResponse(BaseModel):
    """Serialized experience record returned by /api/v1/experience."""

    id: uuid.UUID
    type: ExperienceType
    organization: str
    role: str
    location: str | None
    is_remote: bool
    organization_url: str | None
    start_date: date_type
    end_date: date_type | None
    is_current: bool
    description: str | None
    highlights: list[str] = Field(default_factory=list)
    skills: list[ExperienceSkillRef] = Field(default_factory=list)
    documents: list[DocumentRef] = Field(default_factory=list)
    featured: bool
    order: int
    visibility: ExperienceVisibility
    created_at: datetime
    updated_at: datetime


class ExperienceListResponse(BaseModel):
    """Paginated response payload for GET /api/v1/experience."""

    items: list[ExperienceResponse]
    page: int
    page_size: int
    total: int
    total_pages: int


__all__ = [
    "ExperienceCreate",
    "ExperienceListResponse",
    "ExperienceResponse",
    "ExperienceSkillRef",
    "ExperienceType",
    "ExperienceUpdate",
    "ExperienceVisibility",
    "MAX_EXPERIENCE_DESCRIPTION_LEN",
    "MAX_EXPERIENCE_DOCUMENTS",
    "MAX_EXPERIENCE_HIGHLIGHTS",
    "MAX_EXPERIENCE_HIGHLIGHT_LEN",
    "MAX_EXPERIENCE_SKILLS",
    "validate_experience_dates",
]
