"""Pydantic v2 request and response schemas for Phase 3 Projects Portfolio."""

from datetime import date, datetime
from typing import Any, Literal
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.document import DocumentRef

ProjectVisibility = Literal["private", "public"]

MAX_PROJECT_TECHNOLOGIES = 20
MAX_PROJECT_TECHNOLOGY_LEN = 60
MAX_PROJECT_DESCRIPTION_LEN = 10_000


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
    max_length: int = MAX_PROJECT_DESCRIPTION_LEN,
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


def _clean_technologies(value: Any) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError("technologies must be a list of strings")
    if len(value) > MAX_PROJECT_TECHNOLOGIES:
        raise ValueError(f"technologies must not exceed {MAX_PROJECT_TECHNOLOGIES} items")
    cleaned_items: list[str] = []
    seen_lower: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise ValueError("Each technology must be a string")
        cleaned = item.strip()
        if not cleaned:
            continue
        _reject_control_chars(cleaned, field_label="technology")
        if len(cleaned) > MAX_PROJECT_TECHNOLOGY_LEN:
            raise ValueError(
                f"Each technology must not exceed {MAX_PROJECT_TECHNOLOGY_LEN} characters"
            )
        lowered = cleaned.lower()
        if lowered not in seen_lower:
            seen_lower.add(lowered)
            cleaned_items.append(cleaned)
    return cleaned_items


def _normalize_visibility(value: Any, *, allow_none: bool) -> Any:
    if value is None:
        if allow_none:
            return None
        raise ValueError("visibility cannot be null")
    if not isinstance(value, str):
        raise ValueError("visibility must be a string")
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError("visibility cannot be blank")
    return cleaned


def validate_project_dates(
    *,
    start_date: date | None,
    end_date: date | None,
    is_ongoing: bool,
) -> None:
    """Enforce ongoing/date-order consistency for projects."""
    if is_ongoing and end_date is not None:
        raise ValueError("Ongoing project cannot specify an end_date")
    if start_date is not None and end_date is not None and end_date < start_date:
        raise ValueError("end_date cannot be earlier than start_date")


class ProjectCreate(BaseModel):
    """Request payload for POST /api/v1/projects."""

    model_config = ConfigDict(extra="forbid")

    title: str
    summary: str
    description: str | None = None
    category: str = "General"
    technologies: list[str] = Field(default_factory=list)
    skill_ids: list[uuid.UUID] = Field(default_factory=list)
    github_url: str | None = None
    live_url: str | None = None
    start_date: date | None = None
    end_date: date | None = None
    is_ongoing: bool = False
    report_document_id: uuid.UUID | None = None
    featured: bool = False
    order: int = 0
    visibility: ProjectVisibility = "private"

    @field_validator("title", mode="before")
    @classmethod
    def validate_title(cls, value: Any) -> str:
        return _clean_required_str(value, field_label="title", max_length=200)

    @field_validator("summary", mode="before")
    @classmethod
    def validate_summary(cls, value: Any) -> str:
        return _clean_required_str(value, field_label="summary", max_length=500)

    @field_validator("category", mode="before")
    @classmethod
    def validate_category(cls, value: Any) -> str:
        if value is None or (isinstance(value, str) and not value.strip()):
            return "General"
        return _clean_required_str(value, field_label="category", max_length=80)

    @field_validator("description", mode="before")
    @classmethod
    def validate_description(cls, value: Any) -> str | None:
        return _clean_multiline_str(value, field_label="description")

    @field_validator("technologies", mode="before")
    @classmethod
    def validate_technologies(cls, value: Any) -> list[str]:
        if value is None:
            raise ValueError("technologies cannot be null")
        cleaned = _clean_technologies(value)
        assert cleaned is not None
        return cleaned

    @field_validator("github_url", mode="before")
    @classmethod
    def validate_github_url(cls, value: Any) -> str | None:
        return _clean_http_url(value, field_label="github_url")

    @field_validator("live_url", mode="before")
    @classmethod
    def validate_live_url(cls, value: Any) -> str | None:
        return _clean_http_url(value, field_label="live_url")

    @field_validator("order")
    @classmethod
    def validate_order(cls, value: int) -> int:
        if value < 0:
            raise ValueError("order must be non-negative")
        return value

    @field_validator("visibility", mode="before")
    @classmethod
    def validate_visibility(cls, value: Any) -> Any:
        return _normalize_visibility(value, allow_none=False)

    @model_validator(mode="after")
    def validate_cross_field_rules(self) -> "ProjectCreate":
        validate_project_dates(
            start_date=self.start_date,
            end_date=self.end_date,
            is_ongoing=self.is_ongoing,
        )
        return self


class ProjectUpdate(BaseModel):
    """Partial update request payload for PATCH /api/v1/projects/{id}."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = None
    summary: str | None = None
    description: str | None = None
    category: str | None = None
    technologies: list[str] | None = None
    skill_ids: list[uuid.UUID] | None = None
    github_url: str | None = None
    live_url: str | None = None
    start_date: date | None = None
    end_date: date | None = None
    is_ongoing: bool | None = None
    report_document_id: uuid.UUID | None = None
    featured: bool | None = None
    order: int | None = None
    visibility: ProjectVisibility | None = None

    @field_validator("title", mode="before")
    @classmethod
    def validate_title(cls, value: Any) -> str | None:
        if value is None:
            return None
        return _clean_required_str(value, field_label="title", max_length=200)

    @field_validator("summary", mode="before")
    @classmethod
    def validate_summary(cls, value: Any) -> str | None:
        if value is None:
            return None
        return _clean_required_str(value, field_label="summary", max_length=500)

    @field_validator("category", mode="before")
    @classmethod
    def validate_category(cls, value: Any) -> str | None:
        if value is None:
            return None
        return _clean_required_str(value, field_label="category", max_length=80)

    @field_validator("description", mode="before")
    @classmethod
    def validate_description(cls, value: Any) -> str | None:
        return _clean_multiline_str(value, field_label="description")

    @field_validator("technologies", mode="before")
    @classmethod
    def validate_technologies(cls, value: Any) -> list[str] | None:
        return _clean_technologies(value)

    @field_validator("github_url", mode="before")
    @classmethod
    def validate_github_url(cls, value: Any) -> str | None:
        return _clean_http_url(value, field_label="github_url")

    @field_validator("live_url", mode="before")
    @classmethod
    def validate_live_url(cls, value: Any) -> str | None:
        return _clean_http_url(value, field_label="live_url")

    @field_validator("order")
    @classmethod
    def validate_order(cls, value: int | None) -> int | None:
        if value is not None and value < 0:
            raise ValueError("order must be non-negative")
        return value

    @field_validator("visibility", mode="before")
    @classmethod
    def validate_visibility(cls, value: Any) -> Any:
        return _normalize_visibility(value, allow_none=True)

    @model_validator(mode="after")
    def validate_patch_invariants(self) -> "ProjectUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one project field must be provided")

        for non_nullable_field in (
            "title",
            "summary",
            "category",
            "technologies",
            "is_ongoing",
            "featured",
            "order",
            "visibility",
        ):
            if (
                non_nullable_field in self.model_fields_set
                and getattr(self, non_nullable_field) is None
            ):
                raise ValueError(f"{non_nullable_field} cannot be null")

        if self.is_ongoing is True and self.end_date is not None:
            raise ValueError("Ongoing project cannot specify an end_date")
        if self.start_date is not None and self.end_date is not None and self.end_date < self.start_date:
            raise ValueError("end_date cannot be earlier than start_date")

        return self


class ProjectImageResponse(BaseModel):
    """Serialized project cover/showcase image."""

    id: uuid.UUID
    url: str
    alt: str | None
    order: int


class ProjectImageUpdate(BaseModel):
    """Metadata update payload for PATCH /api/v1/projects/{id}/images/{image_id}."""

    model_config = ConfigDict(extra="forbid")

    alt: str | None = None
    order: int | None = None

    @field_validator("alt", mode="before")
    @classmethod
    def validate_alt(cls, value: Any) -> str | None:
        return _clean_optional_str(value, field_label="alt", max_length=255)

    @field_validator("order")
    @classmethod
    def validate_order(cls, value: int | None) -> int | None:
        if value is not None and value < 0:
            raise ValueError("order must be non-negative")
        return value

    @model_validator(mode="after")
    def require_any_field(self) -> "ProjectImageUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one image field must be provided")
        if "order" in self.model_fields_set and self.order is None:
            raise ValueError("order cannot be null")
        return self


class ProjectSkillRef(BaseModel):
    """Skill reference associated with a project."""

    id: uuid.UUID
    name: str


class ProjectGitHubImportMeta(BaseModel):
    """Provenance metadata for a project imported from GitHub."""

    repo_full_name: str
    imported_at: datetime


class ProjectResponse(BaseModel):
    """Serialized project returned by /api/v1/projects endpoints."""

    id: uuid.UUID
    title: str
    summary: str
    description: str | None
    category: str
    technologies: list[str]
    github_url: str | None
    live_url: str | None
    start_date: date | None
    end_date: date | None
    is_ongoing: bool
    featured: bool
    order: int
    visibility: ProjectVisibility
    images: list[ProjectImageResponse]
    skills: list[ProjectSkillRef] = Field(default_factory=list)
    report_document: DocumentRef | None = None
    github_import: ProjectGitHubImportMeta | None
    created_at: datetime
    updated_at: datetime


class ProjectListResponse(BaseModel):
    """Paginated response payload for GET /api/v1/projects."""

    items: list[ProjectResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
