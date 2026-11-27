"""Pydantic v2 schemas for the Skills module."""

from datetime import datetime
from typing import Any, Literal
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _clean_required_text(value: Any, *, field_label: str, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_label} must be a string")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_label} cannot be blank")
    if len(cleaned) > max_length:
        raise ValueError(f"{field_label} must not exceed {max_length} characters")
    return cleaned


def _clean_optional_text(value: Any, *, field_label: str, max_length: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_label} must be a string")
    cleaned = value.strip()
    if not cleaned:
        return None
    if len(cleaned) > max_length:
        raise ValueError(f"{field_label} must not exceed {max_length} characters")
    return cleaned


class SkillBase(BaseModel):
    """Shared fields for user skill payloads."""

    name: str = Field(..., min_length=1, max_length=100)
    category: str = Field(default="technical", min_length=1, max_length=50)
    proficiency: str | None = Field(default=None, max_length=50)

    @field_validator("name", mode="before")
    @classmethod
    def validate_name(cls, value: Any) -> str:
        return _clean_required_text(value, field_label="name", max_length=100)

    @field_validator("category", mode="before")
    @classmethod
    def validate_category(cls, value: Any) -> str:
        return _clean_required_text(value, field_label="category", max_length=50)

    @field_validator("proficiency", mode="before")
    @classmethod
    def validate_proficiency(cls, value: Any) -> str | None:
        return _clean_optional_text(value, field_label="proficiency", max_length=50)


class SkillCreate(SkillBase):
    """Request schema for creating a new skill."""


class SkillUpdate(BaseModel):
    """Request schema for updating an existing skill."""

    name: str | None = Field(default=None, min_length=1, max_length=100)
    category: str | None = Field(default=None, min_length=1, max_length=50)
    proficiency: str | None = Field(default=None, max_length=50)

    @field_validator("name", mode="before")
    @classmethod
    def validate_name(cls, value: Any) -> str | None:
        if value is None:
            return None
        return _clean_required_text(value, field_label="name", max_length=100)

    @field_validator("category", mode="before")
    @classmethod
    def validate_category(cls, value: Any) -> str | None:
        if value is None:
            return None
        return _clean_required_text(value, field_label="category", max_length=50)

    @field_validator("proficiency", mode="before")
    @classmethod
    def validate_proficiency(cls, value: Any) -> str | None:
        return _clean_optional_text(value, field_label="proficiency", max_length=50)


class SkillResponse(SkillBase):
    """Response schema representing a persisted user skill."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class SkillListResponse(BaseModel):
    """Paginated list response for user skills."""

    items: list[SkillResponse]
    page: int
    page_size: int
    total: int
    total_pages: int


def _clean_string_list(value: Any, *, field_label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field_label} must be a list of strings")
    cleaned_items: list[str] = []
    for item in value:
        if item is None:
            continue
        cleaned = str(item).strip()
        if cleaned:
            cleaned_items.append(cleaned)
    return cleaned_items


class GapAnalysisRequest(BaseModel):
    """Request schema for AI skill gap analysis."""

    target_role: str = Field(..., min_length=1, max_length=150)

    @field_validator("target_role", mode="before")
    @classmethod
    def validate_target_role(cls, value: Any) -> str:
        return _clean_required_text(value, field_label="target_role", max_length=150)


class GapAnalysisResponse(BaseModel):
    """Structured AI response for skill gap analysis."""

    match_percentage: int = Field(..., ge=0, le=100)
    missing_skills: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)

    @field_validator("missing_skills", "recommendations", mode="before")
    @classmethod
    def validate_string_lists(cls, value: Any, info: Any) -> list[str]:
        return _clean_string_list(value, field_label=info.field_name or "items")


SkillImportSource = Literal["project", "resume"]
SkillImportCategory = Literal["technical", "tool", "soft"]


def _normalize_import_category(value: Any) -> SkillImportCategory:
    if not isinstance(value, str):
        return "technical"
    normalized = value.strip().lower()
    if normalized in {"tool", "tools", "tools, software & equipment"}:
        return "tool"
    if normalized in {"soft", "communication", "workplace & soft skills"}:
        return "soft"
    return "technical"


class SkillImportCandidate(BaseModel):
    """Extracted skill candidate ready for user review before persistence."""

    name: str = Field(..., min_length=1, max_length=100)
    category: SkillImportCategory = "technical"
    proficiency: str | None = Field(default=None, max_length=50)
    source: SkillImportSource
    source_label: str | None = Field(default=None, max_length=255)

    @field_validator("name", mode="before")
    @classmethod
    def validate_name(cls, value: Any) -> str:
        return _clean_required_text(value, field_label="name", max_length=100)

    @field_validator("category", mode="before")
    @classmethod
    def validate_category(cls, value: Any) -> SkillImportCategory:
        return _normalize_import_category(value)

    @field_validator("proficiency", mode="before")
    @classmethod
    def validate_proficiency(cls, value: Any) -> str | None:
        return _clean_optional_text(value, field_label="proficiency", max_length=50)

    @field_validator("source_label", mode="before")
    @classmethod
    def validate_source_label(cls, value: Any) -> str | None:
        return _clean_optional_text(value, field_label="source_label", max_length=255)


class SkillImportPreviewRequest(BaseModel):
    """Request payload for previewing skill candidates from Projects and Resumes."""

    sources: list[SkillImportSource] = Field(default_factory=lambda: ["project", "resume"])
    document_id: uuid.UUID | None = None


class SkillImportPreviewResponse(BaseModel):
    """Extracted skill candidates and skipped duplicates for import review."""

    candidates: list[SkillImportCandidate] = Field(default_factory=list)
    skipped_existing: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class SkillBulkCreateRequest(BaseModel):
    """Request payload for bulk-creating selected skills."""

    skills: list[SkillCreate] = Field(..., min_length=1, max_length=100)


class SkillBulkCreateResponse(BaseModel):
    """Result of bulk skill creation with deduplicated skips."""

    created: list[SkillResponse] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)
