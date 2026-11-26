"""Pydantic v2 schemas for Phase 2 Stage 6 AI document analysis and structured extraction."""

from datetime import datetime
import math
from typing import Any, Literal
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

AnalysisStatus = Literal["pending", "processing", "completed", "failed"]
AnalyzedDocumentType = Literal["marksheet", "certificate", "other"]
AnalysisFailureReason = Literal[
    "provider_not_configured",
    "provider_unavailable",
    "provider_timeout",
    "provider_rate_limited",
    "invalid_provider_output",
    "unsupported_content",
    "analysis_error",
]


def _clean_optional_text(
    value: Any,
    *,
    field_name: str,
    max_length: int,
    allow_newlines: bool = False,
) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string or null")
    cleaned = value.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not cleaned:
        return None
    for ch in cleaned:
        code = ord(ch)
        if allow_newlines and ch in {"\n", "\t"}:
            continue
        if code < 0x20 or code == 0x7F:
            raise ValueError(f"{field_name} contains disallowed control characters")
    if len(cleaned) > max_length:
        raise ValueError(f"{field_name} exceeds maximum length of {max_length}")
    return cleaned


def _clean_required_text(
    value: Any,
    *,
    field_name: str,
    max_length: int,
    allow_newlines: bool = False,
) -> str:
    cleaned = _clean_optional_text(
        value,
        field_name=field_name,
        max_length=max_length,
        allow_newlines=allow_newlines,
    )
    if cleaned is None:
        raise ValueError(f"{field_name} cannot be blank")
    return cleaned


def _validate_finite_number(value: float | None, *, field_name: str) -> float | None:
    if value is None:
        return None
    if not math.isfinite(value):
        raise ValueError(f"{field_name} must be a finite number")
    return float(value)


class MarksheetSubjectExtraction(BaseModel):
    """Single subject row extracted from an academic marksheet (unverified)."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    subject_name: str
    subject_code: str | None = None
    marks_obtained: float | None = Field(default=None, ge=0.0, le=10000.0)
    max_marks: float | None = Field(default=None, gt=0.0, le=10000.0)
    grade: str | None = None
    raw_mark_text: str | None = None
    uncertain: bool = False

    @field_validator("subject_name", mode="before")
    @classmethod
    def validate_subject_name(cls, value: Any) -> str:
        return _clean_required_text(value, field_name="subject_name", max_length=200)

    @field_validator("subject_code", "grade", "raw_mark_text", mode="before")
    @classmethod
    def validate_optional_fields(cls, value: Any, info: Any) -> str | None:
        return _clean_optional_text(value, field_name=info.field_name, max_length=64)

    @field_validator("marks_obtained", "max_marks")
    @classmethod
    def validate_finite_marks(cls, value: float | None, info: Any) -> float | None:
        return _validate_finite_number(value, field_name=info.field_name)

    @model_validator(mode="after")
    def validate_marks_bounds(self) -> "MarksheetSubjectExtraction":
        if (
            self.marks_obtained is not None
            and self.max_marks is not None
            and self.marks_obtained > self.max_marks
        ):
            raise ValueError("marks_obtained cannot exceed max_marks")
        return self


class MarksheetExtraction(BaseModel):
    """Structured fields extracted from an academic semester marksheet (unverified)."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    institution_name: str | None = None
    student_name: str | None = None
    program_or_course: str | None = None
    semester_or_exam: str | None = None
    academic_year: str | None = None
    subjects: list[MarksheetSubjectExtraction] = Field(default_factory=list, max_length=100)
    total_marks_obtained: float | None = Field(default=None, ge=0.0, le=100000.0)
    total_max_marks: float | None = Field(default=None, gt=0.0, le=100000.0)
    result_status: str | None = None

    @field_validator(
        "institution_name",
        "student_name",
        "program_or_course",
        "semester_or_exam",
        "academic_year",
        "result_status",
        mode="before",
    )
    @classmethod
    def validate_optional_strings(cls, value: Any, info: Any) -> str | None:
        return _clean_optional_text(value, field_name=info.field_name, max_length=200)

    @field_validator("total_marks_obtained", "total_max_marks")
    @classmethod
    def validate_finite_totals(cls, value: float | None, info: Any) -> float | None:
        return _validate_finite_number(value, field_name=info.field_name)

    @model_validator(mode="after")
    def validate_totals_bounds(self) -> "MarksheetExtraction":
        if (
            self.total_marks_obtained is not None
            and self.total_max_marks is not None
            and self.total_marks_obtained > self.total_max_marks
        ):
            raise ValueError("total_marks_obtained cannot exceed total_max_marks")
        return self


class CertificateExtraction(BaseModel):
    """Structured fields extracted from an academic or achievement certificate (unverified)."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    certificate_title: str | None = None
    issuing_institution: str | None = None
    recipient_name: str | None = None
    award_or_qualification: str | None = None
    issue_date: str | None = None

    @field_validator(
        "certificate_title",
        "issuing_institution",
        "recipient_name",
        "award_or_qualification",
        "issue_date",
        mode="before",
    )
    @classmethod
    def validate_optional_strings(cls, value: Any, info: Any) -> str | None:
        return _clean_optional_text(value, field_name=info.field_name, max_length=200)


class DocumentExtractionPayload(BaseModel):
    """Canonical structured extraction payload emitted and validated from an AI provider."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    document_type: AnalyzedDocumentType
    is_verified: Literal[False] = False
    summary: str
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    uncertain_fields: list[str] = Field(default_factory=list, max_length=50)
    extracted_text_excerpt: str | None = None
    marksheet: MarksheetExtraction | None = None
    certificate: CertificateExtraction | None = None

    @field_validator("summary", mode="before")
    @classmethod
    def validate_summary(cls, value: Any) -> str:
        return _clean_required_text(
            value,
            field_name="summary",
            max_length=1000,
            allow_newlines=True,
        )

    @field_validator("extracted_text_excerpt", mode="before")
    @classmethod
    def validate_excerpt(cls, value: Any) -> str | None:
        return _clean_optional_text(
            value,
            field_name="extracted_text_excerpt",
            max_length=2000,
            allow_newlines=True,
        )

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, value: float | None) -> float | None:
        return _validate_finite_number(value, field_name="confidence")

    @field_validator("uncertain_fields", mode="before")
    @classmethod
    def normalize_uncertain_fields(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError("uncertain_fields must be a list")
        cleaned_items: list[str] = []
        seen: set[str] = set()
        for item in value:
            cleaned = _clean_optional_text(
                item,
                field_name="uncertain_fields[]",
                max_length=120,
            )
            if cleaned is not None and cleaned not in seen:
                seen.add(cleaned)
                cleaned_items.append(cleaned)
        if len(cleaned_items) > 50:
            raise ValueError("uncertain_fields must not exceed 50 items")
        return cleaned_items


class DocumentAnalysisResponse(BaseModel):
    """API response schema for owner-scoped document AI analysis state and extracted data."""

    id: uuid.UUID
    document_id: uuid.UUID
    status: AnalysisStatus
    document_type: AnalyzedDocumentType | None = None
    is_verified: Literal[False] = False
    provider_name: str
    model_name: str
    analyzer_version: str
    attempts: int
    summary: str | None = None
    extracted_data: DocumentExtractionPayload | None = None
    confidence: float | None = None
    uncertain_fields: list[str] = Field(default_factory=list)
    failure_reason: AnalysisFailureReason | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
