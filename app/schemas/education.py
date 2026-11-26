"""Pydantic v2 request and response schemas for Phase 2 Education Backend Core."""

from datetime import datetime
import math
from typing import Any, Literal
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.document import DocumentRef

EducationVisibility = Literal["public", "private", "unlisted", "connections"]
EducationResultType = Literal[
    "cgpa",
    "gpa",
    "percentage",
    "grade",
    "marks",
    "pass_fail",
    "other",
]
EducationResultSource = Literal["manual", "computed"]

MIN_EDUCATION_YEAR = 1900
MAX_EDUCATION_YEAR = 2100
MAX_ACHIEVEMENTS_COUNT = 50
MAX_ACHIEVEMENT_LENGTH = 300
MAX_DESCRIPTION_LENGTH = 5000


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
    max_length: int = MAX_DESCRIPTION_LENGTH,
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


def _reject_bool_for_int(value: Any, *, field_label: str) -> Any:
    if isinstance(value, bool):
        raise ValueError(f"{field_label} must be an integer")
    return value


def _validate_month(value: int | None, *, field_label: str) -> int | None:
    if value is not None and not (1 <= value <= 12):
        raise ValueError(f"{field_label} must be between 1 and 12")
    return value


def _validate_year(value: int | None, *, field_label: str) -> int | None:
    if value is not None and not (MIN_EDUCATION_YEAR <= value <= MAX_EDUCATION_YEAR):
        raise ValueError(
            f"{field_label} must be between {MIN_EDUCATION_YEAR} and {MAX_EDUCATION_YEAR}"
        )
    return value


def _normalize_enum_str(value: Any, *, field_label: str) -> Any:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_label} must be a string")
    cleaned = value.strip().lower()
    if not cleaned:
        return None
    return cleaned


def _clean_result_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("Result value must be a string or number")
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Result value must be finite")
        cleaned = str(value)
    elif isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        _reject_control_chars(cleaned, field_label="Result value")
    else:
        raise ValueError("Result value must be a string or number")

    if len(cleaned) > 64:
        raise ValueError("Result value must not exceed 64 characters")
    return cleaned


def _validate_achievements(value: Any) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError("Achievements must be a list of strings")
    if len(value) > MAX_ACHIEVEMENTS_COUNT:
        raise ValueError(f"Achievements must not exceed {MAX_ACHIEVEMENTS_COUNT} items")
    cleaned_items: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError("Each achievement must be a string")
        cleaned = item.strip()
        if not cleaned:
            raise ValueError("Achievements must not contain blank items")
        _reject_control_chars(cleaned, field_label="Achievement")
        if len(cleaned) > MAX_ACHIEVEMENT_LENGTH:
            raise ValueError(
                f"Each achievement must not exceed {MAX_ACHIEVEMENT_LENGTH} characters"
            )
        cleaned_items.append(cleaned)
    return cleaned_items


def _dedupe_document_ids(value: list[uuid.UUID] | None) -> list[uuid.UUID] | None:
    """Validate and deduplicate document UUIDs preserving input order."""
    if value is None:
        return None
    deduped: list[uuid.UUID] = []
    seen: set[uuid.UUID] = set()
    for doc_id in value:
        if doc_id not in seen:
            seen.add(doc_id)
            deduped.append(doc_id)
    return deduped


def validate_education_dates(
    *,
    start_month: int | None,
    start_year: int | None,
    end_month: int | None,
    end_year: int | None,
    is_current: bool,
) -> None:
    """Enforce start/end date consistency and ongoing-education invariants."""
    if start_month is not None and start_year is None:
        raise ValueError("start_year is required when start_month is provided")
    if end_month is not None and end_year is None:
        raise ValueError("end_year is required when end_month is provided")
    if is_current and (end_year is not None or end_month is not None):
        raise ValueError("Ongoing education cannot specify an end date")
    if start_year is not None and end_year is not None:
        if end_year < start_year:
            raise ValueError("end_year cannot be earlier than start_year")
        if (
            end_year == start_year
            and start_month is not None
            and end_month is not None
            and end_month < start_month
        ):
            raise ValueError("End date cannot be earlier than start date")


def validate_education_result(
    *,
    result_type: str | None,
    result_value: str | None,
) -> None:
    """Validate result_type and result_value consistency and numeric bounds."""
    if result_value is not None and result_type is None:
        raise ValueError("result_type is required when result_value is provided")
    if result_value is None or result_type is None:
        return

    if result_type in {"cgpa", "gpa"}:
        try:
            numeric = float(result_value)
        except ValueError:
            raise ValueError(
                f"result_value must be a valid number when result_type is '{result_type}'"
            ) from None
        if not math.isfinite(numeric) or numeric < 0.0 or numeric > 10.0:
            raise ValueError(
                f"result_value for '{result_type}' must be between 0 and 10"
            )
    elif result_type == "percentage":
        raw_num = result_value[:-1].strip() if result_value.endswith("%") else result_value
        try:
            numeric = float(raw_num)
        except ValueError:
            raise ValueError(
                "result_value must be a valid percentage between 0 and 100"
            ) from None
        if not math.isfinite(numeric) or numeric < 0.0 or numeric > 100.0:
            raise ValueError("Percentage result_value must be between 0 and 100")


class EducationCreate(BaseModel):
    """Request payload for POST /api/v1/education."""

    model_config = ConfigDict(extra="forbid")

    institution: str
    university_or_board: str | None = None
    education_level: str | None = None
    degree: str
    programme: str | None = None
    branch: str | None = None
    specialization: str | None = None
    country: str | None = None
    state: str | None = None
    start_month: int | None = None
    start_year: int | None = None
    end_month: int | None = None
    end_year: int | None = None
    is_current: bool = False
    description: str | None = None
    scheme_id: str | None = None
    result_type: EducationResultType | None = None
    result_value: str | None = None
    show_result_publicly: bool = True
    achievements: list[str] = Field(default_factory=list)
    document_ids: list[uuid.UUID] = Field(default_factory=list)
    visibility: EducationVisibility = "public"

    @field_validator("institution", mode="before")
    @classmethod
    def validate_institution(cls, value: Any) -> str:
        return _clean_required_str(value, field_label="institution", max_length=255)

    @field_validator("degree", mode="before")
    @classmethod
    def validate_degree(cls, value: Any) -> str:
        return _clean_required_str(value, field_label="degree", max_length=255)

    @field_validator("university_or_board", "programme", "branch", "specialization", mode="before")
    @classmethod
    def validate_optional_255(cls, value: Any, info: Any) -> str | None:
        return _clean_optional_str(value, field_label=info.field_name, max_length=255)

    @field_validator("education_level", "scheme_id", mode="before")
    @classmethod
    def validate_optional_64(cls, value: Any, info: Any) -> str | None:
        return _clean_optional_str(value, field_label=info.field_name, max_length=64)

    @field_validator("country", "state", mode="before")
    @classmethod
    def validate_optional_120(cls, value: Any, info: Any) -> str | None:
        return _clean_optional_str(value, field_label=info.field_name, max_length=120)

    @field_validator("description", mode="before")
    @classmethod
    def validate_description(cls, value: Any) -> str | None:
        return _clean_multiline_str(value, field_label="description")

    @field_validator("start_month", "end_month", "start_year", "end_year", mode="before")
    @classmethod
    def reject_bool_dates(cls, value: Any, info: Any) -> Any:
        return _reject_bool_for_int(value, field_label=info.field_name)

    @field_validator("start_month", "end_month", mode="after")
    @classmethod
    def check_month_range(cls, value: int | None, info: Any) -> int | None:
        return _validate_month(value, field_label=info.field_name)

    @field_validator("start_year", "end_year", mode="after")
    @classmethod
    def check_year_range(cls, value: int | None, info: Any) -> int | None:
        return _validate_year(value, field_label=info.field_name)

    @field_validator("result_type", mode="before")
    @classmethod
    def normalize_result_type(cls, value: Any) -> Any:
        return _normalize_enum_str(value, field_label="result_type")

    @field_validator("visibility", mode="before")
    @classmethod
    def normalize_visibility(cls, value: Any) -> Any:
        cleaned = _normalize_enum_str(value, field_label="visibility")
        if cleaned is None:
            raise ValueError("visibility cannot be blank or null")
        return cleaned

    @field_validator("result_value", mode="before")
    @classmethod
    def clean_result_value(cls, value: Any) -> str | None:
        return _clean_result_value(value)

    @field_validator("achievements", mode="before")
    @classmethod
    def validate_achievements(cls, value: Any) -> list[str]:
        if value is None:
            raise ValueError("achievements cannot be null")
        cleaned = _validate_achievements(value)
        assert cleaned is not None
        return cleaned

    @field_validator("document_ids", mode="after")
    @classmethod
    def dedupe_document_ids(cls, value: list[uuid.UUID]) -> list[uuid.UUID]:
        deduped = _dedupe_document_ids(value)
        assert deduped is not None
        return deduped

    @model_validator(mode="after")
    def validate_cross_field_rules(self) -> "EducationCreate":
        validate_education_dates(
            start_month=self.start_month,
            start_year=self.start_year,
            end_month=self.end_month,
            end_year=self.end_year,
            is_current=self.is_current,
        )
        validate_education_result(
            result_type=self.result_type,
            result_value=self.result_value,
        )
        return self


class EducationUpdate(BaseModel):
    """Partial-update request payload for PATCH /api/v1/education/{id}."""

    model_config = ConfigDict(extra="forbid")

    institution: str | None = None
    university_or_board: str | None = None
    education_level: str | None = None
    degree: str | None = None
    programme: str | None = None
    branch: str | None = None
    specialization: str | None = None
    country: str | None = None
    state: str | None = None
    start_month: int | None = None
    start_year: int | None = None
    end_month: int | None = None
    end_year: int | None = None
    is_current: bool | None = None
    description: str | None = None
    scheme_id: str | None = None
    result_type: EducationResultType | None = None
    result_value: str | None = None
    show_result_publicly: bool | None = None
    achievements: list[str] | None = None
    document_ids: list[uuid.UUID] | None = None
    visibility: EducationVisibility | None = None

    @field_validator("institution", mode="before")
    @classmethod
    def validate_institution(cls, value: Any) -> str | None:
        if value is None:
            return None
        return _clean_required_str(value, field_label="institution", max_length=255)

    @field_validator("degree", mode="before")
    @classmethod
    def validate_degree(cls, value: Any) -> str | None:
        if value is None:
            return None
        return _clean_required_str(value, field_label="degree", max_length=255)

    @field_validator("university_or_board", "programme", "branch", "specialization", mode="before")
    @classmethod
    def validate_optional_255(cls, value: Any, info: Any) -> str | None:
        return _clean_optional_str(value, field_label=info.field_name, max_length=255)

    @field_validator("education_level", "scheme_id", mode="before")
    @classmethod
    def validate_optional_64(cls, value: Any, info: Any) -> str | None:
        return _clean_optional_str(value, field_label=info.field_name, max_length=64)

    @field_validator("country", "state", mode="before")
    @classmethod
    def validate_optional_120(cls, value: Any, info: Any) -> str | None:
        return _clean_optional_str(value, field_label=info.field_name, max_length=120)

    @field_validator("description", mode="before")
    @classmethod
    def validate_description(cls, value: Any) -> str | None:
        return _clean_multiline_str(value, field_label="description")

    @field_validator("start_month", "end_month", "start_year", "end_year", mode="before")
    @classmethod
    def reject_bool_dates(cls, value: Any, info: Any) -> Any:
        return _reject_bool_for_int(value, field_label=info.field_name)

    @field_validator("start_month", "end_month", mode="after")
    @classmethod
    def check_month_range(cls, value: int | None, info: Any) -> int | None:
        return _validate_month(value, field_label=info.field_name)

    @field_validator("start_year", "end_year", mode="after")
    @classmethod
    def check_year_range(cls, value: int | None, info: Any) -> int | None:
        return _validate_year(value, field_label=info.field_name)

    @field_validator("result_type", mode="before")
    @classmethod
    def normalize_result_type(cls, value: Any) -> Any:
        return _normalize_enum_str(value, field_label="result_type")

    @field_validator("visibility", mode="before")
    @classmethod
    def normalize_visibility(cls, value: Any) -> Any:
        if value is None:
            return None
        cleaned = _normalize_enum_str(value, field_label="visibility")
        if cleaned is None:
            raise ValueError("visibility cannot be blank or null")
        return cleaned

    @field_validator("result_value", mode="before")
    @classmethod
    def clean_result_value(cls, value: Any) -> str | None:
        return _clean_result_value(value)

    @field_validator("achievements", mode="before")
    @classmethod
    def validate_achievements(cls, value: Any) -> list[str] | None:
        return _validate_achievements(value)

    @field_validator("document_ids", mode="after")
    @classmethod
    def dedupe_document_ids(cls, value: list[uuid.UUID] | None) -> list[uuid.UUID] | None:
        return _dedupe_document_ids(value)

    @model_validator(mode="after")
    def validate_patch_invariants(self) -> "EducationUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one education field must be provided")

        for non_nullable_field in (
            "institution",
            "degree",
            "is_current",
            "show_result_publicly",
            "achievements",
            "document_ids",
            "visibility",
        ):
            if (
                non_nullable_field in self.model_fields_set
                and getattr(self, non_nullable_field) is None
            ):
                raise ValueError(f"{non_nullable_field} cannot be null")

        if self.is_current is True and (
            self.end_year is not None or self.end_month is not None
        ):
            raise ValueError("Ongoing education cannot specify an end date")

        if (
            self.start_month is not None
            and "start_year" in self.model_fields_set
            and self.start_year is None
        ):
            raise ValueError("start_year is required when start_month is provided")

        if (
            self.end_month is not None
            and "end_year" in self.model_fields_set
            and self.end_year is None
        ):
            raise ValueError("end_year is required when end_month is provided")

        if self.start_year is not None and self.end_year is not None:
            if self.end_year < self.start_year:
                raise ValueError("end_year cannot be earlier than start_year")
            if (
                self.end_year == self.start_year
                and self.start_month is not None
                and self.end_month is not None
                and self.end_month < self.start_month
            ):
                raise ValueError("End date cannot be earlier than start date")

        if (
            self.result_value is not None
            and "result_type" in self.model_fields_set
            and self.result_type is None
        ):
            raise ValueError("result_type is required when result_value is provided")

        if self.result_type is not None and self.result_value is not None:
            validate_education_result(
                result_type=self.result_type,
                result_value=self.result_value,
            )

        return self


class EducationResponse(BaseModel):
    """Serialized education record returned by /api/v1/education endpoints."""

    id: uuid.UUID
    user_id: uuid.UUID
    institution: str
    university_or_board: str | None
    education_level: str | None
    degree: str
    programme: str | None
    branch: str | None
    specialization: str | None
    country: str | None
    state: str | None
    start_month: int | None
    start_year: int | None
    end_month: int | None
    end_year: int | None
    is_current: bool
    description: str | None
    scheme_id: str | None
    result_type: str | None
    result_value: str | None
    result_source: EducationResultSource
    computed_cgpa: float | None
    show_result_publicly: bool
    achievements: list[str]
    document_ids: list[uuid.UUID]
    documents: list[DocumentRef]
    visibility: EducationVisibility
    created_at: datetime
    updated_at: datetime


class EducationListResponse(BaseModel):
    """Paginated response payload for GET /api/v1/education."""

    items: list[EducationResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
