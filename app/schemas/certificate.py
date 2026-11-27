"""Pydantic v2 request and response schemas for Certificates and Achievements."""

from datetime import date as date_type, datetime
from typing import Any, Literal
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.document import DocumentRef

CertificateCategory = Literal[
    "course",
    "professional",
    "training",
    "workshop",
    "participation",
    "academic",
    "other",
]
CertificateVerificationStatus = Literal[
    "self_reported",
    "link_provided",
    "issuer_verified",
]
AchievementCategory = Literal[
    "award",
    "competition",
    "publication",
    "scholarship",
    "academic_distinction",
    "hackathon",
    "leadership",
    "extracurricular",
    "other",
]
CredentialVisibility = Literal["private", "public"]

MAX_ACHIEVEMENT_DESCRIPTION_LEN = 5_000
MAX_ACHIEVEMENT_DOCUMENTS = 10
MAX_CERTIFICATE_SKILLS = 30


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
    max_length: int = MAX_ACHIEVEMENT_DESCRIPTION_LEN,
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


def validate_certificate_dates(
    *,
    issue_date: date_type | None,
    expiry_date: date_type | None,
) -> None:
    """Enforce expiry_date >= issue_date when both dates are present."""
    if issue_date is not None and expiry_date is not None and expiry_date < issue_date:
        raise ValueError("expiry_date cannot be earlier than issue_date")


def compute_verification_status(verification_url: str | None) -> CertificateVerificationStatus:
    """Derive verification_status strictly on the server from verification_url."""
    return "link_provided" if verification_url else "self_reported"


class CertificateSkillRef(BaseModel):
    """Skill reference associated with a certificate."""

    id: uuid.UUID
    name: str


class CertificateCreate(BaseModel):
    """Request payload for POST /api/v1/certificates."""

    model_config = ConfigDict(extra="forbid")

    name: str
    issuer: str
    category: CertificateCategory = "course"
    issue_date: date_type | None = None
    expiry_date: date_type | None = None
    credential_id: str | None = None
    verification_url: str | None = None
    document_id: uuid.UUID | None = None
    skill_ids: list[uuid.UUID] = Field(default_factory=list)
    featured: bool = False
    order: int = 0
    visibility: CredentialVisibility = "private"

    @field_validator("name", mode="before")
    @classmethod
    def validate_name(cls, value: Any) -> str:
        return _clean_required_str(value, field_label="name", max_length=200)

    @field_validator("issuer", mode="before")
    @classmethod
    def validate_issuer(cls, value: Any) -> str:
        return _clean_required_str(value, field_label="issuer", max_length=200)

    @field_validator("category", mode="before")
    @classmethod
    def validate_category(cls, value: Any) -> Any:
        if value is None or (isinstance(value, str) and not value.strip()):
            return "course"
        return _normalize_enum_str(value, field_label="category", allow_none=False)

    @field_validator("credential_id", mode="before")
    @classmethod
    def validate_credential_id(cls, value: Any) -> str | None:
        return _clean_optional_str(value, field_label="credential_id", max_length=120)

    @field_validator("verification_url", mode="before")
    @classmethod
    def validate_verification_url(cls, value: Any) -> str | None:
        return _clean_http_url(value, field_label="verification_url")

    @field_validator("skill_ids", mode="before")
    @classmethod
    def validate_skill_ids(cls, value: Any) -> list[uuid.UUID]:
        result = _dedupe_uuids(
            value,
            field_label="skill_ids",
            max_items=MAX_CERTIFICATE_SKILLS,
            allow_none=False,
        )
        assert result is not None
        return result

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
    def validate_dates(self) -> "CertificateCreate":
        validate_certificate_dates(
            issue_date=self.issue_date,
            expiry_date=self.expiry_date,
        )
        return self


class CertificateUpdate(BaseModel):
    """Partial update payload for PATCH /api/v1/certificates/{id}."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    issuer: str | None = None
    category: CertificateCategory | None = None
    issue_date: date_type | None = None
    expiry_date: date_type | None = None
    credential_id: str | None = None
    verification_url: str | None = None
    document_id: uuid.UUID | None = None
    skill_ids: list[uuid.UUID] | None = None
    featured: bool | None = None
    order: int | None = None
    visibility: CredentialVisibility | None = None

    @field_validator("name", mode="before")
    @classmethod
    def validate_name(cls, value: Any) -> str | None:
        if value is None:
            return None
        return _clean_required_str(value, field_label="name", max_length=200)

    @field_validator("issuer", mode="before")
    @classmethod
    def validate_issuer(cls, value: Any) -> str | None:
        if value is None:
            return None
        return _clean_required_str(value, field_label="issuer", max_length=200)

    @field_validator("category", mode="before")
    @classmethod
    def validate_category(cls, value: Any) -> Any:
        return _normalize_enum_str(value, field_label="category", allow_none=True)

    @field_validator("credential_id", mode="before")
    @classmethod
    def validate_credential_id(cls, value: Any) -> str | None:
        return _clean_optional_str(value, field_label="credential_id", max_length=120)

    @field_validator("verification_url", mode="before")
    @classmethod
    def validate_verification_url(cls, value: Any) -> str | None:
        return _clean_http_url(value, field_label="verification_url")

    @field_validator("skill_ids", mode="before")
    @classmethod
    def validate_skill_ids(cls, value: Any) -> list[uuid.UUID] | None:
        return _dedupe_uuids(
            value,
            field_label="skill_ids",
            max_items=MAX_CERTIFICATE_SKILLS,
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
        return _normalize_visibility(value, allow_none=True)

    @model_validator(mode="after")
    def validate_patch_invariants(self) -> "CertificateUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one certificate field must be provided")

        for non_nullable in ("name", "issuer", "category", "skill_ids", "featured", "order", "visibility"):
            if non_nullable in self.model_fields_set and getattr(self, non_nullable) is None:
                raise ValueError(f"{non_nullable} cannot be null")

        validate_certificate_dates(
            issue_date=self.issue_date,
            expiry_date=self.expiry_date,
        )
        return self


class CertificateResponse(BaseModel):
    """Serialized certificate returned by /api/v1/certificates."""

    id: uuid.UUID
    name: str
    issuer: str
    category: CertificateCategory
    issue_date: date_type | None
    expiry_date: date_type | None
    credential_id: str | None
    verification_url: str | None
    verification_status: CertificateVerificationStatus
    document: DocumentRef | None
    skills: list[CertificateSkillRef] = Field(default_factory=list)
    featured: bool
    order: int
    visibility: CredentialVisibility
    created_at: datetime
    updated_at: datetime


class CertificateListResponse(BaseModel):
    """Paginated response payload for GET /api/v1/certificates."""

    items: list[CertificateResponse]
    page: int
    page_size: int
    total: int
    total_pages: int


class AchievementCreate(BaseModel):
    """Request payload for POST /api/v1/achievements."""

    model_config = ConfigDict(extra="forbid")

    title: str
    category: AchievementCategory = "award"
    organization: str | None = None
    date: date_type | None = None
    description: str | None = None
    document_ids: list[uuid.UUID] = Field(default_factory=list)
    featured: bool = False
    order: int = 0
    visibility: CredentialVisibility = "private"

    @field_validator("title", mode="before")
    @classmethod
    def validate_title(cls, value: Any) -> str:
        return _clean_required_str(value, field_label="title", max_length=200)

    @field_validator("category", mode="before")
    @classmethod
    def validate_category(cls, value: Any) -> Any:
        if value is None or (isinstance(value, str) and not value.strip()):
            return "award"
        return _normalize_enum_str(value, field_label="category", allow_none=False)

    @field_validator("organization", mode="before")
    @classmethod
    def validate_organization(cls, value: Any) -> str | None:
        return _clean_optional_str(value, field_label="organization", max_length=200)

    @field_validator("description", mode="before")
    @classmethod
    def validate_description(cls, value: Any) -> str | None:
        return _clean_multiline_str(value, field_label="description")

    @field_validator("document_ids", mode="before")
    @classmethod
    def validate_document_ids(cls, value: Any) -> list[uuid.UUID]:
        result = _dedupe_uuids(
            value,
            field_label="document_ids",
            max_items=MAX_ACHIEVEMENT_DOCUMENTS,
            allow_none=False,
        )
        assert result is not None
        return result

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


class AchievementUpdate(BaseModel):
    """Partial update payload for PATCH /api/v1/achievements/{id}."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = None
    category: AchievementCategory | None = None
    organization: str | None = None
    date: date_type | None = None
    description: str | None = None
    document_ids: list[uuid.UUID] | None = None
    featured: bool | None = None
    order: int | None = None
    visibility: CredentialVisibility | None = None

    @field_validator("title", mode="before")
    @classmethod
    def validate_title(cls, value: Any) -> str | None:
        if value is None:
            return None
        return _clean_required_str(value, field_label="title", max_length=200)

    @field_validator("category", mode="before")
    @classmethod
    def validate_category(cls, value: Any) -> Any:
        return _normalize_enum_str(value, field_label="category", allow_none=True)

    @field_validator("organization", mode="before")
    @classmethod
    def validate_organization(cls, value: Any) -> str | None:
        return _clean_optional_str(value, field_label="organization", max_length=200)

    @field_validator("description", mode="before")
    @classmethod
    def validate_description(cls, value: Any) -> str | None:
        return _clean_multiline_str(value, field_label="description")

    @field_validator("document_ids", mode="before")
    @classmethod
    def validate_document_ids(cls, value: Any) -> list[uuid.UUID] | None:
        return _dedupe_uuids(
            value,
            field_label="document_ids",
            max_items=MAX_ACHIEVEMENT_DOCUMENTS,
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
        return _normalize_visibility(value, allow_none=True)

    @model_validator(mode="after")
    def validate_patch_invariants(self) -> "AchievementUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one achievement field must be provided")

        for non_nullable in ("title", "category", "document_ids", "featured", "order", "visibility"):
            if non_nullable in self.model_fields_set and getattr(self, non_nullable) is None:
                raise ValueError(f"{non_nullable} cannot be null")
        return self


class AchievementResponse(BaseModel):
    """Serialized achievement returned by /api/v1/achievements."""

    id: uuid.UUID
    title: str
    category: AchievementCategory
    organization: str | None
    date: date_type | None
    description: str | None
    documents: list[DocumentRef] = Field(default_factory=list)
    featured: bool
    order: int
    visibility: CredentialVisibility
    created_at: datetime
    updated_at: datetime


class AchievementListResponse(BaseModel):
    """Paginated response payload for GET /api/v1/achievements."""

    items: list[AchievementResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
