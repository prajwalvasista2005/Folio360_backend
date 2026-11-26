"""Pydantic v2 request and response schemas for Phase 2 Stage 4 Document Vault."""

from datetime import datetime
from typing import Any, Literal
import uuid

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

DocumentCategory = Literal[
    "marksheet",
    "certificate",
    "resume",
    "identity",
    "project_report",
    "other",
]
DocumentMimeType = Literal["application/pdf", "image/jpeg", "image/png"]
DocumentProcessingStatus = Literal[
    "pending_scan",
    "scanning",
    "ready",
    "rejected",
    "scan_failed",
]
DocumentFailureReason = Literal[
    "malware_detected",
    "validation_failed",
    "scanner_unavailable",
    "scanner_timeout",
    "scanner_error",
    "promotion_failed",
]

DOCUMENT_CATEGORY_LABELS: dict[DocumentCategory, str] = {
    "marksheet": "Marksheet",
    "certificate": "Certificate",
    "resume": "Resume",
    "identity": "Identity",
    "project_report": "Project Report",
    "other": "Other",
}

MAX_DOCUMENT_TITLE_LENGTH = 255
MAX_DOCUMENT_NOTES_LENGTH = 2000


def _reject_control_chars(value: str, *, field_label: str, allow_newline: bool = False) -> None:
    for ch in value:
        code = ord(ch)
        if allow_newline and ch == "\n":
            continue
        if code < 0x20 or code == 0x7F:
            raise ValueError(f"{field_label} must not contain control characters")


def clean_document_title(value: Any) -> str:
    """Validate and normalize a required document title."""
    if not isinstance(value, str):
        raise ValueError("title must be a string")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("title cannot be blank")
    _reject_control_chars(cleaned, field_label="title")
    if len(cleaned) > MAX_DOCUMENT_TITLE_LENGTH:
        raise ValueError(f"title must not exceed {MAX_DOCUMENT_TITLE_LENGTH} characters")
    return cleaned


def clean_document_notes(value: Any) -> str | None:
    """Validate and normalize optional multiline document notes."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("notes must be a string")
    normalized = value.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not normalized:
        return None
    _reject_control_chars(normalized, field_label="notes", allow_newline=True)
    if len(normalized) > MAX_DOCUMENT_NOTES_LENGTH:
        raise ValueError(f"notes must not exceed {MAX_DOCUMENT_NOTES_LENGTH} characters")
    return normalized


class DocumentCategoryInfo(BaseModel):
    """Single category entry returned by GET /api/v1/documents/categories."""

    key: DocumentCategory
    label: str


class DocumentCategoriesResponse(BaseModel):
    """Response payload for GET /api/v1/documents/categories."""

    items: list[DocumentCategoryInfo]


class DocumentAttachedToItem(BaseModel):
    """Entity reference indicating where a document is currently attached."""

    entity_type: Literal["education"]
    entity_id: uuid.UUID
    label: str


class DocumentRef(BaseModel):
    """Compact document reference embedded in Education and portfolio responses."""

    id: uuid.UUID
    title: str
    category: DocumentCategory
    mime_type: DocumentMimeType


class DocumentResponse(BaseModel):
    """Full document metadata payload matching the frontend Document Vault contract."""

    id: uuid.UUID
    user_id: uuid.UUID
    title: str
    original_filename: str
    category: DocumentCategory
    mime_type: DocumentMimeType
    size_bytes: int
    page_count: int | None
    sha256: str
    notes: str | None
    processing_status: DocumentProcessingStatus
    failure_reason: DocumentFailureReason | None = None
    show_in_education: bool
    attached_to: list[DocumentAttachedToItem]
    uploaded_at: datetime
    updated_at: datetime


class DocumentUploadResponse(BaseModel):
    """Response payload for POST /api/v1/documents (Stage 4 keeps processing_job=None)."""

    document: DocumentResponse
    processing_job: None = None


class DocumentListResponse(BaseModel):
    """Paginated response payload for GET /api/v1/documents."""

    items: list[DocumentResponse]
    page: int
    page_size: int
    total: int
    total_pages: int


class DocumentUpdateRequest(BaseModel):
    """Metadata-only partial update payload for PATCH /api/v1/documents/{id}."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = None
    category: DocumentCategory | None = None
    notes: str | None = None
    show_in_education: bool | None = None

    @field_validator("title", mode="before")
    @classmethod
    def validate_title(cls, value: Any) -> str | None:
        if value is None:
            return None
        return clean_document_title(value)

    @field_validator("category", mode="before")
    @classmethod
    def normalize_category(cls, value: Any) -> Any:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("category must be a string")
        cleaned = value.strip().lower()
        return cleaned

    @field_validator("notes", mode="before")
    @classmethod
    def validate_notes(cls, value: Any) -> str | None:
        return clean_document_notes(value)

    @model_validator(mode="after")
    def validate_patch_invariants(self) -> "DocumentUpdateRequest":
        if not self.model_fields_set:
            raise ValueError("At least one document metadata field must be provided")
        for non_nullable_field in ("title", "category", "show_in_education"):
            if (
                non_nullable_field in self.model_fields_set
                and getattr(self, non_nullable_field) is None
            ):
                raise ValueError(f"{non_nullable_field} cannot be null")
        return self


class DocumentDownloadUrlResponse(BaseModel):
    """Signed download URL response for GET /api/v1/documents/{id}/download."""

    url: str
    expires_at: datetime


class DocumentPreviewUrlResponse(DocumentDownloadUrlResponse):
    """Signed preview URL response for GET /api/v1/documents/{id}/preview."""

    mime_type: DocumentMimeType
