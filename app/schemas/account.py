"""Pydantic v2 schemas for account management, security log, email change, and connections."""

from datetime import datetime
from typing import Any, Literal
import uuid

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.schemas.auth import _preprocess_email, _strip_nonempty_token
from app.core.security import normalize_email


class AccountResponse(BaseModel):
    """Authenticated user's account summary."""

    id: uuid.UUID
    email: EmailStr
    email_verified: bool
    pending_email: EmailStr | None = None
    has_password: bool
    created_at: datetime


class EmailChangeRequest(BaseModel):
    """Request payload for POST /api/v1/account/email."""

    model_config = ConfigDict(extra="forbid")

    new_email: EmailStr
    current_password: str | None = Field(default=None, max_length=256)

    @field_validator("new_email", mode="before")
    @classmethod
    def sanitize_email_before(cls, value: Any) -> Any:
        return _preprocess_email(value)

    @field_validator("new_email", mode="after")
    @classmethod
    def lowercase_email(cls, value: EmailStr) -> str:
        return normalize_email(str(value))


class EmailChangeRequestedResponse(BaseModel):
    """Response payload for POST /api/v1/account/email."""

    message: str
    pending_email: EmailStr | None = None


class EmailChangeConfirmRequest(BaseModel):
    """Request payload for POST /api/v1/account/email/confirm."""

    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1, max_length=512)

    @field_validator("token", mode="before")
    @classmethod
    def strip_token(cls, value: Any) -> str:
        return _strip_nonempty_token(value, "Email change token")


class OAuthConnectionItem(BaseModel):
    """Connected OAuth sign-in provider metadata (never exposes tokens)."""

    provider: Literal["google", "github"]
    provider_email: str | None = None
    linked_at: datetime


class OAuthConnectionListResponse(BaseModel):
    """Response payload for GET /api/v1/account/connections."""

    items: list[OAuthConnectionItem]


class AuditEventResponse(BaseModel):
    """Owner-scoped security audit event entry."""

    id: uuid.UUID
    action: str
    ip_address: str | None = None
    device_label: str | None = None
    created_at: datetime


class AuditEventListResponse(BaseModel):
    """Paginated response payload for GET /api/v1/account/security-log."""

    items: list[AuditEventResponse]
    page: int
    page_size: int
    total: int
    total_pages: int


class AccountDeleteRequest(BaseModel):
    """Confirmation payload for DELETE /api/v1/account."""

    model_config = ConfigDict(extra="forbid")

    confirm: Literal["DELETE"]
    current_password: str | None = Field(default=None, max_length=256)
