"""Pydantic v2 request and response schemas for Stage 3A authentication endpoints."""

from datetime import datetime
from typing import Any, Literal
import uuid

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from app.core.security import normalize_email, validate_password_policy


def _preprocess_email(value: Any) -> Any:
    if not isinstance(value, str):
        raise ValueError("Email must be a string")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("Email must not be empty")
    if len(cleaned) > 320:
        raise ValueError("Email must not exceed 320 characters")
    if any(ch.isspace() for ch in cleaned):
        raise ValueError("Email must not contain whitespace")
    return cleaned


class RegisterRequest(BaseModel):
    """Request payload for POST /api/v1/auth/register."""

    model_config = ConfigDict(extra="ignore")

    email: EmailStr
    password: str

    @field_validator("email", mode="before")
    @classmethod
    def sanitize_email_before(cls, value: Any) -> Any:
        return _preprocess_email(value)

    @field_validator("email", mode="after")
    @classmethod
    def lowercase_email(cls, value: EmailStr) -> str:
        return normalize_email(str(value))

    @model_validator(mode="after")
    def validate_password(self) -> "RegisterRequest":
        validate_password_policy(self.password, str(self.email))
        return self


class VerifyEmailRequest(BaseModel):
    """Request payload for POST /api/v1/auth/verify-email (no arbitrary redirect allowed)."""

    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1, max_length=512)

    @field_validator("token", mode="before")
    @classmethod
    def strip_token(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("Verification token must be a string")
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Verification token must not be empty")
        return cleaned


class ResendVerificationRequest(BaseModel):
    """Request payload for POST /api/v1/auth/resend-verification."""

    model_config = ConfigDict(extra="ignore")

    email: EmailStr

    @field_validator("email", mode="before")
    @classmethod
    def sanitize_email_before(cls, value: Any) -> Any:
        return _preprocess_email(value)

    @field_validator("email", mode="after")
    @classmethod
    def lowercase_email(cls, value: EmailStr) -> str:
        return normalize_email(str(value))


class LoginRequest(BaseModel):
    """Request payload for POST /api/v1/auth/login."""

    model_config = ConfigDict(extra="ignore")

    email: EmailStr
    password: str = Field(min_length=1, max_length=256)

    @field_validator("email", mode="before")
    @classmethod
    def sanitize_email_before(cls, value: Any) -> Any:
        return _preprocess_email(value)

    @field_validator("email", mode="after")
    @classmethod
    def lowercase_email(cls, value: EmailStr) -> str:
        return normalize_email(str(value))


class RefreshRequest(BaseModel):
    """Optional request payload for POST /api/v1/auth/refresh (required for mobile)."""

    model_config = ConfigDict(extra="ignore")

    refresh_token: str | None = Field(default=None, min_length=1, max_length=512)


class LogoutRequest(BaseModel):
    """Optional request payload for POST /api/v1/auth/logout (required for mobile)."""

    model_config = ConfigDict(extra="ignore")

    refresh_token: str | None = Field(default=None, min_length=1, max_length=512)


class UserPublicResponse(BaseModel):
    """Public representation of the authenticated/registered user."""

    id: uuid.UUID
    email: EmailStr
    is_active: bool
    is_email_verified: bool
    has_password: bool
    created_at: datetime


class MeResponse(UserPublicResponse):
    """Response payload for GET /api/v1/auth/me (Stage 3A)."""

    updated_at: datetime


class RegisterResponse(BaseModel):
    """Response payload for POST /api/v1/auth/register."""

    message: str
    user: UserPublicResponse
    verification_email_sent: bool


class VerifyEmailResponse(BaseModel):
    """Non-authenticating JSON-only response payload for POST /api/v1/auth/verify-email."""

    message: str
    email_verified: bool


class GenericAcceptedResponse(BaseModel):
    """Enumeration-safe 202 Accepted response payload."""

    message: str


class WebAuthTokenResponse(BaseModel):
    """Access token + user payload for X-Client-Type: web (refresh token in HttpOnly cookie)."""

    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    user: UserPublicResponse


class MobileAuthTokenResponse(WebAuthTokenResponse):
    """Access + refresh token JSON payload for X-Client-Type: mobile (zero cookies)."""

    refresh_token: str
    refresh_expires_in: int


class LogoutResponse(BaseModel):
    """Response payload for POST /logout and POST /logout-all."""

    message: str
