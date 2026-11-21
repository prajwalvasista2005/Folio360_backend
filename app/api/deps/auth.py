"""Stage 3A authentication, CSRF/Origin, client-IP, and rate-limiting dependencies."""

import ipaddress
import logging
from typing import Callable, Literal

from fastapi import Depends, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.exceptions import auth_error
from app.core.rate_limit import SlidingWindowRateLimiter
from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.user import User

logger = logging.getLogger("folio360.auth.deps")

ClientType = Literal["web", "mobile"]


def get_current_settings(request: Request) -> Settings:
    """Retrieve the Settings instance attached to the active application."""
    return getattr(request.app.state, "settings", None) or get_settings()


def resolve_client_ip(request: Request) -> str:
    """
    Resolve canonical client IP exclusively from ASGI-normalized request.client.host.

    Never reads raw X-Forwarded-For headers directly.
    """
    if request.client is None or not request.client.host:
        return "unknown"

    raw_host = str(request.client.host).strip()
    if not raw_host:
        return "unknown"

    try:
        return str(ipaddress.ip_address(raw_host))
    except ValueError:
        logger.warning("Invalid ASGI client IP encountered; using fallback bucket")
        return "invalid-client-ip"


def rate_limit_dependency(
    bucket: str,
    *,
    limit: int,
    window_seconds: int = 900,
) -> Callable[[Request], None]:
    """Build a synchronous FastAPI dependency enforcing per-IP sliding-window limits."""

    def _enforce_rate_limit(request: Request) -> None:
        settings = get_current_settings(request)
        if not settings.RATE_LIMIT_ENABLED:
            return

        limiter: SlidingWindowRateLimiter | None = getattr(
            request.app.state, "rate_limiter", None
        )
        if limiter is None:
            limiter = SlidingWindowRateLimiter()
            request.app.state.rate_limiter = limiter

        client_ip = resolve_client_ip(request)
        allowed, retry_after = limiter.check_and_record(
            bucket,
            client_ip,
            limit=limit,
            window_seconds=window_seconds,
        )
        if not allowed:
            raise auth_error(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                code="RATE_LIMIT_EXCEEDED",
                public_message="Too many requests. Please try again later.",
                headers={"Retry-After": str(retry_after)},
            )

    return _enforce_rate_limit


def require_client_type(request: Request) -> ClientType:
    """Validate mandatory X-Client-Type header ('web' or 'mobile')."""
    raw_value = request.headers.get("x-client-type")
    if raw_value is None:
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_CLIENT_TYPE",
            public_message="Missing or invalid X-Client-Type header.",
        )
    cleaned = raw_value.strip()
    if cleaned not in {"web", "mobile"}:
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_CLIENT_TYPE",
            public_message="Missing or invalid X-Client-Type header.",
        )
    return cleaned  # type: ignore[return-value]


def optional_client_type(request: Request) -> ClientType | None:
    """Validate optional X-Client-Type header when provided."""
    raw_value = request.headers.get("x-client-type")
    if raw_value is None:
        return None
    cleaned = raw_value.strip()
    if cleaned not in {"web", "mobile"}:
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_CLIENT_TYPE",
            public_message="Missing or invalid X-Client-Type header.",
        )
    return cleaned  # type: ignore[return-value]


def verify_web_origin(request: Request, settings: Settings) -> str:
    """Enforce exact Origin header match against Settings.CORS_ORIGINS for web routes."""
    origin = request.headers.get("origin")
    if origin is None:
        raise auth_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="CSRF_ORIGIN_MISMATCH",
            public_message="Origin header is required and must match an allowed origin.",
        )
    if not origin or origin.lower() == "null" or origin not in settings.CORS_ORIGINS:
        raise auth_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="CSRF_ORIGIN_MISMATCH",
            public_message="Request origin is not permitted.",
        )
    return origin


def enforce_web_origin_if_web(
    request: Request,
    client_type: ClientType,
    settings: Settings,
) -> None:
    """Run strict Origin validation whenever client_type is 'web'."""
    if client_type == "web":
        verify_web_origin(request, settings)


def _extract_bearer_token(request: Request) -> str:
    auth_header = request.headers.get("authorization")
    if not auth_header:
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_ACCESS_TOKEN",
            public_message="Invalid or missing access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    parts = auth_header.strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_ACCESS_TOKEN",
            public_message="Invalid or missing access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = parts[1].strip()
    if not token or any(ch.isspace() for ch in token):
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_ACCESS_TOKEN",
            public_message="Invalid or missing access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> User:
    """Authenticate Bearer Access JWT, enforce auth_version and active account status."""
    token = _extract_bearer_token(request)
    try:
        user_id, token_ver, _payload = decode_access_token(token, settings)
    except (ValueError, RuntimeError):
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_ACCESS_TOKEN",
            public_message="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if user is None or user.auth_version != token_ver:
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_ACCESS_TOKEN",
            public_message="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise auth_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="ACCOUNT_INACTIVE",
            public_message="Account is inactive.",
        )

    return user
