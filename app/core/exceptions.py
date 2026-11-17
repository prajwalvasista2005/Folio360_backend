"""Centralized application exception definitions and safe HTTP exception handlers."""

import logging
from typing import Any, Optional
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.core.logging import sanitize_log_text

logger = logging.getLogger("folio360.exceptions")

DEFAULT_SERVER_ERROR_MESSAGE = "Internal server error"

# Support both RFC 9110 name and legacy Starlette constant
HTTP_422_STATUS = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422)

STATUS_DEFAULT_MESSAGES = {
    status.HTTP_400_BAD_REQUEST: "Bad request",
    status.HTTP_401_UNAUTHORIZED: "Unauthorized",
    status.HTTP_403_FORBIDDEN: "Forbidden",
    status.HTTP_404_NOT_FOUND: "Resource not found",
    HTTP_422_STATUS: "Validation failed",
}

SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "secret",
    "token",
    "credential",
    "auth",
    "conn",
    "dsn",
    "query",
    "sql",
    "traceback",
    "stack",
    "internal",
)


def get_safe_public_message(exc: "AppException") -> str:
    """
    Establish a safe public exception-message policy.

    - 5xx Server Errors: Always return DEFAULT_SERVER_ERROR_MESSAGE ("Internal server error").
      Internal exception messages, database queries, and diagnostics are NEVER exposed.
    - 4xx Client Errors: Only explicitly designated public messages (exc.public_message)
      are returned to clients (sanitized via sanitize_log_text).
      If exc.public_message is None or empty, falls back to a safe generic message appropriate
      to the status code. The internal exc.message is NEVER automatically exposed.
    """
    if exc.status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
        return DEFAULT_SERVER_ERROR_MESSAGE

    if exc.public_message and str(exc.public_message).strip():
        return sanitize_log_text(str(exc.public_message).strip())

    return STATUS_DEFAULT_MESSAGES.get(exc.status_code, "Request error")


def sanitize_internal_diagnostics(details: Any) -> Any:
    """
    Safely redact sensitive keys, connection strings, SQL queries, and credentials
    from internal diagnostics before logging.
    """
    if details is None:
        return None
    return _sanitize_value(details)


def sanitize_public_details(details: Any, status_code: int) -> Optional[Any]:
    """
    Establish a safe public error-response contract.

    - 5xx Server Errors: Omit details entirely (return None) to prevent leaking
      database internals, infrastructure state, or credentials.
    - 4xx Client Errors: Preserve useful domain details (e.g., validation errors,
      field mismatches) while stripping sensitive keys and sanitizing values.
    """
    if details is None or status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
        return None

    return _sanitize_value(details)


def _sanitize_value(val: Any) -> Any:
    if isinstance(val, dict):
        sanitized_dict = {}
        for k, v in val.items():
            key_str = str(k).lower()
            if any(sensitive in key_str for sensitive in SENSITIVE_KEY_SUBSTRINGS):
                sanitized_dict[k] = "[REDACTED]"
            else:
                sanitized_dict[k] = _sanitize_value(v)
        return sanitized_dict

    if isinstance(val, list):
        return [_sanitize_value(item) for item in val]

    if isinstance(val, (int, float, bool)):
        return val

    if isinstance(val, str):
        return sanitize_log_text(val)

    # For unexpected non-primitive types, avoid leaking internal class state
    return "[REDACTED]"


class AppException(Exception):
    """Base exception for all Folio360 domain and application errors."""

    def __init__(
        self,
        message: str = "An internal error occurred",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[Any] = None,
        public_message: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details
        self.public_message = public_message


class ResourceNotFoundError(AppException):
    """Raised when a requested resource is not found."""

    def __init__(
        self,
        message: str = "Resource not found",
        details: Optional[Any] = None,
        public_message: Optional[str] = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=status.HTTP_404_NOT_FOUND,
            details=details,
            public_message=public_message,
        )


class ValidationAppError(AppException):
    """Raised when domain validation fails."""

    def __init__(
        self,
        message: str = "Validation failed",
        details: Optional[Any] = None,
        public_message: Optional[str] = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=HTTP_422_STATUS,
            details=details,
            public_message=public_message,
        )


async def app_exception_handler(request: Request, exc: AppException) -> JSONResponse:
    """
    Handle custom application exceptions and return a structured JSON response.

    Maintains safe public responses and logs internal diagnostics on server errors
    without exposing raw SQL or connection credentials.
    """
    public_message = get_safe_public_message(exc)
    public_details = sanitize_public_details(exc.details, exc.status_code)

    if exc.status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
        # Never log raw SQL statements, raw connection strings, or unredacted diagnostics
        sanitized_details = sanitize_internal_diagnostics(exc.details)
        logger.error(
            "Server error on %s %s: exception=%s status_code=%d details=%s",
            request.method,
            request.url.path,
            type(exc).__name__,
            exc.status_code,
            sanitized_details,
        )

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "message": public_message,
                "status_code": exc.status_code,
                "details": public_details,
            }
        },
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Safely handle unexpected internal exceptions.

    Logs error details internally without leaking stack traces or internal paths to clients.
    Sanitizes exception message and tracebacks before logging through application handlers.
    """
    logger.error(
        "Unhandled server error on %s %s: exception=%s",
        request.method,
        request.url.path,
        type(exc).__name__,
    )
    sanitized_exc_msg = sanitize_log_text(str(exc))
    logger.debug("Unhandled exception details: %s", sanitized_exc_msg, exc_info=exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "message": DEFAULT_SERVER_ERROR_MESSAGE,
                "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "details": None,
            }
        },
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register centralized exception handlers on the FastAPI application."""
    app.add_exception_handler(AppException, app_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
