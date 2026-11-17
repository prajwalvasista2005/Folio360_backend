"""Tests for exception handling, public error response contracts, and detail sanitization."""

import io
import logging
import pytest
from fastapi.testclient import TestClient

from app.core.exceptions import (
    AppException,
    DEFAULT_SERVER_ERROR_MESSAGE,
    ResourceNotFoundError,
    ValidationAppError,
    get_safe_public_message,
    sanitize_internal_diagnostics,
    sanitize_public_details,
)
from app.main import create_app


def test_sanitize_public_details_suppresses_5xx() -> None:
    """Verify that any 5xx error status suppresses details to None."""
    internal_details = {"db_query": "SELECT * FROM users", "password": "abc"}
    assert sanitize_public_details(internal_details, 500) is None
    assert sanitize_public_details(internal_details, 502) is None


def test_sanitize_public_details_preserves_safe_4xx() -> None:
    """Verify that safe client error details are preserved for 4xx status codes."""
    safe_details = {"field": "email", "issue": "Invalid format", "code": 1001}
    sanitized = sanitize_public_details(safe_details, 400)
    assert sanitized == safe_details


def test_sanitize_public_details_redacts_sensitive_4xx() -> None:
    """Verify that sensitive keys and credential patterns are redacted even in 4xx details."""
    dirty_details = {
        "field": "auth_header",
        "auth_token": "secret_token_123",
        "password": "my_password",
        "safe_info": "visible information with access_token=tok123",
    }
    sanitized = sanitize_public_details(dirty_details, 422)
    assert sanitized["auth_token"] == "[REDACTED]"
    assert sanitized["password"] == "[REDACTED]"
    assert "access_token=[REDACTED]" in sanitized["safe_info"]
    assert "tok123" not in sanitized["safe_info"]


def test_custom_app_exception_404_response() -> None:
    """Verify that ResourceNotFoundError produces standard structured JSON."""
    test_app = create_app()

    @test_app.get("/test-not-found")
    def raise_404() -> None:
        raise ResourceNotFoundError(
            message="Internal trace: record 42 not in db",
            public_message="Academic record not found",
            details={"record_id": 42},
        )

    with TestClient(test_app, raise_server_exceptions=False) as c:
        response = c.get("/test-not-found")
        assert response.status_code == 404
        data = response.json()
        assert data["error"]["message"] == "Academic record not found"
        assert data["error"]["status_code"] == 404
        assert data["error"]["details"] == {"record_id": 42}


def test_4xx_with_explicit_approved_public_message() -> None:
    """Verify that a 4xx error with an explicit public message returns that message."""
    test_app = create_app()

    @test_app.get("/test-explicit-public-message")
    def raise_explicit() -> None:
        raise AppException(
            message="Internal database error on key lookup",
            status_code=400,
            public_message="Invalid account request format",
        )

    with TestClient(test_app, raise_server_exceptions=False) as c:
        response = c.get("/test-explicit-public-message")
        assert response.status_code == 400
        data = response.json()
        assert data["error"]["message"] == "Invalid account request format"
        assert "Internal database error" not in response.text


def test_4xx_without_approved_public_message_uses_safe_status_generic() -> None:
    """Verify that a 4xx error without an explicit public message uses a safe generic message."""
    test_app = create_app()

    @test_app.get("/test-implicit-400")
    def raise_implicit_400() -> None:
        raise AppException(
            message="Internal table constraint check failed on column users.email",
            status_code=400,
        )

    @test_app.get("/test-implicit-404")
    def raise_implicit_404() -> None:
        raise ResourceNotFoundError(
            message="Internal query SELECT * FROM users WHERE id=99 returned 0 rows",
        )

    @test_app.get("/test-implicit-422")
    def raise_implicit_422() -> None:
        raise ValidationAppError(
            message="Schema parser internal mismatch in pydantic model",
        )

    with TestClient(test_app, raise_server_exceptions=False) as c:
        # 400 defaults to "Bad request"
        r400 = c.get("/test-implicit-400")
        assert r400.status_code == 400
        assert r400.json()["error"]["message"] == "Bad request"
        assert "Internal table constraint" not in r400.text

        # 404 defaults to "Resource not found"
        r404 = c.get("/test-implicit-404")
        assert r404.status_code == 404
        assert r404.json()["error"]["message"] == "Resource not found"
        assert "SELECT * FROM users" not in r404.text

        # 422 defaults to "Validation failed"
        r422 = c.get("/test-implicit-422")
        assert r422.status_code == 422
        assert r422.json()["error"]["message"] == "Validation failed"
        assert "Schema parser internal" not in r422.text


def test_4xx_internal_message_containing_credentials_never_exposed() -> None:
    """Verify that internal exception message containing credentials never reaches HTTP response."""
    test_app = create_app()

    @test_app.get("/test-credential-internal-msg")
    def raise_cred_400() -> None:
        raise AppException(
            message="Failed validating password=plain_secret_password_123 in internal check",
            status_code=400,
        )

    with TestClient(test_app, raise_server_exceptions=False) as c:
        response = c.get("/test-credential-internal-msg")
        assert response.status_code == 400
        assert response.json()["error"]["message"] == "Bad request"
        assert "plain_secret_password_123" not in response.text
        assert "password=" not in response.text


def test_4xx_internal_message_containing_connection_info_never_exposed() -> None:
    """Verify that internal exception message containing connection info never reaches HTTP response."""
    test_app = create_app()

    @test_app.get("/test-conn-internal-msg")
    def raise_conn_400() -> None:
        raise AppException(
            message="Lookup timeout against postgresql://admin:secret@db.internal:5432/folio",
            status_code=400,
        )

    with TestClient(test_app, raise_server_exceptions=False) as c:
        response = c.get("/test-conn-internal-msg")
        assert response.status_code == 400
        assert response.json()["error"]["message"] == "Bad request"
        assert "postgresql://" not in response.text
        assert "db.internal" not in response.text


def test_app_exception_500_suppresses_details_and_uses_safe_generic_message() -> None:
    """Verify that a 500 AppException never exposes internal messages or details in the response payload."""
    test_app = create_app()

    @test_app.get("/test-server-app-error")
    def raise_500_app() -> None:
        raise AppException(
            message="Database query failed with internal trace info",
            status_code=500,
            details={"sql": "SELECT secret_key FROM credentials", "conn_str": "postgres://user:pass@db"},
        )

    with TestClient(test_app, raise_server_exceptions=False) as c:
        response = c.get("/test-server-app-error")
        assert response.status_code == 500
        data = response.json()
        # Safe public message policy returns generic message for server errors
        assert data["error"]["message"] == DEFAULT_SERVER_ERROR_MESSAGE
        assert data["error"]["status_code"] == 500
        assert data["error"]["details"] is None
        assert "Database query failed" not in response.text
        assert "secret_key" not in response.text
        assert "postgres://" not in response.text


def test_sensitive_app_exception_message_never_reaches_response() -> None:
    """Verify that sensitive credentials in AppException.message do not leak in HTTP responses."""
    test_app = create_app()

    @test_app.get("/test-sensitive-server-error")
    def raise_sensitive_500() -> None:
        raise AppException(
            message="Fatal connection failure to postgres://admin:confidential_pw_999@db:5432/folio",
            status_code=500,
            details={"conn_str": "postgres://admin:confidential_pw_999@db:5432/folio"},
        )

    with TestClient(test_app, raise_server_exceptions=False) as c:
        response = c.get("/test-sensitive-server-error")
        assert response.status_code == 500
        data = response.json()
        assert data["error"]["message"] == DEFAULT_SERVER_ERROR_MESSAGE
        assert data["error"]["details"] is None
        assert "confidential_pw_999" not in response.text
        assert "postgres://" not in response.text


def test_server_error_logs_redact_sql_and_connection_strings() -> None:
    """Verify that server error logging redacts raw SQL, connection strings, and diagnostics."""
    from app.core.logging import protect_handler

    exceptions_logger = logging.getLogger("folio360.exceptions")
    original_handlers = list(exceptions_logger.handlers)
    original_level = exceptions_logger.level
    original_propagate = exceptions_logger.propagate

    stream = io.StringIO()
    handler = protect_handler(logging.StreamHandler(stream))
    exceptions_logger.addHandler(handler)

    test_app = create_app()

    @test_app.get("/test-logging-redaction")
    def raise_error_with_diagnostics() -> None:
        raise AppException(
            message="Query error on postgres://user:super_secret_pw@host:5432/db",
            status_code=500,
            details={
                "sql": "SELECT secret_column, user_email FROM secret_table",
                "conn_str": "postgres://user:super_secret_pw@host:5432/db",
                "password": "plain_password_123",
            },
        )

    try:
        with TestClient(test_app, raise_server_exceptions=False) as c:
            response = c.get("/test-logging-redaction")
            assert response.status_code == 500

        logged_output = stream.getvalue()
        # Verify raw credentials, connection strings, and raw SQL are not in log output
        assert "super_secret_pw" not in logged_output
        assert "plain_password_123" not in logged_output
        assert "SELECT secret_column, user_email FROM secret_table" not in logged_output
        assert "secret_table" not in logged_output
        assert "secret_column" not in logged_output
        # Verify redacted markers appear in log output
        assert "[REDACTED]" in logged_output
    finally:
        exceptions_logger.handlers = original_handlers
        exceptions_logger.setLevel(original_level)
        exceptions_logger.propagate = original_propagate


def test_client_error_preserves_safe_message_and_sanitizes_sensitive_patterns() -> None:
    """Verify that 4xx errors preserve useful client messages while sanitizing accidental sensitive values."""
    test_app = create_app()

    @test_app.get("/test-client-credential-error")
    def raise_client_error() -> None:
        raise AppException(
            message="Internal database message for access_token=secret_token_val",
            status_code=400,
            public_message="Validation failed for access_token=secret_token_val",
            details={"field": "token_header", "access_token": "secret_token_val", "issue": "malformed"},
        )

    with TestClient(test_app, raise_server_exceptions=False) as c:
        response = c.get("/test-client-credential-error")
        assert response.status_code == 400
        data = response.json()
        assert data["error"]["message"] == "Validation failed for access_token=[REDACTED]"
        assert "secret_token_val" not in response.text
        assert data["error"]["details"] == {"field": "token_header", "access_token": "[REDACTED]", "issue": "malformed"}


def test_unhandled_exception_sanitization() -> None:
    """Verify that unhandled exceptions return safe HTTP 500 without leaking stack traces or sensitive details."""
    test_app = create_app()

    @test_app.get("/test-unhandled-error")
    def raise_unhandled() -> None:
        raise RuntimeError("Confidential database internal error details: secret_pass_123")

    with TestClient(test_app, raise_server_exceptions=False) as c:
        response = c.get("/test-unhandled-error")
        assert response.status_code == 500
        data = response.json()
        assert data["error"]["message"] == "Internal server error"
        assert data["error"]["status_code"] == 500
        assert data["error"]["details"] is None
        assert "Confidential" not in response.text
        assert "secret_pass_123" not in response.text
        assert "Traceback" not in response.text
