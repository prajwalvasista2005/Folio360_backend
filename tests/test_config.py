"""Tests for Settings validation and CORS parsing."""

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_cors_valid_json_array() -> None:
    """Verify that a valid JSON array string is parsed into a list of strings."""
    settings = Settings(CORS_ORIGINS='["http://localhost:3000", "https://folio360.app"]')
    assert settings.CORS_ORIGINS == ["http://localhost:3000", "https://folio360.app"]


def test_cors_valid_comma_separated() -> None:
    """Verify that a comma-separated string is parsed into a list of strings."""
    settings = Settings(CORS_ORIGINS="http://localhost:3000, https://folio360.app")
    assert settings.CORS_ORIGINS == ["http://localhost:3000", "https://folio360.app"]


def test_cors_valid_list() -> None:
    """Verify that a native list of strings is accepted."""
    settings = Settings(CORS_ORIGINS=["http://localhost:3000", "https://folio360.app"])
    assert settings.CORS_ORIGINS == ["http://localhost:3000", "https://folio360.app"]


def test_cors_rejects_malformed_json_syntax() -> None:
    """Verify that malformed JSON array strings raise a clear ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS='["http://example.com", missing_quote]')
    assert "Invalid JSON format for CORS_ORIGINS" in str(exc_info.value)


def test_cors_rejects_unbalanced_brackets() -> None:
    """Verify that unbalanced brackets raise a clear ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS='["http://example.com"')
    assert "Malformed JSON array for CORS_ORIGINS" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS='"http://example.com"]')
    assert "Malformed JSON array for CORS_ORIGINS" in str(exc_info.value)


def test_cors_rejects_non_list_json() -> None:
    """Verify that JSON objects or primitives that are not lists raise a ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS='{"origin": "http://example.com"}')
    assert "CORS_ORIGINS must be a list of strings" in str(exc_info.value)


def test_cors_rejects_malformed_json_objects() -> None:
    """Verify that malformed JSON object inputs and unbalanced braces are rejected."""
    # Unbalanced opening brace
    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS='{"origin": "http://example.com"')
    assert "Malformed JSON object for CORS_ORIGINS: unbalanced braces" in str(exc_info.value)

    # Unbalanced closing brace
    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS='"origin": "http://example.com"}')
    assert "Malformed JSON object for CORS_ORIGINS: unbalanced braces" in str(exc_info.value)

    # Malformed JSON syntax inside object
    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS='{"origin": "http://example.com", missing}')
    assert "Invalid JSON format for CORS_ORIGINS" in str(exc_info.value)

    # Native Python dictionary
    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS={"origin": "http://example.com"})  # type: ignore[arg-type]
    assert "CORS_ORIGINS must be a list of strings, got dict" in str(exc_info.value)


def test_cors_rejects_json_primitives() -> None:
    """Verify that JSON primitive values (numbers, booleans, null, strings) are rejected."""
    # Numeric string primitives
    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS="123")
    assert "CORS_ORIGINS cannot be a numeric value" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS="456.78")
    assert "CORS_ORIGINS cannot be a numeric value" in str(exc_info.value)

    # Boolean and null string primitives
    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS="true")
    assert "CORS_ORIGINS cannot be a JSON primitive" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS="false")
    assert "CORS_ORIGINS cannot be a JSON primitive" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS="null")
    assert "CORS_ORIGINS cannot be a JSON primitive" in str(exc_info.value)

    # Quoted string primitive
    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS='"hello"')
    assert "CORS_ORIGINS cannot be a single JSON string primitive" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS="'http://localhost:3000'")
    assert "CORS_ORIGINS cannot be a single JSON string primitive" in str(exc_info.value)

    # Native Python int and bool types
    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS=123)  # type: ignore[arg-type]
    assert "CORS_ORIGINS must be a list of strings, got int" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS=True)  # type: ignore[arg-type]
    assert "CORS_ORIGINS must be a list of strings, got bool" in str(exc_info.value)


def test_cors_rejects_unclosed_and_malformed_quotes() -> None:
    """Verify that unclosed quotes and malformed quoted strings are rejected."""
    # Unclosed double quote
    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS='"http://example.com')
    assert "Malformed quoted string in CORS_ORIGINS: unclosed quote" in str(exc_info.value)

    # Unclosed single quote
    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS="'http://example.com")
    assert "Malformed quoted string in CORS_ORIGINS: unclosed quote" in str(exc_info.value)

    # Malformed unclosed quote containing commas
    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS='"http://example.com, http://foo.com')
    assert "Malformed quoted string in CORS_ORIGINS: unclosed quote" in str(exc_info.value)

    # Comma-separated list with residual quotes (missing array brackets)
    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS='"http://localhost:3000", "http://localhost:5173"')
    assert "Malformed origin in CORS_ORIGINS comma-separated list" in str(exc_info.value)


def test_cors_rejects_non_string_elements() -> None:
    """Verify that non-string elements inside list raise a ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS='[123, 456]')
    assert "Each origin in CORS_ORIGINS must be a non-empty string" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS=[123, 456])  # type: ignore[arg-type]
    assert "Each origin in CORS_ORIGINS must be a non-empty string" in str(exc_info.value)


def test_cors_rejects_empty_elements() -> None:
    """Verify that empty string origins are rejected."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(CORS_ORIGINS='[""]')
    assert "Each origin in CORS_ORIGINS must be a non-empty string" in str(exc_info.value)


def test_log_level_validation() -> None:
    """Verify valid and invalid log level values."""
    assert Settings(LOG_LEVEL="debug").LOG_LEVEL == "DEBUG"
    assert Settings(LOG_LEVEL="WARNING").LOG_LEVEL == "WARNING"

    with pytest.raises(ValidationError) as exc_info:
        Settings(LOG_LEVEL="INVALID_LEVEL")
    assert "Invalid LOG_LEVEL" in str(exc_info.value)
