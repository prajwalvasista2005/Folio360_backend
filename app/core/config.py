"""Application configuration management using Pydantic Settings v2."""

from email.utils import parseaddr
from functools import lru_cache
import ipaddress
import json
import re
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from app.core.crypto_keys import decode_aes256_base64url_key
from app.core.uri_policy import (
    MALFORMED_PERCENT_RE,
    OAUTH_FORBIDDEN_ENCODED_RE,
    canonicalize_mobile_login_allowlist,
    canonicalize_mobile_oauth_redirect_allowlist,
    canonicalize_web_oauth_redirect_allowlist,
    parse_and_canonicalize_web_oauth_redirect_uri,
    validate_strict_authority,
)

OAUTH_EXCHANGE_CODE_EXPIRE_SECONDS = 60
DEFAULT_MOBILE_OAUTH_REDIRECT_URI = "folio360://auth/callback"
RFC6265_COOKIE_NAME_RE = re.compile(r"\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
DOCUMENT_NAMESPACE_RE = re.compile(r"\A[a-z0-9][a-z0-9_-]{0,31}\Z")


def _validate_postgres_psycopg_url(
    value: SecretStr | None,
    *,
    field_name: str,
) -> SecretStr | None:
    """Validate a PostgreSQL psycopg v3 connection URL without leaking credentials."""
    if value is None:
        return None

    stripped = value.get_secret_value().strip()
    if not stripped:
        raise ValueError(f"{field_name} must not be empty")

    try:
        url = make_url(stripped)
    except (ArgumentError, ValueError):
        raise ValueError(
            f"Invalid {field_name} format; expected postgresql+psycopg://..."
        ) from None

    if url.drivername != "postgresql+psycopg":
        raise ValueError(
            f"{field_name} must use the 'postgresql+psycopg' driver"
        )
    if not url.host or not url.host.strip():
        raise ValueError(f"{field_name} must include a non-empty host")
    if not url.database or not url.database.strip():
        raise ValueError(f"{field_name} must include a non-empty database name")

    return SecretStr(stripped)


def _parse_string_list_setting(
    value: Any,
    *,
    field_name: str,
    allow_empty_string: bool = False,
) -> list[str]:
    """Parse a list[str] setting from a native list, JSON array string, or CSV string."""
    if isinstance(value, (int, float, bool, dict)):
        raise ValueError(
            f"{field_name} must be a list of strings, got {type(value).__name__}"
        )

    if isinstance(value, list):
        parsed_list: list[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise ValueError(
                    f"Each entry in {field_name} must be a non-empty string"
                )
            parsed_list.append(item.strip())
        return parsed_list

    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            if allow_empty_string:
                return []
            raise ValueError(f"{field_name} must not be empty")

        if stripped.startswith("[") or stripped.endswith("]"):
            if not (stripped.startswith("[") and stripped.endswith("]")):
                raise ValueError(f"Malformed JSON array for {field_name}")
            try:
                parsed = json.loads(stripped)
            except Exception as exc:
                raise ValueError(f"Invalid JSON format for {field_name}: {exc}") from exc
            if not isinstance(parsed, list):
                raise ValueError(f"{field_name} JSON value must be a list of strings")
            for item in parsed:
                if not isinstance(item, str) or not item.strip():
                    raise ValueError(
                        f"Each entry in {field_name} must be a non-empty string"
                    )
            return [item.strip() for item in parsed]

        items = [part.strip() for part in stripped.split(",") if part.strip()]
        if not items:
            if allow_empty_string:
                return []
            raise ValueError(f"{field_name} contains no valid entries")
        return items

    raise ValueError(
        f"{field_name} must be a list of strings, JSON array, or comma-separated string"
    )


def _validate_production_email_from_address(raw_value: str) -> None:
    """Validate that EMAIL_FROM_ADDRESS is a non-default, non-.local sender in production."""
    stripped = raw_value.strip()
    if not stripped:
        raise RuntimeError("EMAIL_FROM_ADDRESS must be configured in production")

    _, addr = parseaddr(stripped)
    if not addr or "@" not in addr or any(ch.isspace() for ch in addr):
        raise RuntimeError("EMAIL_FROM_ADDRESS must be a valid email address in production")

    local_part, domain_part = addr.rsplit("@", 1)
    domain = domain_part.strip().lower().rstrip(".")
    if (
        not local_part
        or not domain
        or "." not in domain
        or domain == "local"
        or domain.endswith(".local")
        or domain == "localhost"
        or domain.endswith(".localhost")
        or addr.strip().lower() == "no-reply@folio360.local"
    ):
        raise RuntimeError(
            "EMAIL_FROM_ADDRESS must not use the default or a .local sender domain in production"
        )


class Settings(BaseSettings):
    """Folio360 application configuration settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
        hide_input_in_errors=True,
    )

    # Application Information
    APP_NAME: str = "Folio360"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = (
        "Folio360: A User-Centred Unified Profile for Academic, "
        "Professional, and Lifelong Learning Records."
    )

    # Environment
    ENVIRONMENT: Literal["development", "testing", "production"] = "development"
    DEBUG: bool = False

    # API Routing
    API_V1_PREFIX: str = "/api/v1"

    # Logging
    LOG_LEVEL: str = "INFO"

    # CORS Configuration
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    # Documentation Endpoints (can be disabled in production if desired)
    DOCS_URL: str | None = "/docs"
    OPENAPI_URL: str | None = "/openapi.json"

    # Database & Readiness Configuration
    DATABASE_URL: SecretStr | None = None
    MIGRATION_DATABASE_URL: SecretStr | None = None
    DB_POOL_SIZE: int = Field(default=5, ge=1, le=50)
    DB_MAX_OVERFLOW: int = Field(default=10, ge=0, le=100)
    DB_POOL_TIMEOUT: int = Field(default=30, ge=1, le=120)
    DB_CONNECT_TIMEOUT: int = Field(default=5, ge=1, le=30)
    DB_READINESS_MAX_CONCURRENCY: int = Field(default=2, ge=1, le=10)
    DB_READINESS_CONNECT_TIMEOUT: int = Field(default=3, ge=1, le=4)
    DB_READINESS_QUERY_TIMEOUT_MS: int = Field(default=1000, ge=100, le=3000)
    DB_ECHO: bool = False

    # Stage 3A: JWT & Refresh Session Configuration
    JWT_SECRET_KEY: SecretStr | None = None
    JWT_ISSUER: str = "folio360"
    JWT_AUDIENCE: str = "folio360-api"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15, ge=1, le=60)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=14, ge=1, le=30)
    REFRESH_TOKEN_ABSOLUTE_EXPIRE_DAYS: int = Field(default=30, ge=1, le=90)

    # Stage 3A: Deployment-Aware Web Refresh Cookie Policy
    COOKIE_DEPLOYMENT_MODE: Literal["same_site", "cross_site"] = "same_site"
    REFRESH_COOKIE_NAME: str = "folio360_refresh_token"
    REFRESH_COOKIE_SECURE: bool = False
    REFRESH_COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"
    REFRESH_COOKIE_DOMAIN: str | None = None

    # Stage 3A: Email Verification, Resend & Frontend Return Configuration
    FRONTEND_BASE_URL: str = "http://localhost:5173"
    EMAIL_VERIFICATION_MOBILE_LOGIN_URIS: list[str] = ["folio360://auth/login"]
    EMAIL_VERIFICATION_EXPIRE_HOURS: int = Field(default=24, ge=1, le=72)
    EMAIL_COOLDOWN_SECONDS: int = Field(default=60, ge=1, le=3600)
    EMAIL_MAX_PER_HOUR: int = Field(default=3, ge=1, le=50)
    EMAIL_FAILED_RETRY_BACKOFF_SECONDS: int = Field(default=10, ge=1, le=300)
    EMAIL_PENDING_STALE_SECONDS: int = Field(default=30, ge=5, le=600)
    EMAIL_SEND_TIMEOUT_SECONDS: float = Field(default=5.0, ge=1.0, le=15.0)
    RESEND_API_KEY: SecretStr | None = None
    EMAIL_FROM_ADDRESS: str = "no-reply@folio360.local"
    PASSWORD_RESET_EXPIRE_MINUTES: int = Field(default=30, ge=5, le=120)

    # Stage 3A: Rate Limiting & Uvicorn Proxy Policy
    RATE_LIMIT_ENABLED: bool = True
    PROXY_HEADERS_ENABLED: bool = False
    TRUSTED_PROXY_IPS: list[str] = []

    # Stage 3C: OAuth 2.0 / OIDC Configuration (F360-S3C-SPEC-REV12)
    BACKEND_BASE_URL: str = "http://localhost:8000"
    OAUTH_BINDING_COOKIE_NAME: str = "folio360_oauth_binding"
    OAUTH_EXCHANGE_COOKIE_NAME: str = "folio360_oauth_exchange"
    OAUTH_PKCE_ENCRYPTION_KEY: SecretStr | None = None
    OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS: SecretStr | None = None
    GOOGLE_CLIENT_ID: str | None = None
    GOOGLE_CLIENT_SECRET: SecretStr | None = None
    GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES: list[str] = []
    GITHUB_CLIENT_ID: str | None = None
    GITHUB_CLIENT_SECRET: SecretStr | None = None
    OAUTH_ALLOWED_WEB_REDIRECT_URIS: list[str] = []
    OAUTH_ALLOWED_MOBILE_REDIRECT_URIS: list[str] = [DEFAULT_MOBILE_OAUTH_REDIRECT_URI]
    OAUTH_STATE_EXPIRE_MINUTES: int = Field(default=10, ge=1, le=30)
    OAUTH_HTTP_TIMEOUT_SECONDS: float = Field(default=5.0, ge=1.0, le=15.0)
    GITHUB_EMAILS_PER_PAGE: int = Field(default=100, ge=1, le=100)
    GITHUB_EMAILS_MAX_PAGES: int = Field(default=10, ge=1, le=20)

    # Phase 2 Stage 4: Document Vault & Storage Configuration
    STORAGE_BACKEND: Literal["local", "s3"] = "local"
    DOCUMENT_LOCAL_STORAGE_DIR: str = "/tmp/folio360_documents"
    DOCUMENT_MAX_SIZE_BYTES: int = Field(
        default=10 * 1024 * 1024,
        ge=1024,
        le=50 * 1024 * 1024,
    )
    DOCUMENT_SIGNED_URL_TTL_SECONDS: int = Field(default=300, ge=30, le=3600)
    DOCUMENT_SIGNING_SECRET: SecretStr | None = None
    S3_ENDPOINT_URL: str | None = None
    S3_BUCKET_NAME: str | None = None
    S3_REGION: str = "auto"
    S3_ACCESS_KEY_ID: SecretStr | None = None
    S3_SECRET_ACCESS_KEY: SecretStr | None = None
    S3_FORCE_PATH_STYLE: bool = False

    # Phase 2 Stage 5: File Validation, Quarantine & Malware Scanning
    DOCUMENT_QUARANTINE_NAMESPACE: str = "quarantine"
    DOCUMENT_TRUSTED_NAMESPACE: str = "trusted"
    MALWARE_SCANNER_BACKEND: Literal["clamav", "mock"] = "clamav"
    CLAMAV_HOST: str = "127.0.0.1"
    CLAMAV_PORT: int = Field(default=3310, ge=1, le=65535)
    CLAMAV_UNIX_SOCKET: str | None = None
    DOCUMENT_SCAN_TIMEOUT_SECONDS: float = Field(default=10.0, gt=0.5, le=60.0)
    DOCUMENT_SCAN_PROCESSING_MODE: Literal["inline", "deferred"] = "inline"
    DOCUMENT_SCAN_MAX_RETRIES: int = Field(default=3, ge=1, le=10)
    DOCUMENT_SCAN_STALE_SECONDS: int = Field(default=300, ge=30, le=3600)
    DOCUMENT_REJECTED_RETENTION_POLICY: Literal["delete", "retain_quarantine"] = "delete"

    # Phase 2 Stage 6: AI Analyzer
    AI_ANALYZER_PROVIDER: Literal["none", "gemini", "mock"] = "none"
    AI_ANALYZER_API_KEY: SecretStr | None = None
    AI_ANALYZER_MODEL: str = "gemini-2.5-flash"
    AI_ANALYZER_BASE_URL: str = "https://generativelanguage.googleapis.com"
    AI_ANALYZER_TIMEOUT_SECONDS: float = Field(default=30.0, gt=1.0, le=120.0)
    AI_ANALYZER_MAX_RETRIES: int = Field(default=3, ge=1, le=10)
    AI_ANALYZER_MAX_INPUT_BYTES: int = Field(
        default=10 * 1024 * 1024,
        ge=1024,
        le=50 * 1024 * 1024,
    )
    AI_ANALYZER_PROCESSING_MODE: Literal["inline", "deferred"] = "inline"
    AI_ANALYZER_STALE_SECONDS: int = Field(default=300, ge=30, le=3600)

    @property
    def oauth_enabled(self) -> bool:
        """Return True when at least one OAuth provider is configured."""
        return bool(self.GOOGLE_CLIENT_ID) or bool(self.GITHUB_CLIENT_ID)

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, value: Any) -> list[str]:
        """
        Parse and validate CORS_ORIGINS.

        Supports:
          1. Native list of strings
          2. JSON array string of strings (e.g. '["http://localhost:3000", "http://localhost:5173"]')
          3. Comma-separated string of origins (e.g. "http://localhost:3000,http://localhost:5173")

        Rejects:
          - Non-array JSON structures (objects, dicts)
          - JSON primitives (numbers, booleans, null, quoted strings)
          - Malformed JSON structures (unbalanced brackets, unbalanced braces, syntax errors)
          - Empty elements or non-string elements inside lists
        """
        # Reject non-string, non-list types immediately (e.g. int, bool, float, dict)
        if isinstance(value, (int, float, bool)):
            raise ValueError(
                f"CORS_ORIGINS must be a list of strings, got {type(value).__name__}"
            )
        if isinstance(value, dict):
            raise ValueError("CORS_ORIGINS must be a list of strings, got dict")

        if isinstance(value, list):
            for item in value:
                if not isinstance(item, str) or not item.strip():
                    raise ValueError(
                        f"Each origin in CORS_ORIGINS must be a non-empty string, got {item!r}"
                    )
            return [item.strip() for item in value]

        if isinstance(value, str):
            stripped = value.strip()

            # 1. Reject unbalanced brackets (attempted JSON array)
            if (stripped.startswith("[") and not stripped.endswith("]")) or (
                stripped.endswith("]") and not stripped.startswith("[")
            ):
                raise ValueError(
                    f"Malformed JSON array for CORS_ORIGINS: unbalanced brackets in '{value}'"
                )

            # 2. Reject unbalanced braces (attempted JSON object)
            if (stripped.startswith("{") and not stripped.endswith("}")) or (
                stripped.endswith("}") and not stripped.startswith("{")
            ):
                raise ValueError(
                    f"Malformed JSON object for CORS_ORIGINS: unbalanced braces in '{value}'"
                )

            # 3. Reject unclosed or unbalanced quotes (attempted quoted string / JSON literal)
            has_unbalanced_double_quotes = stripped.count('"') % 2 != 0
            has_unbalanced_single_quotes = stripped.count("'") % 2 != 0
            if has_unbalanced_double_quotes or has_unbalanced_single_quotes:
                raise ValueError(
                    f"Malformed quoted string in CORS_ORIGINS: unclosed quote in '{value}'"
                )

            # 4. Check for balanced JSON array: [...]
            if stripped.startswith("[") and stripped.endswith("]"):
                try:
                    parsed = json.loads(stripped)
                except Exception as exc:
                    raise ValueError(
                        f"Invalid JSON format for CORS_ORIGINS: {exc}"
                    ) from exc

                if not isinstance(parsed, list):
                    raise ValueError(
                        f"CORS_ORIGINS must be a list of strings, got {type(parsed).__name__}"
                    )
                for item in parsed:
                    if not isinstance(item, str) or not item.strip():
                        raise ValueError(
                            f"Each origin in CORS_ORIGINS must be a non-empty string, got {item!r}"
                        )
                return [item.strip() for item in parsed]

            # 5. Check for balanced JSON object: {...}
            if stripped.startswith("{") and stripped.endswith("}"):
                try:
                    parsed = json.loads(stripped)
                except Exception as exc:
                    raise ValueError(
                        f"Invalid JSON format for CORS_ORIGINS: {exc}"
                    ) from exc
                raise ValueError(
                    f"CORS_ORIGINS must be a list of strings, got {type(parsed).__name__}"
                )

            # 6. Reject JSON primitives: booleans, null, numbers, quoted strings
            if stripped.lower() in {"true", "false", "null"}:
                raise ValueError(
                    f"CORS_ORIGINS cannot be a JSON primitive ({stripped}), expected a list of strings or comma-separated origins"
                )

            try:
                float(stripped)
                raise ValueError(
                    f"CORS_ORIGINS cannot be a numeric value ({stripped}), expected a list of strings or comma-separated origins"
                )
            except ValueError as e:
                if "CORS_ORIGINS cannot be a numeric value" in str(e):
                    raise

            if stripped.startswith('"') and stripped.endswith('"') and len(stripped) >= 2:
                try:
                    parsed_prim = json.loads(stripped)
                    if isinstance(parsed_prim, str):
                        raise ValueError(
                            f"CORS_ORIGINS cannot be a single JSON string primitive ({stripped}), expected a list of strings or comma-separated origins"
                        )
                except json.JSONDecodeError:
                    pass
                except ValueError as e:
                    if "CORS_ORIGINS cannot be a single JSON string primitive" in str(e):
                        raise

            if (
                stripped.startswith("'")
                and stripped.endswith("'")
                and len(stripped) >= 2
                and "," not in stripped
            ):
                raise ValueError(
                    f"CORS_ORIGINS cannot be a single JSON string primitive ({stripped}), expected a list of strings or comma-separated origins"
                )

            # 7. Comma-separated string format
            origins = [origin.strip() for origin in stripped.split(",") if origin.strip()]
            if not origins and stripped:
                raise ValueError("CORS_ORIGINS comma-separated string contains no valid origins")

            # In comma-separated format, individual origins must not contain residual quotes
            for origin in origins:
                if origin.startswith(('"', "'")) or origin.endswith(('"', "'")):
                    raise ValueError(
                        f"Malformed origin in CORS_ORIGINS comma-separated list: quoted origin '{origin}' is invalid. For JSON arrays, enclose in brackets [ ... ]"
                    )

            return origins

        raise ValueError(
            f"CORS_ORIGINS must be a list of strings, a JSON array string, or a comma-separated string, got {type(value).__name__}"
        )

    @field_validator("EMAIL_VERIFICATION_MOBILE_LOGIN_URIS", mode="before")
    @classmethod
    def parse_mobile_login_uris(cls, value: Any) -> list[str]:
        """Parse EMAIL_VERIFICATION_MOBILE_LOGIN_URIS from list, JSON array, or CSV."""
        return _parse_string_list_setting(
            value,
            field_name="EMAIL_VERIFICATION_MOBILE_LOGIN_URIS",
            allow_empty_string=True,
        )

    @field_validator("TRUSTED_PROXY_IPS", mode="before")
    @classmethod
    def parse_trusted_proxy_ips(cls, value: Any) -> list[str]:
        """Parse TRUSTED_PROXY_IPS from list, JSON array, or CSV."""
        return _parse_string_list_setting(
            value,
            field_name="TRUSTED_PROXY_IPS",
            allow_empty_string=True,
        )

    @field_validator("GOOGLE_CLIENT_ID", "GITHUB_CLIENT_ID", mode="before")
    @classmethod
    def normalize_optional_provider_client_id(cls, value: Any) -> str | None:
        """Normalize empty or whitespace-only OAuth client IDs to None."""
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("OAuth client ID must be a string or None")
        stripped = value.strip()
        return stripped or None

    @field_validator(
        "GOOGLE_CLIENT_SECRET",
        "GITHUB_CLIENT_SECRET",
        "OAUTH_PKCE_ENCRYPTION_KEY",
        "OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS",
        "DOCUMENT_SIGNING_SECRET",
        "S3_ACCESS_KEY_ID",
        "S3_SECRET_ACCESS_KEY",
        "AI_ANALYZER_API_KEY",
        mode="before",
    )
    @classmethod
    def normalize_optional_oauth_secret(cls, value: Any) -> SecretStr | None:
        """Normalize blank optional secrets to None without echoing secret values."""
        if value is None:
            return None
        if isinstance(value, SecretStr):
            raw = value.get_secret_value()
        elif isinstance(value, str):
            raw = value
        else:
            raise ValueError("Secret setting must be a string or None")
        if not raw.strip():
            return None
        return SecretStr(raw)

    @field_validator("S3_ENDPOINT_URL", "S3_BUCKET_NAME", mode="before")
    @classmethod
    def normalize_optional_s3_strings(cls, value: Any) -> str | None:
        """Normalize blank optional S3 settings to None."""
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("S3 setting must be a string or None")
        cleaned = value.strip().rstrip("/")
        return cleaned or None

    @field_validator("DOCUMENT_LOCAL_STORAGE_DIR", "S3_REGION", "CLAMAV_HOST", "AI_ANALYZER_MODEL")
    @classmethod
    def validate_non_empty_storage_setting(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Configuration value must not be blank")
        return cleaned

    @field_validator("AI_ANALYZER_BASE_URL")
    @classmethod
    def validate_ai_analyzer_base_url(cls, value: str) -> str:
        """Validate AI_ANALYZER_BASE_URL as a clean http/https base URL without credentials."""
        cleaned = value.strip().rstrip("/")
        if not cleaned or any(ch.isspace() for ch in cleaned):
            raise ValueError("AI_ANALYZER_BASE_URL must not be empty or contain whitespace")
        parts = urlsplit(cleaned)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            raise ValueError("AI_ANALYZER_BASE_URL must use http:// or https:// with a host")
        if parts.username is not None or parts.password is not None:
            raise ValueError("AI_ANALYZER_BASE_URL must not contain credentials")
        if parts.query or parts.fragment:
            raise ValueError("AI_ANALYZER_BASE_URL must not contain query or fragment")
        return cleaned

    @field_validator("DOCUMENT_QUARANTINE_NAMESPACE", "DOCUMENT_TRUSTED_NAMESPACE")
    @classmethod
    def validate_document_storage_namespace(cls, value: str) -> str:
        """Validate safe lowercase storage namespace names without slashes or traversal."""
        cleaned = value.strip().lower()
        if not DOCUMENT_NAMESPACE_RE.fullmatch(cleaned):
            raise ValueError(
                "Document storage namespace must match ^[a-z0-9][a-z0-9_-]{0,31}$"
            )
        return cleaned

    @field_validator("CLAMAV_UNIX_SOCKET", mode="before")
    @classmethod
    def normalize_clamav_unix_socket(cls, value: Any) -> str | None:
        """Normalize blank CLAMAV_UNIX_SOCKET strings to None."""
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("CLAMAV_UNIX_SOCKET must be a string or None")
        cleaned = value.strip()
        return cleaned or None

    @field_validator("API_V1_PREFIX")
    @classmethod
    def validate_api_v1_prefix(cls, value: str) -> str:
        """Normalize API_V1_PREFIX consistently with FastAPI APIRouter and OAuth callbacks."""
        return normalize_api_v1_prefix(value)

    @field_validator("GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES", mode="before")
    @classmethod
    def parse_google_trusted_additional_audiences(cls, value: Any) -> list[str]:
        """Parse GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES and reject wildcards, spaces, or duplicates."""
        entries = _parse_string_list_setting(
            value,
            field_name="GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES",
            allow_empty_string=True,
        )
        seen: set[str] = set()
        for entry in entries:
            if "*" in entry:
                raise ValueError(
                    "GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES must not contain wildcards ('*')"
                )
            if any(ch.isspace() for ch in entry):
                raise ValueError(
                    "GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES entries must not contain whitespace"
                )
            if entry in seen:
                raise ValueError(
                    "Duplicate entry detected in GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES"
                )
            seen.add(entry)
        return entries

    @field_validator("OAUTH_ALLOWED_WEB_REDIRECT_URIS", mode="before")
    @classmethod
    def parse_oauth_allowed_web_redirect_uris(cls, value: Any) -> list[str]:
        """Parse OAUTH_ALLOWED_WEB_REDIRECT_URIS from list, JSON array, or CSV."""
        return _parse_string_list_setting(
            value,
            field_name="OAUTH_ALLOWED_WEB_REDIRECT_URIS",
            allow_empty_string=True,
        )

    @field_validator("OAUTH_ALLOWED_MOBILE_REDIRECT_URIS", mode="before")
    @classmethod
    def parse_oauth_allowed_mobile_redirect_uris(cls, value: Any) -> list[str]:
        """Parse OAUTH_ALLOWED_MOBILE_REDIRECT_URIS from list, JSON array, or CSV."""
        return _parse_string_list_setting(
            value,
            field_name="OAUTH_ALLOWED_MOBILE_REDIRECT_URIS",
            allow_empty_string=True,
        )

    @field_validator("OAUTH_BINDING_COOKIE_NAME", "OAUTH_EXCHANGE_COOKIE_NAME")
    @classmethod
    def validate_oauth_cookie_names(cls, value: str) -> str:
        """Ensure OAuth cookie names are non-empty valid RFC 6265 HTTP token strings."""
        if not isinstance(value, str) or not RFC6265_COOKIE_NAME_RE.fullmatch(value):
            raise ValueError(
                "OAuth cookie name must be a non-empty valid RFC 6265 token"
            )
        return value

    @field_validator("BACKEND_BASE_URL")
    @classmethod
    def validate_backend_base_url(cls, value: str) -> str:
        """Validate BACKEND_BASE_URL as an exact scheme://host[:port] base URL."""
        if not isinstance(value, str):
            raise ValueError("BACKEND_BASE_URL must be a string")
        if not value or any(ch.isspace() for ch in value) or not value.isascii():
            raise ValueError("BACKEND_BASE_URL must be a non-empty ASCII URL without whitespace")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
            raise ValueError("BACKEND_BASE_URL must not contain control characters")
        for forbidden_char in ("\\", "*", "@", "?", "#"):
            if forbidden_char in value:
                raise ValueError(
                    f"BACKEND_BASE_URL contains forbidden character {forbidden_char!r}"
                )
        if value.endswith("/"):
            raise ValueError("BACKEND_BASE_URL must not end with a trailing '/'")
        if "://" not in value:
            raise ValueError("BACKEND_BASE_URL must contain '://' scheme-authority separator")

        raw_scheme, rest = value.split("://", 1)
        scheme_lower = raw_scheme.lower()
        if not rest:
            raise ValueError("BACKEND_BASE_URL must include a non-empty authority")
        if "/" in rest:
            raise ValueError("BACKEND_BASE_URL must not contain a path")
        if "%" in rest:
            raise ValueError("BACKEND_BASE_URL authority must not contain percent-encoded sequences")
        if rest.endswith(":"):
            raise ValueError("BACKEND_BASE_URL authority must not end with an empty port ':'")

        validate_strict_authority(rest, scheme_lower=scheme_lower)

        try:
            parts = urlsplit(value)
            port = parts.port
        except ValueError as exc:
            raise ValueError(f"Malformed BACKEND_BASE_URL: {exc}") from exc

        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError("BACKEND_BASE_URL must use http:// or https://")
        if not parts.hostname:
            raise ValueError("BACKEND_BASE_URL must include a non-empty host")
        if parts.username is not None or parts.password is not None:
            raise ValueError("BACKEND_BASE_URL must not contain credentials")
        if parts.path != "":
            raise ValueError("BACKEND_BASE_URL must not contain a path")
        if parts.query or parts.fragment:
            raise ValueError("BACKEND_BASE_URL must not contain query parameters or fragments")
        if scheme == "https" and port == 443:
            raise ValueError("BACKEND_BASE_URL must not specify redundant default port :443")
        if scheme == "http" and port == 80:
            raise ValueError("BACKEND_BASE_URL must not specify redundant default port :80")
        if scheme == "http":
            host_lower = parts.hostname.lower()
            if ":" in host_lower:
                normalized_host = f"[{ipaddress.IPv6Address(host_lower).compressed}]"
            else:
                normalized_host = host_lower
            if normalized_host not in {"localhost", "127.0.0.1", "[::1]"}:
                raise ValueError(
                    "http:// BACKEND_BASE_URL is permitted only for loopback hosts "
                    "(localhost, 127.0.0.1, [::1])"
                )
        return value

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        """Validate that the log level is a recognized logging level."""
        valid_levels = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}
        upper_val = value.strip().upper()
        if upper_val not in valid_levels:
            raise ValueError(f"Invalid LOG_LEVEL '{value}'. Expected one of {valid_levels}")
        return upper_val

    @field_validator("DATABASE_URL", mode="after")
    @classmethod
    def validate_database_url(cls, value: SecretStr | None) -> SecretStr | None:
        """Validate DATABASE_URL when configured without echoing URL or credentials."""
        return _validate_postgres_psycopg_url(value, field_name="DATABASE_URL")

    @field_validator("MIGRATION_DATABASE_URL", mode="after")
    @classmethod
    def validate_migration_database_url(cls, value: SecretStr | None) -> SecretStr | None:
        """Validate MIGRATION_DATABASE_URL when configured without echoing credentials."""
        return _validate_postgres_psycopg_url(
            value,
            field_name="MIGRATION_DATABASE_URL",
        )

    @field_validator("REFRESH_COOKIE_DOMAIN", mode="before")
    @classmethod
    def normalize_cookie_domain(cls, value: Any) -> str | None:
        """Normalize empty REFRESH_COOKIE_DOMAIN strings to None."""
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("REFRESH_COOKIE_DOMAIN must be a string or None")
        stripped = value.strip()
        return stripped or None

    @field_validator("REFRESH_COOKIE_NAME")
    @classmethod
    def validate_refresh_cookie_name(cls, value: str) -> str:
        """Ensure refresh cookie name is non-empty without whitespace."""
        stripped = value.strip()
        if not stripped or any(ch.isspace() for ch in stripped):
            raise ValueError("REFRESH_COOKIE_NAME must be a non-empty token without whitespace")
        return stripped

    @field_validator("FRONTEND_BASE_URL")
    @classmethod
    def validate_frontend_base_url(cls, value: str) -> str:
        """Validate FRONTEND_BASE_URL as an exact scheme://host[:port] base URL."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("FRONTEND_BASE_URL must not be empty")
        if any(ch.isspace() for ch in stripped):
            raise ValueError("FRONTEND_BASE_URL must not contain whitespace")
        parts = urlsplit(stripped)
        if parts.scheme.lower() not in {"http", "https"}:
            raise ValueError("FRONTEND_BASE_URL must use http:// or https://")
        if not parts.hostname:
            raise ValueError("FRONTEND_BASE_URL must include a non-empty host")
        if parts.username is not None or parts.password is not None:
            raise ValueError("FRONTEND_BASE_URL must not contain credentials")
        if parts.path not in {"", "/"} and parts.path != "":
            raise ValueError("FRONTEND_BASE_URL must not contain a path")
        if stripped.endswith("/"):
            raise ValueError("FRONTEND_BASE_URL must not end with a trailing '/'")
        if parts.query or parts.fragment:
            raise ValueError("FRONTEND_BASE_URL must not contain query parameters or fragments")
        return stripped

    @model_validator(mode="after")
    def validate_readiness_budget_and_auth_invariants(self) -> "Settings":
        """Enforce cross-field readiness timeout, token lifetime, cookie, and URI invariants."""
        total_budget = self.DB_READINESS_CONNECT_TIMEOUT + (
            self.DB_READINESS_QUERY_TIMEOUT_MS / 1000.0
        )
        if total_budget > 5.0:
            raise ValueError(
                "Readiness total timeout budget "
                "(DB_READINESS_CONNECT_TIMEOUT + DB_READINESS_QUERY_TIMEOUT_MS / 1000.0) "
                "must not exceed 5.0 seconds"
            )

        if self.REFRESH_TOKEN_ABSOLUTE_EXPIRE_DAYS < self.REFRESH_TOKEN_EXPIRE_DAYS:
            raise ValueError(
                "REFRESH_TOKEN_ABSOLUTE_EXPIRE_DAYS must be >= REFRESH_TOKEN_EXPIRE_DAYS"
            )

        if self.REFRESH_COOKIE_SAMESITE == "none" and not self.REFRESH_COOKIE_SECURE:
            raise ValueError(
                "REFRESH_COOKIE_SECURE must be True when REFRESH_COOKIE_SAMESITE is 'none'"
            )

        if self.EMAIL_VERIFICATION_MOBILE_LOGIN_URIS:
            self.EMAIL_VERIFICATION_MOBILE_LOGIN_URIS = canonicalize_mobile_login_allowlist(
                self.EMAIL_VERIFICATION_MOBILE_LOGIN_URIS,
                environment=self.ENVIRONMENT,
            )

        # Stage 3C OAuth Configuration Invariants (REV12)
        if (
            len(
                {
                    self.REFRESH_COOKIE_NAME,
                    self.OAUTH_BINDING_COOKIE_NAME,
                    self.OAUTH_EXCHANGE_COOKIE_NAME,
                }
            )
            != 3
        ):
            raise ValueError(
                "REFRESH_COOKIE_NAME, OAUTH_BINDING_COOKIE_NAME, and "
                "OAUTH_EXCHANGE_COOKIE_NAME must be pairwise distinct"
            )

        if bool(self.GOOGLE_CLIENT_ID) != bool(self.GOOGLE_CLIENT_SECRET):
            raise ValueError(
                "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must both be configured or both unset"
            )
        if bool(self.GITHUB_CLIENT_ID) != bool(self.GITHUB_CLIENT_SECRET):
            raise ValueError(
                "GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must both be configured or both unset"
            )

        if self.OAUTH_PKCE_ENCRYPTION_KEY is not None:
            decode_aes256_base64url_key(
                self.OAUTH_PKCE_ENCRYPTION_KEY.get_secret_value(),
                field_name="OAUTH_PKCE_ENCRYPTION_KEY",
            )
        if self.OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS is not None:
            if self.OAUTH_PKCE_ENCRYPTION_KEY is None:
                raise ValueError(
                    "OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS requires OAUTH_PKCE_ENCRYPTION_KEY"
                )
            decode_aes256_base64url_key(
                self.OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS.get_secret_value(),
                field_name="OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS",
            )

        if self.oauth_enabled and self.OAUTH_PKCE_ENCRYPTION_KEY is None:
            raise ValueError(
                "OAUTH_PKCE_ENCRYPTION_KEY is required whenever an OAuth provider is configured"
            )

        if self.OAUTH_ALLOWED_WEB_REDIRECT_URIS:
            self.OAUTH_ALLOWED_WEB_REDIRECT_URIS = canonicalize_web_oauth_redirect_allowlist(
                self.OAUTH_ALLOWED_WEB_REDIRECT_URIS,
                environment=self.ENVIRONMENT,
            )

        if self.OAUTH_ALLOWED_MOBILE_REDIRECT_URIS:
            if self.oauth_enabled or "OAUTH_ALLOWED_MOBILE_REDIRECT_URIS" in self.model_fields_set:
                self.OAUTH_ALLOWED_MOBILE_REDIRECT_URIS = (
                    canonicalize_mobile_oauth_redirect_allowlist(
                        self.OAUTH_ALLOWED_MOBILE_REDIRECT_URIS,
                        environment=self.ENVIRONMENT,
                    )
                )
            elif self.ENVIRONMENT == "production":
                # Do not expose dev default custom scheme allowlist when OAuth is disabled in production.
                self.OAUTH_ALLOWED_MOBILE_REDIRECT_URIS = []
            else:
                self.OAUTH_ALLOWED_MOBILE_REDIRECT_URIS = (
                    canonicalize_mobile_oauth_redirect_allowlist(
                        self.OAUTH_ALLOWED_MOBILE_REDIRECT_URIS,
                        environment=self.ENVIRONMENT,
                    )
                )

        if self.oauth_enabled:
            cors_origin_set = set(self.CORS_ORIGINS)
            for web_uri in self.OAUTH_ALLOWED_WEB_REDIRECT_URIS:
                parsed_web = parse_and_canonicalize_web_oauth_redirect_uri(
                    web_uri,
                    environment=self.ENVIRONMENT,
                )
                if parsed_web.origin not in cors_origin_set:
                    raise ValueError(
                        "Every origin in OAUTH_ALLOWED_WEB_REDIRECT_URIS must be an exact "
                        "member of CORS_ORIGINS when OAuth is enabled (D19)"
                    )

        if self.DOCUMENT_QUARANTINE_NAMESPACE == self.DOCUMENT_TRUSTED_NAMESPACE:
            raise ValueError(
                "DOCUMENT_QUARANTINE_NAMESPACE and DOCUMENT_TRUSTED_NAMESPACE must be distinct"
            )

        return self

    def validate_runtime_requirements(self) -> None:
        """Enforce production runtime requirements at application startup."""
        if self.ENVIRONMENT not in {"production", "staging"}:
            return

        if self.DATABASE_URL is None:
            raise RuntimeError(
                "DATABASE_URL must be configured when ENVIRONMENT is 'production'"
            )
        if self.DB_ECHO:
            raise RuntimeError(
                "DB_ECHO must be False when ENVIRONMENT is 'production'"
            )

        if self.JWT_SECRET_KEY is None or len(self.JWT_SECRET_KEY.get_secret_value().strip()) < 32:
            raise RuntimeError(
                "JWT_SECRET_KEY must be configured with at least 32 characters in production"
            )
        if not self.JWT_ISSUER.strip() or not self.JWT_AUDIENCE.strip():
            raise RuntimeError("JWT_ISSUER and JWT_AUDIENCE must be non-empty in production")

        if self.RESEND_API_KEY is None or not self.RESEND_API_KEY.get_secret_value().strip():
            raise RuntimeError("RESEND_API_KEY must be configured in production")
        _validate_production_email_from_address(self.EMAIL_FROM_ADDRESS)

        frontend_parts = urlsplit(self.FRONTEND_BASE_URL)
        if frontend_parts.scheme.lower() != "https" or self.FRONTEND_BASE_URL.endswith("/"):
            raise RuntimeError(
                "FRONTEND_BASE_URL must be an exact https:// origin without trailing slash in production"
            )

        if not self.RATE_LIMIT_ENABLED:
            raise RuntimeError("RATE_LIMIT_ENABLED must be True in production")

        if not self.REFRESH_COOKIE_SECURE:
            raise RuntimeError("REFRESH_COOKIE_SECURE must be True in production")
        if self.COOKIE_DEPLOYMENT_MODE == "cross_site":
            if self.REFRESH_COOKIE_SAMESITE != "none":
                raise RuntimeError(
                    "REFRESH_COOKIE_SAMESITE must be 'none' when COOKIE_DEPLOYMENT_MODE is 'cross_site'"
                )
            if self.REFRESH_COOKIE_DOMAIN is not None:
                raise RuntimeError(
                    "REFRESH_COOKIE_DOMAIN must be None when COOKIE_DEPLOYMENT_MODE is 'cross_site'"
                )
        elif self.REFRESH_COOKIE_SAMESITE not in {"lax", "strict"}:
            raise RuntimeError(
                "REFRESH_COOKIE_SAMESITE must be 'lax' or 'strict' when COOKIE_DEPLOYMENT_MODE is 'same_site'"
            )

        if not self.CORS_ORIGINS:
            raise RuntimeError("CORS_ORIGINS must be non-empty in production")
        for origin in self.CORS_ORIGINS:
            if origin == "*" or origin.endswith("/"):
                raise RuntimeError(
                    "CORS_ORIGINS must contain exact origins without '*' or trailing '/' in production"
                )
            origin_parts = urlsplit(origin)
            if (
                origin_parts.scheme.lower() != "https"
                or not origin_parts.hostname
                or origin_parts.path
                or origin_parts.query
                or origin_parts.fragment
                or origin_parts.username is not None
                or origin_parts.password is not None
            ):
                raise RuntimeError(
                    "All CORS_ORIGINS entries must be exact https:// origins in production"
                )

        if self.EMAIL_VERIFICATION_MOBILE_LOGIN_URIS:
            canonicalize_mobile_login_allowlist(
                self.EMAIL_VERIFICATION_MOBILE_LOGIN_URIS,
                environment="production",
            )

        if self.oauth_enabled:
            if urlsplit(self.BACKEND_BASE_URL).scheme.lower() != "https":
                raise RuntimeError(
                    "BACKEND_BASE_URL must use https:// in production when OAuth is enabled"
                )
            if self.OAUTH_ALLOWED_WEB_REDIRECT_URIS:
                canonicalize_web_oauth_redirect_allowlist(
                    self.OAUTH_ALLOWED_WEB_REDIRECT_URIS,
                    environment="production",
                )
            if self.OAUTH_ALLOWED_MOBILE_REDIRECT_URIS:
                canonicalize_mobile_oauth_redirect_allowlist(
                    self.OAUTH_ALLOWED_MOBILE_REDIRECT_URIS,
                    environment="production",
                )

        if not self.PROXY_HEADERS_ENABLED:
            if self.TRUSTED_PROXY_IPS:
                raise RuntimeError(
                    "TRUSTED_PROXY_IPS must be empty when PROXY_HEADERS_ENABLED is False"
                )
        else:
            if not self.TRUSTED_PROXY_IPS:
                raise RuntimeError(
                    "TRUSTED_PROXY_IPS must list explicit IP addresses or CIDRs when PROXY_HEADERS_ENABLED is True"
                )
            for entry in self.TRUSTED_PROXY_IPS:
                if entry == "*" or not entry:
                    raise RuntimeError(
                        "TRUSTED_PROXY_IPS must not contain '*' or empty entries"
                    )
                try:
                    if "/" in entry:
                        ipaddress.ip_network(entry, strict=False)
                    else:
                        ipaddress.ip_address(entry)
                except ValueError as exc:
                    raise RuntimeError(
                        f"TRUSTED_PROXY_IPS entry {entry!r} is not a valid IP address or CIDR"
                    ) from exc

        if self.STORAGE_BACKEND == "s3":
            if not self.S3_BUCKET_NAME:
                raise RuntimeError("S3_BUCKET_NAME must be configured when STORAGE_BACKEND is 's3'")
            if self.S3_ACCESS_KEY_ID is None or self.S3_SECRET_ACCESS_KEY is None:
                raise RuntimeError(
                    "S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY must be configured when STORAGE_BACKEND is 's3'"
                )
            if self.S3_ENDPOINT_URL is not None:
                endpoint_parts = urlsplit(self.S3_ENDPOINT_URL)
                if endpoint_parts.scheme.lower() != "https" or not endpoint_parts.hostname:
                    raise RuntimeError(
                        "S3_ENDPOINT_URL must be an https:// URL in production"
                    )

        if self.MALWARE_SCANNER_BACKEND != "clamav":
            raise RuntimeError(
                "MALWARE_SCANNER_BACKEND must be 'clamav' when ENVIRONMENT is production or staging"
            )
        if self.CLAMAV_UNIX_SOCKET is None and not self.CLAMAV_HOST.strip():
            raise RuntimeError(
                "CLAMAV_HOST or CLAMAV_UNIX_SOCKET must be configured for ClamAV scanning"
            )

        if self.AI_ANALYZER_PROVIDER == "mock":
            raise RuntimeError(
                "AI_ANALYZER_PROVIDER='mock' is forbidden when ENVIRONMENT is production or staging"
            )
        if self.AI_ANALYZER_PROVIDER == "gemini":
            if self.AI_ANALYZER_API_KEY is None:
                raise RuntimeError(
                    "AI_ANALYZER_API_KEY must be configured when AI_ANALYZER_PROVIDER is 'gemini'"
                )
            if urlsplit(self.AI_ANALYZER_BASE_URL).scheme.lower() != "https":
                raise RuntimeError(
                    "AI_ANALYZER_BASE_URL must use https:// in production or staging"
                )


@lru_cache
def get_settings() -> Settings:
    """Return a cached singleton instance of application settings."""
    return Settings()


def normalize_api_v1_prefix(api_v1_prefix: str) -> str:
    """Normalize API_V1_PREFIX consistently across cookie paths, routers, and OAuth callback URLs."""
    if type(api_v1_prefix) is not str:
        raise ValueError("API_V1_PREFIX must be a string")
    if not api_v1_prefix.isascii():
        raise ValueError("API_V1_PREFIX must contain ASCII characters only")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in api_v1_prefix):
        raise ValueError("API_V1_PREFIX must not contain whitespace or control characters")
    for forbidden in ("?", "#", "\\", "//"):
        if forbidden in api_v1_prefix:
            raise ValueError(f"API_V1_PREFIX must not contain {forbidden!r}")
    if MALFORMED_PERCENT_RE.search(api_v1_prefix):
        raise ValueError("API_V1_PREFIX contains malformed percent encoding")
    if OAUTH_FORBIDDEN_ENCODED_RE.search(api_v1_prefix):
        raise ValueError(
            "API_V1_PREFIX must not contain percent-encoded dot segments, separators, or control characters"
        )
    trimmed = api_v1_prefix.rstrip("/")
    if not trimmed:
        return ""
    normalized = f"/{trimmed.lstrip('/')}"
    for segment in normalized.split("/")[1:]:
        if segment in {".", ".."}:
            raise ValueError("API_V1_PREFIX must not contain dot segments")
    return normalized


def get_allowed_redirect_uris_snapshot(
    settings: Settings,
    client_type: Literal["web", "mobile"],
) -> frozenset[str]:
    """Return an immutable snapshot of configured redirect URIs for the requested client_type."""
    if client_type == "web":
        return frozenset(settings.OAUTH_ALLOWED_WEB_REDIRECT_URIS)
    if client_type == "mobile":
        return frozenset(settings.OAUTH_ALLOWED_MOBILE_REDIRECT_URIS)
    raise ValueError(f"Unsupported client_type: {client_type!r}")


def get_oauth_callback_url(
    settings: Settings,
    provider: Literal["google", "github"],
) -> str:
    """Build the authoritative server-side OAuth callback URL from BACKEND_BASE_URL + API_V1_PREFIX."""
    if provider not in {"google", "github"}:
        raise ValueError(f"Unsupported OAuth provider: {provider!r}")
    prefix = normalize_api_v1_prefix(settings.API_V1_PREFIX)
    return f"{settings.BACKEND_BASE_URL}{prefix}/auth/oauth/{provider}/callback"
