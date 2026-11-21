"""Application configuration management using Pydantic Settings v2."""

from email.utils import parseaddr
from functools import lru_cache
import ipaddress
import json
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from app.core.uri_policy import canonicalize_mobile_login_allowlist


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


@lru_cache
def get_settings() -> Settings:
    """Return a cached singleton instance of application settings."""
    return Settings()
