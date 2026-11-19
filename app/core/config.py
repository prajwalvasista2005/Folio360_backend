"""Application configuration management using Pydantic Settings v2."""

import json
from functools import lru_cache
from typing import Any, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


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
    DB_POOL_SIZE: int = Field(default=5, ge=1, le=50)
    DB_MAX_OVERFLOW: int = Field(default=10, ge=0, le=100)
    DB_POOL_TIMEOUT: int = Field(default=30, ge=1, le=120)
    DB_CONNECT_TIMEOUT: int = Field(default=5, ge=1, le=30)
    DB_READINESS_MAX_CONCURRENCY: int = Field(default=2, ge=1, le=10)
    DB_READINESS_CONNECT_TIMEOUT: int = Field(default=3, ge=1, le=4)
    DB_READINESS_QUERY_TIMEOUT_MS: int = Field(default=1000, ge=100, le=3000)
    DB_ECHO: bool = False

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
        if value is None:
            return None

        stripped = value.get_secret_value().strip()
        if not stripped:
            raise ValueError("DATABASE_URL must not be empty")

        try:
            url = make_url(stripped)
        except (ArgumentError, ValueError):
            raise ValueError(
                "Invalid DATABASE_URL format; expected postgresql+psycopg://..."
            ) from None

        if url.drivername != "postgresql+psycopg":
            raise ValueError(
                "DATABASE_URL must use the 'postgresql+psycopg' driver"
            )
        if not url.host or not url.host.strip():
            raise ValueError("DATABASE_URL must include a non-empty host")
        if not url.database or not url.database.strip():
            raise ValueError("DATABASE_URL must include a non-empty database name")

        return SecretStr(stripped)

    @model_validator(mode="after")
    def validate_readiness_budget(self) -> "Settings":
        """Enforce total readiness probe timeout budget <= 5.0 seconds."""
        total_budget = self.DB_READINESS_CONNECT_TIMEOUT + (
            self.DB_READINESS_QUERY_TIMEOUT_MS / 1000.0
        )
        if total_budget > 5.0:
            raise ValueError(
                "Readiness total timeout budget "
                "(DB_READINESS_CONNECT_TIMEOUT + DB_READINESS_QUERY_TIMEOUT_MS / 1000.0) "
                "must not exceed 5.0 seconds"
            )
        return self

    def validate_runtime_requirements(self) -> None:
        """Enforce production runtime requirements at application startup."""
        if self.ENVIRONMENT == "production":
            if self.DATABASE_URL is None:
                raise RuntimeError(
                    "DATABASE_URL must be configured when ENVIRONMENT is 'production'"
                )
            if self.DB_ECHO:
                raise RuntimeError(
                    "DB_ECHO must be False when ENVIRONMENT is 'production'"
                )


@lru_cache
def get_settings() -> Settings:
    """Return a cached singleton instance of application settings."""
    return Settings()
