"""Unit tests for Phase 3 Project schemas, GitHub schemas, and token encryption."""

from datetime import date
import uuid

from pydantic import ValidationError
import pytest

from app.core.config import Settings
from app.core.security import (
    PKCEDecryptionError,
    decrypt_github_access_token,
    encrypt_github_access_token,
)
from app.schemas.github import GitHubImportRequest
from app.schemas.project import ProjectCreate, ProjectUpdate


def test_project_create_defaults_to_private_and_cleans_technologies() -> None:
    payload = ProjectCreate(
        title="  Folio360 Portfolio  ",
        summary="  Unified academic and project showcase  ",
        technologies=[" React ", "TypeScript", "react", "  "],
    )
    assert payload.title == "Folio360 Portfolio"
    assert payload.summary == "Unified academic and project showcase"
    assert payload.visibility == "private"
    assert payload.technologies == ["React", "TypeScript"]
    assert payload.category == "General"


def test_project_create_rejects_ongoing_with_end_date_and_invalid_urls() -> None:
    with pytest.raises(ValidationError):
        ProjectCreate(
            title="Bad Dates",
            summary="Ongoing project should not have end date",
            is_ongoing=True,
            end_date=date(2026, 10, 1),
        )

    with pytest.raises(ValidationError):
        ProjectCreate(
            title="Bad Order",
            summary="End date before start date",
            start_date=date(2026, 10, 1),
            end_date=date(2026, 9, 1),
        )

    with pytest.raises(ValidationError):
        ProjectCreate(
            title="Bad URL",
            summary="Javascript scheme must be rejected",
            live_url="javascript:alert(1)",
        )


def test_project_update_requires_fields_and_non_null_visibility() -> None:
    with pytest.raises(ValidationError):
        ProjectUpdate()

    with pytest.raises(ValidationError):
        ProjectUpdate(visibility=None)

    patch = ProjectUpdate(visibility="public", featured=True)
    assert patch.visibility == "public"
    assert patch.featured is True


def test_github_import_request_validates_owner_repo_format() -> None:
    req = GitHubImportRequest(repos=[{"full_name": "NyNehalJois/Folio360_frontend"}])
    assert req.repos[0].full_name == "NyNehalJois/Folio360_frontend"

    with pytest.raises(ValidationError):
        GitHubImportRequest(repos=[{"full_name": "not-a-repo"}])

    with pytest.raises(ValidationError):
        GitHubImportRequest(repos=[])


def test_github_access_token_encryption_binds_to_user_id() -> None:
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        JWT_SECRET_KEY="project-unit-jwt-secret-key-at-least-32-chars",
    )
    user_a = uuid.uuid4()
    user_b = uuid.uuid4()
    ciphertext = encrypt_github_access_token("gho_secret_token_123", user_id=user_a, settings=settings)

    assert ciphertext.startswith("v1:")
    assert "gho_secret_token_123" not in ciphertext
    assert decrypt_github_access_token(ciphertext, user_id=user_a, settings=settings) == "gho_secret_token_123"

    with pytest.raises(PKCEDecryptionError):
        decrypt_github_access_token(ciphertext, user_id=user_b, settings=settings)


def test_github_portfolio_credentials_must_be_paired() -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            ENVIRONMENT="testing",
            GITHUB_PORTFOLIO_CLIENT_ID="only-id",
        )

    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            ENVIRONMENT="testing",
            GITHUB_PORTFOLIO_CLIENT_SECRET="only-secret",
        )

    ok = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        GITHUB_PORTFOLIO_CLIENT_ID="portfolio-id",
        GITHUB_PORTFOLIO_CLIENT_SECRET="portfolio-secret",
    )
    assert ok.GITHUB_PORTFOLIO_CLIENT_ID == "portfolio-id"
