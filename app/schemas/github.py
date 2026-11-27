"""Pydantic v2 request and response schemas for Phase 3 separate GitHub integration."""

from datetime import datetime
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.project import ProjectResponse

_REPO_FULL_NAME_RE = re.compile(r"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


class GitHubConnectRequest(BaseModel):
    """Request payload for POST /api/v1/github/connect."""

    model_config = ConfigDict(extra="forbid")

    client_type: Literal["web", "mobile"] = "web"
    redirect_uri: str | None = None


class GitHubConnectResponse(BaseModel):
    """Response payload containing the GitHub OAuth authorization URL."""

    authorization_url: str


class GitHubConnectionResponse(BaseModel):
    """Current user's GitHub portfolio connection status (never exposes token)."""

    connected: bool
    username: str | None = None
    avatar_url: str | None = None
    connected_at: datetime | None = None


class GitHubRepoResponse(BaseModel):
    """Accessible GitHub repository metadata for the import browser."""

    full_name: str
    name: str
    description: str | None
    html_url: str
    homepage: str | None
    languages: dict[str, int]
    topics: list[str]
    stars: int
    private: bool = False
    updated_at: datetime
    already_imported: bool


class GitHubRepoListResponse(BaseModel):
    """Paginated response payload for GET /api/v1/github/repositories."""

    items: list[GitHubRepoResponse]
    page: int
    page_size: int
    total: int
    total_pages: int


class GitHubRepoImportItem(BaseModel):
    """Single repository selector (`owner/repo`) for import."""

    model_config = ConfigDict(extra="forbid")

    full_name: str

    @field_validator("full_name", mode="before")
    @classmethod
    def validate_full_name(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("full_name must be a string")
        cleaned = value.strip()
        if not _REPO_FULL_NAME_RE.fullmatch(cleaned):
            raise ValueError("full_name must be formatted as 'owner/repo'")
        return cleaned


class GitHubImportRequest(BaseModel):
    """Request payload for POST /api/v1/github/repositories/import."""

    model_config = ConfigDict(extra="forbid")

    repos: list[GitHubRepoImportItem] = Field(min_length=1, max_length=25)


class GitHubImportSkippedItem(BaseModel):
    """Entry describing why a requested repository import was skipped."""

    full_name: str
    reason: str


class GitHubImportResultResponse(BaseModel):
    """Result payload for POST /api/v1/github/repositories/import."""

    created: list[ProjectResponse]
    skipped: list[GitHubImportSkippedItem]
