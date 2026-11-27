"""Phase 3 separate GitHub portfolio connection, repo listing, and import service."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
import math
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit
import uuid

from fastapi import status
import httpx
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings, normalize_api_v1_prefix
from app.core.exceptions import AppException, ValidationAppError
from app.core.security import (
    PKCEDecryptionError,
    decrypt_github_access_token,
    encrypt_github_access_token,
    generate_opaque_token,
    hash_opaque_token,
)
from app.models.github import GitHubConnection, GitHubOAuthState
from app.models.project import Project
from app.services.project_service import _load_owned_project

logger = logging.getLogger("folio360.github.service")

GITHUB_OAUTH_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_OAUTH_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_BASE_URL = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"


@dataclass(frozen=True, slots=True)
class GitHubRepoSnapshot:
    """Normalized GitHub repository payload returned by GitHub API transport helpers."""

    repo_id: int
    full_name: str
    name: str
    description: str | None
    html_url: str
    homepage: str | None
    languages: dict[str, int]
    topics: list[str]
    stars: int
    private: bool
    updated_at: datetime


def _ensure_github_configured(settings: Settings) -> tuple[str, str]:
    client_id = (settings.GITHUB_PORTFOLIO_CLIENT_ID or "").strip()
    client_secret = (
        settings.GITHUB_PORTFOLIO_CLIENT_SECRET.get_secret_value().strip()
        if settings.GITHUB_PORTFOLIO_CLIENT_SECRET is not None
        else ""
    )
    if not client_id or not client_secret:
        raise AppException(
            message="GitHub portfolio OAuth client credentials are not configured",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            public_message="GitHub portfolio integration is not configured on the server.",
            error_code="GITHUB_NOT_CONFIGURED",
        )
    return client_id, client_secret


def _get_callback_url(settings: Settings) -> str:
    prefix = normalize_api_v1_prefix(settings.API_V1_PREFIX)
    return f"{settings.BACKEND_BASE_URL.rstrip('/')}{prefix}/github/callback"


def _resolve_safe_frontend_redirect(
    redirect_uri: str | None,
    *,
    settings: Settings,
) -> str:
    default_uri = f"{settings.FRONTEND_BASE_URL.rstrip('/')}/workspace/projects"
    if not redirect_uri or not redirect_uri.strip():
        return default_uri
    candidate = redirect_uri.strip()
    parts = urlsplit(candidate)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValidationAppError(
            message="Invalid redirect_uri scheme or host",
            public_message="redirect_uri must be a valid frontend HTTP/HTTPS URL.",
            error_code="VALIDATION_ERROR",
        )
    if parts.username is not None or parts.password is not None or parts.fragment:
        raise ValidationAppError(
            message="redirect_uri must not contain credentials or fragments",
            public_message="Invalid redirect_uri.",
            error_code="VALIDATION_ERROR",
        )
    origin = f"{parts.scheme.lower()}://{parts.netloc}"
    allowed_origins = {settings.FRONTEND_BASE_URL.rstrip("/"), *settings.CORS_ORIGINS}
    if origin not in allowed_origins:
        raise ValidationAppError(
            message="Untrusted GitHub connect redirect_uri origin",
            public_message="redirect_uri origin is not allowed.",
            error_code="VALIDATION_ERROR",
        )
    return candidate


def _append_query_params(url: str, params: dict[str, str]) -> str:
    parts = urlsplit(url)
    existing = parts.query
    encoded = urlencode(params)
    combined_query = f"{existing}&{encoded}" if existing else encoded
    return urlunsplit((parts.scheme, parts.netloc, parts.path, combined_query, ""))


def _github_headers(access_token: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "User-Agent": "Folio360-Portfolio-Client",
    }
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    return headers


def _exchange_github_code(
    *,
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    settings: Settings,
) -> tuple[str, str | None]:
    """Exchange a GitHub authorization code for an OAuth access token."""
    try:
        with httpx.Client(timeout=settings.OAUTH_HTTP_TIMEOUT_SECONDS) as client:
            resp = client.post(
                GITHUB_OAUTH_TOKEN_URL,
                headers={"Accept": "application/json"},
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
            )
    except httpx.HTTPError as exc:
        logger.warning("GitHub token exchange failed: %s", type(exc).__name__)
        raise AppException(
            message="Failed to reach GitHub token endpoint",
            status_code=status.HTTP_502_BAD_GATEWAY,
            public_message="Unable to complete GitHub authorization right now.",
            error_code="GITHUB_UNAVAILABLE",
        ) from None

    if resp.status_code != 200:
        raise AppException(
            message="GitHub token endpoint rejected exchange",
            status_code=status.HTTP_502_BAD_GATEWAY,
            public_message="GitHub rejected the authorization exchange.",
            error_code="GITHUB_TOKEN_ERROR",
        )
    data = resp.json()
    access_token = str(data.get("access_token") or "").strip()
    if not access_token:
        raise AppException(
            message="GitHub token response missing access_token",
            status_code=status.HTTP_502_BAD_GATEWAY,
            public_message="GitHub did not return a valid access token.",
            error_code="GITHUB_TOKEN_ERROR",
        )
    scope = str(data.get("scope") or "").strip() or None
    return access_token, scope


def _fetch_github_user(
    *,
    access_token: str,
    settings: Settings,
) -> tuple[str, str, str | None]:
    """Fetch authenticated GitHub user ID, login username, and avatar URL."""
    try:
        with httpx.Client(timeout=settings.OAUTH_HTTP_TIMEOUT_SECONDS) as client:
            resp = client.get(
                f"{GITHUB_API_BASE_URL}/user",
                headers=_github_headers(access_token),
            )
    except httpx.HTTPError as exc:
        logger.warning("GitHub user profile request failed: %s", type(exc).__name__)
        raise AppException(
            message="Failed to reach GitHub API",
            status_code=status.HTTP_502_BAD_GATEWAY,
            public_message="Unable to fetch your GitHub profile.",
            error_code="GITHUB_UNAVAILABLE",
        ) from None

    if resp.status_code != 200:
        raise AppException(
            message="GitHub /user endpoint returned non-200",
            status_code=status.HTTP_502_BAD_GATEWAY,
            public_message="Unable to read your GitHub profile.",
            error_code="GITHUB_API_ERROR",
        )
    data = resp.json()
    gh_id = str(data.get("id") or "").strip()
    login = str(data.get("login") or "").strip()
    avatar = str(data.get("avatar_url") or "").strip() or None
    if not gh_id or not login:
        raise AppException(
            message="GitHub /user payload missing id or login",
            status_code=status.HTTP_502_BAD_GATEWAY,
            public_message="GitHub returned an incomplete user profile.",
            error_code="GITHUB_API_ERROR",
        )
    return gh_id, login, avatar


def _parse_github_repo(item: dict[str, Any], *, languages: dict[str, int] | None = None) -> GitHubRepoSnapshot:
    primary_lang = str(item.get("language") or "").strip()
    resolved_languages = languages if languages is not None else ({primary_lang: 1} if primary_lang else {})
    raw_homepage = str(item.get("homepage") or "").strip()
    homepage = raw_homepage if raw_homepage.lower().startswith(("http://", "https://")) else None
    updated_raw = str(item.get("updated_at") or item.get("pushed_at") or "").strip()
    try:
        updated_at = (
            datetime.fromisoformat(updated_raw.replace("Z", "+00:00"))
            if updated_raw
            else datetime.now(timezone.utc)
        )
    except ValueError:
        updated_at = datetime.now(timezone.utc)

    return GitHubRepoSnapshot(
        repo_id=int(item["id"]),
        full_name=str(item["full_name"]),
        name=str(item["name"]),
        description=str(item["description"]).strip() if item.get("description") else None,
        html_url=str(item["html_url"]),
        homepage=homepage,
        languages=resolved_languages,
        topics=[str(t).strip() for t in (item.get("topics") or []) if str(t).strip()],
        stars=int(item.get("stargazers_count") or 0),
        private=bool(item.get("private", False)),
        updated_at=updated_at,
    )


def _fetch_github_repos(
    *,
    access_token: str,
    settings: Settings,
) -> list[GitHubRepoSnapshot]:
    """Fetch accessible repositories for the connected GitHub account."""
    try:
        with httpx.Client(timeout=settings.OAUTH_HTTP_TIMEOUT_SECONDS) as client:
            resp = client.get(
                f"{GITHUB_API_BASE_URL}/user/repos",
                headers=_github_headers(access_token),
                params={
                    "sort": "updated",
                    "direction": "desc",
                    "per_page": 100,
                    "affiliation": "owner,collaborator,organization_member",
                },
            )
    except httpx.HTTPError as exc:
        logger.warning("GitHub repositories request failed: %s", type(exc).__name__)
        raise AppException(
            message="Failed to reach GitHub API",
            status_code=status.HTTP_502_BAD_GATEWAY,
            public_message="Unable to load repositories from GitHub right now.",
            error_code="GITHUB_UNAVAILABLE",
        ) from None

    if resp.status_code == 401:
        raise AppException(
            message="GitHub access token rejected",
            status_code=status.HTTP_401_UNAUTHORIZED,
            public_message="Your GitHub authorization has expired. Please reconnect GitHub.",
            error_code="GITHUB_TOKEN_EXPIRED",
        )
    if resp.status_code != 200:
        raise AppException(
            message=f"GitHub /user/repos returned {resp.status_code}",
            status_code=status.HTTP_502_BAD_GATEWAY,
            public_message="GitHub rejected the repository list request.",
            error_code="GITHUB_API_ERROR",
        )
    payload = resp.json()
    if not isinstance(payload, list):
        return []
    return [_parse_github_repo(item) for item in payload if isinstance(item, dict) and item.get("id")]


def _fetch_github_repo_details(
    *,
    access_token: str,
    full_name: str,
    settings: Settings,
) -> GitHubRepoSnapshot | None:
    """Fetch single repository metadata and language breakdown from GitHub."""
    try:
        with httpx.Client(timeout=settings.OAUTH_HTTP_TIMEOUT_SECONDS) as client:
            repo_resp = client.get(
                f"{GITHUB_API_BASE_URL}/repos/{full_name}",
                headers=_github_headers(access_token),
            )
            if repo_resp.status_code == 401:
                raise AppException(
                    message="GitHub access token rejected",
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    public_message="Your GitHub authorization has expired. Please reconnect GitHub.",
                    error_code="GITHUB_TOKEN_EXPIRED",
                )
            if repo_resp.status_code in {403, 404}:
                return None
            if repo_resp.status_code != 200:
                return None
            repo_json = repo_resp.json()

            languages: dict[str, int] = {}
            lang_resp = client.get(
                f"{GITHUB_API_BASE_URL}/repos/{full_name}/languages",
                headers=_github_headers(access_token),
            )
            if lang_resp.status_code == 200 and isinstance(lang_resp.json(), dict):
                languages = {
                    str(k): int(v)
                    for k, v in lang_resp.json().items()
                    if isinstance(v, (int, float))
                }
            return _parse_github_repo(repo_json, languages=languages or None)
    except httpx.HTTPError:
        return None


def start_github_connect(
    db: Session,
    *,
    user_id: uuid.UUID,
    redirect_uri: str | None,
    settings: Settings,
) -> str:
    """Create single-use GitHub connect state and return the GitHub authorization URL."""
    client_id, _ = _ensure_github_configured(settings)
    safe_redirect = _resolve_safe_frontend_redirect(redirect_uri, settings=settings)

    raw_state = generate_opaque_token()
    state_row = GitHubOAuthState(
        user_id=user_id,
        state_hash=hash_opaque_token(raw_state),
        redirect_uri=safe_redirect,
        expires_at=datetime.now(timezone.utc)
        + timedelta(minutes=settings.OAUTH_STATE_EXPIRE_MINUTES),
    )
    db.add(state_row)
    db.commit()

    query = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": _get_callback_url(settings),
            "scope": settings.GITHUB_PORTFOLIO_SCOPE,
            "state": raw_state,
            "allow_signup": "true",
        }
    )
    return f"{GITHUB_OAUTH_AUTHORIZE_URL}?{query}"


def handle_github_callback(
    db: Session,
    *,
    code: str | None,
    state: str | None,
    error: str | None,
    settings: Settings,
) -> str:
    """Consume GitHub connect OAuth state, encrypt token, upsert GitHubConnection, and return redirect."""
    default_redirect = f"{settings.FRONTEND_BASE_URL.rstrip('/')}/workspace/projects"
    if not state or not state.strip():
        return _append_query_params(default_redirect, {"github": "error", "reason": "invalid_state"})

    state_hash = hash_opaque_token(state.strip())
    state_row = db.execute(
        select(GitHubOAuthState).where(GitHubOAuthState.state_hash == state_hash)
    ).scalar_one_or_none()
    if state_row is None:
        return _append_query_params(default_redirect, {"github": "error", "reason": "invalid_state"})

    target_redirect = state_row.redirect_uri
    now = datetime.now(timezone.utc)
    if state_row.consumed_at is not None or state_row.expires_at <= now:
        return _append_query_params(target_redirect, {"github": "error", "reason": "expired_state"})

    user_id = state_row.user_id
    state_row.consumed_at = now
    db.commit()

    if error and error.strip():
        return _append_query_params(
            target_redirect,
            {"github": "error", "reason": error.strip()[:64]},
        )

    if not code or not code.strip():
        return _append_query_params(target_redirect, {"github": "error", "reason": "missing_code"})

    try:
        client_id, client_secret = _ensure_github_configured(settings)
        access_token, scope = _exchange_github_code(
            code=code.strip(),
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=_get_callback_url(settings),
            settings=settings,
        )
        gh_user_id, username, avatar_url = _fetch_github_user(
            access_token=access_token,
            settings=settings,
        )
        encrypted_token = encrypt_github_access_token(
            access_token,
            user_id=user_id,
            settings=settings,
        )
    except AppException as exc:
        reason = (exc.error_code or "github_error").lower()
        return _append_query_params(target_redirect, {"github": "error", "reason": reason})

    existing = db.execute(
        select(GitHubConnection).where(GitHubConnection.user_id == user_id)
    ).scalar_one_or_none()
    if existing is None:
        db.add(
            GitHubConnection(
                user_id=user_id,
                github_user_id=gh_user_id,
                username=username,
                avatar_url=avatar_url,
                access_token_encrypted=encrypted_token,
                token_scope=scope,
                connected_at=now,
            )
        )
    else:
        existing.github_user_id = gh_user_id
        existing.username = username
        existing.avatar_url = avatar_url
        existing.access_token_encrypted = encrypted_token
        existing.token_scope = scope
        existing.connected_at = now
    db.commit()

    return _append_query_params(target_redirect, {"github": "connected"})


def get_connection(db: Session, *, user_id: uuid.UUID) -> GitHubConnection | None:
    """Return the user's current GitHub portfolio connection if connected."""
    return db.execute(
        select(GitHubConnection).where(GitHubConnection.user_id == user_id)
    ).scalar_one_or_none()


def disconnect(db: Session, *, user_id: uuid.UUID) -> None:
    """Disconnect the user's GitHub portfolio integration without deleting imported projects."""
    conn = get_connection(db, user_id=user_id)
    if conn is not None:
        db.delete(conn)
        db.commit()


def _require_decrypted_token(
    db: Session,
    *,
    user_id: uuid.UUID,
    settings: Settings,
) -> str:
    conn = get_connection(db, user_id=user_id)
    if conn is None:
        raise AppException(
            message="GitHub account is not connected",
            status_code=status.HTTP_400_BAD_REQUEST,
            public_message="Connect your GitHub account before accessing repositories.",
            error_code="GITHUB_NOT_CONNECTED",
        )
    try:
        return decrypt_github_access_token(
            conn.access_token_encrypted,
            user_id=user_id,
            settings=settings,
        )
    except PKCEDecryptionError:
        raise AppException(
            message="Stored GitHub token could not be decrypted",
            status_code=status.HTTP_401_UNAUTHORIZED,
            public_message="Your GitHub connection needs to be re-authorized.",
            error_code="GITHUB_TOKEN_EXPIRED",
        ) from None


def _load_imported_repo_sets(
    db: Session,
    *,
    user_id: uuid.UUID,
) -> tuple[set[int], set[str]]:
    rows = db.execute(
        select(Project.github_repo_id, Project.github_repo_full_name).where(
            Project.user_id == user_id,
            (Project.github_repo_id.is_not(None)) | (Project.github_repo_full_name.is_not(None)),
        )
    ).all()
    ids = {int(repo_id) for repo_id, _ in rows if repo_id is not None}
    names = {str(full_name).strip().lower() for _, full_name in rows if full_name}
    return ids, names


def list_repositories(
    db: Session,
    *,
    user_id: uuid.UUID,
    page: int = 1,
    page_size: int = 50,
    q: str | None = None,
    settings: Settings,
) -> tuple[list[tuple[GitHubRepoSnapshot, bool]], int, int]:
    """List accessible GitHub repositories marked with already_imported status."""
    token = _require_decrypted_token(db, user_id=user_id, settings=settings)
    repos = _fetch_github_repos(access_token=token, settings=settings)
    imported_ids, imported_names = _load_imported_repo_sets(db, user_id=user_id)

    if q and q.strip():
        needle = q.strip().lower()
        repos = [
            repo
            for repo in repos
            if needle in repo.full_name.lower()
            or (repo.description and needle in repo.description.lower())
            or any(needle in t.lower() for t in repo.topics)
            or any(needle in lang.lower() for lang in repo.languages)
        ]

    total = len(repos)
    total_pages = max(1, math.ceil(total / page_size)) if total > 0 else 1
    start = (page - 1) * page_size
    page_items = repos[start : start + page_size]

    annotated = [
        (
            repo,
            (repo.repo_id in imported_ids) or (repo.full_name.lower() in imported_names),
        )
        for repo in page_items
    ]
    return annotated, total, total_pages


def _derive_technologies(repo: GitHubRepoSnapshot) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for name in list(repo.languages.keys()) + list(repo.topics):
        cleaned = name.strip()[:60]
        if not cleaned:
            continue
        key = cleaned.lower()
        if key not in seen:
            seen.add(key)
            ordered.append(cleaned)
        if len(ordered) >= 10:
            break
    return ordered


def import_repositories(
    db: Session,
    *,
    user_id: uuid.UUID,
    full_names: list[str],
    settings: Settings,
) -> tuple[list[Project], list[tuple[str, str]]]:
    """Import selected GitHub repositories as private Folio360 projects, skipping duplicates."""
    token = _require_decrypted_token(db, user_id=user_id, settings=settings)
    imported_ids, imported_names = _load_imported_repo_sets(db, user_id=user_id)

    created_projects: list[Project] = []
    skipped: list[tuple[str, str]] = []
    seen_request: set[str] = set()
    next_order = (
        int(
            db.execute(
                select(func.coalesce(func.max(Project.display_order), -1)).where(
                    Project.user_id == user_id
                )
            ).scalar_one()
        )
        + 1
    )

    for raw_name in full_names:
        norm = raw_name.strip().lower()
        if norm in seen_request:
            skipped.append((raw_name, "Duplicate in import request"))
            continue
        seen_request.add(norm)

        if norm in imported_names:
            skipped.append((raw_name, "Already imported"))
            continue

        repo = _fetch_github_repo_details(
            access_token=token,
            full_name=raw_name.strip(),
            settings=settings,
        )
        if repo is None:
            skipped.append((raw_name, "Repository not found or inaccessible"))
            continue

        if repo.repo_id in imported_ids or repo.full_name.lower() in imported_names:
            skipped.append((repo.full_name, "Already imported"))
            continue

        now = datetime.now(timezone.utc)
        summary = (repo.description or f"Imported from GitHub repository {repo.full_name}.")[:500]
        project = Project(
            user_id=user_id,
            title=repo.name[:200],
            summary=summary,
            description=repo.description,
            category="Software",
            technologies=_derive_technologies(repo),
            github_url=repo.html_url[:512],
            live_url=repo.homepage[:512] if repo.homepage else None,
            is_ongoing=False,
            featured=False,
            display_order=next_order,
            # Keep GitHub visibility separate: imported repositories ALWAYS start Private.
            visibility="private",
            github_repo_id=repo.repo_id,
            github_repo_full_name=repo.full_name,
            github_imported_at=now,
        )

        try:
            with db.begin_nested():
                db.add(project)
                db.flush()
        except IntegrityError:
            skipped.append((repo.full_name, "Already imported"))
            continue

        imported_ids.add(repo.repo_id)
        imported_names.add(repo.full_name.lower())
        next_order += 1
        created_projects.append(project)

    db.commit()
    loaded = [_load_owned_project(db, user_id=user_id, project_id=p.id) for p in created_projects]
    return loaded, skipped
