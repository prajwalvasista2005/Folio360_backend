"""End-to-end Phase 3 Projects Portfolio & GitHub integration tests against PostgreSQL 17."""

from datetime import date, datetime, timezone
import struct
import uuid
import zlib

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import Engine, select, text

from app.core.config import Settings
from app.core.exceptions import AppException
from app.core.security import create_access_token, hash_password
from app.db.session import build_sessionmaker
from app.main import create_app
from app.models.github import GitHubConnection, GitHubOAuthState
from app.models.profile import UserProfile
from app.models.user import User
from app.services import github_service
from app.services.github_service import GitHubRepoSnapshot
from app.services.oauth_providers import build_github_authorization_url


def _build_minimal_png() -> bytes:
    """Construct a valid 1x1 RGB PNG payload with valid CRC32 checksums."""
    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _build_test_app(
    test_database_url: str,
    *,
    storage_dir: str = "/tmp/folio360_project_test_media",
    include_portfolio_github: bool = True,
) -> tuple[Settings, object]:
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL=test_database_url,
        JWT_SECRET_KEY="project-integration-jwt-secret-key-at-least-32-chars",
        JWT_ISSUER="folio360",
        JWT_AUDIENCE="folio360-api",
        JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15,
        FRONTEND_BASE_URL="http://localhost:5173",
        BACKEND_BASE_URL="http://localhost:8000",
        CORS_ORIGINS=["http://localhost:5173"],
        OAUTH_PKCE_ENCRYPTION_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        GITHUB_CLIENT_ID="test-login-gh-client-id",
        GITHUB_CLIENT_SECRET="test-login-gh-client-secret",
        GITHUB_PORTFOLIO_CLIENT_ID="test-portfolio-gh-client-id" if include_portfolio_github else None,
        GITHUB_PORTFOLIO_CLIENT_SECRET="test-portfolio-gh-client-secret" if include_portfolio_github else None,
        OAUTH_ALLOWED_WEB_REDIRECT_URIS=["http://localhost:5173/auth/oauth/callback"],
        EMAIL_FROM_ADDRESS="no-reply@folio360.com",
        RATE_LIMIT_ENABLED=False,
        STORAGE_BACKEND="local",
        DOCUMENT_LOCAL_STORAGE_DIR=storage_dir,
        MALWARE_SCANNER_BACKEND="mock",
    )
    return settings, create_app(settings=settings)


@pytest.fixture
def clean_projects_db(db_engine: Engine):
    """Clean users (and cascaded projects/github connections) around each test."""
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))
    yield
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))


def _create_db_user_with_profile(
    db_engine: Engine,
    *,
    email: str,
    slug: str,
) -> User:
    session_factory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password("StrongPassword!2026"),
        is_active=True,
        is_email_verified=True,
        email_verified_at=now,
        auth_version=0,
    )
    profile = UserProfile(
        id=uuid.uuid4(),
        user_id=user.id,
        slug=slug,
        full_name=f"User {slug}",
        date_of_birth=date(2002, 5, 10),
        interests=["Python", "TypeScript"],
        profile_completed=True,
        profile_completed_at=now,
    )
    with session_factory() as session:
        session.add(user)
        session.flush()
        session.add(profile)
        session.commit()
        session.refresh(user)
    return user


def _auth_headers(user: User, settings: Settings) -> dict[str, str]:
    token, _ = create_access_token(
        user_id=user.id,
        auth_version=user.auth_version,
        settings=settings,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.db
def test_manual_project_crud_ownership_cover_image_and_public_filtering(
    db_engine: Engine,
    test_database_url: str,
    clean_projects_db: None,
    tmp_path,
) -> None:
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    owner = _create_db_user_with_profile(db_engine, email="proj.owner@example.com", slug="proj_owner")
    other = _create_db_user_with_profile(db_engine, email="proj.other@example.com", slug="proj_other")

    with TestClient(app) as client:  # type: ignore[arg-type]
        # 1. Create private project manually without GitHub
        create_res = client.post(
            "/api/v1/projects",
            headers=_auth_headers(owner, settings),
            json={
                "title": "Folio360 Core",
                "summary": "Unified academic identity backend and portfolio.",
                "category": "Software",
                "technologies": ["FastAPI", "PostgreSQL", "React"],
                "live_url": "https://folio360.in",
                "visibility": "private",
            },
        )
        assert create_res.status_code == 201, create_res.text
        private_proj = create_res.json()
        assert private_proj["visibility"] == "private"

        # 2. Create public project + upload cover image
        pub_res = client.post(
            "/api/v1/projects",
            headers=_auth_headers(owner, settings),
            json={
                "title": "Public Portfolio Showcase",
                "summary": "Publicly visible showcase project.",
                "technologies": ["TypeScript"],
                "visibility": "public",
                "featured": True,
            },
        )
        assert pub_res.status_code == 201
        public_proj = pub_res.json()

        img_res = client.post(
            f"/api/v1/projects/{public_proj['id']}/images",
            headers=_auth_headers(owner, settings),
            files={"file": ("cover.png", _build_minimal_png(), "image/png")},
            data={"alt": "Showcase cover"},
        )
        assert img_res.status_code == 201, img_res.text
        uploaded_img = img_res.json()
        assert uploaded_img["alt"] == "Showcase cover"

        # 3. Serve public project image without token
        content_res = client.get(uploaded_img["url"])
        assert content_res.status_code == 200
        assert content_res.headers["content-type"] == "image/png"

        # 4. Owner-scoped enforcement: another user cannot get, update, or delete
        assert (
            client.get(
                f"/api/v1/projects/{private_proj['id']}",
                headers=_auth_headers(other, settings),
            ).status_code
            == 404
        )
        assert (
            client.patch(
                f"/api/v1/projects/{private_proj['id']}",
                headers=_auth_headers(other, settings),
                json={"title": "Hijacked"},
            ).status_code
            == 404
        )
        assert (
            client.delete(
                f"/api/v1/projects/{private_proj['id']}",
                headers=_auth_headers(other, settings),
            ).status_code
            == 404
        )

        # 5. Public profile excludes private project and includes public project + cover image
        public_profile_res = client.get("/api/v1/public/profiles/proj_owner")
        assert public_profile_res.status_code == 200, public_profile_res.text
        pub_projects = public_profile_res.json()["sections"]["projects"]
        assert [p["title"] for p in pub_projects] == ["Public Portfolio Showcase"]
        assert len(pub_projects[0]["images"]) == 1

        # 6. Toggle private project to public -> appears on public profile; delete removes it
        toggle_res = client.patch(
            f"/api/v1/projects/{private_proj['id']}",
            headers=_auth_headers(owner, settings),
            json={"visibility": "public"},
        )
        assert toggle_res.status_code == 200
        assert toggle_res.json()["visibility"] == "public"

        pub_after = client.get("/api/v1/public/profiles/proj_owner").json()["sections"]["projects"]
        assert {p["title"] for p in pub_after} == {"Public Portfolio Showcase", "Folio360 Core"}

        del_res = client.delete(
            f"/api/v1/projects/{public_proj['id']}",
            headers=_auth_headers(owner, settings),
        )
        assert del_res.status_code == 204


@pytest.mark.db
def test_github_connect_list_import_duplicate_skip_and_disconnect(
    db_engine: Engine,
    test_database_url: str,
    clean_projects_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, app = _build_test_app(test_database_url)
    user = _create_db_user_with_profile(db_engine, email="gh.user@example.com", slug="gh_user")
    headers = _auth_headers(user, settings)

    sample_repo = GitHubRepoSnapshot(
        repo_id=987654,
        full_name="octocat/folio-demo",
        name="folio-demo",
        description="Demo portfolio repo on GitHub",
        html_url="https://github.com/octocat/folio-demo",
        homepage="https://demo.example.com",
        languages={"Python": 12000, "TypeScript": 4000},
        topics=["fastapi", "react"],
        stars=42,
        private=False,  # GitHub repo is public, but Folio360 import MUST remain private!
        updated_at=datetime.now(timezone.utc),
    )

    exchange_calls: list[dict[str, str]] = []

    def _fake_exchange(**kwargs: str) -> tuple[str, str]:
        exchange_calls.append(
            {
                "client_id": kwargs["client_id"],
                "client_secret": kwargs["client_secret"],
                "redirect_uri": kwargs["redirect_uri"],
            }
        )
        return ("gho_test_access_token_xyz", "read:user repo")

    monkeypatch.setattr(
        github_service,
        "_exchange_github_code",
        _fake_exchange,
    )
    monkeypatch.setattr(
        github_service,
        "_fetch_github_user",
        lambda **kwargs: ("424242", "octocat", "https://avatars.githubusercontent.com/u/1?v=4"),
    )
    monkeypatch.setattr(
        github_service,
        "_fetch_github_repos",
        lambda **kwargs: [sample_repo],
    )
    monkeypatch.setattr(
        github_service,
        "_fetch_github_repo_details",
        lambda **kwargs: sample_repo if kwargs["full_name"].lower() == "octocat/folio-demo" else None,
    )

    with TestClient(app) as client:  # type: ignore[arg-type]
        # 1. Initially disconnected
        status_res = client.get("/api/v1/github/connection", headers=headers)
        assert status_res.status_code == 200
        assert status_res.json() == {
            "connected": False,
            "username": None,
            "avatar_url": None,
            "connected_at": None,
        }

        # 2. Initiate connect and simulate callback
        connect_res = client.post(
            "/api/v1/github/connect",
            headers=headers,
            json={"client_type": "web", "redirect_uri": "http://localhost:5173/workspace/projects"},
        )
        assert connect_res.status_code == 200
        auth_url = connect_res.json()["authorization_url"]
        assert "github.com/login/oauth/authorize" in auth_url
        assert "client_id=test-portfolio-gh-client-id" in auth_url
        assert "test-login-gh-client-id" not in auth_url
        assert "http%3A%2F%2Flocalhost%3A8000%2Fapi%2Fv1%2Fgithub%2Fcallback" in auth_url
        state_param = [
            part.split("=", 1)[1]
            for part in auth_url.split("?", 1)[1].split("&")
            if part.startswith("state=")
        ][0]

        cb_res = client.get(
            f"/api/v1/github/callback?code=gh_code_123&state={state_param}",
            follow_redirects=False,
        )
        assert cb_res.status_code == 302
        assert cb_res.headers["location"] == "http://localhost:5173/workspace/projects?github=connected"
        assert exchange_calls == [
            {
                "client_id": "test-portfolio-gh-client-id",
                "client_secret": "test-portfolio-gh-client-secret",
                "redirect_uri": "http://localhost:8000/api/v1/github/callback",
            }
        ]

        # Verify encrypted token stored in DB (not plaintext)
        session_factory = build_sessionmaker(db_engine)
        with session_factory() as session:
            conn_row = session.execute(
                select(GitHubConnection).where(GitHubConnection.user_id == user.id)
            ).scalar_one()
            assert conn_row.username == "octocat"
            assert conn_row.access_token_encrypted.startswith("v1:")
            assert "gho_test_access_token_xyz" not in conn_row.access_token_encrypted

        # 3. Connection status & repo browser
        conn_status = client.get("/api/v1/github/connection", headers=headers).json()
        assert conn_status["connected"] is True
        assert conn_status["username"] == "octocat"

        repos_res = client.get("/api/v1/github/repositories", headers=headers)
        assert repos_res.status_code == 200
        repo_items = repos_res.json()["items"]
        assert len(repo_items) == 1
        assert repo_items[0]["full_name"] == "octocat/folio-demo"
        assert repo_items[0]["already_imported"] is False

        # 4. Import repository -> created as PRIVATE even though GitHub repo is public
        import_res = client.post(
            "/api/v1/github/repositories/import",
            headers=headers,
            json={"repos": [{"full_name": "octocat/folio-demo"}]},
        )
        assert import_res.status_code == 200
        import_data = import_res.json()
        assert len(import_data["created"]) == 1
        assert import_data["skipped"] == []
        imported_proj = import_data["created"][0]
        assert imported_proj["visibility"] == "private"
        assert imported_proj["github_import"]["repo_full_name"] == "octocat/folio-demo"

        # Public profile must NOT expose newly imported private repo
        pub_res = client.get("/api/v1/public/profiles/gh_user").json()
        assert pub_res["sections"]["projects"] == []

        # 5. Repo list now marks already_imported=True, and re-importing skips duplicate
        repos_after = client.get("/api/v1/github/repositories", headers=headers).json()["items"]
        assert repos_after[0]["already_imported"] is True

        dup_res = client.post(
            "/api/v1/github/repositories/import",
            headers=headers,
            json={"repos": [{"full_name": "octocat/folio-demo"}]},
        )
        assert dup_res.status_code == 200
        assert dup_res.json()["created"] == []
        assert dup_res.json()["skipped"] == [
            {"full_name": "octocat/folio-demo", "reason": "Already imported"}
        ]

        # 6. Disconnect removes connection while preserving imported project
        disc_res = client.delete("/api/v1/github/connection", headers=headers)
        assert disc_res.status_code == 204
        assert client.get("/api/v1/github/connection", headers=headers).json()["connected"] is False
        assert client.get("/api/v1/projects", headers=headers).json()["total"] == 1


@pytest.mark.db
def test_github_portfolio_connect_does_not_fallback_to_login_credentials(
    db_engine: Engine,
    test_database_url: str,
    clean_projects_db: None,
) -> None:
    settings, app = _build_test_app(test_database_url, include_portfolio_github=False)
    user = _create_db_user_with_profile(db_engine, email="nofallback@example.com", slug="nofallback")
    headers = _auth_headers(user, settings)

    # Stage 3C GitHub Login continues using GITHUB_CLIENT_ID and /auth/oauth/github/callback
    login_url = build_github_authorization_url(
        settings,
        state="s" * 43,
        code_challenge="c" * 43,
    )
    assert "client_id=test-login-gh-client-id" in login_url
    assert "%2Fapi%2Fv1%2Fauth%2Foauth%2Fgithub%2Fcallback" in login_url

    with pytest.raises(AppException) as exc_info:
        github_service._ensure_github_configured(settings)
    assert exc_info.value.status_code == 503
    assert exc_info.value.error_code == "GITHUB_NOT_CONFIGURED"

    with TestClient(app) as client:  # type: ignore[arg-type]
        res = client.post(
            "/api/v1/github/connect",
            headers=headers,
            json={"client_type": "web", "redirect_uri": "http://localhost:5173/workspace/projects"},
        )
        assert res.status_code == 503
        assert "code" not in res.json()["error"]
        assert res.json()["error"]["status_code"] == 503

    with build_sessionmaker(db_engine)() as session:
        assert session.execute(select(GitHubOAuthState)).scalars().all() == []
