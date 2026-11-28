"""Integration tests for Settings APIs (visibility, preferences, sessions, and password change)."""

from datetime import date, datetime, timedelta, timezone
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import Engine, text

from app.core.config import Settings
from app.core.security import create_access_token, hash_opaque_token, hash_password
from app.db.session import build_sessionmaker
from app.main import create_app
from app.models.profile import UserProfile
from app.models.project import Project
from app.models.refresh_session import RefreshSession
from app.models.user import User

pytestmark = pytest.mark.db


def _build_test_app(test_database_url: str, *, storage_dir: str) -> tuple[Settings, object]:
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL=test_database_url,
        JWT_SECRET_KEY="settings-integration-jwt-secret-key-32chars",
        JWT_ISSUER="folio360",
        JWT_AUDIENCE="folio360-api",
        JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15,
        FRONTEND_BASE_URL="http://localhost:5173",
        BACKEND_BASE_URL="http://localhost:8000",
        CORS_ORIGINS=["http://localhost:5173"],
        OAUTH_PKCE_ENCRYPTION_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        EMAIL_FROM_ADDRESS="no-reply@folio360.com",
        RATE_LIMIT_ENABLED=False,
        STORAGE_BACKEND="local",
        DOCUMENT_LOCAL_STORAGE_DIR=storage_dir,
        MALWARE_SCANNER_BACKEND="mock",
    )
    return settings, create_app(settings=settings)


@pytest.fixture
def clean_settings_db(db_engine: Engine):
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))
    yield
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))


def _create_user(
    db_engine: Engine,
    *,
    email: str,
    verified: bool = True,
    password: str = "StrongPassword!2026",
) -> User:
    session_factory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password(password),
        is_active=True,
        is_email_verified=verified,
        email_verified_at=now if verified else None,
        auth_version=0,
    )
    with session_factory() as session:
        session.add(user)
        session.commit()
        session.refresh(user)
    return user


def _create_profile(
    db_engine: Engine,
    *,
    user_id: uuid.UUID,
    slug: str,
) -> UserProfile:
    session_factory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)
    profile = UserProfile(
        id=uuid.uuid4(),
        user_id=user_id,
        slug=slug,
        full_name=f"User {slug}",
        date_of_birth=date(2002, 5, 10),
        interests=["Systems"],
        profile_completed=True,
        profile_completed_at=now,
    )
    with session_factory() as session:
        session.add(profile)
        session.commit()
        session.refresh(profile)
    return profile


def _auth_headers(user: User, settings: Settings) -> dict[str, str]:
    token, _ = create_access_token(
        user_id=user.id,
        auth_version=user.auth_version,
        settings=settings,
    )
    return {"Authorization": f"Bearer {token}"}


def test_settings_endpoints_require_verified_auth(
    db_engine: Engine,
    test_database_url: str,
    tmp_path,
    clean_settings_db,
) -> None:
    del clean_settings_db
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    unverified = _create_user(db_engine, email="unverified@example.com", verified=False)

    with TestClient(app) as client:
        for path in (
            "/api/v1/profile/me/visibility",
            "/api/v1/profile/me/preferences",
            "/api/v1/auth/sessions",
        ):
            assert client.get(path).status_code == 401
            res = client.get(path, headers=_auth_headers(unverified, settings))
            assert res.status_code == 403
            assert res.json()["error"]["details"]["code"] == "EMAIL_NOT_VERIFIED"


def test_visibility_persistence_and_public_profile_enforcement(
    db_engine: Engine,
    test_database_url: str,
    tmp_path,
    clean_settings_db,
) -> None:
    del clean_settings_db
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    user = _create_user(db_engine, email="vis.owner@example.com")
    _create_profile(db_engine, user_id=user.id, slug="vis_owner")
    session_factory = build_sessionmaker(db_engine)
    with session_factory() as session:
        session.add(
            Project(
                id=uuid.uuid4(),
                user_id=user.id,
                title="Public Showcase Project",
                summary="Visible when projects enabled",
                category="Web",
                visibility="public",
            )
        )
        session.add(
            Project(
                id=uuid.uuid4(),
                user_id=user.id,
                title="Secret Draft Project",
                summary="Never exposed publicly",
                category="Web",
                visibility="private",
            )
        )
        session.commit()

    headers = _auth_headers(user, settings)
    with TestClient(app) as client:
        # Defaults
        res_get = client.get("/api/v1/profile/me/visibility", headers=headers)
        assert res_get.status_code == 200
        assert res_get.json()["public_enabled"] is True
        assert res_get.json()["public_sections"]["projects"] is True

        # Public profile initially shows only public project
        pub_initial = client.get("/api/v1/public/profiles/vis_owner")
        assert pub_initial.status_code == 200
        titles = [p["title"] for p in pub_initial.json()["sections"]["projects"]]
        assert titles == ["Public Showcase Project"]

        # Hide projects section via PATCH
        res_hide_projects = client.patch(
            "/api/v1/profile/me/visibility",
            headers=headers,
            json={"public_sections": {"projects": False}, "discoverable": True},
        )
        assert res_hide_projects.status_code == 200
        assert res_hide_projects.json()["public_sections"]["projects"] is False
        assert res_hide_projects.json()["discoverable"] is True

        pub_no_projects = client.get("/api/v1/public/profiles/vis_owner")
        assert pub_no_projects.status_code == 200
        assert pub_no_projects.json()["sections"]["projects"] == []

        # Disable public_enabled -> forces discoverable=False & public profile returns 404
        res_disable = client.patch(
            "/api/v1/profile/me/visibility",
            headers=headers,
            json={"public_enabled": False, "discoverable": True},
        )
        assert res_disable.status_code == 200
        assert res_disable.json()["public_enabled"] is False
        assert res_disable.json()["discoverable"] is False

        # Reload still persisted
        res_reload = client.get("/api/v1/profile/me/visibility", headers=headers)
        assert res_reload.status_code == 200
        assert res_reload.json()["public_enabled"] is False
        assert res_reload.json()["public_sections"]["projects"] is False

        assert client.get("/api/v1/public/profiles/vis_owner").status_code == 404


def test_preferences_read_update_and_validation(
    db_engine: Engine,
    test_database_url: str,
    tmp_path,
    clean_settings_db,
) -> None:
    del clean_settings_db
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    user = _create_user(db_engine, email="prefs@example.com")
    headers = _auth_headers(user, settings)

    with TestClient(app) as client:
        # Works even before UserProfile exists
        res_default = client.get("/api/v1/profile/me/preferences", headers=headers)
        assert res_default.status_code == 200
        assert res_default.json() == {"theme": "light"}

        res_update = client.patch(
            "/api/v1/profile/me/preferences",
            headers=headers,
            json={"theme": "dark"},
        )
        assert res_update.status_code == 200
        assert res_update.json() == {"theme": "dark"}

        res_reload = client.get("/api/v1/profile/me/preferences", headers=headers)
        assert res_reload.status_code == 200
        assert res_reload.json() == {"theme": "dark"}

        res_invalid = client.patch(
            "/api/v1/profile/me/preferences",
            headers=headers,
            json={"theme": "neon"},
        )
        assert res_invalid.status_code == 422


def test_sessions_listing_ownership_revocation_and_password_change(
    db_engine: Engine,
    test_database_url: str,
    tmp_path,
    clean_settings_db,
) -> None:
    del clean_settings_db
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    user_a = _create_user(db_engine, email="sec.a@example.com")
    user_b = _create_user(db_engine, email="sec.b@example.com")
    now = datetime.now(timezone.utc)

    raw_a_current = "raw-token-a-current"
    raw_a_other = "raw-token-a-other"
    raw_b = "raw-token-b"
    session_a_other_id = uuid.uuid4()
    session_b_id = uuid.uuid4()

    session_factory = build_sessionmaker(db_engine)
    with session_factory() as session:
        session.add_all(
            [
                RefreshSession(
                    id=uuid.uuid4(),
                    user_id=user_a.id,
                    family_id=uuid.uuid4(),
                    token_hash=hash_opaque_token(raw_a_current),
                    client_type="web",
                    user_agent="Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0",
                    expires_at=now + timedelta(days=7),
                    family_expires_at=now + timedelta(days=14),
                    last_used_at=now,
                ),
                RefreshSession(
                    id=session_a_other_id,
                    user_id=user_a.id,
                    family_id=uuid.uuid4(),
                    token_hash=hash_opaque_token(raw_a_other),
                    client_type="web",
                    user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X) Firefox/122.0",
                    expires_at=now + timedelta(days=7),
                    family_expires_at=now + timedelta(days=14),
                    last_used_at=now - timedelta(hours=1),
                ),
                RefreshSession(
                    id=session_b_id,
                    user_id=user_b.id,
                    family_id=uuid.uuid4(),
                    token_hash=hash_opaque_token(raw_b),
                    client_type="web",
                    user_agent="curl/8.0.0",
                    expires_at=now + timedelta(days=7),
                    family_expires_at=now + timedelta(days=14),
                    last_used_at=now,
                ),
            ]
        )
        session.commit()

    headers_a = _auth_headers(user_a, settings)
    headers_b = _auth_headers(user_b, settings)

    with TestClient(app) as client:
        client.cookies.set(settings.REFRESH_COOKIE_NAME, raw_a_current)
        res_list = client.get("/api/v1/auth/sessions", headers=headers_a)
        assert res_list.status_code == 200
        items = res_list.json()["items"]
        assert len(items) == 2
        assert items[0]["current"] is True
        assert items[0]["device_label"] == "Chrome on Linux"
        assert items[1]["current"] is False
        assert items[1]["device_label"] == "Firefox on macOS"
        assert all("token" not in item for item in items)

        # Cross-user ownership enforcement: User B cannot revoke User A's session
        res_cross = client.delete(
            f"/api/v1/auth/sessions/{session_a_other_id}",
            headers=headers_b,
        )
        assert res_cross.status_code == 404

        # User A revokes own other session
        res_del = client.delete(
            f"/api/v1/auth/sessions/{session_a_other_id}",
            headers=headers_a,
        )
        assert res_del.status_code == 204

        res_after = client.get("/api/v1/auth/sessions", headers=headers_a)
        assert res_after.status_code == 200
        assert len(res_after.json()["items"]) == 1

        # Password change rejects wrong password and accepts valid password
        res_bad_pw = client.post(
            "/api/v1/auth/change-password",
            headers={**headers_a, "X-Client-Type": "web", "Origin": "http://localhost:5173"},
            json={
                "current_password": "WrongPassword!2026",
                "new_password": "NewStrongPassword!2027",
            },
        )
        assert res_bad_pw.status_code == 401

        res_good_pw = client.post(
            "/api/v1/auth/change-password",
            headers={**headers_a, "X-Client-Type": "web", "Origin": "http://localhost:5173"},
            json={
                "current_password": "StrongPassword!2026",
                "new_password": "NewStrongPassword!2027",
            },
        )
        assert res_good_pw.status_code == 200
        assert res_good_pw.json()["access_token"]
