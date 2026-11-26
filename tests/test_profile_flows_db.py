"""End-to-end Phase 1 Profile Creation integration tests against PostgreSQL 17."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import threading
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import Engine, select, text

from app.core.config import Settings
from app.core.security import create_access_token, hash_password
from app.db.session import build_sessionmaker
from app.main import create_app
from app.models.profile import UserProfile
from app.models.user import User


def _build_test_app(
    test_database_url: str,
    *,
    environment: str = "testing",
    rate_limit_enabled: bool = True,
) -> tuple[Settings, object]:
    settings = Settings(
        _env_file=None,
        ENVIRONMENT=environment,
        DATABASE_URL=test_database_url,
        JWT_SECRET_KEY="profile-integration-jwt-secret-key-at-least-32-chars",
        JWT_ISSUER="folio360",
        JWT_AUDIENCE="folio360-api",
        JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15,
        REFRESH_TOKEN_EXPIRE_DAYS=14,
        REFRESH_TOKEN_ABSOLUTE_EXPIRE_DAYS=30,
        FRONTEND_BASE_URL="http://localhost:5173",
        CORS_ORIGINS=["http://localhost:5173"],
        RESEND_API_KEY="re_profile_integration_mock_key",
        EMAIL_FROM_ADDRESS="no-reply@folio360.com",
        RATE_LIMIT_ENABLED=rate_limit_enabled,
    )
    return settings, create_app(settings=settings)


@pytest.fixture
def clean_profile_db(db_engine: Engine):
    """Clean users (and cascaded profiles/activities) before and after each test."""
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))
    yield
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))


def _create_db_user(
    db_engine: Engine,
    *,
    email: str,
    password: str = "StrongPassword!2026",
    is_active: bool = True,
    is_email_verified: bool = True,
) -> User:
    session_factory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password(password),
        is_active=is_active,
        is_email_verified=is_email_verified,
        email_verified_at=now if is_email_verified else None,
        auth_version=0,
    )
    with session_factory() as session:
        session.add(user)
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
def test_full_profile_creation_flow_and_auth_completion_integration(
    test_database_url: str,
    db_engine: Engine,
    clean_profile_db: None,
) -> None:
    """
    Verify end-to-end onboarding flow:
      - /auth/login and /auth/me start with profile_completed=false (and no DOB)
      - GET /profile/me initially returns 404 PROFILE_NOT_FOUND
      - GET /profile/slug-availability checks malformed (422), reserved, and available
      - PATCH /profile/me/slug persists slug on draft
      - PATCH /profile/me saves fields and marks profile_completed=true
      - /auth/me, /auth/login, /auth/refresh, /auth/change-password expose profile_completed=true
      - Completed profile cannot be reverted to profile_completed=false
      - Activities can be updated cleanly and avatar upload routes remain absent
    """
    settings, app = _build_test_app(test_database_url, rate_limit_enabled=False)
    user = _create_db_user(db_engine, email="onboard.user@example.com")

    with TestClient(app) as client:  # type: ignore[arg-type]
        # 1. Login exposes profile_completed=false and excludes date_of_birth
        login_resp = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "onboard.user@example.com", "password": "StrongPassword!2026"},
        )
        assert login_resp.status_code == 200
        login_data = login_resp.json()
        assert login_data["user"]["profile_completed"] is False
        assert "date_of_birth" not in login_data["user"]
        headers = {"Authorization": f"Bearer {login_data['access_token']}"}
        refresh_tok = login_data["refresh_token"]

        # 2. /auth/me shows profile_completed=false
        me_before = client.get("/api/v1/auth/me", headers=headers)
        assert me_before.status_code == 200
        assert me_before.json()["profile_completed"] is False
        assert "date_of_birth" not in me_before.json()

        # 3. GET /profile/me returns 404 PROFILE_NOT_FOUND before profile creation
        prof_404 = client.get("/api/v1/profile/me", headers=headers)
        assert prof_404.status_code == 404
        assert prof_404.json()["error"]["code"] == "PROFILE_NOT_FOUND"
        assert prof_404.json()["error"]["details"] is None

        # 4. Slug availability checks
        bad_avail = client.get(
            "/api/v1/profile/slug-availability",
            params={"slug": "bad.slug"},
            headers=headers,
        )
        assert bad_avail.status_code == 422
        assert bad_avail.json()["error"]["code"] == "VALIDATION_ERROR"
        assert bad_avail.json()["error"]["details"] is None

        reserved_avail = client.get(
            "/api/v1/profile/slug-availability",
            params={"slug": "workspace"},
            headers=headers,
        )
        assert reserved_avail.status_code == 200
        assert reserved_avail.json() == {
            "slug": "workspace",
            "available": False,
            "reason": "reserved",
        }

        ok_avail = client.get(
            "/api/v1/profile/slug-availability",
            params={"slug": "  Prajwal_01 "},
            headers=headers,
        )
        assert ok_avail.status_code == 200
        assert ok_avail.json() == {
            "slug": "prajwal_01",
            "available": True,
            "reason": None,
        }

        # 5. Claim slug via PATCH /profile/me/slug
        slug_resp = client.patch(
            "/api/v1/profile/me/slug",
            headers=headers,
            json={"slug": "  Prajwal_01 "},
        )
        assert slug_resp.status_code == 200
        slug_body = slug_resp.json()
        assert slug_body["slug"] == "prajwal_01"
        assert slug_body["profile_completed"] is False
        assert slug_body["profile_completed_at"] is None

        # Self-owned slug remains available=true for current user
        self_avail = client.get(
            "/api/v1/profile/slug-availability",
            params={"slug": "prajwal_01"},
            headers=headers,
        )
        assert self_avail.status_code == 200
        assert self_avail.json()["available"] is True

        # Cannot complete profile without full_name and date_of_birth
        incomplete_err = client.patch(
            "/api/v1/profile/me",
            headers=headers,
            json={"profile_completed": True},
        )
        assert incomplete_err.status_code == 422
        assert incomplete_err.json()["error"]["code"] == "VALIDATION_ERROR"
        assert incomplete_err.json()["error"]["details"] == {
            "missing_fields": ["full name", "date of birth"]
        }

        # 6. Complete profile via PATCH /profile/me
        many_interests = [f"Skill {i}" for i in range(30)] + ["skill 0"]
        complete_resp = client.patch(
            "/api/v1/profile/me",
            headers=headers,
            json={
                "full_name": "  Prajwal Vasista  ",
                "date_of_birth": "1895-05-03",
                "bio": "  Building Folio360  ",
                "avatar_url": "https://cdn.example.com/u/prajwal.png",
                "interests": many_interests,
                "current_activities": [
                    {"key": "studying", "description": "B.E. Computer Science"},
                    {"key": "building_project", "description": "Folio360"},
                    {"key": "learning_skills"},
                    {
                        "key": "other",
                        "label": "Open Source Maintainer",
                        "description": "Python ecosystem",
                    },
                ],
                "profile_completed": True,
            },
        )
        assert complete_resp.status_code == 200
        prof = complete_resp.json()
        assert prof["slug"] == "prajwal_01"
        assert prof["full_name"] == "Prajwal Vasista"
        assert prof["date_of_birth"] == "1895-05-03"
        assert prof["bio"] == "Building Folio360"
        assert prof["avatar_url"] == "https://cdn.example.com/u/prajwal.png"
        assert "profile_picture_url" not in prof
        assert len(prof["interests"]) == 30
        assert prof["current_activities"] == [
            {"key": "studying", "label": None, "description": "B.E. Computer Science"},
            {"key": "building_project", "label": None, "description": "Folio360"},
            {"key": "learning_skills", "label": None, "description": None},
            {
                "key": "other",
                "label": "Open Source Maintainer",
                "description": "Python ecosystem",
            },
        ]
        assert prof["profile_completed"] is True
        assert prof["profile_completed_at"] is not None

        # 7. GET /profile/me returns completed profile
        get_prof = client.get("/api/v1/profile/me", headers=headers)
        assert get_prof.status_code == 200
        assert get_prof.json()["slug"] == "prajwal_01"
        assert get_prof.json()["date_of_birth"] == "1895-05-03"

        # 8. /auth/me, /auth/refresh, /auth/login, /auth/change-password now expose profile_completed=true and NO DOB
        me_after = client.get("/api/v1/auth/me", headers=headers)
        assert me_after.status_code == 200
        assert me_after.json()["profile_completed"] is True
        assert "date_of_birth" not in me_after.json()

        refresh_resp = client.post(
            "/api/v1/auth/refresh",
            headers={"X-Client-Type": "mobile"},
            json={"refresh_token": refresh_tok},
        )
        assert refresh_resp.status_code == 200
        assert refresh_resp.json()["user"]["profile_completed"] is True
        assert "date_of_birth" not in refresh_resp.json()["user"]

        login_after = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "onboard.user@example.com", "password": "StrongPassword!2026"},
        )
        assert login_after.status_code == 200
        assert login_after.json()["user"]["profile_completed"] is True
        assert "date_of_birth" not in login_after.json()["user"]

        cp_resp = client.post(
            "/api/v1/auth/change-password",
            headers={
                "X-Client-Type": "mobile",
                "Authorization": f"Bearer {login_after.json()['access_token']}",
            },
            json={
                "current_password": "StrongPassword!2026",
                "new_password": "UpdatedStrongPassword!2026",
            },
        )
        assert cp_resp.status_code == 200
        assert cp_resp.json()["user"]["profile_completed"] is True
        assert "date_of_birth" not in cp_resp.json()["user"]

        new_headers = {"Authorization": f"Bearer {cp_resp.json()['access_token']}"}

        # 9. Partial update replaces activities, clears bio/avatar_url, and updates slug
        patch_resp = client.patch(
            "/api/v1/profile/me",
            headers=new_headers,
            json={
                "bio": "",
                "avatar_url": None,
                "current_activities": [
                    {"key": "working", "description": "Software Engineer"}
                ],
            },
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["bio"] is None
        assert patch_resp.json()["avatar_url"] is None
        assert patch_resp.json()["current_activities"] == [
            {"key": "working", "label": None, "description": "Software Engineer"}
        ]

        reslug_resp = client.patch(
            "/api/v1/profile/me/slug",
            headers=new_headers,
            json={"slug": "prajwal_updated"},
        )
        assert reslug_resp.status_code == 200
        assert reslug_resp.json()["slug"] == "prajwal_updated"
        assert reslug_resp.json()["profile_completed"] is True

        # Cannot revert completed profile to False or clear required fields
        revert_resp = client.patch(
            "/api/v1/profile/me",
            headers=new_headers,
            json={"profile_completed": False},
        )
        assert revert_resp.status_code == 422
        assert revert_resp.json()["error"]["code"] == "VALIDATION_ERROR"
        assert revert_resp.json()["error"]["details"] is None

        clear_name_resp = client.patch(
            "/api/v1/profile/me",
            headers=new_headers,
            json={"full_name": None},
        )
        assert clear_name_resp.status_code == 422
        assert clear_name_resp.json()["error"]["code"] == "VALIDATION_ERROR"
        assert clear_name_resp.json()["error"]["details"] is None

        # Avatar upload/removal endpoints remain deferred (not implemented)
        assert client.post("/api/v1/profile/me/avatar", headers=new_headers).status_code in {404, 405}
        assert client.delete("/api/v1/profile/me/avatar", headers=new_headers).status_code in {404, 405}


@pytest.mark.db
def test_slug_collision_returns_top_level_slug_taken_and_handles_concurrency(
    test_database_url: str,
    db_engine: Engine,
    clean_profile_db: None,
) -> None:
    """Verify 409 error.code == 'SLUG_TAKEN' at top level and concurrent slug claim serialization."""
    settings, app = _build_test_app(test_database_url, rate_limit_enabled=False)
    user_a = _create_db_user(db_engine, email="slug.a@example.com")
    user_b = _create_db_user(db_engine, email="slug.b@example.com")
    user_c = _create_db_user(db_engine, email="slug.c@example.com")

    headers_a = _auth_headers(user_a, settings)
    headers_b = _auth_headers(user_b, settings)
    headers_c = _auth_headers(user_c, settings)

    with TestClient(app) as client:  # type: ignore[arg-type]
        r_a = client.patch(
            "/api/v1/profile/me/slug",
            headers=headers_a,
            json={"slug": "shared_handle"},
        )
        assert r_a.status_code == 200

        # User B checks availability -> available=false, reason=taken
        avail_b = client.get(
            "/api/v1/profile/slug-availability",
            params={"slug": "SHARED_HANDLE"},
            headers=headers_b,
        )
        assert avail_b.status_code == 200
        assert avail_b.json() == {
            "slug": "shared_handle",
            "available": False,
            "reason": "taken",
        }

        # User B attempts to claim -> 409 with top-level error.code == "SLUG_TAKEN"
        r_b = client.patch(
            "/api/v1/profile/me/slug",
            headers=headers_b,
            json={"slug": "SHARED_HANDLE"},
        )
        assert r_b.status_code == 409
        err = r_b.json()["error"]
        assert err["code"] == "SLUG_TAKEN"
        assert err["status_code"] == 409
        assert err["details"] is None

    # Concurrent race between User B and User C for the same fresh slug
    barrier = threading.Barrier(2)

    def _claim(hdrs: dict[str, str]) -> tuple[int, dict]:
        with TestClient(app) as c:  # type: ignore[arg-type]
            barrier.wait(timeout=5)
            resp = c.patch(
                "/api/v1/profile/me/slug",
                headers=hdrs,
                json={"slug": "raced_slug"},
            )
            return resp.status_code, resp.json()

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_b = pool.submit(_claim, headers_b)
        f_c = pool.submit(_claim, headers_c)
        res_b = f_b.result(timeout=10)
        res_c = f_c.result(timeout=10)

    statuses = sorted([res_b[0], res_c[0]])
    assert statuses == [200, 409]
    loser_body = res_b[1] if res_b[0] == 409 else res_c[1]
    assert loser_body["error"]["code"] == "SLUG_TAKEN"
    assert loser_body["error"]["details"] is None


@pytest.mark.db
def test_profile_authorization_isolation_production_avatar_and_rate_limits(
    test_database_url: str,
    db_engine: Engine,
    clean_profile_db: None,
) -> None:
    """Verify unauthenticated/inactive/unverified blocks, cross-user isolation, prod URL rule, and 429."""
    settings, app = _build_test_app(
        test_database_url,
        environment="testing",
        rate_limit_enabled=True,
    )
    unverified = _create_db_user(
        db_engine,
        email="unverified.prof@example.com",
        is_email_verified=False,
    )
    inactive = _create_db_user(
        db_engine,
        email="inactive.prof@example.com",
        is_active=False,
        is_email_verified=True,
    )
    owner = _create_db_user(db_engine, email="owner.prof@example.com")
    other = _create_db_user(db_engine, email="other.prof@example.com")

    unverified_hdrs = _auth_headers(unverified, settings)
    inactive_hdrs = _auth_headers(inactive, settings)
    owner_hdrs = _auth_headers(owner, settings)
    other_hdrs = _auth_headers(other, settings)

    with TestClient(app) as client:  # type: ignore[arg-type]
        # Unauthenticated -> 401
        assert client.get("/api/v1/profile/me").status_code == 401
        assert client.patch("/api/v1/profile/me/slug", json={"slug": "abc"}).status_code == 401
        assert client.patch("/api/v1/profile/me", json={"bio": "hi"}).status_code == 401
        assert client.get("/api/v1/profile/slug-availability?slug=abc").status_code == 401

        # Inactive -> 403 ACCOUNT_INACTIVE
        r_inact = client.get("/api/v1/profile/me", headers=inactive_hdrs)
        assert r_inact.status_code == 403
        assert r_inact.json()["error"]["details"]["code"] == "ACCOUNT_INACTIVE"

        # Unverified email -> 403 EMAIL_NOT_VERIFIED
        for method, path, kwargs in (
            ("GET", "/api/v1/profile/me", {}),
            ("GET", "/api/v1/profile/slug-availability?slug=valid_name", {}),
            ("PATCH", "/api/v1/profile/me/slug", {"json": {"slug": "valid_name"}}),
            ("PATCH", "/api/v1/profile/me", {"json": {"bio": "hi"}}),
        ):
            r_unver = client.request(method, path, headers=unverified_hdrs, **kwargs)
            assert r_unver.status_code == 403
            assert r_unver.json()["error"]["details"]["code"] == "EMAIL_NOT_VERIFIED"

        # Production rejects http://localhost avatar URLs (requires https://)
        from app.schemas.profile import ProfileUpdateRequest
        from app.services import profile_service
        from app.core.exceptions import ValidationAppError

        prod_settings = Settings(
            _env_file=None,
            ENVIRONMENT="production",
            DATABASE_URL=test_database_url,
            JWT_SECRET_KEY="profile-prod-jwt-secret-key-at-least-32-chars",
            FRONTEND_BASE_URL="https://app.folio360.com",
            BACKEND_BASE_URL="https://api.folio360.com",
            RESEND_API_KEY="re_prod_mock_key",
            EMAIL_FROM_ADDRESS="no-reply@folio360.com",
            CORS_ORIGINS=["https://app.folio360.com"],
            REFRESH_COOKIE_SECURE=True,
        )
        session_factory = build_sessionmaker(db_engine)
        with session_factory() as s:
            with pytest.raises(ValidationAppError):
                profile_service.update_profile(
                    s,
                    user_id=owner.id,
                    payload=ProfileUpdateRequest(
                        avatar_url="http://localhost:5173/avatar.png"
                    ),
                    settings=prod_settings,
                )

        # Owner saves profile; Other user cannot read or overwrite Owner's profile
        assert (
            client.patch(
                "/api/v1/profile/me/slug",
                headers=owner_hdrs,
                json={"slug": "owner_slug"},
            ).status_code
            == 200
        )
        assert (
            client.patch(
                "/api/v1/profile/me",
                headers=owner_hdrs,
                json={"full_name": "Owner Private"},
            ).status_code
            == 200
        )
        other_get = client.get("/api/v1/profile/me", headers=other_hdrs)
        assert other_get.status_code == 404

        # Rate limit on slug-availability (60/15m/IP)
        app.state.rate_limiter.clear()  # type: ignore[attr-defined]
        for idx in range(60):
            r_ok = client.get(
                "/api/v1/profile/slug-availability",
                params={"slug": f"avail_{idx}"},
                headers=owner_hdrs,
            )
            assert r_ok.status_code == 200
        r_429 = client.get(
            "/api/v1/profile/slug-availability",
            params={"slug": "avail_overflow"},
            headers=owner_hdrs,
        )
        assert r_429.status_code == 429
        assert r_429.json()["error"]["details"]["code"] == "RATE_LIMIT_EXCEEDED"
        assert "retry-after" in {k.lower() for k in r_429.headers.keys()}

        # Revoking JWT via logout-all invalidates access to /profile/me
        assert (
            client.post("/api/v1/auth/logout-all", headers=owner_hdrs).status_code
            == 200
        )
        assert client.get("/api/v1/profile/me", headers=owner_hdrs).status_code == 401


@pytest.mark.db
def test_oauth_exchange_returns_profile_completed_false_then_true_without_dob(
    test_database_url: str,
    db_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify real /auth/oauth/exchange DB flow exposes profile_completed (false -> true) without DOB."""
    import base64
    import hashlib
    import secrets
    from urllib.parse import parse_qs, urlsplit

    from app.services import oauth_service
    from app.services.oauth_providers import GoogleIdentity

    def _clean_oauth_tables() -> None:
        with db_engine.begin() as conn:
            conn.execute(text("DELETE FROM oauth_exchange_codes"))
            conn.execute(text("DELETE FROM oauth_accounts"))
            conn.execute(text("DELETE FROM oauth_states"))
            conn.execute(text("DELETE FROM refresh_sessions"))
            conn.execute(text("DELETE FROM users"))

    _clean_oauth_tables()
    try:
        settings = Settings(
            _env_file=None,
            ENVIRONMENT="testing",
            DATABASE_URL=test_database_url,
            JWT_SECRET_KEY="profile-oauth-integration-jwt-secret-key-32",
            OAUTH_PKCE_ENCRYPTION_KEY=secrets.token_urlsafe(32),
            GOOGLE_CLIENT_ID="google-client-profile-db",
            GOOGLE_CLIENT_SECRET="google-secret-profile-db",
            CORS_ORIGINS=["http://localhost:5173"],
            OAUTH_ALLOWED_WEB_REDIRECT_URIS=["http://localhost:5173/auth/oauth/callback"],
            OAUTH_ALLOWED_MOBILE_REDIRECT_URIS=["folio360://auth/callback"],
            RATE_LIMIT_ENABLED=False,
        )
        app = create_app(settings=settings)

        monkeypatch.setattr(
            oauth_service,
            "exchange_google_authorization_code",
            lambda db, **kw: "mock-google-id-token",
        )
        monkeypatch.setattr(
            oauth_service,
            "verify_google_id_token",
            lambda db, **kw: GoogleIdentity(
                "google-profile-sub-1",
                "oauth.profile@example.com",
                True,
            ),
        )

        def _run_web_oauth_exchange(client: TestClient) -> dict:
            verifier = secrets.token_urlsafe(40)
            challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("utf-8")).digest())
                .rstrip(b"=")
                .decode("ascii")
            )
            r_start = client.get(
                "/api/v1/auth/oauth/google/start",
                params={
                    "client_type": "web",
                    "redirect_uri": "http://localhost:5173/auth/oauth/callback",
                    "exchange_code_challenge": challenge,
                    "exchange_code_challenge_method": "S256",
                },
                follow_redirects=False,
            )
            assert r_start.status_code == 302
            state_val = parse_qs(urlsplit(r_start.headers["location"]).query)["state"][0]

            r_cb = client.get(
                "/api/v1/auth/oauth/google/callback",
                params={"state": state_val, "code": "google-auth-code"},
                follow_redirects=False,
            )
            assert r_cb.status_code == 302
            ex_code = parse_qs(urlsplit(r_cb.headers["location"]).query)["code"][0]

            r_ex = client.post(
                "/api/v1/auth/oauth/exchange",
                headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
                json={"code": ex_code, "exchange_code_verifier": verifier},
            )
            assert r_ex.status_code == 200
            return r_ex.json()

        with TestClient(app) as client:
            # 1. First OAuth sign-in: profile_completed is False and DOB is absent
            first_exchange = _run_web_oauth_exchange(client)
            assert first_exchange["user"]["email"] == "oauth.profile@example.com"
            assert first_exchange["user"]["profile_completed"] is False
            assert "date_of_birth" not in first_exchange["user"]

            headers = {"Authorization": f"Bearer {first_exchange['access_token']}"}

            # 2. Complete profile including multi-line bio and activity description
            assert (
                client.patch(
                    "/api/v1/profile/me/slug",
                    headers=headers,
                    json={"slug": "oauth_learner"},
                ).status_code
                == 200
            )
            r_complete = client.patch(
                "/api/v1/profile/me",
                headers=headers,
                json={
                    "full_name": "OAuth Learner",
                    "date_of_birth": "2002-08-15",
                    "bio": "Line one\r\nLine two",
                    "current_activities": [
                        {
                            "key": "studying",
                            "description": "Year 3\r\nComputer Science",
                        }
                    ],
                    "profile_completed": True,
                },
            )
            assert r_complete.status_code == 200
            assert r_complete.json()["bio"] == "Line one\nLine two"
            assert r_complete.json()["current_activities"] == [
                {
                    "key": "studying",
                    "label": None,
                    "description": "Year 3\nComputer Science",
                }
            ]

            # 3. Second OAuth sign-in: profile_completed is True and DOB remains absent
            second_exchange = _run_web_oauth_exchange(client)
            assert second_exchange["user"]["profile_completed"] is True
            assert "date_of_birth" not in second_exchange["user"]
    finally:
        _clean_oauth_tables()
