"""End-to-end Stage 3C.6 HTTP + PostgreSQL 17 integration tests (REV12)."""

import base64
from datetime import datetime, timezone
import hashlib
import secrets
from typing import Any
from urllib.parse import parse_qs, urlsplit
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import Engine, select, text

from app.core.config import Settings
from app.main import create_app
from app.models.oauth import OAuthAccount
from app.models.user import User
from app.services import oauth_service
from app.services.oauth_providers import GitHubUser, GoogleIdentity

pytestmark = pytest.mark.db

PRIMARY_KEY = secrets.token_urlsafe(32)


def _settings(test_database_url: str, **overrides: Any) -> Settings:
    params: dict[str, Any] = {
        "_env_file": None,
        "ENVIRONMENT": "testing",
        "DATABASE_URL": test_database_url,
        "JWT_SECRET_KEY": "stage3c6-db-jwt-secret-key-at-least-32-chars",
        "OAUTH_PKCE_ENCRYPTION_KEY": PRIMARY_KEY,
        "GOOGLE_CLIENT_ID": "google-client-3c6-db",
        "GOOGLE_CLIENT_SECRET": "google-secret-3c6-db",
        "GITHUB_CLIENT_ID": "github-client-3c6-db",
        "GITHUB_CLIENT_SECRET": "github-secret-3c6-db",
        "CORS_ORIGINS": ["http://localhost:5173"],
        "OAUTH_ALLOWED_WEB_REDIRECT_URIS": ["http://localhost:5173/auth/oauth/callback"],
        "OAUTH_ALLOWED_MOBILE_REDIRECT_URIS": ["folio360://auth/callback"],
        "RATE_LIMIT_ENABLED": True,
    }
    params.update(overrides)
    return Settings(**params)


def _exchange_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(40)
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


@pytest.fixture
def clean_oauth_http_db(db_engine: Engine):
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM oauth_exchange_codes"))
        conn.execute(text("DELETE FROM oauth_accounts"))
        conn.execute(text("DELETE FROM oauth_states"))
        conn.execute(text("DELETE FROM refresh_sessions"))
        conn.execute(text("DELETE FROM users"))
    yield
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM oauth_exchange_codes"))
        conn.execute(text("DELETE FROM oauth_accounts"))
        conn.execute(text("DELETE FROM oauth_states"))
        conn.execute(text("DELETE FROM refresh_sessions"))
        conn.execute(text("DELETE FROM users"))


def test_e2e_web_google_oauth_flow_exchange_refresh_and_me(
    test_database_url: str,
    db_engine: Engine,
    clean_oauth_http_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = _settings(test_database_url)
    app = create_app(settings=cfg)
    verifier, challenge = _exchange_pair()

    monkeypatch.setattr(
        oauth_service,
        "exchange_google_authorization_code",
        lambda db, **kw: "mock-google-id-token",
    )
    monkeypatch.setattr(
        oauth_service,
        "verify_google_id_token",
        lambda db, **kw: GoogleIdentity("google-e2e-sub-1", "e2e.web@example.com", True),
    )

    with TestClient(app) as client:
        # 1. /start -> 302 Google + folio360_oauth_binding cookie
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
        binding_cookie = client.cookies.get(cfg.OAUTH_BINDING_COOKIE_NAME)
        assert binding_cookie

        # 2. /callback -> 302 frontend?code=... + clears binding cookie + sets exchange cookie
        r_cb = client.get(
            "/api/v1/auth/oauth/google/callback",
            params={"state": state_val, "code": "google-auth-code"},
            follow_redirects=False,
        )
        assert r_cb.status_code == 302
        cb_loc = r_cb.headers["location"]
        ex_code = parse_qs(urlsplit(cb_loc).query)["code"][0]
        assert any(
            h.startswith(f"{cfg.OAUTH_BINDING_COOKIE_NAME}=") and "Max-Age=0" in h
            for h in r_cb.headers.get_list("set-cookie")
        )
        assert client.cookies.get(cfg.OAUTH_EXCHANGE_COOKIE_NAME)

        # 3. /exchange -> 200 WebAuthTokenResponse + clears exchange cookie + sets refresh cookie
        r_ex = client.post(
            "/api/v1/auth/oauth/exchange",
            headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
            json={"code": ex_code, "exchange_code_verifier": verifier},
        )
        assert r_ex.status_code == 200
        data = r_ex.json()
        assert "refresh_token" not in data
        assert data["user"]["email"] == "e2e.web@example.com"
        assert data["user"]["has_password"] is False
        access_token = data["access_token"]
        assert client.cookies.get(cfg.REFRESH_COOKIE_NAME)

        # 4. Replay of single-use exchange code -> 400
        r_replay = client.post(
            "/api/v1/auth/oauth/exchange",
            headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
            json={"code": ex_code, "exchange_code_verifier": verifier},
        )
        assert r_replay.status_code == 400
        assert r_replay.json()["error"]["details"] == {"code": "INVALID_OAUTH_EXCHANGE_CODE"}

        # 5. /me includes sorted oauth_providers=["google"]
        r_me = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert r_me.status_code == 200
        assert r_me.json()["oauth_providers"] == ["google"]

        # 6. Issued web refresh cookie works on /auth/refresh
        r_ref = client.post(
            "/api/v1/auth/refresh",
            headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
        )
        assert r_ref.status_code == 200


def test_e2e_mobile_github_zero_cookies_sorted_providers_and_tx_guard_http_500(
    test_database_url: str,
    db_engine: Engine,
    clean_oauth_http_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = _settings(test_database_url)
    app = create_app(settings=cfg)
    verifier, challenge = _exchange_pair()

    monkeypatch.setattr(
        oauth_service,
        "exchange_github_authorization_code",
        lambda db, **kw: "gh-tok-e2e",
    )
    monkeypatch.setattr(
        oauth_service,
        "fetch_github_user",
        lambda db, **kw: GitHubUser("gh-e2e-42"),
    )
    monkeypatch.setattr(
        oauth_service,
        "fetch_github_verified_email",
        lambda db, **kw: "e2e.mobile@example.com",
    )

    with TestClient(app) as client:
        r_start = client.get(
            "/api/v1/auth/oauth/github/start",
            params={
                "client_type": "mobile",
                "redirect_uri": "folio360://auth/callback",
                "exchange_code_challenge": challenge,
                "exchange_code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert r_start.status_code == 302
        assert r_start.headers.get_list("set-cookie") == []
        state_val = parse_qs(urlsplit(r_start.headers["location"]).query)["state"][0]

        r_cb = client.get(
            "/api/v1/auth/oauth/github/callback",
            params={"state": state_val, "code": "gh-code"},
            follow_redirects=False,
        )
        assert r_cb.status_code == 302
        assert r_cb.headers.get_list("set-cookie") == []
        ex_code = parse_qs(urlsplit(r_cb.headers["location"]).query)["code"][0]

        r_ex = client.post(
            "/api/v1/auth/oauth/exchange",
            headers={"X-Client-Type": "mobile"},
            json={"code": ex_code, "exchange_code_verifier": verifier},
        )
        assert r_ex.status_code == 200
        assert r_ex.headers.get_list("set-cookie") == []
        access_token = r_ex.json()["access_token"]
        assert r_ex.json()["refresh_token"]

        # Link second provider in DB to confirm sorted ["github", "google"] on /me
        with db_engine.begin() as conn:
            uid = conn.execute(
                select(User.id).where(User.email == "e2e.mobile@example.com")
            ).scalar_one()
            conn.execute(
                OAuthAccount.__table__.insert().values(
                    id=uuid.uuid4(),
                    user_id=uid,
                    provider="google",
                    provider_user_id="linked-google-sub",
                    provider_email="e2e.mobile@example.com",
                    provider_email_verified=True,
                )
            )

        r_me = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert r_me.status_code == 200
        assert r_me.json()["oauth_providers"] == ["github", "google"]

        # Real DB transaction-guard violation -> HTTP 500 JSON with OAuth headers + CORS + cleared binding cookie
        _, ch_guard = _exchange_pair()
        r_s2 = client.get(
            "/api/v1/auth/oauth/github/start",
            params={
                "client_type": "web",
                "redirect_uri": "http://localhost:5173/auth/oauth/callback",
                "exchange_code_challenge": ch_guard,
            },
            follow_redirects=False,
        )
        assert r_s2.status_code == 302
        st2 = parse_qs(urlsplit(r_s2.headers["location"]).query)["state"][0]

        def _open_tx_before_guard(db: Any, **kw: Any) -> str:
            db.execute(select(User.id).limit(1)).all()  # triggers SQLAlchemy autobegin
            assert db.in_transaction() is True
            from app.services.oauth_providers import ensure_no_open_db_transaction

            ensure_no_open_db_transaction(db)
            return "unreachable"

        monkeypatch.setattr(oauth_service, "exchange_github_authorization_code", _open_tx_before_guard)

        r_guard = client.get(
            "/api/v1/auth/oauth/github/callback",
            params={"state": st2, "code": "gh-guard"},
            headers={"Origin": "http://localhost:5173"},
            follow_redirects=False,
        )
        assert r_guard.status_code == 500
        assert r_guard.json() == {
            "error": {
                "message": "Internal server error",
                "status_code": 500,
                "details": None,
            }
        }
        assert r_guard.headers.get("cache-control") == "no-store"
        assert r_guard.headers.get("pragma") == "no-cache"
        assert r_guard.headers.get("referrer-policy") == "no-referrer"
        assert r_guard.headers.get("access-control-allow-origin") == "http://localhost:5173"
        assert any(
            h.startswith(f"{cfg.OAUTH_BINDING_COOKIE_NAME}=") and "Max-Age=0" in h
            for h in r_guard.headers.get_list("set-cookie")
        )
        assert client.cookies.get(cfg.OAUTH_EXCHANGE_COOKIE_NAME) is None
