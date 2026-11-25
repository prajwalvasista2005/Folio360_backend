"""Stage 3C.7 Final End-to-End PostgreSQL Security & Compatibility Tests (REV12)."""

import base64
import hashlib
import secrets
from typing import Any
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import Engine, select, text

from app.core.config import Settings
from app.core.security import PKCE_VERIFIER_CONSUMED_MARKER, hash_opaque_token
from app.main import create_app
from app.models.oauth import OAuthAccount, OAuthExchangeCode, OAuthState
from app.models.password_reset_token import PasswordResetToken
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.services import email_service as email_service_module
from app.services import oauth_service
from app.services.oauth_providers import (
    GitHubUser,
    GitHubVerifiedEmailRequiredError,
    GoogleIdentity,
)
from tests.conftest import verify_test_database_identity

pytestmark = pytest.mark.db

PRIMARY_KEY = secrets.token_urlsafe(32)


def _settings(test_database_url: str, **overrides: Any) -> Settings:
    params: dict[str, Any] = {
        "_env_file": None,
        "ENVIRONMENT": "testing",
        "DATABASE_URL": test_database_url,
        "JWT_SECRET_KEY": "stage3c7-e2e-jwt-secret-key-at-least-32-chars",
        "OAUTH_PKCE_ENCRYPTION_KEY": PRIMARY_KEY,
        "GOOGLE_CLIENT_ID": "google-client-3c7-db",
        "GOOGLE_CLIENT_SECRET": "google-secret-3c7-db",
        "GITHUB_CLIENT_ID": "github-client-3c7-db",
        "GITHUB_CLIENT_SECRET": "github-secret-3c7-db",
        "CORS_ORIGINS": ["http://localhost:5173"],
        "OAUTH_ALLOWED_WEB_REDIRECT_URIS": ["http://localhost:5173/auth/oauth/callback"],
        "OAUTH_ALLOWED_MOBILE_REDIRECT_URIS": ["folio360://auth/callback"],
        "RESEND_API_KEY": "re_test_key_3c7_placeholder",
        "EMAIL_FROM_ADDRESS": "no-reply@folio360.local",
        "RATE_LIMIT_ENABLED": False,
    }
    params.update(overrides)
    return Settings(**params)


def _exchange_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(40)
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


@pytest.fixture
def clean_oauth_e2e_db(test_database_url: str, db_engine: Engine):
    verify_test_database_identity(test_database_url, engine=db_engine, allow_migrator=False)
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM password_reset_tokens"))
        conn.execute(text("DELETE FROM email_verification_tokens"))
        conn.execute(text("DELETE FROM oauth_exchange_codes"))
        conn.execute(text("DELETE FROM oauth_accounts"))
        conn.execute(text("DELETE FROM oauth_states"))
        conn.execute(text("DELETE FROM refresh_sessions"))
        conn.execute(text("DELETE FROM users"))
    yield
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM password_reset_tokens"))
        conn.execute(text("DELETE FROM email_verification_tokens"))
        conn.execute(text("DELETE FROM oauth_exchange_codes"))
        conn.execute(text("DELETE FROM oauth_accounts"))
        conn.execute(text("DELETE FROM oauth_states"))
        conn.execute(text("DELETE FROM refresh_sessions"))
        conn.execute(text("DELETE FROM users"))


def _complete_oauth_login(
    client: TestClient,
    *,
    provider: str,
    client_type: str,
    redirect_uri: str,
    origin: str | None = None,
) -> dict[str, Any]:
    verifier, challenge = _exchange_pair()
    r_start = client.get(
        f"/api/v1/auth/oauth/{provider}/start",
        params={
            "client_type": client_type,
            "redirect_uri": redirect_uri,
            "exchange_code_challenge": challenge,
            "exchange_code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert r_start.status_code == 302
    state_val = parse_qs(urlsplit(r_start.headers["location"]).query)["state"][0]

    r_cb = client.get(
        f"/api/v1/auth/oauth/{provider}/callback",
        params={"state": state_val, "code": f"{provider}-auth-code"},
        follow_redirects=False,
    )
    assert r_cb.status_code == 302
    ex_code = parse_qs(urlsplit(r_cb.headers["location"]).query)["code"][0]

    headers: dict[str, str] = {"X-Client-Type": client_type}
    if origin is not None:
        headers["Origin"] = origin
    r_ex = client.post(
        "/api/v1/auth/oauth/exchange",
        headers=headers,
        json={"code": ex_code, "exchange_code_verifier": verifier},
    )
    assert r_ex.status_code == 200
    return r_ex.json()


# ---------------------------------------------------------------------------
# 1. OAuth-Only User vs. Stage 3A/3B Auth & Revocation Routes (REV12 §1, D14)
# ---------------------------------------------------------------------------


def test_oauth_only_user_compatibility_with_stage3a_3b_routes(
    test_database_url: str,
    db_engine: Engine,
    clean_oauth_e2e_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REV12 §1 L9 & D14: OAuth-only user defaults & Stage 3A/3B /login, /forgot, /reset, /change, /logout, /logout-all."""
    cfg = _settings(test_database_url)
    app = create_app(settings=cfg)

    sent_emails: list[dict[str, Any]] = []
    monkeypatch.setattr(
        email_service_module.resend.Emails,
        "send",
        lambda params, options=None: sent_emails.append(dict(params)) or {"id": "m1"},
    )
    monkeypatch.setattr(
        oauth_service,
        "exchange_google_authorization_code",
        lambda db, **kw: "mock-id-token",
    )
    monkeypatch.setattr(
        oauth_service,
        "verify_google_id_token",
        lambda db, **kw: GoogleIdentity("sub-oauth-only-3c7", "oauth.only@example.com", True),
    )

    with TestClient(app) as client:
        # Provision OAuth-only user on mobile channel
        tok_1 = _complete_oauth_login(
            client,
            provider="google",
            client_type="mobile",
            redirect_uri="folio360://auth/callback",
        )
        access_1 = tok_1["access_token"]
        refresh_1 = tok_1["refresh_token"]

        with db_engine.connect() as conn:
            u = conn.execute(
                select(User).where(User.email == "oauth.only@example.com")
            ).mappings().one()
            assert u["password_hash"] is None
            assert u["is_email_verified"] is True
            assert u["email_verified_at"] is not None
            assert u["is_active"] is True
            assert u["auth_version"] == 0
            assert u["password_changed_at"] is None

        # 1. /login -> 401 INVALID_CREDENTIALS
        r_login = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "oauth.only@example.com", "password": "SomePassword!2026"},
        )
        assert r_login.status_code == 401
        assert r_login.json()["error"]["details"] == {"code": "INVALID_CREDENTIALS"}

        # 2. /forgot-password -> 202 no-op (zero email sent, zero PasswordResetToken created)
        r_forgot = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "oauth.only@example.com"},
        )
        assert r_forgot.status_code == 202
        assert sent_emails == []
        with db_engine.connect() as conn:
            assert conn.execute(select(PasswordResetToken)).all() == []

        # 3. /reset-password -> 400 INVALID_RESET_TOKEN
        r_reset = client.post(
            "/api/v1/auth/reset-password",
            json={"token": "nonexistent-reset-token", "new_password": "NewStrongPassword!2026"},
        )
        assert r_reset.status_code == 400
        assert r_reset.json()["error"]["details"] == {"code": "INVALID_RESET_TOKEN"}

        # 4. /change-password -> 400 PASSWORD_NOT_SET
        r_change = client.post(
            "/api/v1/auth/change-password",
            headers={
                "Authorization": f"Bearer {access_1}",
                "X-Client-Type": "mobile",
            },
            json={
                "current_password": "OldPassword!2026",
                "new_password": "NewStrongPassword!2026",
            },
        )
        assert r_change.status_code == 400
        assert r_change.json()["error"]["details"] == {"code": "PASSWORD_NOT_SET"}

        # 5. /logout revokes refresh session cleanly
        r_logout = client.post(
            "/api/v1/auth/logout",
            headers={"X-Client-Type": "mobile"},
            json={"refresh_token": refresh_1},
        )
        assert r_logout.status_code == 200
        r_ref_after = client.post(
            "/api/v1/auth/refresh",
            headers={"X-Client-Type": "mobile"},
            json={"refresh_token": refresh_1},
        )
        assert r_ref_after.status_code == 401

        # 6. Returning OAuth sign-in + /logout-all invalidates access JWT via auth_version bump
        tok_2 = _complete_oauth_login(
            client,
            provider="google",
            client_type="mobile",
            redirect_uri="folio360://auth/callback",
        )
        access_2 = tok_2["access_token"]
        r_logout_all = client.post(
            "/api/v1/auth/logout-all",
            headers={"Authorization": f"Bearer {access_2}"},
        )
        assert r_logout_all.status_code == 200

        r_me_revoked = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {access_2}"},
        )
        assert r_me_revoked.status_code == 401
        with db_engine.connect() as conn:
            av = conn.execute(
                select(User.auth_version).where(User.email == "oauth.only@example.com")
            ).scalar_one()
            assert av == 1


# ---------------------------------------------------------------------------
# 2. HTTP-Level D05 No-Email-Auto-Merge Against Existing Password User
# ---------------------------------------------------------------------------


def test_http_d05_no_email_auto_merge_against_password_account(
    test_database_url: str,
    db_engine: Engine,
    clean_oauth_e2e_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REV12 §1 D05: Google OAuth HTTP flow never auto-merges into existing password user."""
    cfg = _settings(test_database_url)
    app = create_app(settings=cfg)

    sent_emails: list[dict[str, Any]] = []
    monkeypatch.setattr(
        email_service_module.resend.Emails,
        "send",
        lambda params, options=None: sent_emails.append(dict(params)) or {"id": "m2"},
    )
    monkeypatch.setattr(
        oauth_service,
        "exchange_google_authorization_code",
        lambda db, **kw: "mock-id-tok",
    )
    monkeypatch.setattr(
        oauth_service,
        "verify_google_id_token",
        lambda db, **kw: GoogleIdentity("sub-d05-collision", "alice.d05@example.com", True),
    )

    with TestClient(app) as client:
        r_reg = client.post(
            "/api/v1/auth/register",
            json={"email": "alice.d05@example.com", "password": "StrongPassword!2026"},
        )
        assert r_reg.status_code == 201
        verify_url = [
            line.strip()
            for line in sent_emails[0]["text"].splitlines()
            if "/verify-email?token=" in line
        ][0]
        verify_tok = parse_qs(urlsplit(verify_url).query)["token"][0]
        assert client.post("/api/v1/auth/verify-email", json={"token": verify_tok}).status_code == 200

        _, ch = _exchange_pair()
        r_start = client.get(
            "/api/v1/auth/oauth/google/start",
            params={
                "client_type": "mobile",
                "redirect_uri": "folio360://auth/callback",
                "exchange_code_challenge": ch,
            },
            follow_redirects=False,
        )
        assert r_start.status_code == 302
        st = parse_qs(urlsplit(r_start.headers["location"]).query)["state"][0]

        r_cb = client.get(
            "/api/v1/auth/oauth/google/callback",
            params={"state": st, "code": "google-code"},
            follow_redirects=False,
        )
        assert r_cb.status_code == 302
        assert r_cb.headers["location"] == "folio360://auth/callback?error=email_already_registered"

        # Existing password account remains intact with zero OAuth links
        r_pw = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "alice.d05@example.com", "password": "StrongPassword!2026"},
        )
        assert r_pw.status_code == 200

    with db_engine.connect() as conn:
        assert conn.execute(select(OAuthAccount)).all() == []
        assert conn.execute(select(OAuthExchangeCode)).all() == []


# ---------------------------------------------------------------------------
# 3. HTTP-Level GitHub D02 verified_email_required & D03 Returning Fast Path
# ---------------------------------------------------------------------------


def test_http_github_d02_verified_email_required_and_d03_returning_fast_path(
    test_database_url: str,
    db_engine: Engine,
    clean_oauth_e2e_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REV12 §1 D02–D03 & REV12-1: HTTP /callback rejects noreply-only new GitHub user & skips /user/emails on return."""
    cfg = _settings(test_database_url)
    app = create_app(settings=cfg)

    email_fetch_calls = 0
    monkeypatch.setattr(
        oauth_service,
        "exchange_github_authorization_code",
        lambda db, **kw: "gh-tok",
    )
    monkeypatch.setattr(
        oauth_service,
        "fetch_github_user",
        lambda db, **kw: GitHubUser(provider_user_id="gh-e2e-3c7-99"),
    )

    fail_email = {"flag": True}

    def _mock_gh_email(db: Any, **kw: Any) -> str:
        nonlocal email_fetch_calls
        email_fetch_calls += 1
        if fail_email["flag"]:
            raise GitHubVerifiedEmailRequiredError()
        return "gh.e2e@example.com"

    monkeypatch.setattr(oauth_service, "fetch_github_verified_email", _mock_gh_email)

    with TestClient(app) as client:
        # 1. D02: noreply / unverified only on first login -> verified_email_required redirect
        _, ch1 = _exchange_pair()
        r_s1 = client.get(
            "/api/v1/auth/oauth/github/start",
            params={
                "client_type": "mobile",
                "redirect_uri": "folio360://auth/callback",
                "exchange_code_challenge": ch1,
            },
            follow_redirects=False,
        )
        st1 = parse_qs(urlsplit(r_s1.headers["location"]).query)["state"][0]
        r_cb1 = client.get(
            "/api/v1/auth/oauth/github/callback",
            params={"state": st1, "code": "c1"},
            follow_redirects=False,
        )
        assert r_cb1.status_code == 302
        assert r_cb1.headers["location"] == "folio360://auth/callback?error=verified_email_required"
        assert email_fetch_calls == 1
        with db_engine.connect() as conn:
            assert conn.execute(select(User)).all() == []
            assert conn.execute(select(OAuthAccount)).all() == []

        # 2. First successful signup fetches verified email once
        fail_email["flag"] = False
        _complete_oauth_login(
            client,
            provider="github",
            client_type="mobile",
            redirect_uri="folio360://auth/callback",
        )
        assert email_fetch_calls == 2

        # 3. D03 + REV12-1 returning user skips fetch_github_verified_email completely
        _complete_oauth_login(
            client,
            provider="github",
            client_type="mobile",
            redirect_uri="folio360://auth/callback",
        )
        assert email_fetch_calls == 2


# ---------------------------------------------------------------------------
# 4. Parallel-Tab Single-Cookie Overwrite Fails Closed (REV12 §7)
# ---------------------------------------------------------------------------


def test_http_parallel_tab_single_cookie_overwrite_fails_closed(
    test_database_url: str,
    db_engine: Engine,
    clean_oauth_e2e_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REV12 §7 L125: Parallel web tabs overwriting binding or exchange cookie fail closed safely."""
    cfg = _settings(test_database_url)
    app = create_app(settings=cfg)

    monkeypatch.setattr(
        oauth_service,
        "exchange_github_authorization_code",
        lambda db, **kw: "gh-tok-tabs",
    )
    monkeypatch.setattr(
        oauth_service,
        "fetch_github_user",
        lambda db, **kw: GitHubUser(provider_user_id="gh-tabs-user"),
    )
    monkeypatch.setattr(
        oauth_service,
        "fetch_github_verified_email",
        lambda db, **kw: "tabs.user@example.com",
    )

    # Scenario A: Independent fresh flow — Tab 2 /start overwrites Tab 1 binding cookie -> Tab 1 /callback fails Order 8
    with TestClient(app) as browser_a:
        _, ch_t1 = _exchange_pair()
        r_t1_start = browser_a.get(
            "/api/v1/auth/oauth/github/start",
            params={
                "client_type": "web",
                "redirect_uri": "http://localhost:5173/auth/oauth/callback",
                "exchange_code_challenge": ch_t1,
            },
            follow_redirects=False,
        )
        st_tab1 = parse_qs(urlsplit(r_t1_start.headers["location"]).query)["state"][0]

        _, ch_t2 = _exchange_pair()
        r_t2_start = browser_a.get(
            "/api/v1/auth/oauth/github/start",
            params={
                "client_type": "web",
                "redirect_uri": "http://localhost:5173/auth/oauth/callback",
                "exchange_code_challenge": ch_t2,
            },
            follow_redirects=False,
        )
        assert r_t2_start.status_code == 302

        # Tab 1 returns with st_tab1, but browser cookie jar holds Tab 2's binding cookie
        r_t1_cb = browser_a.get(
            "/api/v1/auth/oauth/github/callback",
            params={"state": st_tab1, "code": "c-tab1"},
            follow_redirects=False,
        )
        assert r_t1_cb.status_code == 302
        assert r_t1_cb.headers["location"] == "http://localhost:5173/auth/oauth/callback?error=invalid_oauth_state"

    with db_engine.connect() as conn:
        st1_row = (
            conn.execute(
                select(OAuthState.consumed_at, OAuthState.pkce_verifier_encrypted).where(
                    OAuthState.state_hash == hash_opaque_token(st_tab1)
                )
            )
            .mappings()
            .one()
        )
        assert st1_row["consumed_at"] is not None
        assert st1_row["pkce_verifier_encrypted"] == PKCE_VERIFIER_CONSUMED_MARKER

    # Scenario B: Independent fresh flow — Tab 2 /callback overwrites Tab 1 exchange cookie -> Tab 1 /exchange burns code
    with TestClient(app) as browser_b:
        # Tab 1 /start + /callback (save its exchange code; capture binding cookie explicitly so Tab 1 completes first)
        ver1, ch1 = _exchange_pair()
        r_b1_s = browser_b.get(
            "/api/v1/auth/oauth/github/start",
            params={
                "client_type": "web",
                "redirect_uri": "http://localhost:5173/auth/oauth/callback",
                "exchange_code_challenge": ch1,
            },
            follow_redirects=False,
        )
        st_b1 = parse_qs(urlsplit(r_b1_s.headers["location"]).query)["state"][0]
        r_b1_cb = browser_b.get(
            "/api/v1/auth/oauth/github/callback",
            params={"state": st_b1, "code": "c-b1"},
            follow_redirects=False,
        )
        ex_code_1 = parse_qs(urlsplit(r_b1_cb.headers["location"]).query)["code"][0]

        # Tab 2 /start + /callback overwrites folio360_oauth_exchange in browser_b's jar
        _, ch2 = _exchange_pair()
        r_b2_s = browser_b.get(
            "/api/v1/auth/oauth/github/start",
            params={
                "client_type": "web",
                "redirect_uri": "http://localhost:5173/auth/oauth/callback",
                "exchange_code_challenge": ch2,
            },
            follow_redirects=False,
        )
        st_b2 = parse_qs(urlsplit(r_b2_s.headers["location"]).query)["state"][0]
        r_b2_cb = browser_b.get(
            "/api/v1/auth/oauth/github/callback",
            params={"state": st_b2, "code": "c-b2"},
            follow_redirects=False,
        )
        assert r_b2_cb.status_code == 302

        # Tab 1 calls /exchange with ex_code_1 while cookie jar holds Tab 2's exchange cookie -> 400 + burn
        r_b1_ex = browser_b.post(
            "/api/v1/auth/oauth/exchange",
            headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
            json={"code": ex_code_1, "exchange_code_verifier": ver1},
        )
        assert r_b1_ex.status_code == 400
        assert r_b1_ex.json()["error"]["details"] == {"code": "INVALID_OAUTH_EXCHANGE_CODE"}

    with db_engine.connect() as conn:
        consumed_at = conn.execute(
            select(OAuthExchangeCode.consumed_at).where(
                OAuthExchangeCode.code_hash == hash_opaque_token(ex_code_1)
            )
        ).scalar_one()
        assert consumed_at is not None
        assert conn.execute(select(RefreshSession)).all() == []
