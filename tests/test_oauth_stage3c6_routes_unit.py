"""Route, schema, middleware, cookie, and CSRF unit tests for Stage 3C.6 (REV12)."""

import base64
import hashlib
import secrets
from typing import Any, Generator
import uuid

from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from app.api.deps.auth import get_current_user
from app.core.config import OAUTH_EXCHANGE_CODE_EXPIRE_SECONDS, Settings
from app.core.exceptions import auth_error
from app.db.session import get_db
from app.main import create_app
from app.models.user import User
from app.schemas.auth import OAuthExchangeRequest
from app.services import oauth_service, profile_service
from app.services.oauth_providers import HttpxJWKClient, OAuthTransactionGuardError
from app.services.oauth_service import (
    OAuthCallbackJsonError,
    OAuthCallbackResult,
    OAuthStartResult,
)

PRIMARY_KEY = secrets.token_urlsafe(32)


def _settings(**overrides: Any) -> Settings:
    params: dict[str, Any] = {
        "_env_file": None,
        "ENVIRONMENT": "testing",
        "JWT_SECRET_KEY": "stage3c6-unit-jwt-secret-key-at-least-32-chars",
        "OAUTH_PKCE_ENCRYPTION_KEY": PRIMARY_KEY,
        "GOOGLE_CLIENT_ID": "google-client-3c6",
        "GOOGLE_CLIENT_SECRET": "google-secret-3c6",
        "GITHUB_CLIENT_ID": "github-client-3c6",
        "GITHUB_CLIENT_SECRET": "github-secret-3c6",
        "CORS_ORIGINS": ["http://localhost:5173", "https://app.folio360.com"],
        "OAUTH_ALLOWED_WEB_REDIRECT_URIS": [
            "http://localhost:5173/auth/oauth/callback",
            "https://app.folio360.com/auth/oauth/callback",
        ],
        "OAUTH_ALLOWED_MOBILE_REDIRECT_URIS": [
            "folio360://auth/callback",
        ],
    }
    params.update(overrides)
    return Settings(**params)


class _DummyDb:
    def rollback(self) -> None:
        return None


def _make_app(settings: Settings | None = None) -> tuple[Settings, Any]:
    cfg = settings or _settings()
    app = create_app(settings=cfg)

    def _override_db() -> Generator[_DummyDb, None, None]:
        yield _DummyDb()

    app.dependency_overrides[get_db] = _override_db
    return cfg, app


def _exchange_pair() -> tuple[str, str]:
    verifier = "V" * 48
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _assert_oauth_security_headers(headers: Any) -> None:
    assert headers.get("cache-control") == "no-store"
    assert headers.get("pragma") == "no-cache"
    assert headers.get("referrer-policy") == "no-referrer"


# ---------------------------------------------------------------------------
# 1. Schema Validation (OAuthExchangeRequest, Secret Non-Echo) & App Wiring
# ---------------------------------------------------------------------------


def test_oauth_exchange_request_unmodified_validation_and_non_echo() -> None:
    cfg, app = _make_app()
    assert isinstance(app.state.google_jwk_client, HttpxJWKClient)

    valid_verifier, _ = _exchange_pair()
    ok = OAuthExchangeRequest(code="opaque-code-123", exchange_code_verifier=valid_verifier)
    assert ok.code == "opaque-code-123"
    assert ok.exchange_code_verifier == valid_verifier

    secret_code = " secret-code-SENTINEL "
    secret_verifier = f" {'x' * 48} "
    with pytest.raises(ValidationError):
        OAuthExchangeRequest(code=secret_code, exchange_code_verifier=valid_verifier)
    with pytest.raises(ValidationError):
        OAuthExchangeRequest(code="valid-code", exchange_code_verifier=secret_verifier)
    with pytest.raises(ValidationError):
        OAuthExchangeRequest(
            code="valid-code",
            exchange_code_verifier=valid_verifier,
            extra_field="forbidden",  # type: ignore[call-arg]
        )

    # Route-level 422 must never echo code or verifier and must include OAuth security headers
    with TestClient(app) as client:
        r_bad_code = client.post(
            "/api/v1/auth/oauth/exchange",
            headers={"X-Client-Type": "mobile", "Origin": "http://localhost:5173"},
            json={"code": secret_code, "exchange_code_verifier": valid_verifier},
        )
        assert r_bad_code.status_code == 422
        assert secret_code not in r_bad_code.text
        assert secret_code.strip() not in r_bad_code.text
        assert valid_verifier not in r_bad_code.text
        _assert_oauth_security_headers(r_bad_code.headers)

        r_bad_ver = client.post(
            "/api/v1/auth/oauth/exchange",
            headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
            cookies={cfg.OAUTH_EXCHANGE_COOKIE_NAME: "present-cookie"},
            json={"code": "valid-code", "exchange_code_verifier": "bad verifier!"},
        )
        assert r_bad_ver.status_code == 422
        assert "bad verifier!" not in r_bad_ver.text
        _assert_oauth_security_headers(r_bad_ver.headers)
        # Trusted Origin + present cookie + web -> cleared on 422
        assert any(
            h.startswith(f"{cfg.OAUTH_EXCHANGE_COOKIE_NAME}=") and "Max-Age=0" in h
            for h in r_bad_ver.headers.get_list("set-cookie")
        )


# ---------------------------------------------------------------------------
# 2. /start Routing, Raw getlist Forwarding, Cookies & Rate Limit
# ---------------------------------------------------------------------------


def test_oauth_start_web_mobile_cookies_duplicate_params_and_rate_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg, app = _make_app()
    _, challenge = _exchange_pair()
    recorded_calls: list[dict[str, Any]] = []

    def _fake_start(db: Any, **kw: Any) -> OAuthStartResult:
        recorded_calls.append(kw)
        if kw.get("duplicate_params"):
            raise auth_error(
                status_code=400,
                code="INVALID_REDIRECT_URI",
                public_message="Duplicate redirect_uri.",
            )
        return OAuthStartResult(
            authorization_url="https://accounts.google.com/o/oauth2/v2/auth?state=s1",
            client_type=kw["client_type"],
            binding_cookie_value="bind-secret" if kw["client_type"] == "web" else None,
        )

    monkeypatch.setattr(oauth_service, "start_oauth_flow", _fake_start)

    with TestClient(app) as client:
        # Web -> 302 + host-only HttpOnly SameSite=Lax binding cookie
        r_web = client.get(
            "/api/v1/auth/oauth/google/start",
            params={
                "client_type": "web",
                "redirect_uri": "http://localhost:5173/auth/oauth/callback",
                "exchange_code_challenge": challenge,
                "exchange_code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert r_web.status_code == 302
        _assert_oauth_security_headers(r_web.headers)
        set_cookies = r_web.headers.get_list("set-cookie")
        assert len(set_cookies) == 1
        c_str = set_cookies[0]
        assert f"{cfg.OAUTH_BINDING_COOKIE_NAME}=bind-secret" in c_str
        assert "HttpOnly" in c_str
        assert "SameSite=lax" in c_str.lower().replace("samesite=lax", "SameSite=lax")
        assert "Path=/api/v1/auth/oauth" in c_str
        assert f"Max-Age={cfg.OAUTH_STATE_EXPIRE_MINUTES * 60}" in c_str
        assert "Domain=" not in c_str

        # Mobile -> 302 + ZERO Set-Cookie headers
        r_mob = client.get(
            "/api/v1/auth/oauth/github/start",
            params={
                "client_type": "mobile",
                "redirect_uri": "folio360://auth/callback",
                "exchange_code_challenge": challenge,
            },
            follow_redirects=False,
        )
        assert r_mob.status_code == 302
        _assert_oauth_security_headers(r_mob.headers)
        assert r_mob.headers.get_list("set-cookie") == []

        # Duplicate query params forwarded via getlist()
        r_dup = client.get(
            "/api/v1/auth/oauth/google/start"
            f"?client_type=web&redirect_uri=a&redirect_uri=b&exchange_code_challenge={challenge}",
            follow_redirects=False,
        )
        assert r_dup.status_code == 400
        assert r_dup.json()["error"]["details"] == {"code": "INVALID_REDIRECT_URI"}
        _assert_oauth_security_headers(r_dup.headers)
        assert "redirect_uri" in recorded_calls[-1]["duplicate_params"]

        # Rate limit 20/15m/IP (already spent 3 requests from 127.0.0.1 / testclient)
        for _ in range(17):
            r_ok = client.get(
                "/api/v1/auth/oauth/github/start",
                params={
                    "client_type": "mobile",
                    "redirect_uri": "folio360://auth/callback",
                    "exchange_code_challenge": challenge,
                },
                follow_redirects=False,
            )
            assert r_ok.status_code == 302

        r_429 = client.get(
            "/api/v1/auth/oauth/github/start",
            params={
                "client_type": "mobile",
                "redirect_uri": "folio360://auth/callback",
                "exchange_code_challenge": challenge,
            },
            follow_redirects=False,
        )
        assert r_429.status_code == 429
        assert r_429.json()["error"]["details"] == {"code": "RATE_LIMIT_EXCEEDED"}
        assert "retry-after" in r_429.headers
        _assert_oauth_security_headers(r_429.headers)


# ---------------------------------------------------------------------------
# 3. /callback Cookie Clearing Matrix, 503, 429 & Transaction Guard 500 + CORS
# ---------------------------------------------------------------------------


def test_oauth_callback_cookies_json_errors_429_and_tx_guard_500(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg, app = _make_app()
    captured: list[dict[str, Any]] = []
    mode_holder = {"mode": "success_web"}

    def _fake_callback(db: Any, **kw: Any) -> OAuthCallbackResult:
        captured.append(kw)
        m = mode_holder["mode"]
        if m == "success_web":
            return OAuthCallbackResult(
                redirect_url="http://localhost:5173/auth/oauth/callback?code=ex1",
                client_type="web",
                clear_binding_cookie=True,
                exchange_cookie_value="ex-cookie-val",
            )
        if m == "success_mobile":
            return OAuthCallbackResult(
                redirect_url="folio360://auth/callback?code=ex2",
                client_type="mobile",
                clear_binding_cookie=False,
                exchange_cookie_value=None,
            )
        if m == "json_503_always":
            raise OAuthCallbackJsonError(
                status_code=503,
                code="SERVICE_UNAVAILABLE",
                public_message="Unavailable",
                clear_binding_cookie_mode="always",
            )
        if m == "json_400_if_present":
            raise OAuthCallbackJsonError(
                status_code=400,
                code="INVALID_OAUTH_STATE",
                public_message="Invalid state",
                clear_binding_cookie_mode="if_present",
            )
        if m == "tx_guard_web":
            exc = OAuthTransactionGuardError("transaction open before HTTP")
            setattr(exc, "clear_binding_cookie_mode", "always")
            raise exc
        raise AssertionError(f"Unknown mode {m}")

    monkeypatch.setattr(oauth_service, "handle_oauth_callback", _fake_callback)

    with TestClient(app) as client:
        # 1. Web success clears binding cookie and sets exchange cookie
        r_web = client.get(
            "/api/v1/auth/oauth/google/callback?state= s1 &code=c1",
            cookies={cfg.OAUTH_BINDING_COOKIE_NAME: "b-tok"},
            follow_redirects=False,
        )
        assert r_web.status_code == 302
        _assert_oauth_security_headers(r_web.headers)
        # Forwarded unmodified query values (space preserved in state)
        assert captured[-1]["state_values"] == [" s1 "]
        sc = r_web.headers.get_list("set-cookie")
        assert any(cfg.OAUTH_BINDING_COOKIE_NAME in h and "Max-Age=0" in h for h in sc)
        ex_headers = [h for h in sc if h.startswith(f"{cfg.OAUTH_EXCHANGE_COOKIE_NAME}=")]
        assert len(ex_headers) == 1
        assert f"{cfg.OAUTH_EXCHANGE_COOKIE_NAME}=ex-cookie-val" in ex_headers[0]
        assert f"Path=/api/v1/auth/oauth/exchange" in ex_headers[0]
        assert f"Max-Age={OAUTH_EXCHANGE_CODE_EXPIRE_SECONDS}" in ex_headers[0]
        assert "HttpOnly" in ex_headers[0]
        assert "Domain=" not in ex_headers[0]

        # 2. Mobile success emits zero cookies
        mode_holder["mode"] = "success_mobile"
        client.cookies.clear()
        r_mob = client.get(
            "/api/v1/auth/oauth/github/callback?state=s2&code=c2",
            follow_redirects=False,
        )
        assert r_mob.status_code == 302
        assert r_mob.headers.get_list("set-cookie") == []

        # 3. Order 7 503 ("always") clears binding cookie even when absent, CORS header preserved
        mode_holder["mode"] = "json_503_always"
        r_503 = client.get(
            "/api/v1/auth/oauth/github/callback?state=s3&code=c3",
            headers={"Origin": "http://localhost:5173"},
            follow_redirects=False,
        )
        assert r_503.status_code == 503
        assert r_503.headers.get("access-control-allow-origin") == "http://localhost:5173"
        _assert_oauth_security_headers(r_503.headers)
        assert any(
            h.startswith(f"{cfg.OAUTH_BINDING_COOKIE_NAME}=") and "Max-Age=0" in h
            for h in r_503.headers.get_list("set-cookie")
        )

        # 4. Orders 1-3 400 ("if_present"): clears ONLY when cookie was sent
        mode_holder["mode"] = "json_400_if_present"
        r_400_absent = client.get("/api/v1/auth/oauth/google/callback", follow_redirects=False)
        assert r_400_absent.status_code == 400
        assert r_400_absent.headers.get_list("set-cookie") == []

        r_400_present = client.get(
            "/api/v1/auth/oauth/google/callback",
            cookies={cfg.OAUTH_BINDING_COOKIE_NAME: "stale-b"},
            follow_redirects=False,
        )
        assert r_400_present.status_code == 400
        assert any(
            h.startswith(f"{cfg.OAUTH_BINDING_COOKIE_NAME}=") and "Max-Age=0" in h
            for h in r_400_present.headers.get_list("set-cookie")
        )

        # 5. OAuthTransactionGuardError -> sanitized JSON 500 inside CORSMiddleware
        mode_holder["mode"] = "tx_guard_web"
        r_500 = client.get(
            "/api/v1/auth/oauth/google/callback?state=s5&code=c5",
            headers={"Origin": "http://localhost:5173"},
            follow_redirects=False,
        )
        assert r_500.status_code == 500
        assert r_500.json() == {
            "error": {
                "message": "Internal server error",
                "status_code": 500,
                "details": None,
            }
        }
        assert r_500.headers.get("access-control-allow-origin") == "http://localhost:5173"
        _assert_oauth_security_headers(r_500.headers)
        sc_500 = r_500.headers.get_list("set-cookie")
        assert any(h.startswith(f"{cfg.OAUTH_BINDING_COOKIE_NAME}=") and "Max-Age=0" in h for h in sc_500)
        assert not any(cfg.OAUTH_EXCHANGE_COOKIE_NAME in h for h in sc_500)

        # 6. Consume remaining callback quota up to 20 -> 21st triggers Order 0 429 clearing binding if present
        mode_holder["mode"] = "success_mobile"
        for _ in range(14):
            r_fill = client.get("/api/v1/auth/oauth/github/callback?state=sx&code=cx", follow_redirects=False)
            assert r_fill.status_code == 302

        r_429_absent = client.get("/api/v1/auth/oauth/github/callback", follow_redirects=False)
        assert r_429_absent.status_code == 429
        assert r_429_absent.headers.get_list("set-cookie") == []
        _assert_oauth_security_headers(r_429_absent.headers)

        # Reset bucket by bumping rate limiter and test 429 with binding cookie present
        app.state.rate_limiter.clear()
        for _ in range(20):
            client.get("/api/v1/auth/oauth/github/callback?state=sx&code=cx", follow_redirects=False)
        r_429_present = client.get(
            "/api/v1/auth/oauth/github/callback",
            cookies={cfg.OAUTH_BINDING_COOKIE_NAME: "b-429"},
            follow_redirects=False,
        )
        assert r_429_present.status_code == 429
        _assert_oauth_security_headers(r_429_present.headers)
        assert any(
            h.startswith(f"{cfg.OAUTH_BINDING_COOKIE_NAME}=") and "Max-Age=0" in h
            for h in r_429_present.headers.get_list("set-cookie")
        )


# ---------------------------------------------------------------------------
# 4. /exchange CSRF, Cookie Clearing Matrix, Token Responses & /me (D15)
# ---------------------------------------------------------------------------


def test_oauth_exchange_csrf_cookie_matrix_500_429_and_me_providers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg, app = _make_app()
    verifier, _ = _exchange_pair()
    uid = uuid.uuid4()
    user_obj = User(
        id=uid,
        email="oauth.unit@example.com",
        password_hash=None,
        is_active=True,
        is_email_verified=True,
        auth_version=0,
    )
    from datetime import datetime, timezone

    user_obj.created_at = datetime.now(timezone.utc)
    user_obj.updated_at = datetime.now(timezone.utc)

    exchange_mode = {"mode": "ok"}

    def _fake_exchange(db: Any, **kw: Any) -> tuple[User, str, int, str, int]:
        m = exchange_mode["mode"]
        if m == "ok":
            return user_obj, "jwt-access-123", 900, "refresh-tok-456", 1209600
        if m == "invalid_code":
            raise auth_error(
                status_code=400,
                code="INVALID_OAUTH_EXCHANGE_CODE",
                public_message="Invalid code.",
            )
        if m == "email_unverified":
            raise auth_error(
                status_code=403,
                code="EMAIL_NOT_VERIFIED",
                public_message="Verify email.",
            )
        raise RuntimeError("boom in exchange service")

    monkeypatch.setattr(oauth_service, "exchange_oauth_code", _fake_exchange)
    monkeypatch.setattr(
        oauth_service,
        "list_user_oauth_providers",
        lambda db, *, user_id: ["github", "google"],
    )
    monkeypatch.setattr(
        profile_service,
        "is_profile_completed",
        lambda db, *, user_id: False,
    )

    body = {"code": "raw-ex-code", "exchange_code_verifier": verifier}

    with TestClient(app) as client:
        # 1. Web success: clears exchange cookie, sets refresh cookie, returns WebAuthTokenResponse
        r_web = client.post(
            "/api/v1/auth/oauth/exchange",
            headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
            cookies={cfg.OAUTH_EXCHANGE_COOKIE_NAME: "ex-cook"},
            json=body,
        )
        assert r_web.status_code == 200
        assert "refresh_token" not in r_web.json()
        assert r_web.json()["access_token"] == "jwt-access-123"
        _assert_oauth_security_headers(r_web.headers)
        sc_ok = r_web.headers.get_list("set-cookie")
        assert any(h.startswith(f"{cfg.OAUTH_EXCHANGE_COOKIE_NAME}=") and "Max-Age=0" in h for h in sc_ok)
        assert any(h.startswith(f"{cfg.REFRESH_COOKIE_NAME}=refresh-tok-456") for h in sc_ok)

        # 2. Mobile success: returns MobileAuthTokenResponse with ZERO cookies
        client.cookies.clear()
        r_mob = client.post(
            "/api/v1/auth/oauth/exchange",
            headers={"X-Client-Type": "mobile", "Origin": "http://localhost:5173"},
            cookies={cfg.OAUTH_EXCHANGE_COOKIE_NAME: "should-not-touch"},
            json=body,
        )
        assert r_mob.status_code == 200
        assert r_mob.json()["refresh_token"] == "refresh-tok-456"
        assert r_mob.headers.get_list("set-cookie") == []

        # 3. 403 CSRF_ORIGIN_MISMATCH (missing & untrusted Origin) MUST NOT clear exchange cookie
        for bad_headers in (
            {"X-Client-Type": "web"},
            {"X-Client-Type": "web", "Origin": "https://evil.example.com"},
            {"X-Client-Type": "web", "Origin": "null"},
        ):
            r_csrf = client.post(
                "/api/v1/auth/oauth/exchange",
                headers=bad_headers,
                cookies={cfg.OAUTH_EXCHANGE_COOKIE_NAME: "keep-me"},
                json=body,
            )
            assert r_csrf.status_code == 403
            assert r_csrf.json()["error"]["details"] == {"code": "CSRF_ORIGIN_MISMATCH"}
            assert r_csrf.headers.get_list("set-cookie") == []

        # 4. 400 INVALID_CLIENT_TYPE (pre-CSRF) MUST NOT clear exchange cookie even with trusted Origin
        r_bad_ct = client.post(
            "/api/v1/auth/oauth/exchange",
            headers={"Origin": "http://localhost:5173"},
            cookies={cfg.OAUTH_EXCHANGE_COOKIE_NAME: "keep-me"},
            json=body,
        )
        assert r_bad_ct.status_code == 400
        assert r_bad_ct.json()["error"]["details"] == {"code": "INVALID_CLIENT_TYPE"}
        assert r_bad_ct.headers.get_list("set-cookie") == []

        # 5. Trusted Origin web 400 & 403 EMAIL_NOT_VERIFIED ALWAYS clear exchange cookie
        for m_name, st_code in (("invalid_code", 400), ("email_unverified", 403)):
            exchange_mode["mode"] = m_name
            r_err = client.post(
                "/api/v1/auth/oauth/exchange",
                headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
                json=body,
            )
            assert r_err.status_code == st_code
            assert any(
                h.startswith(f"{cfg.OAUTH_EXCHANGE_COOKIE_NAME}=") and "Max-Age=0" in h
                for h in r_err.headers.get_list("set-cookie")
            )

        # 6. Trusted Origin web 500 clears if present; untrusted 500 does NOT clear
        exchange_mode["mode"] = "boom"
        r_500_trusted = client.post(
            "/api/v1/auth/oauth/exchange",
            headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
            cookies={cfg.OAUTH_EXCHANGE_COOKIE_NAME: "clear-me"},
            json=body,
        )
        assert r_500_trusted.status_code == 500
        assert r_500_trusted.headers.get("access-control-allow-origin") == "http://localhost:5173"
        assert any(
            h.startswith(f"{cfg.OAUTH_EXCHANGE_COOKIE_NAME}=") and "Max-Age=0" in h
            for h in r_500_trusted.headers.get_list("set-cookie")
        )

        # Rate limit (10/15m/IP): 9 requests sent above -> 10th allowed -> 11th & 12th trigger 429
        exchange_mode["mode"] = "ok"
        r_tenth = client.post(
            "/api/v1/auth/oauth/exchange",
            headers={"X-Client-Type": "mobile"},
            json=body,
        )
        assert r_tenth.status_code == 200

        r_429_untrusted = client.post(
            "/api/v1/auth/oauth/exchange",
            headers={"X-Client-Type": "web", "Origin": "https://evil.example.com"},
            cookies={cfg.OAUTH_EXCHANGE_COOKIE_NAME: "keep-429"},
            json=body,
        )
        assert r_429_untrusted.status_code == 429
        assert r_429_untrusted.headers.get_list("set-cookie") == []

        r_429_trusted = client.post(
            "/api/v1/auth/oauth/exchange",
            headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
            cookies={cfg.OAUTH_EXCHANGE_COOKIE_NAME: "clear-429"},
            json=body,
        )
        assert r_429_trusted.status_code == 429
        assert any(
            h.startswith(f"{cfg.OAUTH_EXCHANGE_COOKIE_NAME}=") and "Max-Age=0" in h
            for h in r_429_trusted.headers.get_list("set-cookie")
        )

        # 7. GET /auth/me returns sorted oauth_providers and is NOT forced into OAuth no-referrer middleware
        app.dependency_overrides[get_current_user] = lambda: user_obj
        r_me = client.get("/api/v1/auth/me")
        assert r_me.status_code == 200
        assert r_me.json()["oauth_providers"] == ["github", "google"]
        assert r_me.headers.get("referrer-policy") is None


def test_oauth_github_login_start_route_and_legacy_404(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify Stage 3C GitHub login uses /auth/oauth/github/start and does not expose /auth/github."""
    cfg, app = _make_app()
    _, challenge = _exchange_pair()

    monkeypatch.setattr(
        oauth_service,
        "start_oauth_flow",
        lambda db, **kw: OAuthStartResult(
            authorization_url="https://github.com/login/oauth/authorize?client_id=login-id&state=s1",
            client_type=kw["client_type"],
            binding_cookie_value="gh-bind-secret",
        ),
    )

    with TestClient(app) as client:
        r_start = client.get(
            "/api/v1/auth/oauth/github/start",
            params={
                "client_type": "web",
                "redirect_uri": "http://localhost:5173/auth/oauth/callback",
                "exchange_code_challenge": challenge,
                "exchange_code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert r_start.status_code == 302
        assert r_start.headers["location"].startswith("https://github.com/login/oauth/authorize?")
        _assert_oauth_security_headers(r_start.headers)
        assert any(
            h.startswith(f"{cfg.OAUTH_BINDING_COOKIE_NAME}=")
            for h in r_start.headers.get_list("set-cookie")
        )

        # Unregistered legacy path must remain 404 (no duplicate route)
        r_legacy = client.get("/api/v1/auth/github", follow_redirects=False)
        assert r_legacy.status_code == 404
