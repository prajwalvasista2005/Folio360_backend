"""Stage 3C.7 Final OAuth Security & Negative-Path Unit Tests (REV12)."""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import logging
import secrets
from typing import Any, Generator
from urllib.parse import parse_qs, urlsplit
import uuid

from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient
import pytest

from app.core.config import Settings
from app.core.oauth_middleware import OAuthSecurityResponseMiddleware
from app.core.security import (
    encrypt_pkce_verifier_for_settings,
    generate_pkce_verifier,
    hash_opaque_token,
)
from app.db.session import get_db
from app.main import create_app
from app.models.oauth import OAuthState
from app.models.user import User
from app.services import oauth_service, profile_service
from app.services.oauth_providers import ensure_no_open_db_transaction
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
        "JWT_SECRET_KEY": "stage3c7-security-jwt-secret-at-least-32-chars",
        "OAUTH_PKCE_ENCRYPTION_KEY": PRIMARY_KEY,
        "GOOGLE_CLIENT_ID": "google-client-3c7",
        "GOOGLE_CLIENT_SECRET": "google-secret-3c7",
        "GITHUB_CLIENT_ID": "github-client-3c7",
        "GITHUB_CLIENT_SECRET": "github-secret-3c7",
        "CORS_ORIGINS": ["https://app.folio360.com"],
        "OAUTH_ALLOWED_WEB_REDIRECT_URIS": [
            "https://app.folio360.com/auth/oauth/callback",
        ],
        "OAUTH_ALLOWED_MOBILE_REDIRECT_URIS": [
            "folio360://auth/callback",
        ],
    }
    params.update(overrides)
    return Settings(**params)


def _exchange_pair() -> tuple[str, str]:
    verifier = "X" * 48
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _assert_security_headers(headers: Any) -> None:
    if headers.get("cache-control") != "no-store":
        pytest.fail(f"Expected Cache-Control: no-store, got {headers.get('cache-control')!r}")
    if headers.get("pragma") != "no-cache":
        pytest.fail(f"Expected Pragma: no-cache, got {headers.get('pragma')!r}")
    if headers.get("referrer-policy") != "no-referrer":
        pytest.fail(f"Expected Referrer-Policy: no-referrer, got {headers.get('referrer-policy')!r}")


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


# ---------------------------------------------------------------------------
# 1. Cross-Site Cookie Deployment Topology (REV12 §6)
# ---------------------------------------------------------------------------


def test_cross_site_cookie_topology_attributes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REV12 §6: cross_site sets SameSite=None; Secure on exchange/refresh while keeping binding SameSite=Lax; Secure."""
    cfg, app = _make_app(
        _settings(
            COOKIE_DEPLOYMENT_MODE="cross_site",
            REFRESH_COOKIE_SAMESITE="none",
            REFRESH_COOKIE_SECURE=True,
        )
    )
    verifier, challenge = _exchange_pair()
    uid = uuid.uuid4()
    user_obj = User(
        id=uid,
        email="crosssite@example.com",
        password_hash=None,
        is_active=True,
        is_email_verified=True,
        auth_version=0,
    )
    user_obj.created_at = datetime.now(timezone.utc)
    user_obj.updated_at = datetime.now(timezone.utc)

    monkeypatch.setattr(
        oauth_service,
        "start_oauth_flow",
        lambda db, **kw: OAuthStartResult(
            authorization_url="https://accounts.google.com/o/oauth2/v2/auth?state=s-cs",
            client_type="web",
            binding_cookie_value="bind-cs",
        ),
    )
    monkeypatch.setattr(
        oauth_service,
        "handle_oauth_callback",
        lambda db, **kw: OAuthCallbackResult(
            redirect_url="https://app.folio360.com/auth/oauth/callback?code=ex-cs",
            client_type="web",
            clear_binding_cookie=True,
            exchange_cookie_value="exchange-cs",
        ),
    )
    monkeypatch.setattr(
        oauth_service,
        "exchange_oauth_code",
        lambda db, **kw: (user_obj, "jwt-cs", 900, "refresh-cs", 1209600),
    )
    monkeypatch.setattr(
        profile_service,
        "is_profile_completed",
        lambda db, *, user_id: False,
    )

    with TestClient(app) as client:
        # 1. /start -> binding cookie stays SameSite=Lax + Secure
        r_start = client.get(
            "/api/v1/auth/oauth/google/start",
            params={
                "client_type": "web",
                "redirect_uri": "https://app.folio360.com/auth/oauth/callback",
                "exchange_code_challenge": challenge,
                "exchange_code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert r_start.status_code == 302
        sc_start = r_start.headers.get_list("set-cookie")
        assert len(sc_start) == 1
        bind_set = sc_start[0].lower()
        assert f"{cfg.OAUTH_BINDING_COOKIE_NAME}=bind-cs" in sc_start[0]
        assert "httponly" in bind_set
        assert "secure" in bind_set
        assert "samesite=lax" in bind_set
        assert "path=/api/v1/auth/oauth" in bind_set
        assert "domain=" not in bind_set

        # 2. /callback -> clears binding cookie (Lax; Secure) + sets exchange cookie (None; Secure)
        r_cb = client.get(
            "/api/v1/auth/oauth/google/callback?state=s-cs&code=c-cs",
            headers={"Cookie": f"{cfg.OAUTH_BINDING_COOKIE_NAME}=bind-cs"},
            follow_redirects=False,
        )
        assert r_cb.status_code == 302
        sc_cb = r_cb.headers.get_list("set-cookie")
        bind_clr = [h for h in sc_cb if h.startswith(f"{cfg.OAUTH_BINDING_COOKIE_NAME}=")]
        ex_set = [h for h in sc_cb if h.startswith(f"{cfg.OAUTH_EXCHANGE_COOKIE_NAME}=")]
        assert len(bind_clr) == 1 and "max-age=0" in bind_clr[0].lower() and "samesite=lax" in bind_clr[0].lower()
        assert len(ex_set) == 1
        ex_lower = ex_set[0].lower()
        assert f"{cfg.OAUTH_EXCHANGE_COOKIE_NAME}=exchange-cs" in ex_set[0]
        assert "httponly" in ex_lower
        assert "secure" in ex_lower
        assert "samesite=none" in ex_lower
        assert "path=/api/v1/auth/oauth/exchange" in ex_lower
        assert "max-age=60" in ex_lower
        assert "domain=" not in ex_lower

        # 3. /exchange -> clears exchange cookie (None; Secure) + sets refresh cookie (None; Secure)
        r_ex = client.post(
            "/api/v1/auth/oauth/exchange",
            headers={
                "X-Client-Type": "web",
                "Origin": "https://app.folio360.com",
                "Cookie": f"{cfg.OAUTH_EXCHANGE_COOKIE_NAME}=exchange-cs",
            },
            json={"code": "ex-cs", "exchange_code_verifier": verifier},
        )
        assert r_ex.status_code == 200
        sc_ex = r_ex.headers.get_list("set-cookie")
        ex_clr = [h for h in sc_ex if h.startswith(f"{cfg.OAUTH_EXCHANGE_COOKIE_NAME}=")]
        ref_set = [h for h in sc_ex if h.startswith(f"{cfg.REFRESH_COOKIE_NAME}=")]
        assert len(ex_clr) == 1 and "max-age=0" in ex_clr[0].lower() and "samesite=none" in ex_clr[0].lower()
        assert len(ref_set) == 1
        assert "httponly" in ref_set[0].lower()
        assert "secure" in ref_set[0].lower()
        assert "samesite=none" in ref_set[0].lower()


# ---------------------------------------------------------------------------
# 2. ASGI Middleware Ordering, Security Headers & CORS on Errors (REV12 §7)
# ---------------------------------------------------------------------------


def test_asgi_middleware_ordering_and_oauth_headers_across_all_status_codes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REV12 §7: CORSMiddleware wraps OAuthSecurityResponseMiddleware; all 8 OAuth statuses carry headers."""
    cfg, app = _make_app()
    middleware_classes = [m.cls for m in app.user_middleware]
    assert CORSMiddleware in middleware_classes
    assert OAuthSecurityResponseMiddleware in middleware_classes
    assert middleware_classes.index(CORSMiddleware) < middleware_classes.index(
        OAuthSecurityResponseMiddleware
    )

    verifier, challenge = _exchange_pair()
    uid = uuid.uuid4()
    user_obj = User(
        id=uid,
        email="mw@example.com",
        password_hash=None,
        is_active=True,
        is_email_verified=True,
        auth_version=0,
    )
    user_obj.created_at = datetime.now(timezone.utc)
    user_obj.updated_at = datetime.now(timezone.utc)

    cb_mode = {"val": "302"}

    def _fake_cb(db: Any, **kw: Any) -> OAuthCallbackResult:
        if cb_mode["val"] == "302":
            return OAuthCallbackResult(
                redirect_url="folio360://auth/callback?code=ok",
                client_type="mobile",
                clear_binding_cookie=False,
                exchange_cookie_value=None,
            )
        if cb_mode["val"] == "400":
            raise OAuthCallbackJsonError(
                status_code=400,
                code="INVALID_OAUTH_STATE",
                public_message="Bad state.",
                clear_binding_cookie_mode="if_present",
            )
        if cb_mode["val"] == "503":
            raise OAuthCallbackJsonError(
                status_code=503,
                code="SERVICE_UNAVAILABLE",
                public_message="Provider disabled.",
                clear_binding_cookie_mode="always",
            )
        raise RuntimeError("unhandled 500")

    monkeypatch.setattr(oauth_service, "handle_oauth_callback", _fake_cb)
    monkeypatch.setattr(
        oauth_service,
        "exchange_oauth_code",
        lambda db, **kw: (user_obj, "jwt-mw", 900, "rt-mw", 1209600),
    )
    monkeypatch.setattr(
        profile_service,
        "is_profile_completed",
        lambda db, *, user_id: False,
    )

    origin_hdr = {"Origin": "https://app.folio360.com"}

    with TestClient(app) as client:
        # 200
        r200 = client.post(
            "/api/v1/auth/oauth/exchange",
            headers={**origin_hdr, "X-Client-Type": "mobile"},
            json={"code": "c", "exchange_code_verifier": verifier},
        )
        assert r200.status_code == 200 and r200.headers.get("access-control-allow-origin") == "https://app.folio360.com"
        _assert_security_headers(r200.headers)

        # 302
        r302 = client.get("/api/v1/auth/oauth/github/callback?state=s&code=c", headers=origin_hdr, follow_redirects=False)
        assert r302.status_code == 302
        _assert_security_headers(r302.headers)

        # 400
        cb_mode["val"] = "400"
        r400 = client.get("/api/v1/auth/oauth/github/callback", headers=origin_hdr, follow_redirects=False)
        assert r400.status_code == 400 and r400.headers.get("access-control-allow-origin") == "https://app.folio360.com"
        _assert_security_headers(r400.headers)

        # 403
        r403 = client.post(
            "/api/v1/auth/oauth/exchange",
            headers={"X-Client-Type": "web", "Origin": "https://evil.example.com"},
            json={"code": "c", "exchange_code_verifier": verifier},
        )
        assert r403.status_code == 403
        _assert_security_headers(r403.headers)

        # 422
        r422 = client.post(
            "/api/v1/auth/oauth/exchange",
            headers={**origin_hdr, "X-Client-Type": "mobile"},
            json={"code": " bad ", "exchange_code_verifier": verifier},
        )
        assert r422.status_code == 422 and r422.headers.get("access-control-allow-origin") == "https://app.folio360.com"
        _assert_security_headers(r422.headers)

        # 503
        cb_mode["val"] = "503"
        r503 = client.get("/api/v1/auth/oauth/github/callback?state=s", headers=origin_hdr, follow_redirects=False)
        assert r503.status_code == 503 and r503.headers.get("access-control-allow-origin") == "https://app.folio360.com"
        _assert_security_headers(r503.headers)

        # 500
        cb_mode["val"] = "500"
        r500 = client.get("/api/v1/auth/oauth/github/callback?state=s&code=c", headers=origin_hdr, follow_redirects=False)
        assert r500.status_code == 500 and r500.headers.get("access-control-allow-origin") == "https://app.folio360.com"
        _assert_security_headers(r500.headers)

        # 429 on /start
        for _ in range(20):
            client.get(
                "/api/v1/auth/oauth/google/start",
                params={
                    "client_type": "mobile",
                    "redirect_uri": "bad://uri",
                    "exchange_code_challenge": challenge,
                },
                follow_redirects=False,
            )
        r429 = client.get(
            "/api/v1/auth/oauth/google/start",
            params={
                "client_type": "mobile",
                "redirect_uri": "bad://uri",
                "exchange_code_challenge": challenge,
            },
            headers=origin_hdr,
            follow_redirects=False,
        )
        assert r429.status_code == 429 and r429.headers.get("access-control-allow-origin") == "https://app.folio360.com"
        _assert_security_headers(r429.headers)


# ---------------------------------------------------------------------------
# 3. D11 No Secrets in Redirects, Error Bodies, or Captured Logs
# ---------------------------------------------------------------------------


def test_d11_no_secrets_in_redirects_errors_or_logs(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REV12 §1 D11 & §8: No tokens, codes, states, verifiers, or cookies in redirects, errors, or logs."""
    cfg, app = _make_app()
    caplog.set_level(logging.DEBUG)

    sentinels = {
        "raw_state": "STATE-SECRET-SENTINEL-3C7",
        "provider_code": "PROV-CODE-SECRET-SENTINEL-3C7",
        "binding_cookie": "BIND-COOKIE-SENTINEL-3C7",
        "exchange_verifier": f"VERIFIER-SENTINEL-3C7-{'Z' * 30}",
        "bad_exchange_code": " BAD-EX-CODE-SENTINEL-3C7 ",
        "id_token": "ID-TOKEN-SECRET-SENTINEL-3C7",
        "access_token": "GH-ACCESS-TOKEN-SENTINEL-3C7",
    }

    def _boom_callback(db: Any, **kw: Any) -> OAuthCallbackResult:
        if kw.get("state_values") == ["err-redirect"]:
            return OAuthCallbackResult(
                redirect_url="https://app.folio360.com/auth/oauth/callback?error=oauth_provider_error",
                client_type="web",
                clear_binding_cookie=True,
                exchange_cookie_value=None,
            )
        raise RuntimeError(
            f"provider boom id_token={sentinels['id_token']} access_token={sentinels['access_token']}"
        )

    monkeypatch.setattr(oauth_service, "handle_oauth_callback", _boom_callback)

    with TestClient(app) as client:
        # 1. Error redirect contains zero state/code/token/cookie secrets
        r_redir = client.get(
            f"/api/v1/auth/oauth/github/callback?state=err-redirect&code={sentinels['provider_code']}",
            headers={"Cookie": f"{cfg.OAUTH_BINDING_COOKIE_NAME}={sentinels['binding_cookie']}"},
            follow_redirects=False,
        )
        assert r_redir.status_code == 302
        loc = r_redir.headers["location"]
        q = parse_qs(urlsplit(loc).query)
        assert list(q.keys()) == ["error"]
        for val in sentinels.values():
            assert val not in loc

        # 2. Unhandled 500 error body never echoes exception message containing secret sentinels
        r_500 = client.get(
            f"/api/v1/auth/oauth/google/callback?state={sentinels['raw_state']}&code={sentinels['provider_code']}",
            headers={"Cookie": f"{cfg.OAUTH_BINDING_COOKIE_NAME}={sentinels['binding_cookie']}"},
            follow_redirects=False,
        )
        assert r_500.status_code == 500
        for val in sentinels.values():
            assert val not in r_500.text

        # 3. 422 /exchange error body never echoes invalid code or verifier
        r_422 = client.post(
            "/api/v1/auth/oauth/exchange",
            headers={"X-Client-Type": "mobile"},
            json={
                "code": sentinels["bad_exchange_code"],
                "exchange_code_verifier": sentinels["exchange_verifier"],
            },
        )
        assert r_422.status_code == 422
        for val in sentinels.values():
            assert val not in r_422.text
            assert val.strip() not in r_422.text

    full_logs = "\n".join(rec.getMessage() for rec in caplog.records)
    for key in ("raw_state", "provider_code", "binding_cookie", "exchange_verifier", "id_token", "access_token"):
        assert sentinels[key] not in full_logs


# ---------------------------------------------------------------------------
# 4. Transaction-Closure Guard Under Optimized Python (-O) (REV12 §4, §9)
# ---------------------------------------------------------------------------


def test_http_callback_transaction_guard_returns_500_under_optimized_python(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REV12 §4 & §9: HTTP /callback guard fires and returns sanitized 500 + CORS + headers even under python -O."""
    cfg = _settings()
    app = create_app(settings=cfg)

    raw_state = "state-tx-guard-opt-test"
    state_hash = hash_opaque_token(raw_state)
    binding_cookie = "binding-tx-guard-opt"
    now_utc = datetime.now(timezone.utc)
    pkce_enc = encrypt_pkce_verifier_for_settings(
        generate_pkce_verifier(),
        settings=cfg,
        provider="github",
        state_hash=state_hash,
    )
    state_row = OAuthState(
        id=uuid.uuid4(),
        state_hash=state_hash,
        provider="github",
        client_type="web",
        pkce_verifier_encrypted=pkce_enc,
        nonce_hash=None,
        redirect_uri="https://app.folio360.com/auth/oauth/callback",
        client_binding_hash=hash_opaque_token(binding_cookie),
        exchange_code_challenge_hash="a" * 64,
        expires_at=now_utc + timedelta(minutes=10),
        consumed_at=None,
    )
    state_row.created_at = now_utc

    class _FakeScalar:
        def __init__(self, v: Any) -> None:
            self._v = v

        def scalar_one_or_none(self) -> Any:
            return self._v

    class _TxGuardDb:
        def __init__(self) -> None:
            self._tx_open = False
            self.rolled_back = 0

        def in_transaction(self) -> bool:
            return self._tx_open

        def execute(self, stmt: Any) -> _FakeScalar:
            self._tx_open = True
            return _FakeScalar(state_row)

        def commit(self) -> None:
            self._tx_open = False

        def rollback(self) -> None:
            self._tx_open = False
            self.rolled_back += 1

        def force_open_tx(self) -> None:
            self._tx_open = True

    fake_db = _TxGuardDb()

    def _override_db() -> Generator[_TxGuardDb, None, None]:
        yield fake_db

    app.dependency_overrides[get_db] = _override_db

    def _simulate_open_tx_provider(db: Any, **kw: Any) -> str:
        db.force_open_tx()
        ensure_no_open_db_transaction(db)
        return "unreachable"

    monkeypatch.setattr(
        oauth_service,
        "exchange_github_authorization_code",
        _simulate_open_tx_provider,
    )

    with TestClient(app) as client:
        resp = client.get(
            f"/api/v1/auth/oauth/github/callback?state={raw_state}&code=gh-code-1",
            headers={
                "Origin": "https://app.folio360.com",
                "Cookie": f"{cfg.OAUTH_BINDING_COOKIE_NAME}={binding_cookie}",
            },
            follow_redirects=False,
        )

    # Explicit non-assert checks ensure verification stays enforced even under `python -O`!
    if resp.status_code != 500:
        pytest.fail(f"Expected 500 on OAuthTransactionGuardError, got {resp.status_code}")
    if resp.json() != {
        "error": {"message": "Internal server error", "status_code": 500, "details": None}
    }:
        pytest.fail(f"Unexpected 500 body: {resp.json()!r}")
    if fake_db.rolled_back < 1:
        pytest.fail("Expected DB rollback on transaction guard violation")
    _assert_security_headers(resp.headers)
    if resp.headers.get("access-control-allow-origin") != "https://app.folio360.com":
        pytest.fail("Missing CORS header on 500 transaction guard response")
    sc = resp.headers.get_list("set-cookie")
    if not any(h.startswith(f"{cfg.OAUTH_BINDING_COOKIE_NAME}=") and "Max-Age=0" in h for h in sc):
        pytest.fail(f"Expected cleared web binding cookie on 500, got {sc!r}")
    if any(cfg.OAUTH_EXCHANGE_COOKIE_NAME in h for h in sc):
        pytest.fail(f"Unexpected exchange cookie on 500: {sc!r}")
