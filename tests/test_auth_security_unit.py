"""Unit tests for Stage 3A security primitives, config, 422 stripping, logging, and rate limiting."""

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import uuid

from fastapi import Body, Depends, FastAPI, Request
from fastapi.testclient import TestClient
import jwt
from pydantic import BaseModel, ValidationError
import pytest

from app.api.deps.auth import (
    AuthenticatedUser,
    get_current_auth_context,
    get_current_settings,
    get_current_user,
    resolve_client_ip,
)
from app.db.session import get_db
from app.models.user import User
from app.core.config import Settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import REDACTED, sanitize_log_text
from app.core.rate_limit import SlidingWindowRateLimiter
from app.core.security import (
    DUMMY_PASSWORD_HASH,
    create_access_token,
    decode_access_token,
    generate_opaque_token,
    hash_opaque_token,
    hash_password,
    validate_password_policy,
    verify_password,
)


def _dev_jwt_settings(**overrides) -> Settings:
    params = {
        "_env_file": None,
        "ENVIRONMENT": "testing",
        "JWT_SECRET_KEY": "unit-test-jwt-secret-key-at-least-32-bytes",
        "JWT_ISSUER": "folio360",
        "JWT_AUDIENCE": "folio360-api",
        "JWT_ACCESS_TOKEN_EXPIRE_MINUTES": 15,
    }
    params.update(overrides)
    return Settings(**params)


def test_argon2id_hashing_verification_and_dummy_hash() -> None:
    pw = "CorrectHorseBatteryStaple!2026"
    hashed = hash_password(pw)
    assert hashed.startswith("$argon2id$")
    assert verify_password(pw, hashed) is True
    assert verify_password("wrong-password-123", hashed) is False
    assert verify_password(pw, "corrupt-hash") is False
    assert DUMMY_PASSWORD_HASH.startswith("$argon2id$")
    assert verify_password(pw, DUMMY_PASSWORD_HASH) is False


def test_password_policy_validation() -> None:
    assert validate_password_policy("ValidPassphrase123", "alice@example.com") == (
        "ValidPassphrase123"
    )
    for bad_pw in (
        "short11char",
        "            ",
        "a" * 129,
        "é" * 65,  # 130 UTF-8 bytes > 128
        "Alice@Example.com",
    ):
        with pytest.raises(ValueError):
            validate_password_policy(bad_pw, "alice@example.com")


def test_opaque_token_generation_and_sha256_hex_digest() -> None:
    t1 = generate_opaque_token()
    t2 = generate_opaque_token()
    assert t1 != t2
    h1 = hash_opaque_token(t1)
    assert len(h1) == 64
    assert all(ch in "0123456789abcdef" for ch in h1)


def test_access_jwt_claims_and_strict_validation() -> None:
    settings = _dev_jwt_settings()
    uid = uuid.uuid4()
    token, expires_in = create_access_token(user_id=uid, auth_version=2, settings=settings)
    assert expires_in == 900

    parsed_uid, parsed_ver, payload = decode_access_token(token, settings)
    assert parsed_uid == uid
    assert parsed_ver == 2
    assert type(parsed_ver) is int
    assert payload["type"] == "access"

    secret = settings.JWT_SECRET_KEY.get_secret_value()
    now = datetime.now(timezone.utc)
    base_claims = {
        "sub": str(uid),
        "ver": 0,
        "type": "access",
        "iss": "folio360",
        "aud": "folio360-api",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "jti": str(uuid.uuid4()),
    }

    # Reject bool/str/float/negative ver, wrong type, wrong iss, wrong aud, expired
    for bad_override in (
        {"ver": True},
        {"ver": "0"},
        {"ver": 1.5},
        {"ver": -1},
        {"type": "refresh"},
        {"iss": "other"},
        {"aud": "other"},
        {"sub": "not-a-uuid"},
        {"exp": int((now - timedelta(seconds=10)).timestamp())},
    ):
        bad_claims = {**base_claims, **bad_override}
        bad_token = jwt.encode(bad_claims, secret, algorithm="HS256")
        with pytest.raises(ValueError):
            decode_access_token(bad_token, settings)


def test_deployment_aware_cookie_and_production_config_validation() -> None:
    # SameSite=None with Secure=False rejected in all environments
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            ENVIRONMENT="development",
            REFRESH_COOKIE_SAMESITE="none",
            REFRESH_COOKIE_SECURE=False,
        )

    # Valid Mode 1 same-site prod
    same_site_prod = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        DATABASE_URL="postgresql+psycopg://u:p@db:5432/folio360",
        JWT_SECRET_KEY="x" * 32,
        RESEND_API_KEY="re_valid_key_1234567890",
        EMAIL_FROM_ADDRESS="no-reply@folio360.com",
        FRONTEND_BASE_URL="https://app.folio360.com",
        CORS_ORIGINS=["https://app.folio360.com"],
        COOKIE_DEPLOYMENT_MODE="same_site",
        REFRESH_COOKIE_SECURE=True,
        REFRESH_COOKIE_SAMESITE="lax",
    )
    same_site_prod.validate_runtime_requirements()

    # Valid Mode 2 cross-site prod
    cross_site_prod = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        DATABASE_URL="postgresql+psycopg://u:p@db:5432/folio360",
        JWT_SECRET_KEY="x" * 32,
        RESEND_API_KEY="re_valid_key_1234567890",
        EMAIL_FROM_ADDRESS="no-reply@folio360.com",
        FRONTEND_BASE_URL="https://frontend.host-a.app",
        CORS_ORIGINS=["https://frontend.host-a.app"],
        COOKIE_DEPLOYMENT_MODE="cross_site",
        REFRESH_COOKIE_SECURE=True,
        REFRESH_COOKIE_SAMESITE="none",
        REFRESH_COOKIE_DOMAIN=None,
    )
    cross_site_prod.validate_runtime_requirements()

    # Mode 2 with Domain set rejected in production
    with pytest.raises(RuntimeError, match="REFRESH_COOKIE_DOMAIN"):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            DATABASE_URL="postgresql+psycopg://u:p@db:5432/folio360",
            JWT_SECRET_KEY="x" * 32,
            RESEND_API_KEY="re_valid_key_1234567890",
            EMAIL_FROM_ADDRESS="no-reply@folio360.com",
            FRONTEND_BASE_URL="https://frontend.host-a.app",
            CORS_ORIGINS=["https://frontend.host-a.app"],
            COOKIE_DEPLOYMENT_MODE="cross_site",
            REFRESH_COOKIE_SECURE=True,
            REFRESH_COOKIE_SAMESITE="none",
            REFRESH_COOKIE_DOMAIN="host-a.app",
        ).validate_runtime_requirements()

    # Wildcard or HTTP CORS_ORIGINS rejected in production
    with pytest.raises(RuntimeError, match="CORS_ORIGINS"):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            DATABASE_URL="postgresql+psycopg://u:p@db:5432/folio360",
            JWT_SECRET_KEY="x" * 32,
            RESEND_API_KEY="re_valid_key_1234567890",
            EMAIL_FROM_ADDRESS="no-reply@folio360.com",
            FRONTEND_BASE_URL="https://app.folio360.com",
            CORS_ORIGINS=["http://app.folio360.com"],
            REFRESH_COOKIE_SECURE=True,
        ).validate_runtime_requirements()


def test_extended_log_redaction_for_stage_3a_secrets_and_cookies() -> None:
    sample_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.signature12345678"
    raw = (
        f"new_password=MyNewPass1234 current_password=OldPass1234 "
        f"api_key=secret_api_val resend_key=re_AbCdEfGhIjKlMnOpQr "
        f"code_verifier=pkce_secret_val cookie: folio360_refresh_token=raw_rt_123 "
        f"set-cookie: folio360_refresh_token=raw_rt_456; HttpOnly "
        f"jwt={sample_jwt} verification_token=vt_secret_999"
    )
    sanitized = sanitize_log_text(raw)
    for secret in (
        "MyNewPass1234",
        "OldPass1234",
        "secret_api_val",
        "re_AbCdEfGhIjKlMnOpQr",
        "pkce_secret_val",
        "raw_rt_123",
        "raw_rt_456",
        sample_jwt,
        "vt_secret_999",
    ):
        assert secret not in sanitized
    assert REDACTED in sanitized


def test_request_validation_422_strips_input_never_echoes_passwords() -> None:
    app = FastAPI()
    register_exception_handlers(app)

    class Payload(BaseModel):
        email: str
        password: str

        def model_post_init(self, _ctx) -> None:
            if len(self.password) < 12:
                raise ValueError("Password too short")

    @app.post("/_validate")
    def _route(body: Payload = Body(...)) -> dict[str, bool]:
        return {"ok": True}

    secret_pw = "TinySecret9"
    with TestClient(app) as client:
        resp = client.post("/_validate", json={"email": "a@b.com", "password": secret_pw})
    assert resp.status_code == 422
    data = resp.json()
    assert data["error"]["details"]["code"] == "VALIDATION_ERROR"
    assert secret_pw not in resp.text
    for err in data["error"]["details"]["errors"]:
        assert "input" not in err


def test_sliding_window_rate_limiter_and_resolve_client_ip() -> None:
    now = [100.0]
    limiter = SlidingWindowRateLimiter(max_keys=2, clock=lambda: now[0])

    assert limiter.check_and_record("auth:login", "1.2.3.4", limit=2, window_seconds=60) == (
        True,
        0,
    )
    now[0] = 110.0
    assert limiter.check_and_record("auth:login", "1.2.3.4", limit=2, window_seconds=60) == (
        True,
        0,
    )
    allowed, retry_after = limiter.check_and_record(
        "auth:login", "1.2.3.4", limit=2, window_seconds=60
    )
    assert allowed is False
    assert retry_after >= 50

    now[0] = 161.0
    assert limiter.check_and_record("auth:login", "1.2.3.4", limit=2, window_seconds=60) == (
        True,
        0,
    )

    # Eviction caps memory at max_keys
    assert limiter.check_and_record("auth:login", "1.2.3.5", limit=2, window_seconds=60)[0]
    assert limiter.check_and_record("auth:login", "1.2.3.6", limit=2, window_seconds=60)[0]

    # resolve_client_ip ignores X-Forwarded-For and handles invalid/missing client
    req_valid = SimpleNamespace(
        client=SimpleNamespace(host="2001:0db8::1"),
        headers={"x-forwarded-for": "9.9.9.9"},
    )
    assert resolve_client_ip(req_valid) == "2001:db8::1"  # type: ignore[arg-type]

    req_missing = SimpleNamespace(client=None, headers={})
    assert resolve_client_ip(req_missing) == "unknown"  # type: ignore[arg-type]

    req_bad = SimpleNamespace(client=SimpleNamespace(host="not-an-ip"), headers={})
    assert resolve_client_ip(req_bad) == "invalid-client-ip"  # type: ignore[arg-type]


def test_cookie_path_derived_from_api_v1_prefix_for_set_and_clear() -> None:
    from fastapi import Response
    from pydantic import SecretStr

    from app.api.routes.auth import (
        _clear_refresh_cookie,
        _get_refresh_cookie_path,
        _set_refresh_cookie,
    )

    default_settings = Settings(_env_file=None, ENVIRONMENT="testing")
    assert _get_refresh_cookie_path(default_settings) == "/api/v1/auth"

    set_default = Response()
    _set_refresh_cookie(
        set_default,
        raw_refresh_token="rt_default_123",
        max_age_seconds=3600,
        settings=default_settings,
    )
    clear_default = Response()
    _clear_refresh_cookie(clear_default, settings=default_settings)
    assert "Path=/api/v1/auth;" in set_default.headers["set-cookie"]
    assert "Path=/api/v1/auth;" in clear_default.headers["set-cookie"]

    custom_settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        API_V1_PREFIX="/api/v2/",
    )
    assert _get_refresh_cookie_path(custom_settings) == "/api/v2/auth"

    set_custom = Response()
    _set_refresh_cookie(
        set_custom,
        raw_refresh_token="rt_custom_123",
        max_age_seconds=3600,
        settings=custom_settings,
    )
    clear_custom = Response()
    _clear_refresh_cookie(clear_custom, settings=custom_settings)
    assert "Path=/api/v2/auth;" in set_custom.headers["set-cookie"]
    assert "Path=/api/v2/auth;" in clear_custom.headers["set-cookie"]

    # Ensure SecretStr is valid when explicitly constructed in future tests
    assert isinstance(SecretStr("ok"), SecretStr)


def test_production_email_from_address_validation() -> None:
    # Development allows default .local sender
    dev_settings = Settings(_env_file=None, ENVIRONMENT="development")
    assert dev_settings.EMAIL_FROM_ADDRESS == "no-reply@folio360.local"
    dev_settings.validate_runtime_requirements()

    prod_base = {
        "_env_file": None,
        "ENVIRONMENT": "production",
        "DATABASE_URL": "postgresql+psycopg://u:p@db:5432/folio360",
        "JWT_SECRET_KEY": "x" * 32,
        "RESEND_API_KEY": "re_valid_key_1234567890",
        "FRONTEND_BASE_URL": "https://app.folio360.com",
        "CORS_ORIGINS": ["https://app.folio360.com"],
        "REFRESH_COOKIE_SECURE": True,
    }

    # Production rejects default .local sender
    with pytest.raises(RuntimeError, match="EMAIL_FROM_ADDRESS"):
        Settings(**prod_base).validate_runtime_requirements()

    # Production rejects other .local sender domains
    for bad_sender in ("alerts@custom.local", "Folio360 <noreply@mail.local>"):
        with pytest.raises(RuntimeError, match="EMAIL_FROM_ADDRESS"):
            Settings(**{**prod_base, "EMAIL_FROM_ADDRESS": bad_sender}).validate_runtime_requirements()

    # Production accepts valid configured senders
    for good_sender in ("no-reply@folio360.com", "Folio360 <no-reply@folio360.com>"):
        Settings(**{**prod_base, "EMAIL_FROM_ADDRESS": good_sender}).validate_runtime_requirements()


def test_resend_http_client_cached_by_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services import email_service as email_service_module

    email_service_module.get_resend_http_client.cache_clear()
    seen_clients: list[object] = []

    def fake_send(params, options=None):
        seen_clients.append(email_service_module.resend.default_http_client)
        return {"id": f"msg_{len(seen_clients)}"}

    monkeypatch.setattr(email_service_module.resend.Emails, "send", fake_send)

    s5 = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        RESEND_API_KEY="re_unit_mock_key_123456",
        EMAIL_SEND_TIMEOUT_SECONDS=5.0,
    )
    res1 = email_service_module.send_verification_email(
        to_email="user1@example.com",
        raw_token="raw_tok_1",
        settings=s5,
    )
    res2 = email_service_module.send_verification_email(
        to_email="user2@example.com",
        raw_token="raw_tok_2",
        settings=s5,
    )
    assert res1.sent is True and res2.sent is True
    assert len(seen_clients) == 2
    assert seen_clients[0] is seen_clients[1]

    s10 = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        RESEND_API_KEY="re_unit_mock_key_123456",
        EMAIL_SEND_TIMEOUT_SECONDS=10.0,
    )
    res3 = email_service_module.send_verification_email(
        to_email="user3@example.com",
        raw_token="raw_tok_3",
        settings=s10,
    )
    assert res3.sent is True
    assert seen_clients[2] is not seen_clients[0]


def test_authenticated_user_context_immutability_and_single_query_delegation() -> None:
    uid = uuid.uuid4()
    sample_user = User(
        id=uid,
        email="ctx.user@example.com",
        is_active=True,
        is_email_verified=True,
        auth_version=2,
    )
    auth_ctx = AuthenticatedUser(user=sample_user, token_ver=2)
    with pytest.raises(FrozenInstanceError):
        auth_ctx.token_ver = 3  # type: ignore[misc]

    settings = _dev_jwt_settings()

    class _FakeScalarResult:
        def __init__(self, row: User | None) -> None:
            self._row = row

        def scalar_one_or_none(self) -> User | None:
            return self._row

    class _FakeDB:
        def __init__(self) -> None:
            self.execute_calls = 0
            self.user_to_return: User | None = sample_user

        def execute(self, _stmt):
            self.execute_calls += 1
            return _FakeScalarResult(self.user_to_return)

    fake_db = _FakeDB()
    app = FastAPI()
    register_exception_handlers(app)
    app.dependency_overrides[get_current_settings] = lambda: settings
    app.dependency_overrides[get_db] = lambda: fake_db

    observed: dict[str, object] = {}

    @app.get("/_auth-ctx")
    def _auth_ctx_route(
        ctx: AuthenticatedUser = Depends(get_current_auth_context),
        user: User = Depends(get_current_user),
    ) -> dict[str, object]:
        observed["same_instance"] = ctx.user is user
        observed["token_ver"] = ctx.token_ver
        return {"id": str(user.id), "token_ver": ctx.token_ver}

    @app.get("/_auth-user-only")
    def _auth_user_only_route(
        user: User = Depends(get_current_user),
    ) -> dict[str, str]:
        return {"id": str(user.id)}

    valid_jwt, _ = create_access_token(user_id=uid, auth_version=2, settings=settings)
    stale_jwt, _ = create_access_token(user_id=uid, auth_version=1, settings=settings)

    with TestClient(app) as client:
        # Both dependencies in one request perform a single DB lookup
        ok_resp = client.get(
            "/_auth-ctx",
            headers={"Authorization": f"Bearer {valid_jwt}"},
        )
        assert ok_resp.status_code == 200
        assert ok_resp.json() == {"id": str(uid), "token_ver": 2}
        assert observed == {"same_instance": True, "token_ver": 2}
        assert fake_db.execute_calls == 1

        # get_current_user standalone compatibility
        user_only_resp = client.get(
            "/_auth-user-only",
            headers={"Authorization": f"Bearer {valid_jwt}"},
        )
        assert user_only_resp.status_code == 200
        assert user_only_resp.json() == {"id": str(uid)}

        # Mismatched JWT auth_version returns 401 INVALID_ACCESS_TOKEN + WWW-Authenticate
        stale_resp = client.get(
            "/_auth-ctx",
            headers={"Authorization": f"Bearer {stale_jwt}"},
        )
        assert stale_resp.status_code == 401
        assert stale_resp.headers.get("www-authenticate") == "Bearer"
        assert stale_resp.json()["error"]["details"]["code"] == "INVALID_ACCESS_TOKEN"

        # Inactive user returns 403 ACCOUNT_INACTIVE
        sample_user.is_active = False
        inactive_resp = client.get(
            "/_auth-ctx",
            headers={"Authorization": f"Bearer {valid_jwt}"},
        )
        assert inactive_resp.status_code == 403
        assert inactive_resp.json()["error"]["details"]["code"] == "ACCOUNT_INACTIVE"
