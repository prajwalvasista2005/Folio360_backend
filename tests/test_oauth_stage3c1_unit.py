"""Comprehensive unit tests for Stage 3C Substage 3C.1 (REV12).

Covers:
  1. Acyclic crypto_keys / config / security imports & decode_aes256_base64url_key
  2. Web & mobile OAuth redirect URI validation, IPv6 loopback, exact matching, build_oauth_redirect_url
  3. Stage 3C Settings validation, D19 CORS subset, production HTTPS gates, allowlist snapshots, callback URLs
  4. Query-string & OAuth key-value redaction, UvicornAccessSanitizingFilter 5-tuple safety & idempotency
"""

import asyncio
import base64
import io
import logging
import os
import secrets
import subprocess
import sys
from unittest.mock import patch

from fastapi import APIRouter
from pydantic import ValidationError
import pytest
from uvicorn.logging import AccessFormatter

from app.core.config import (
    OAUTH_EXCHANGE_CODE_EXPIRE_SECONDS,
    Settings,
    get_allowed_redirect_uris_snapshot,
    get_oauth_callback_url,
    normalize_api_v1_prefix,
)
from app.core.crypto_keys import decode_aes256_base64url_key
from app.core.logging import (
    FAILSAFE_FALLBACK_MESSAGE,
    FOLIO360_HANDLER_NAME,
    SecurityFilter,
    UvicornAccessSanitizingFilter,
    attach_protected_handler,
    protect_handler,
    protect_uvicorn_access_handler,
    protect_uvicorn_loggers,
    register_sensitive_key_names,
    sanitize_log_text,
    setup_logging,
)
from app.core.uri_policy import (
    build_oauth_redirect_url,
    canonicalize_mobile_oauth_redirect_allowlist,
    canonicalize_web_oauth_redirect_allowlist,
    match_exact_oauth_redirect_uri,
    parse_and_canonicalize_mobile_oauth_redirect_uri,
    parse_and_canonicalize_web_oauth_redirect_uri,
)
from app.main import create_app

CANONICAL_UNPADDED_KEY = secrets.token_urlsafe(32)
CANONICAL_PADDED_KEY = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def _valid_oauth_settings(**overrides) -> dict:
    params: dict = {
        "_env_file": None,
        "ENVIRONMENT": "testing",
        "OAUTH_PKCE_ENCRYPTION_KEY": CANONICAL_UNPADDED_KEY,
        "GOOGLE_CLIENT_ID": "google-client-id",
        "GOOGLE_CLIENT_SECRET": "google-client-secret",
        "GITHUB_CLIENT_ID": "github-client-id",
        "GITHUB_CLIENT_SECRET": "github-client-secret",
        "CORS_ORIGINS": ["http://localhost:5173", "https://app.folio360.com"],
        "OAUTH_ALLOWED_WEB_REDIRECT_URIS": [
            "http://localhost:5173/auth/oauth/callback",
            "https://app.folio360.com/auth/oauth/callback",
        ],
        "OAUTH_ALLOWED_MOBILE_REDIRECT_URIS": [
            "folio360://auth/callback",
            "https://app.folio360.com/mobile/callback",
        ],
    }
    params.update(overrides)
    return params


# ---------------------------------------------------------------------------
# 1. Acyclic Imports & Cryptographic Key Decoder
# ---------------------------------------------------------------------------


def test_acyclic_imports_in_any_order() -> None:
    for modules in (
        "import app.core.crypto_keys, app.core.config, app.core.security",
        "import app.core.config, app.core.security, app.core.crypto_keys",
        "import app.core.security, app.core.config, app.core.crypto_keys",
    ):
        proc = subprocess.run(
            [sys.executable, "-c", modules],
            check=False,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stderr


def test_decode_aes256_base64url_key_accepts_canonical_43_and_44_char_forms() -> None:
    raw = b"\x01\x23\x45\x67" * 8
    padded = base64.urlsafe_b64encode(raw).decode("ascii")
    unpadded = padded.rstrip("=")
    assert len(padded) == 44 and padded.endswith("=") and not padded.endswith("==")
    assert len(unpadded) == 43

    assert decode_aes256_base64url_key(unpadded, field_name="OAUTH_PKCE_ENCRYPTION_KEY") == raw
    assert decode_aes256_base64url_key(padded, field_name="OAUTH_PKCE_ENCRYPTION_KEY") == raw


def test_decode_aes256_base64url_key_rejects_malformed_and_nonzero_trailing_bits_without_leaking() -> None:
    # Construct canonical 43-char key whose last char has non-zero unused lower 2 bits.
    raw = b"\x00" * 32
    canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    assert canonical == "A" * 43
    non_canonical_01 = ("A" * 42) + "B"  # low 2 bits = 01 != 00
    non_canonical_10 = ("A" * 42) + "C"  # low 2 bits = 10 != 00
    non_canonical_11 = ("A" * 42) + "D"  # low 2 bits = 11 != 00

    standard_b64 = base64.b64encode(b"\xff\xfb" * 16).decode("ascii")  # includes '+' and '/'
    assert "+" in standard_b64 and "/" in standard_b64

    bad_inputs = [
        non_canonical_01,
        f"{non_canonical_01}=",
        non_canonical_10,
        f"{non_canonical_10}=",
        non_canonical_11,
        f"{non_canonical_11}=",
        standard_b64.rstrip("="),
        standard_b64,
        f" {canonical}",
        f"{canonical} ",
        f"{canonical}\n",
        f"{canonical[:20]} {canonical[20:]}",
        f"{canonical}==",
        f"{canonical[:10]}={canonical[11:]}",
        canonical[:-1],
        f"{canonical}A",
        ("é" * 43),
        "",
        "short-secret",
    ]

    for bad in bad_inputs:
        with pytest.raises(ValueError) as exc_info:
            decode_aes256_base64url_key(bad, field_name="TEST_PKCE_KEY")
        msg = str(exc_info.value)
        assert "TEST_PKCE_KEY" in msg
        if bad.strip():
            assert bad not in msg

    with pytest.raises(ValueError, match="TEST_PKCE_KEY"):
        decode_aes256_base64url_key(12345, field_name="TEST_PKCE_KEY")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 2. OAuth URI Security Policy & Safe Redirect Builder
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("env", ["development", "testing"])
@pytest.mark.parametrize(
    "uri,expected",
    [
        ("http://localhost:5173/auth/oauth/callback", "http://localhost:5173/auth/oauth/callback"),
        ("http://127.0.0.1:3000/callback", "http://127.0.0.1:3000/callback"),
        ("http://[::1]:5173/auth/oauth/callback", "http://[::1]:5173/auth/oauth/callback"),
        (
            "http://[0:0:0:0:0:0:0:1]:5173/auth/oauth/callback",
            "http://[::1]:5173/auth/oauth/callback",
        ),
        ("https://app.folio360.com/auth/oauth/callback", "https://app.folio360.com/auth/oauth/callback"),
    ],
)
def test_web_oauth_redirect_uri_dev_and_testing_loopback_ipv6(
    env: str,
    uri: str,
    expected: str,
) -> None:
    parsed = parse_and_canonicalize_web_oauth_redirect_uri(uri, environment=env)
    assert parsed.canonical == expected


def test_web_and_mobile_production_oauth_redirect_rules() -> None:
    # Web production rejects all http:// (including IPv6 loopback) and custom schemes
    for bad_web in (
        "http://localhost:5173/callback",
        "http://127.0.0.1:5173/callback",
        "http://[::1]:5173/callback",
        "folio360://auth/callback",
    ):
        with pytest.raises(ValueError):
            parse_and_canonicalize_web_oauth_redirect_uri(bad_web, environment="production")

    assert (
        parse_and_canonicalize_web_oauth_redirect_uri(
            "https://app.folio360.com/oauth/cb",
            environment="production",
        ).canonical
        == "https://app.folio360.com/oauth/cb"
    )

    # Mobile dev/testing accepts custom scheme (without port) and https://, rejects http://
    assert (
        parse_and_canonicalize_mobile_oauth_redirect_uri(
            "folio360://auth/callback",
            environment="development",
        ).canonical
        == "folio360://auth/callback"
    )
    assert (
        parse_and_canonicalize_mobile_oauth_redirect_uri(
            "folio360://auth/callback",
            environment="testing",
        ).canonical
        == "folio360://auth/callback"
    )
    with pytest.raises(ValueError):
        parse_and_canonicalize_mobile_oauth_redirect_uri(
            "folio360://auth:8080/callback",
            environment="development",
        )
    with pytest.raises(ValueError):
        parse_and_canonicalize_mobile_oauth_redirect_uri(
            "http://localhost:5173/callback",
            environment="development",
        )

    # Mobile production (Decision #2): strictly HTTPS Universal/App Links ONLY
    with pytest.raises(ValueError, match="https://"):
        parse_and_canonicalize_mobile_oauth_redirect_uri(
            "folio360://auth/callback",
            environment="production",
        )
    with pytest.raises(ValueError, match="https://"):
        parse_and_canonicalize_mobile_oauth_redirect_uri(
            "com.folio360.app://auth/callback",
            environment="production",
        )
    assert (
        parse_and_canonicalize_mobile_oauth_redirect_uri(
            "https://app.folio360.com/mobile/oauth",
            environment="production",
        ).canonical
        == "https://app.folio360.com/mobile/oauth"
    )


@pytest.mark.parametrize(
    "bad_uri",
    [
        "https://app.folio360.com/cb%ZZ",
        "https://app.folio360.com/cb%2",
        "https://app.folio360.com/cb%2fnext",
        "https://app.folio360.com/cb%5cnext",
        "https://app.folio360.com/%2e%2e/cb",
        "https://app.folio360.com/cb%00",
        "https://app.folio360.com/cb\\next",
        "https://user:pass@app.folio360.com/cb",
        "https://user@app.folio360.com/cb",
        "https://app.folio360.com/cb?foo=bar",
        "https://app.folio360.com/cb#frag",
        "https://app.folio360.com:443/cb",
        "http://localhost:80/cb",
        "https://[::1/cb",
        "https://[not-ipv6]/cb",
        "https://app.folio360.com:abc/cb",
        "https://app.folio360.com:0/cb",
        "https://app.folio360.com:70000/cb",
        "https://app.folio360.com:0808/cb",
        "https://app.folio360.com:/cb",
        "https://xn--bcher-kva.example/cb",
        "https://2130706433/cb",
        "https://0x7f000001/cb",
        "http://0177.0.0.1/cb",
        "https://app.folio360.com//cb",
        "https://app.folio360.com/../cb",
        "https://app.folio360.com/cb/",
        "https://app.folio360.com/cb ",
        " https://app.folio360.com/cb",
    ],
)
def test_oauth_redirect_uri_rejects_malformed_percent_separators_userinfo_fragments_ports_and_authorities(
    bad_uri: str,
) -> None:
    with pytest.raises(ValueError):
        parse_and_canonicalize_web_oauth_redirect_uri(bad_uri, environment="development")


def test_exact_allowlist_matching_and_build_oauth_redirect_url() -> None:
    allowlist = frozenset(["https://app.folio360.com/auth/oauth/callback"])

    # Exact raw match only — no silent normalization of scheme/case/trailing slash/IPv6 form
    assert (
        match_exact_oauth_redirect_uri("https://app.folio360.com/auth/oauth/callback", allowlist)
        == "https://app.folio360.com/auth/oauth/callback"
    )
    for variant in (
        "HTTPS://app.folio360.com/auth/oauth/callback",
        "https://App.Folio360.com/auth/oauth/callback",
        "https://app.folio360.com/auth/oauth/callback/",
        " https://app.folio360.com/auth/oauth/callback",
    ):
        assert match_exact_oauth_redirect_uri(variant, allowlist) is None
        with pytest.raises(ValueError):
            build_oauth_redirect_url(variant, allowlist=allowlist, code="abc")

    # Duplicate allowlist entries fail loudly
    with pytest.raises(ValueError, match="Duplicate"):
        canonicalize_web_oauth_redirect_allowlist(
            ["https://app.folio360.com/cb", "HTTPS://App.Folio360.COM/cb"],
            environment="production",
        )
    with pytest.raises(ValueError, match="Duplicate"):
        canonicalize_mobile_oauth_redirect_allowlist(
            ["folio360://auth/callback", "FOLIO360://auth/callback"],
            environment="development",
        )

    assert (
        build_oauth_redirect_url(
            "https://app.folio360.com/auth/oauth/callback",
            allowlist=allowlist,
            code="exch_123",
        )
        == "https://app.folio360.com/auth/oauth/callback?code=exch_123"
    )
    assert (
        build_oauth_redirect_url(
            "https://app.folio360.com/auth/oauth/callback",
            allowlist=allowlist,
            error="invalid_oauth_state",
        )
        == "https://app.folio360.com/auth/oauth/callback?error=invalid_oauth_state"
    )

    with pytest.raises(ValueError):
        build_oauth_redirect_url(
            "https://app.folio360.com/auth/oauth/callback",
            allowlist=allowlist,
            code="abc",
            error="err",
        )
    with pytest.raises(ValueError):
        build_oauth_redirect_url(
            "https://app.folio360.com/auth/oauth/callback",
            allowlist=allowlist,
        )


# ---------------------------------------------------------------------------
# 3. Stage 3C Settings, Snapshots & Callback URL Derivation
# ---------------------------------------------------------------------------


def test_settings_no_oauth_env_and_non_oauth_production_startup_pass() -> None:
    dev_settings = Settings(_env_file=None)
    assert dev_settings.oauth_enabled is False
    assert dev_settings.BACKEND_BASE_URL == "http://localhost:8000"
    assert OAUTH_EXCHANGE_CODE_EXPIRE_SECONDS == 60

    prod_non_oauth = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        DATABASE_URL="postgresql+psycopg://app:pass@db.internal:5432/folio360",
        JWT_SECRET_KEY="a" * 32,
        RESEND_API_KEY="re_prod_key_1234567890123456",
        EMAIL_FROM_ADDRESS="no-reply@folio360.com",
        FRONTEND_BASE_URL="https://app.folio360.com",
        CORS_ORIGINS=["https://app.folio360.com"],
        REFRESH_COOKIE_SECURE=True,
    )
    prod_non_oauth.validate_runtime_requirements()


def test_settings_oauth_validation_rules_pairing_pkce_cookies_d19_and_prod() -> None:
    # Single provider enabled works; both enabled works; padded 44-char key works
    google_only = Settings(
        **_valid_oauth_settings(
            GITHUB_CLIENT_ID=None,
            GITHUB_CLIENT_SECRET=None,
            OAUTH_PKCE_ENCRYPTION_KEY=CANONICAL_PADDED_KEY,
        )
    )
    assert google_only.oauth_enabled is True

    github_only = Settings(
        **_valid_oauth_settings(GOOGLE_CLIENT_ID=None, GOOGLE_CLIENT_SECRET=None)
    )
    assert github_only.oauth_enabled is True

    # Half-configured provider rejected
    with pytest.raises(ValidationError):
        Settings(**_valid_oauth_settings(GOOGLE_CLIENT_SECRET=None))
    with pytest.raises(ValidationError):
        Settings(**_valid_oauth_settings(GITHUB_CLIENT_ID=None))

    # Missing PKCE key rejected in all environments when any provider is configured
    with pytest.raises(ValidationError, match="OAUTH_PKCE_ENCRYPTION_KEY"):
        Settings(**_valid_oauth_settings(OAUTH_PKCE_ENCRYPTION_KEY=None))

    # _PREVIOUS without primary rejected; invalid key rejected even when OAuth disabled
    with pytest.raises(ValidationError, match="OAUTH_PKCE_ENCRYPTION_KEY"):
        Settings(_env_file=None, OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS=CANONICAL_UNPADDED_KEY)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, OAUTH_PKCE_ENCRYPTION_KEY="bad-key")

    # Pairwise cookie collisions rejected
    with pytest.raises(ValidationError, match="pairwise distinct"):
        Settings(_env_file=None, OAUTH_BINDING_COOKIE_NAME="folio360_refresh_token")
    with pytest.raises(ValidationError, match="pairwise distinct"):
        Settings(_env_file=None, OAUTH_EXCHANGE_COOKIE_NAME="folio360_oauth_binding")

    # D19: web redirect origin must be in CORS_ORIGINS
    with pytest.raises(ValidationError, match="CORS_ORIGINS"):
        Settings(
            **_valid_oauth_settings(
                CORS_ORIGINS=["https://app.folio360.com"],
                OAUTH_ALLOWED_WEB_REDIRECT_URIS=["http://localhost:5173/auth/oauth/callback"],
            )
        )

    # GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES rejects wildcard, whitespace, duplicates
    for bad_aud in (["*"], ["aud one"], ["aud1", "aud1"]):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES=bad_aud)

    # Production OAuth rejects custom mobile schemes and http BACKEND_BASE_URL
    with pytest.raises(ValidationError, match="https://"):
        Settings(
            **_valid_oauth_settings(
                ENVIRONMENT="production",
                BACKEND_BASE_URL="https://api.folio360.com",
                CORS_ORIGINS=["https://app.folio360.com"],
                OAUTH_ALLOWED_WEB_REDIRECT_URIS=["https://app.folio360.com/auth/oauth/callback"],
                OAUTH_ALLOWED_MOBILE_REDIRECT_URIS=["folio360://auth/callback"],
            )
        )

    prod_oauth = Settings(
        **_valid_oauth_settings(
            ENVIRONMENT="production",
            DATABASE_URL="postgresql+psycopg://app:pass@db.internal:5432/folio360",
            JWT_SECRET_KEY="b" * 32,
            RESEND_API_KEY="re_prod_key_1234567890123456",
            EMAIL_FROM_ADDRESS="no-reply@folio360.com",
            FRONTEND_BASE_URL="https://app.folio360.com",
            BACKEND_BASE_URL="https://api.folio360.com",
            CORS_ORIGINS=["https://app.folio360.com"],
            OAUTH_ALLOWED_WEB_REDIRECT_URIS=["https://app.folio360.com/auth/oauth/callback"],
            OAUTH_ALLOWED_MOBILE_REDIRECT_URIS=["https://app.folio360.com/mobile/callback"],
            REFRESH_COOKIE_SECURE=True,
        )
    )
    prod_oauth.validate_runtime_requirements()

    prod_http_backend = Settings(
        **_valid_oauth_settings(
            ENVIRONMENT="production",
            DATABASE_URL="postgresql+psycopg://app:pass@db.internal:5432/folio360",
            JWT_SECRET_KEY="b" * 32,
            RESEND_API_KEY="re_prod_key_1234567890123456",
            EMAIL_FROM_ADDRESS="no-reply@folio360.com",
            FRONTEND_BASE_URL="https://app.folio360.com",
            BACKEND_BASE_URL="http://localhost:8000",
            CORS_ORIGINS=["https://app.folio360.com"],
            OAUTH_ALLOWED_WEB_REDIRECT_URIS=["https://app.folio360.com/auth/oauth/callback"],
            OAUTH_ALLOWED_MOBILE_REDIRECT_URIS=["https://app.folio360.com/mobile/callback"],
            REFRESH_COOKIE_SECURE=True,
        )
    )
    with pytest.raises(RuntimeError, match="BACKEND_BASE_URL"):
        prod_http_backend.validate_runtime_requirements()


def test_immutable_allowlist_snapshot_and_callback_url_builder() -> None:
    s = Settings(
        **_valid_oauth_settings(
            API_V1_PREFIX="/custom/v2/",
            BACKEND_BASE_URL="https://api.folio360.com",
        )
    )
    web_snap = get_allowed_redirect_uris_snapshot(s, "web")
    assert isinstance(web_snap, frozenset)
    assert "http://localhost:5173/auth/oauth/callback" in web_snap

    # Mutating list afterward does not affect an already-taken immutable snapshot
    s.OAUTH_ALLOWED_WEB_REDIRECT_URIS.append("https://mutated.example/cb")
    assert "https://mutated.example/cb" not in web_snap

    assert (
        get_oauth_callback_url(s, "google")
        == "https://api.folio360.com/custom/v2/auth/oauth/google/callback"
    )
    assert (
        get_oauth_callback_url(s, "github")
        == "https://api.folio360.com/custom/v2/auth/oauth/github/callback"
    )


# ---------------------------------------------------------------------------
# 4. Logging & Uvicorn Access-Log Redaction
# ---------------------------------------------------------------------------


def test_sanitize_log_text_redacts_oauth_query_params_and_key_values() -> None:
    line = (
        'GET "/api/v1/auth/oauth/google/callback'
        "?code=auth_secret_999&state=state_secret_888&error_description=internal_secret_reason"
        '&status_code=200&error_code=NONE&client_type=web" '
        "oauth_pkce_encryption_key_previous=prevkey123 "
        "folio360_oauth_binding=bindtok456 "
        "folio360_oauth_exchange=exchcook789 "
        "exchange_code_verifier=verif000 "
        "authorization_code=ac111 oauth_state=os222"
    )
    sanitized = sanitize_log_text(line)
    for secret in (
        "auth_secret_999",
        "state_secret_888",
        "internal_secret_reason",
        "prevkey123",
        "bindtok456",
        "exchcook789",
        "verif000",
        "ac111",
        "os222",
    ):
        assert secret not in sanitized

    assert "?code=[REDACTED]" in sanitized
    assert "&state=[REDACTED]" in sanitized
    assert "&error_description=[REDACTED]" in sanitized
    assert "status_code=200" in sanitized
    assert "error_code=NONE" in sanitized
    assert "client_type=web" in sanitized


def test_uvicorn_access_filter_preserves_5tuple_redacts_across_handlers_fails_safely_and_is_idempotent() -> None:
    access_logger = logging.getLogger("uvicorn.access")
    uv_logger = logging.getLogger("uvicorn")
    uv_err_logger = logging.getLogger("uvicorn.error")
    root_logger = logging.getLogger()

    orig_state = {
        "root": (list(root_logger.handlers), list(root_logger.filters), root_logger.level),
        "access": (
            list(access_logger.handlers),
            list(access_logger.filters),
            access_logger.level,
            access_logger.propagate,
        ),
        "uv": (list(uv_logger.handlers), list(uv_logger.filters), uv_logger.level),
        "uv_err": (list(uv_err_logger.handlers), list(uv_err_logger.filters), uv_err_logger.level),
    }

    s1, s2 = io.StringIO(), io.StringIO()
    h1 = logging.StreamHandler(s1)
    h2 = logging.StreamHandler(s2)
    h1.setFormatter(AccessFormatter(fmt='%(client_addr)s - "%(request_line)s" %(status_code)s'))
    h2.setFormatter(AccessFormatter(fmt='%(client_addr)s - "%(request_line)s" %(status_code)s'))
    access_logger.handlers = [h1, h2]
    access_logger.filters = []
    access_logger.setLevel(logging.INFO)
    access_logger.propagate = True

    try:
        setup_logging(log_level="INFO")
        setup_logging(log_level="INFO")

        assert access_logger.propagate is False
        assert sum(isinstance(f, UvicornAccessSanitizingFilter) for f in access_logger.filters) == 1
        assert sum(isinstance(f, UvicornAccessSanitizingFilter) for f in h1.filters) == 1
        assert sum(isinstance(f, UvicornAccessSanitizingFilter) for f in h2.filters) == 1

        # 1. Valid 5-tuple formats cleanly via Uvicorn AccessFormatter and redacts secrets on all handlers
        access_logger.info(
            '%s - "%s %s HTTP/%s" %d',
            "127.0.0.1:51234",
            "GET",
            "/api/v1/auth/oauth/google/callback?code=secret_cb_code&state=secret_cb_state",
            "1.1",
            302,
        )
        for out in (s1.getvalue(), s2.getvalue()):
            assert "secret_cb_code" not in out
            assert "secret_cb_state" not in out
            assert "code=[REDACTED]" in out
            assert "state=[REDACTED]" in out
            assert "302" in out

        # 2. Normal non-OAuth access log preserved intact
        s1.truncate(0)
        s1.seek(0)
        access_logger.info('%s - "%s %s HTTP/%s" %d', "10.0.0.5:444", "GET", "/api/v1/health", "1.1", 200)
        assert 'GET /api/v1/health HTTP/1.1" 200' in s1.getvalue()

        # 3. Unexpected args structure (non-5-tuple) fails closed (dropped) without crashing AccessFormatter or leaking secrets
        s1.truncate(0)
        s1.seek(0)
        filt = UvicornAccessSanitizingFilter()
        bad_record = logging.LogRecord(
            name="uvicorn.access",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Unexpected access args: %s",
            args=("code=leak_me_not",),
            exc_info=None,
        )
        assert filt.filter(bad_record) is False
        assert bad_record.msg == FAILSAFE_FALLBACK_MESSAGE
        assert bad_record.args is None
        assert "leak_me_not" not in bad_record.getMessage()

        # Emitting directly through handler with AccessFormatter never raises TypeError
        access_logger.info("Malformed one-arg secret code=%s", "leak_via_accessformatter")
        assert s1.getvalue() == ""

        # 4. Direct protect_uvicorn_access_handler is idempotent
        h3 = logging.StreamHandler(io.StringIO())
        protect_uvicorn_access_handler(h3)
        protect_uvicorn_access_handler(h3)
        assert sum(isinstance(f, UvicornAccessSanitizingFilter) for f in h3.filters) == 1
    finally:
        root_logger.handlers, root_logger.filters, root_logger.level = orig_state["root"]
        (
            access_logger.handlers,
            access_logger.filters,
            access_logger.level,
            access_logger.propagate,
        ) = orig_state["access"]
        uv_logger.handlers, uv_logger.filters, uv_logger.level = orig_state["uv"]
        uv_err_logger.handlers, uv_err_logger.filters, uv_err_logger.level = orig_state["uv_err"]
        # Clean test-added folio handler if setup_logging registered one
        folio_handlers = [h for h in root_logger.handlers if h.get_name() == FOLIO360_HANDLER_NAME]
        assert len(folio_handlers) <= 1


# ---------------------------------------------------------------------------
# 5. Substage 3C.1 Audit Remediation Regression Tests (H-1..H-2, M-1..M-4, L-1..L-4)
# ---------------------------------------------------------------------------


def test_remediation_h1_malformed_uvicorn_access_records_never_crash_access_formatter() -> None:
    access_logger = logging.getLogger("uvicorn.access")
    orig = (
        list(access_logger.handlers),
        list(access_logger.filters),
        access_logger.level,
        access_logger.propagate,
    )
    stream = io.StringIO()
    handler = protect_uvicorn_access_handler(logging.StreamHandler(stream))
    handler.setFormatter(AccessFormatter(fmt='%(client_addr)s - "%(request_line)s" %(status_code)s'))
    access_logger.handlers = [handler]
    access_logger.filters = [UvicornAccessSanitizingFilter()]
    access_logger.setLevel(logging.INFO)
    access_logger.propagate = False

    try:
        # 1. Wrong tuple arity, args=None, non-numeric status_code, boolean status_code
        access_logger.info("code=secret_1arg %s", "token=secret_arg")
        access_logger.info("code=secret_no_args")
        access_logger.info('%s - "%s %s HTTP/%s" %s', "127.0.0.1", "GET", "/cb?code=abc", "1.1", "not_int")
        access_logger.info('%s - "%s %s HTTP/%s" %s', "127.0.0.1", "GET", "/cb?code=abc", "1.1", True)
        assert stream.getvalue() == ""

        # 2. Sanitizer failure drops record safely without crashing AccessFormatter
        with patch("app.core.logging.sanitize_log_text", side_effect=RuntimeError("boom")):
            access_logger.info(
                '%s - "%s %s HTTP/%s" %d',
                "127.0.0.1:1234",
                "GET",
                "/api/v1/auth/oauth/google/callback?code=dont_leak",
                "1.1",
                302,
            )
        assert stream.getvalue() == ""

        # 3. String digit status code coerced safely and formatted through AccessFormatter
        access_logger.info(
            '%s - "%s %s HTTP/%s" %s',
            "127.0.0.1:1234",
            "GET",
            "/api/v1/auth/oauth/google/callback?code=cb_secret&state=st_secret",
            "1.1",
            "302",
        )
        out = stream.getvalue()
        assert "cb_secret" not in out
        assert "st_secret" not in out
        assert "code=[REDACTED]" in out
        assert "302 Found" in out
    finally:
        (
            access_logger.handlers,
            access_logger.filters,
            access_logger.level,
            access_logger.propagate,
        ) = orig


def test_remediation_h2_non_uvicorn_5tuple_on_shared_handler_is_not_corrupted() -> None:
    stream = io.StringIO()
    shared_handler = protect_uvicorn_access_handler(logging.StreamHandler(stream))
    shared_handler.setFormatter(logging.Formatter("%(levelname)s:%(name)s:%(message)s"))

    app_logger = logging.getLogger("folio360.shared_5tuple_test")
    orig = (list(app_logger.handlers), list(app_logger.filters), app_logger.level, app_logger.propagate)
    app_logger.handlers = [shared_handler]
    app_logger.filters = []
    app_logger.setLevel(logging.INFO)
    app_logger.propagate = False

    try:
        app_logger.info(
            "user=%s password=%s token=%s oauth_state=%s attempt=%d",
            "alice",
            "PWD_5TUPLE_SECRET",
            "TOK_5TUPLE_SECRET",
            "ST_5TUPLE_SECRET",
            2,
        )
        out = stream.getvalue()
        assert "PWD_5TUPLE_SECRET" not in out
        assert "TOK_5TUPLE_SECRET" not in out
        assert "ST_5TUPLE_SECRET" not in out
        assert "user=alice" in out
        assert "password=[REDACTED]" in out
        assert "token=[REDACTED]" in out
        assert "oauth_state=[REDACTED]" in out
        assert "attempt=2" in out
    finally:
        app_logger.handlers, app_logger.filters, app_logger.level, app_logger.propagate = orig


def test_remediation_m2_and_l3_uvicorn_loggers_child_loggers_and_query_edge_cases() -> None:
    root_logger = logging.getLogger()
    uv_logger = logging.getLogger("uvicorn")
    uv_err_logger = logging.getLogger("uvicorn.error")
    uv_err_child = logging.getLogger("uvicorn.error.child_test")
    access_logger = logging.getLogger("uvicorn.access")
    access_child = logging.getLogger("uvicorn.access.child_test")

    orig = {
        "root": (list(root_logger.handlers), list(root_logger.filters), root_logger.level),
        "uv": (list(uv_logger.handlers), list(uv_logger.filters), uv_logger.level),
        "uv_err": (list(uv_err_logger.handlers), list(uv_err_logger.filters), uv_err_logger.level, uv_err_logger.propagate),
        "uv_err_child": (list(uv_err_child.handlers), list(uv_err_child.filters), uv_err_child.level, uv_err_child.propagate),
        "access": (list(access_logger.handlers), list(access_logger.filters), access_logger.level, access_logger.propagate),
        "access_child": (list(access_child.handlers), list(access_child.filters), access_child.level, access_child.propagate),
    }

    err_stream = io.StringIO()
    err_handler = logging.StreamHandler(err_stream)
    uv_err_logger.handlers = [err_handler]
    uv_err_logger.filters = []
    uv_err_logger.setLevel(logging.INFO)
    uv_err_logger.propagate = True

    access_stream = io.StringIO()
    access_handler = logging.StreamHandler(access_stream)
    access_handler.setFormatter(AccessFormatter(fmt='%(client_addr)s - "%(request_line)s" %(status_code)s'))
    access_logger.handlers = [access_handler]
    access_logger.filters = []
    access_logger.setLevel(logging.INFO)

    try:
        setup_logging(
            log_level="INFO",
            extra_sensitive_keys=["f360_ob_unit", "f360_ox_unit"],
        )

        # Handler attached AFTER setup_logging() to uvicorn.error is still protected by logger-level SecurityFilter
        late_uv_stream = io.StringIO()
        late_uv_handler = logging.StreamHandler(late_uv_stream)
        uv_err_logger.addHandler(late_uv_handler)
        uv_err_logger.error("Failed callback client_secret=%s f360_ob_unit=%s", "ERR_SEC", "CUSTOM_COOK_VAL")
        uv_err_child.error("Child error access_token=%s", "CHILD_ERR_TOK")

        for out in (err_stream.getvalue(), late_uv_stream.getvalue()):
            assert "ERR_SEC" not in out
            assert "CUSTOM_COOK_VAL" not in out
            assert "client_secret=[REDACTED]" in out
            assert "f360_ob_unit=[REDACTED]" in out
        assert "CHILD_ERR_TOK" not in err_stream.getvalue()

        # Child logger of uvicorn.access protected at handler level when propagated to uvicorn.access
        access_child.info(
            '%s - "%s %s HTTP/%s" %d',
            "127.0.0.1:9000",
            "GET",
            "/api/v1/auth/oauth/github/callback?code=child_cb_code&state=child_cb_state",
            "1.1",
            302,
        )
        access_out = access_stream.getvalue()
        assert "child_cb_code" not in access_out
        assert "child_cb_state" not in access_out
        assert "code=[REDACTED]" in access_out

        # L-3 query/matrix/fragment/encoded secret edge cases
        samples = [
            ("/cb?code=&state=ST123&status_code=200", ["ST123"], ["?code=&state=[REDACTED]", "status_code=200"]),
            ("/cb?code=SEC_C#access_token=SEC_AT&state=SEC_ST", ["SEC_C", "SEC_AT", "SEC_ST"], ["code=[REDACTED]#access_token=[REDACTED]&state=[REDACTED]"]),
            ("/cb?token=T1&id_token=IDT1&access_token=AT1&refresh_token=RT1&error_description=ED1&error_code=EC1&client_type=mobile", ["T1", "IDT1", "AT1", "RT1", "ED1"], ["error_code=EC1", "client_type=mobile"]),
            ("/cb;code=SEMI_C", ["SEMI_C"], [";code=[REDACTED]"]),
            ("next=https%3A%2F%2Fapi%2Fcb%3Fcode%3DENC_C%26state%3DENC_S", ["ENC_C", "ENC_S"], ["%3Fcode%3D[REDACTED]%26state%3D[REDACTED]"]),
            ("f360_ox_unit=CUSTOM_EXCH_SECRET", ["CUSTOM_EXCH_SECRET"], ["f360_ox_unit=[REDACTED]"]),
        ]
        for raw, hidden, expected in samples:
            cleaned = sanitize_log_text(raw)
            for s in hidden:
                assert s not in cleaned
            for exp in expected:
                assert exp in cleaned
    finally:
        register_sensitive_key_names((), replace=True)
        root_logger.handlers, root_logger.filters, root_logger.level = orig["root"]
        uv_logger.handlers, uv_logger.filters, uv_logger.level = orig["uv"]
        (
            uv_err_logger.handlers,
            uv_err_logger.filters,
            uv_err_logger.level,
            uv_err_logger.propagate,
        ) = orig["uv_err"]
        (
            uv_err_child.handlers,
            uv_err_child.filters,
            uv_err_child.level,
            uv_err_child.propagate,
        ) = orig["uv_err_child"]
        (
            access_logger.handlers,
            access_logger.filters,
            access_logger.level,
            access_logger.propagate,
        ) = orig["access"]
        (
            access_child.handlers,
            access_child.filters,
            access_child.level,
            access_child.propagate,
        ) = orig["access_child"]


def test_remediation_m1_and_l4_bare_string_allowlists_injection_and_mobile_ws_schemes() -> None:
    allowlist = frozenset(["https://app.folio360.com/auth/oauth/callback"])

    # Bare str/bytes/dict allowlists rejected explicitly
    for bad_allowlist in (
        "https://app.folio360.com/auth/oauth/callback",
        b"https://app.folio360.com/auth/oauth/callback",
        {"https://app.folio360.com/auth/oauth/callback": True},
    ):
        with pytest.raises(ValueError, match="collection"):
            match_exact_oauth_redirect_uri("https://app.folio360.com", bad_allowlist)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="collection"):
            build_oauth_redirect_url("https://app.folio360.com", allowlist=bad_allowlist, code="abc")  # type: ignore[arg-type]

    # Empty redirect_uri and empty/whitespace/control code/error rejected
    with pytest.raises(ValueError):
        build_oauth_redirect_url("", allowlist=frozenset([""]), code="abc")
    for bad_val in ("", "   ", "abc def", "abc\r\nX-Inject:1", "abc\x00"):
        with pytest.raises(ValueError):
            build_oauth_redirect_url(
                "https://app.folio360.com/auth/oauth/callback",
                allowlist=allowlist,
                code=bad_val,
            )
        with pytest.raises(ValueError):
            build_oauth_redirect_url(
                "https://app.folio360.com/auth/oauth/callback",
                allowlist=allowlist,
                error=bad_val,
            )

    # Query injection safely percent-encoded as value (cannot inject extra query param)
    built = build_oauth_redirect_url(
        "https://app.folio360.com/auth/oauth/callback",
        allowlist=allowlist,
        code="abc&admin=true",
    )
    assert built == "https://app.folio360.com/auth/oauth/callback?code=abc%26admin%3Dtrue"

    # Case-insensitive stripping of existing CODE/Error and fragment removal
    dirty_entry = "https://app.folio360.com/cb?keep=1&CODE=old&Error=old2#frag"
    cleaned_redirect = build_oauth_redirect_url(
        dirty_entry,
        allowlist=[dirty_entry],
        code="new_code",
    )
    assert cleaned_redirect == "https://app.folio360.com/cb?keep=1&code=new_code"

    # Expanded vs compressed IPv6 raw-string exact matching (no silent normalization)
    canonical_ipv6 = "http://[::1]:5173/auth/oauth/callback"
    expanded_ipv6 = "http://[0:0:0:0:0:0:0:1]:5173/auth/oauth/callback"
    assert match_exact_oauth_redirect_uri(expanded_ipv6, frozenset([canonical_ipv6])) is None

    # ws:// and wss:// rejected as mobile redirect schemes
    for scheme_uri in ("ws://app.folio360.com/cb", "wss://app.folio360.com/cb"):
        with pytest.raises(ValueError):
            parse_and_canonicalize_mobile_oauth_redirect_uri(scheme_uri, environment="development")


@pytest.mark.parametrize(
    "bad_uri",
    [
        "https://app.folio360.com/cb%0d%0aInjected:1",
        "https://app.folio360.com/cb%3ffoo=bar",
        "https://app.folio360.com/cb%23frag",
        "https://app.folio360.com/cb%252fnext",
        "https://app.folio360.com/cb%40evil",
        'https://app.folio360.com/cb"<>',
        "https://app.folio360.com/cb'evil",
        "https://bad!host'\"<>/cb",
        "https://-bad-.example.com/cb",
        "https://a.123/cb",
        "https://127.0.0.1.2/cb",
        "http://[::ffff:127.0.0.1]:5173/cb",
    ],
)
def test_remediation_m4_strict_host_path_delimiter_and_encoded_sequences_rejected(bad_uri: str) -> None:
    with pytest.raises(ValueError):
        parse_and_canonicalize_web_oauth_redirect_uri(bad_uri, environment="development")


def test_remediation_m3_l1_l2_l4_i2_configuration_hardening() -> None:
    # M-3: BACKEND_BASE_URL rejects malformed authorities, ports, backslashes, hex IPs, punycode, percent
    for bad_base in (
        "http://localhost:0",
        "http://localhost:",
        "http://localhost:08000",
        "http://localhost:80",
        "https://api.folio360.com:443",
        "https://example.com\\evil",
        "https://0x7f000001",
        "https://xn--bcher-kva.example",
        "https://api.folio360.com%2f",
        "https://bad!host.example.com",
        "http://api.folio360.com",
        "https://user:pass@api.folio360.com",
        "https://api.folio360.com/path",
        "https://api.folio360.com?a=1",
        "https://api.folio360.com#frag",
    ):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, BACKEND_BASE_URL=bad_base)

    assert (
        Settings(_env_file=None, BACKEND_BASE_URL="http://[::1]:8000").BACKEND_BASE_URL
        == "http://[::1]:8000"
    )

    # L-1: API_V1_PREFIX normalized and aligned with FastAPI APIRouter
    assert normalize_api_v1_prefix("") == ""
    assert normalize_api_v1_prefix("/") == ""
    assert normalize_api_v1_prefix("/custom/v2/") == "/custom/v2"
    s_empty_prefix = Settings(_env_file=None, API_V1_PREFIX="/", BACKEND_BASE_URL="https://api.folio360.com")
    assert s_empty_prefix.API_V1_PREFIX == ""
    assert get_oauth_callback_url(s_empty_prefix, "google") == "https://api.folio360.com/auth/oauth/google/callback"
    APIRouter(prefix=s_empty_prefix.API_V1_PREFIX)
    s_custom_prefix = Settings(_env_file=None, API_V1_PREFIX="/custom/v2/", BACKEND_BASE_URL="https://api.folio360.com")
    assert s_custom_prefix.API_V1_PREFIX == "/custom/v2"
    APIRouter(prefix=s_custom_prefix.API_V1_PREFIX)

    for bad_prefix in ("/api//v1", "/api?v=1", "/api#frag", "/api v1", "/api\\v1", "/api/../v1"):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, API_V1_PREFIX=bad_prefix)

    # L-2: RFC 6265 cookie names reject separators and invalid chars
    for bad_cookie in ("a;Path=/;b=1", "cookie=val", "a,b", "a b", "café", ""):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, OAUTH_BINDING_COOKIE_NAME=bad_cookie)
        with pytest.raises(ValidationError):
            Settings(_env_file=None, OAUTH_EXCHANGE_COOKIE_NAME=bad_cookie)

    # L-4: Non-OAuth production clears dev default mobile scheme; explicit custom scheme still rejected
    prod_non_oauth = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        DATABASE_URL="postgresql+psycopg://app:pass@db.internal:5432/folio360",
        JWT_SECRET_KEY="a" * 32,
        RESEND_API_KEY="re_prod_key_1234567890123456",
        EMAIL_FROM_ADDRESS="no-reply@folio360.com",
        FRONTEND_BASE_URL="https://app.folio360.com",
        CORS_ORIGINS=["https://app.folio360.com"],
        REFRESH_COOKIE_SECURE=True,
    )
    assert prod_non_oauth.OAUTH_ALLOWED_MOBILE_REDIRECT_URIS == []
    assert get_allowed_redirect_uris_snapshot(prod_non_oauth, "mobile") == frozenset()
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            OAUTH_ALLOWED_MOBILE_REDIRECT_URIS=["folio360://auth/callback"],
        )

    # I-2 & key rotation / bounds checks
    for bad_aud in ("*foo", "foo*"):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES=[bad_aud])

    rotated = Settings(
        **_valid_oauth_settings(OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS=CANONICAL_PADDED_KEY)
    )
    assert rotated.OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS is not None
    with pytest.raises(ValidationError):
        Settings(**_valid_oauth_settings(OAUTH_PKCE_ENCRYPTION_KEY=f" {CANONICAL_UNPADDED_KEY}"))
    with pytest.raises(ValidationError):
        Settings(**_valid_oauth_settings(GOOGLE_CLIENT_SECRET="   "))
    with pytest.raises(ValidationError):
        Settings(_env_file=None, OAUTH_HTTP_TIMEOUT_SECONDS=float("nan"))


# ---------------------------------------------------------------------------
# 6. Final Audit Remediation Regression Tests (N-1, N-2, N-3, N-4, M-2 residual, N-5)
# ---------------------------------------------------------------------------


def test_remediation_n1_shared_handler_both_filter_orders_preserve_access_and_app_logs() -> None:
    access_logger = logging.getLogger("uvicorn.access")
    app_logger = logging.getLogger("folio360.n1_shared")
    root_logger = logging.getLogger()

    orig = {
        "root": (list(root_logger.handlers), list(root_logger.filters), root_logger.level),
        "access": (list(access_logger.handlers), list(access_logger.filters), access_logger.level, access_logger.propagate),
        "app": (list(app_logger.handlers), list(app_logger.filters), app_logger.level, app_logger.propagate),
    }

    try:
        # Test BOTH explicit filter attachment orders directly on a shared handler
        for attach_order in (
            lambda h: protect_uvicorn_access_handler(protect_handler(h)),
            lambda h: protect_handler(protect_uvicorn_access_handler(h)),
        ):
            stream = io.StringIO()
            shared = attach_order(logging.StreamHandler(stream))
            shared.setFormatter(AccessFormatter(fmt='%(client_addr)s - "%(request_line)s" %(status_code)s'))

            # Idempotency check
            attach_order(shared)
            assert sum(isinstance(f, SecurityFilter) for f in shared.filters) == 1
            assert sum(isinstance(f, UvicornAccessSanitizingFilter) for f in shared.filters) == 1

            access_logger.handlers = [shared]
            access_logger.filters = []
            access_logger.setLevel(logging.INFO)
            access_logger.propagate = False

            # Valid uvicorn.access 5-tuple must be preserved, formatted, and redacted
            access_logger.info(
                '%s - "%s %s HTTP/%s" %d',
                "127.0.0.1:5000",
                "GET",
                "/api/v1/auth/oauth/google/callback?code=SECRET_N1_CODE&state=SECRET_N1_ST",
                "1.1",
                302,
            )
            out = stream.getvalue()
            assert "SECRET_N1_CODE" not in out
            assert "SECRET_N1_ST" not in out
            assert "code=[REDACTED]" in out
            assert "302 Found" in out

            # Malformed uvicorn.access record dropped safely without crashing AccessFormatter
            stream.truncate(0)
            stream.seek(0)
            access_logger.info("malformed code=%s", "LEAK_DROP")
            assert stream.getvalue() == ""

        # Shared handler registered on BOTH root (via setup_logging) and uvicorn.access
        shared_root_stream = io.StringIO()
        shared_root_handler = logging.StreamHandler(shared_root_stream)
        shared_root_handler.setFormatter(logging.Formatter("%(name)s:%(message)s"))
        root_logger.handlers = [shared_root_handler]
        root_logger.filters = []
        access_logger.handlers = [shared_root_handler]
        access_logger.filters = []
        access_logger.setLevel(logging.INFO)
        app_logger.handlers = []
        app_logger.setLevel(logging.INFO)
        app_logger.propagate = True

        setup_logging(log_level="INFO")
        access_logger.info(
            '%s - "%s %s HTTP/%s" %d',
            "127.0.0.1:5001",
            "GET",
            "/api/v1/auth/oauth/github/callback?code=SHARED_CODE&state=SHARED_ST",
            "1.1",
            302,
        )
        app_logger.info("user=%s client_secret=%s a=%s b=%s c=%s", "bob", "SHARED_CS", 1, 2, 3)

        combined = shared_root_stream.getvalue()
        assert "SHARED_CODE" not in combined
        assert "SHARED_ST" not in combined
        assert "SHARED_CS" not in combined
        assert "uvicorn.access:" in combined and "code=[REDACTED]" in combined
        assert "folio360.n1_shared:user=bob client_secret=[REDACTED] a=1 b=2 c=3" in combined
    finally:
        root_logger.handlers, root_logger.filters, root_logger.level = orig["root"]
        access_logger.handlers, access_logger.filters, access_logger.level, access_logger.propagate = orig["access"]
        app_logger.handlers, app_logger.filters, app_logger.level, app_logger.propagate = orig["app"]


def test_remediation_n2_real_startup_wires_custom_cookie_names_into_logging() -> None:
    root_logger = logging.getLogger()
    app_logger = logging.getLogger("folio360")
    uv_logger = logging.getLogger("uvicorn")
    uv_err = logging.getLogger("uvicorn.error")
    access_logger = logging.getLogger("uvicorn.access")

    orig = {
        "root": (list(root_logger.handlers), list(root_logger.filters), root_logger.level),
        "app": (list(app_logger.handlers), list(app_logger.filters), app_logger.level),
        "uv": (list(uv_logger.handlers), list(uv_logger.filters), uv_logger.level),
        "uv_err": (list(uv_err.handlers), list(uv_err.filters), uv_err.level),
        "access": (list(access_logger.handlers), list(access_logger.filters), access_logger.level, access_logger.propagate),
    }

    async def _run_lifespan(custom_settings: Settings, stream: io.StringIO) -> None:
        application = create_app(custom_settings)
        handler = protect_handler(logging.StreamHandler(stream))
        handler.setFormatter(logging.Formatter("%(levelname)s:%(name)s:%(message)s"))
        root_logger.handlers = [handler]
        async with application.router.lifespan_context(application):
            log = logging.getLogger("folio360.test.n2")
            log.info("raw f360_ob=OB_SEC_111 f360_ox=OX_SEC_222 f360_rt=RT_SEC_333 job=42")
            log.info('{"f360_ob": "OB_JSON_1", "f360_ox": "OX_JSON_2", "status_code": "200"}')
            try:
                raise RuntimeError("mismatch f360_ob=OB_EXC_3 f360_ox=OX_EXC_4")
            except RuntimeError:
                log.exception("OAuth cookie error")

    try:
        # Custom names without "cookie", "token", or "secret" substrings
        s1 = Settings(
            _env_file=None,
            ENVIRONMENT="testing",
            OAUTH_BINDING_COOKIE_NAME="f360_ob",
            OAUTH_EXCHANGE_COOKIE_NAME="f360_ox",
            REFRESH_COOKIE_NAME="f360_rt",
        )
        out1_stream = io.StringIO()
        asyncio.run(_run_lifespan(s1, out1_stream))
        out1 = out1_stream.getvalue()
        for secret in ("OB_SEC_111", "OX_SEC_222", "RT_SEC_333", "OB_JSON_1", "OX_JSON_2", "OB_EXC_3", "OX_EXC_4"):
            assert secret not in out1
        assert "f360_ob=[REDACTED]" in out1
        assert "f360_ox=[REDACTED]" in out1
        assert "f360_rt=[REDACTED]" in out1
        assert '"f360_ob": "[REDACTED]"' in out1
        assert '"f360_ox": "[REDACTED]"' in out1
        assert "job=42" in out1
        assert '"status_code": "200"' in out1

        # Second startup replaces stale registrations while defaults remain protected
        s2 = Settings(
            _env_file=None,
            ENVIRONMENT="testing",
            OAUTH_BINDING_COOKIE_NAME="f360_ob_v2",
            OAUTH_EXCHANGE_COOKIE_NAME="f360_ox_v2",
            REFRESH_COOKIE_NAME="f360_rt_v2",
        )
        out2_stream = io.StringIO()
        asyncio.run(_run_lifespan(s2, out2_stream))
        out2 = out2_stream.getvalue()
        assert "f360_ob_v2=V2_OK" not in out2
        assert "f360_ob_v2=[REDACTED]" in sanitize_log_text("f360_ob_v2=V2_OK")
        assert "f360_ob=STALE_OK" == sanitize_log_text("f360_ob=STALE_OK")
        assert "folio360_oauth_binding=[REDACTED]" in sanitize_log_text("folio360_oauth_binding=DEF_1")
    finally:
        register_sensitive_key_names((), replace=True)
        root_logger.handlers, root_logger.filters, root_logger.level = orig["root"]
        app_logger.handlers, app_logger.filters, app_logger.level = orig["app"]
        uv_logger.handlers, uv_logger.filters, uv_logger.level = orig["uv"]
        uv_err.handlers, uv_err.filters, uv_err.level = orig["uv_err"]
        access_logger.handlers, access_logger.filters, access_logger.level, access_logger.propagate = orig["access"]


def test_remediation_n3_nonce_and_oauth_nonce_redaction() -> None:
    samples = [
        ("nonce=NONCE_SEC_1", ["NONCE_SEC_1"], "nonce=[REDACTED]"),
        ("oauth_nonce=ONONCE_SEC_2", ["ONONCE_SEC_2"], "oauth_nonce=[REDACTED]"),
        ("NONCE=UPPER_N1 OAUTH_NONCE=UPPER_ON2", ["UPPER_N1", "UPPER_ON2"], "NONCE=[REDACTED] OAUTH_NONCE=[REDACTED]"),
        ('/cb?nonce=Q_NONCE_3&oauth_nonce=Q_ONONCE_4&code=Q_CODE_5&status_code=200', ["Q_NONCE_3", "Q_ONONCE_4", "Q_CODE_5"], "nonce=[REDACTED]&oauth_nonce=[REDACTED]&code=[REDACTED]&status_code=200"),
        ('{"nonce": "JSON_N_1", "oauth_nonce": "JSON_ON_2", "has_nonce": true}', ["JSON_N_1", "JSON_ON_2"], '"has_nonce": true'),
        ("has_nonce=true client_type=web", [], "has_nonce=true client_type=web"),
    ]
    for raw, hidden, expected in samples:
        sanitized = sanitize_log_text(raw)
        for secret in hidden:
            assert secret not in sanitized
        assert expected in sanitized


@pytest.mark.parametrize(
    "bad_prefix",
    [
        "/api/%2e%2e",
        "/api/%2E%2E",
        "/api/v1%2fextra",
        "/api/v1%2Fextra",
        "/api/v1%5cextra",
        "/api/v1%5Cextra",
        "/api/%252e%252e",
        "/api/v1%ZZ",
        "/api/v1%2",
        "/api/v1%",
        "/api/v1%00",
    ],
)
def test_remediation_n4_api_v1_prefix_rejects_encoded_traversal_separators_and_malformed_percent(
    bad_prefix: str,
) -> None:
    with pytest.raises(ValueError):
        normalize_api_v1_prefix(bad_prefix)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, API_V1_PREFIX=bad_prefix)


def test_remediation_m2_late_handler_child_logger_protection() -> None:
    uv_err = logging.getLogger("uvicorn.error")
    uv_err_child = logging.getLogger("uvicorn.error.late_child")
    uv_access = logging.getLogger("uvicorn.access")
    uv_access_child = logging.getLogger("uvicorn.access.late_child")
    root_logger = logging.getLogger()

    orig = {
        "root": (list(root_logger.handlers), list(root_logger.filters), root_logger.level),
        "uv_err": (list(uv_err.handlers), list(uv_err.filters), uv_err.level, uv_err.propagate),
        "uv_err_child": (list(uv_err_child.handlers), list(uv_err_child.filters), uv_err_child.level, uv_err_child.propagate),
        "uv_access": (list(uv_access.handlers), list(uv_access.filters), uv_access.level, uv_access.propagate),
        "uv_access_child": (list(uv_access_child.handlers), list(uv_access_child.filters), uv_access_child.level, uv_access_child.propagate),
    }

    try:
        setup_logging(log_level="INFO")

        # 1. Late handler attached via attach_protected_handler() on uvicorn.error
        s_err_attached = io.StringIO()
        h_err_attached = logging.StreamHandler(s_err_attached)
        attach_protected_handler(uv_err, h_err_attached)
        uv_err.setLevel(logging.INFO)
        uv_err.propagate = False

        # 2. Late handler attached manually then covered by protect_uvicorn_loggers()
        s_err_rescanned = io.StringIO()
        h_err_rescanned = logging.StreamHandler(s_err_rescanned)
        uv_err.addHandler(h_err_rescanned)
        protect_uvicorn_loggers()

        uv_err_child.error("Late child secret=%s", "LATE_CHILD_ERR_SECRET")
        uv_err_child.info("Late child normal message id=%d", 7)

        for err_out in (s_err_attached.getvalue(), s_err_rescanned.getvalue()):
            assert "LATE_CHILD_ERR_SECRET" not in err_out
            assert "secret=[REDACTED]" in err_out
            assert "Late child normal message id=7" in err_out

        # 3. Repeat for uvicorn.access.late_child with AccessFormatter
        s_acc = io.StringIO()
        h_acc = logging.StreamHandler(s_acc)
        h_acc.setFormatter(AccessFormatter(fmt='%(client_addr)s - "%(request_line)s" %(status_code)s'))
        attach_protected_handler(uv_access, h_acc)
        uv_access.setLevel(logging.INFO)

        uv_access_child.info(
            '%s - "%s %s HTTP/%s" %d',
            "127.0.0.1:6000",
            "GET",
            "/api/v1/auth/oauth/google/callback?code=LATE_CHILD_ACC_CODE&state=LATE_CHILD_ACC_ST",
            "1.1",
            302,
        )
        acc_out = s_acc.getvalue()
        assert "LATE_CHILD_ACC_CODE" not in acc_out
        assert "LATE_CHILD_ACC_ST" not in acc_out
        assert "code=[REDACTED]" in acc_out
        assert "302 Found" in acc_out
    finally:
        root_logger.handlers, root_logger.filters, root_logger.level = orig["root"]
        uv_err.handlers, uv_err.filters, uv_err.level, uv_err.propagate = orig["uv_err"]
        uv_err_child.handlers, uv_err_child.filters, uv_err_child.level, uv_err_child.propagate = orig["uv_err_child"]
        uv_access.handlers, uv_access.filters, uv_access.level, uv_access.propagate = orig["uv_access"]
        uv_access_child.handlers, uv_access_child.filters, uv_access_child.level, uv_access_child.propagate = orig["uv_access_child"]


def test_remediation_n5_encoded_param_names_and_quoted_query_values() -> None:
    cases = [
        (
            "/cb?%63ode=PCT_SECRET_1&%43%4f%44%45=PCT_SECRET_2&%73tate=PCT_ST_3&status_code=200",
            ["PCT_SECRET_1", "PCT_SECRET_2", "PCT_ST_3"],
            ["?%63ode=[REDACTED]&%43%4f%44%45=[REDACTED]&%73tate=[REDACTED]&status_code=200"],
        ),
        (
            "next=https%3A%2F%2Fapi%2Fcb%3F%63ode%3DENC_Q1%26%53tate%3DENC_Q2%26nonce%3DENC_N3",
            ["ENC_Q1", "ENC_Q2", "ENC_N3"],
            ["%3F%63ode%3D[REDACTED]%26%53tate%3D[REDACTED]%26nonce%3D[REDACTED]"],
        ),
        (
            "/cb?code=ABC'DEF&state=ST123&error_code=NONE",
            ["ABC", "DEF", "ST123"],
            ["/cb?code=[REDACTED]&state=[REDACTED]&error_code=NONE"],
        ),
        (
            '/cb?code=ABC"DEF&state=ST123',
            ["ABC", "DEF", "ST123"],
            ["/cb?code=[REDACTED]&state=[REDACTED]"],
        ),
        (
            "/cb?code=ABC'&state=ST123",
            ["ABC", "ST123"],
            ["/cb?code=[REDACTED]&state=[REDACTED]"],
        ),
        (
            'GET "/cb?code=ABC\'DEF" 302 client_type=web',
            ["ABC", "DEF"],
            ['GET "/cb?code=[REDACTED]" 302 client_type=web'],
        ),
        (
            '{"url": "/cb?code=JSON_SEC_1", "ok": true}',
            ["JSON_SEC_1"],
            ['{"url": "/cb?code=[REDACTED]", "ok": true}'],
        ),
        (
            "{'url': '/cb?code=PYDICT_SEC_1'}",
            ["PYDICT_SEC_1"],
            ["{'url': '/cb?code=[REDACTED]'}"],
        ),
    ]
    for raw, hidden, expected_parts in cases:
        once = sanitize_log_text(raw)
        twice = sanitize_log_text(once)
        assert once == twice
        for secret in hidden:
            assert secret not in once
        for part in expected_parts:
            assert part in once

    # Avoid decoding arbitrary non-param text globally
    assert sanitize_log_text("message=%68%65%6c%6c%6f") == "message=%68%65%6c%6c%6f"
