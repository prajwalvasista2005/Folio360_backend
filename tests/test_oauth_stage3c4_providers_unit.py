"""Unit tests for Stage 3C Substage 3C.4 OAuth Providers (REV12).

Covers:
  A. ensure_no_open_db_transaction guard (incl. python -O)
  B. Bounded streaming HTTP transport & fail-closed exception sanitization
  C. Google token exchange
  D. Google raw JWKS metadata validation & RSA signing key eligibility filtering
  E. HttpxJWKClient split-lock TTL, single-flight refresh, cooldown & stale fallback
  F. verify_google_id_token (NumericDate bounds/overflow, leeway, headers, claims, email)
  G. GitHub token exchange
  H. GitHub GET /user immutable subject resolution
  I. Strict GitHub /user/emails pagination URL validator (all REV12-3 cases)
  J. GitHub paginated email fetch & Link header validation
  K. GitHub verified non-noreply email selection & GitHubVerifiedEmailRequiredError
  L. Unified normalize_and_validate_oauth_email
  M. Google & GitHub authorization URL builders
  N. Safe logging & zero secret leakage in logs/exceptions/repr
  O. Provider isolation & 3C.1-3C.3 interface compatibility
"""

import base64
from collections.abc import Callable
import inspect
import json
import math
import pathlib
import secrets
import subprocess
import sys
import threading
import time
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import httpx
import jwt
from jwt.exceptions import PyJWKClientError
import pytest
from sqlalchemy.orm import Session

from app.core.config import Settings, get_oauth_callback_url
from app.core.security import (
    compute_pkce_s256_challenge,
    generate_pkce_verifier,
    hash_opaque_token,
)
import app.services.oauth_providers as oauth_providers
from app.services.oauth_providers import (
    CLOCK_SKEW_LEEWAY_SECONDS,
    GITHUB_AUTHORIZATION_ENDPOINT,
    GITHUB_EMAILS_PAGE_MAX_BYTES,
    GITHUB_TOKEN_ENDPOINT,
    GITHUB_TOKEN_MAX_BYTES,
    GITHUB_USER_ENDPOINT,
    GOOGLE_AUTHORIZATION_ENDPOINT,
    GOOGLE_JWKS_MAX_BYTES,
    GOOGLE_JWKS_URI,
    GOOGLE_TOKEN_ENDPOINT,
    GOOGLE_TOKEN_MAX_BYTES,
    JWKS_COOLDOWN_SECONDS,
    JWKS_TTL_SECONDS,
    MAX_JWKS_STALE_FALLBACK_SECONDS,
    MAX_NUMERIC_DATE,
    MIN_NUMERIC_DATE,
    GitHubEmailEntry,
    GitHubUser,
    GitHubVerifiedEmailRequiredError,
    GoogleIdentity,
    HttpxJWKClient,
    OAuthProviderError,
    OAuthTransactionGuardError,
    build_eligible_google_jwk_set,
    build_github_authorization_url,
    build_google_authorization_url,
    build_google_jwk_client,
    ensure_no_open_db_transaction,
    exchange_github_authorization_code,
    exchange_google_authorization_code,
    fetch_github_user,
    fetch_github_verified_email,
    normalize_and_validate_oauth_email,
    parse_numeric_date,
    provider_http_request,
    select_github_verified_email,
    validate_github_emails_pagination_url,
    verify_google_id_token,
)

TEST_PKCE_KEY = secrets.token_urlsafe(32)
GOOGLE_SECRET_SENTINEL = "google-secret-SENTINEL-9f1b"
GITHUB_SECRET_SENTINEL = "github-secret-SENTINEL-4a8e"
AUTH_CODE_SENTINEL = "auth-code-SENTINEL-7c2d"
PKCE_VERIFIER_SENTINEL = "pkceVERIFIERsentinel" + ("A" * 66)
assert len(PKCE_VERIFIER_SENTINEL) == 86
ACCESS_TOKEN_SENTINEL = "gho_access_SENTINEL_token_8842"
NONCE_SENTINEL = "nonce-SENTINEL-" + ("n" * 28)
assert len(NONCE_SENTINEL) == 43


def _build_oauth_settings(**overrides: Any) -> Settings:
    params: dict[str, Any] = {
        "_env_file": None,
        "ENVIRONMENT": "testing",
        "OAUTH_PKCE_ENCRYPTION_KEY": TEST_PKCE_KEY,
        "GOOGLE_CLIENT_ID": "google-client-id.apps.googleusercontent.com",
        "GOOGLE_CLIENT_SECRET": GOOGLE_SECRET_SENTINEL,
        "GITHUB_CLIENT_ID": "github-client-id-sentinel",
        "GITHUB_CLIENT_SECRET": GITHUB_SECRET_SENTINEL,
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


class _FakeDb:
    def __init__(self, *, open_tx: bool = False) -> None:
        self._open_tx = open_tx

    def in_transaction(self) -> bool:
        return self._open_tx


class _CountingStream(httpx.SyncByteStream):
    def __init__(self, chunk_size: int, chunk_count: int) -> None:
        self._chunk = b"a" * chunk_size
        self._chunk_count = chunk_count
        self.chunks_read = 0

    def __iter__(self):
        for _ in range(self._chunk_count):
            self.chunks_read += 1
            yield self._chunk


@pytest.fixture
def mock_http(monkeypatch: pytest.MonkeyPatch):
    """Patch oauth_providers.httpx.Client to record kwargs and requests via MockTransport."""
    real_client_cls = httpx.Client
    state: dict[str, Any] = {
        "handler": lambda request: httpx.Response(500, json={"error": "unconfigured"}),
        "client_kwargs": [],
        "requests": [],
    }

    def _recording_handler(request: httpx.Request) -> httpx.Response:
        state["requests"].append(request)
        resp = state["handler"](request)
        if resp.is_stream_consumed and hasattr(resp, "_content"):
            return httpx.Response(
                resp.status_code,
                headers=resp.headers.multi_items(),
                stream=httpx.ByteStream(resp._content),
                request=request,
            )
        return resp

    def _client_factory(*args: Any, **kwargs: Any) -> httpx.Client:
        state["client_kwargs"].append(dict(kwargs))
        kwargs["transport"] = httpx.MockTransport(_recording_handler)
        return real_client_cls(*args, **kwargs)

    monkeypatch.setattr(oauth_providers.httpx, "Client", _client_factory)
    return state


@pytest.fixture(scope="module")
def rsa_keys() -> dict[str, Any]:
    priv_1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_small = rsa.generate_private_key(public_exponent=65537, key_size=1024)

    def _pub_jwk(priv: rsa.RSAPrivateKey, kid: str, **extra: Any) -> dict[str, Any]:
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(priv.public_key(), as_dict=True)
        jwk["kid"] = kid
        jwk.setdefault("use", "sig")
        jwk.setdefault("alg", "RS256")
        jwk.update(extra)
        return jwk

    return {
        "priv_1": priv_1,
        "priv_2": priv_2,
        "priv_small": priv_small,
        "jwk_1": _pub_jwk(priv_1, "kid-1"),
        "jwk_2": _pub_jwk(priv_2, "kid-2"),
        "jwk_small": _pub_jwk(priv_small, "kid-small"),
    }


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _sign_raw_jwt(
    private_key: rsa.RSAPrivateKey,
    *,
    header: dict[str, Any],
    payload_json: str,
) -> str:
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(payload_json.encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"


def _base_google_claims(
    settings: Settings,
    *,
    now: float,
    nonce: str = NONCE_SENTINEL,
) -> dict[str, Any]:
    return {
        "iss": "https://accounts.google.com",
        "sub": "google-sub-1234567890",
        "aud": settings.GOOGLE_CLIENT_ID,
        "azp": settings.GOOGLE_CLIENT_ID,
        "nonce": nonce,
        "email": "Student.User@Example.COM",
        "email_verified": True,
        "iat": int(now) - 10,
        "exp": int(now) + 300,
    }


class _FakeClock:
    def __init__(self, initial: float = 1000.0) -> None:
        self.now = initial

    def __call__(self) -> float:
        return self.now


# ---------------------------------------------------------------------------
# A. Transaction Guard
# ---------------------------------------------------------------------------


def test_transaction_guard_rejects_open_tx_across_all_http_entry_points(
    mock_http: dict[str, Any],
    rsa_keys: dict[str, Any],
) -> None:
    settings = _build_oauth_settings()
    open_db = _FakeDb(open_tx=True)
    jwk_client = build_google_jwk_client(settings)

    with pytest.raises(OAuthTransactionGuardError) as exc_info:
        ensure_no_open_db_transaction(open_db)  # type: ignore[arg-type]
    assert isinstance(exc_info.value, RuntimeError)

    with pytest.raises(OAuthTransactionGuardError):
        provider_http_request(
            open_db,  # type: ignore[arg-type]
            provider="google",
            method="GET",
            url=GOOGLE_JWKS_URI,
            headers={},
            max_bytes=1024,
            timeout=2.0,
        )

    with pytest.raises(OAuthTransactionGuardError):
        exchange_google_authorization_code(
            open_db,  # type: ignore[arg-type]
            settings=settings,
            code=AUTH_CODE_SENTINEL,
            code_verifier=PKCE_VERIFIER_SENTINEL,
        )

    with pytest.raises(OAuthTransactionGuardError):
        exchange_github_authorization_code(
            open_db,  # type: ignore[arg-type]
            settings=settings,
            code=AUTH_CODE_SENTINEL,
            code_verifier=PKCE_VERIFIER_SENTINEL,
        )

    with pytest.raises(OAuthTransactionGuardError):
        fetch_github_user(
            open_db,  # type: ignore[arg-type]
            settings=settings,
            access_token=ACCESS_TOKEN_SENTINEL,
        )

    with pytest.raises(OAuthTransactionGuardError):
        fetch_github_verified_email(
            open_db,  # type: ignore[arg-type]
            settings=settings,
            access_token=ACCESS_TOKEN_SENTINEL,
        )

    assert mock_http["client_kwargs"] == []

    # Verify unbound real SQLAlchemy Session reports no open transaction cleanly
    unbound = Session()
    try:
        ensure_no_open_db_transaction(unbound)
    finally:
        unbound.close()


def test_verify_google_id_token_enforces_guard_before_jwk_lookup(
    rsa_keys: dict[str, Any],
) -> None:
    settings = _build_oauth_settings()
    now = 1_700_000_000.0
    token = jwt.encode(
        _base_google_claims(settings, now=now),
        rsa_keys["priv_1"],
        algorithm="RS256",
        headers={"kid": "kid-1"},
    )

    class _SpyJWKClient:
        called = False

        def get_signing_key_from_jwt(self, token: str) -> Any:
            self.called = True
            raise AssertionError("get_signing_key_from_jwt must not run while DB tx open")

    spy = _SpyJWKClient()
    with pytest.raises(OAuthTransactionGuardError):
        verify_google_id_token(
            _FakeDb(open_tx=True),  # type: ignore[arg-type]
            settings=settings,
            jwk_client=spy,  # type: ignore[arg-type]
            id_token=token,
            expected_nonce_hash=hash_opaque_token(NONCE_SENTINEL),
            now=now,
        )
    assert spy.called is False


def test_transaction_guard_enforced_under_python_dash_O() -> None:
    script = (
        "from app.services.oauth_providers import ensure_no_open_db_transaction, OAuthTransactionGuardError\n"
        "class Db:\n"
        "    def in_transaction(self): return True\n"
        "try:\n"
        "    ensure_no_open_db_transaction(Db())\n"
        "except OAuthTransactionGuardError:\n"
        "    print('GUARD_RAISED')\n"
        "else:\n"
        "    raise SystemExit(2)\n"
    )
    proc = subprocess.run(
        [sys.executable, "-O", "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "GUARD_RAISED" in proc.stdout


# ---------------------------------------------------------------------------
# B. Bounded Streaming Transport
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_status", [201, 204, 301, 302, 307, 308, 400, 401, 500])
def test_transport_rejects_non_200_statuses_before_reading_body(
    mock_http: dict[str, Any],
    bad_status: int,
) -> None:
    stream = _CountingStream(chunk_size=128, chunk_count=3)
    mock_http["handler"] = lambda req: httpx.Response(bad_status, stream=stream)

    with pytest.raises(OAuthProviderError) as exc_info:
        provider_http_request(
            _FakeDb(),  # type: ignore[arg-type]
            provider="google",
            method="GET",
            url="https://example.test/data",
            headers={},
            max_bytes=1024,
            timeout=4.5,
        )
    assert exc_info.value.category == "unexpected_status"
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__suppress_context__ is True
    assert stream.chunks_read == 0
    assert mock_http["client_kwargs"] == [{"timeout": 4.5, "follow_redirects": False}]


@pytest.mark.parametrize(
    "enc_headers",
    [
        [("Content-Encoding", "gzip")],
        [("Content-Encoding", "deflate")],
        [("Content-Encoding", "br")],
        [("Content-Encoding", "zstd")],
        [("Content-Encoding", "gzip, identity")],
        [("Content-Encoding", "identity"), ("Content-Encoding", "gzip")],
    ],
)
def test_transport_rejects_disallowed_content_encoding_pre_read(
    mock_http: dict[str, Any],
    enc_headers: list[tuple[str, str]],
) -> None:
    stream = _CountingStream(chunk_size=128, chunk_count=2)
    mock_http["handler"] = lambda req: httpx.Response(
        200,
        headers=enc_headers,
        stream=stream,
    )

    with pytest.raises(OAuthProviderError) as exc_info:
        provider_http_request(
            _FakeDb(),  # type: ignore[arg-type]
            provider="github",
            method="GET",
            url="https://example.test/data",
            headers={},
            max_bytes=1024,
            timeout=3.0,
        )
    assert exc_info.value.category == "unsupported_content_encoding"
    assert stream.chunks_read == 0


@pytest.mark.parametrize(
    "allowed_headers",
    [
        [],
        [("Content-Encoding", "identity")],
        [("Content-Encoding", "IDENTITY")],
        [("Content-Encoding", "")],
    ],
)
def test_transport_accepts_identity_or_absent_content_encoding_and_forces_request_header(
    mock_http: dict[str, Any],
    allowed_headers: list[tuple[str, str]],
) -> None:
    mock_http["handler"] = lambda req: httpx.Response(
        200,
        headers=allowed_headers,
        content=b'{"ok":true}',
    )

    resp = provider_http_request(
        _FakeDb(),  # type: ignore[arg-type]
        provider="google",
        method="GET",
        url="https://example.test/data",
        headers={"Accept-Encoding": "gzip"},  # must be overwritten to identity
        max_bytes=1024,
        timeout=5.0,
    )
    assert resp.payload == {"ok": True}
    assert mock_http["requests"][0].headers["accept-encoding"] == "identity"


@pytest.mark.parametrize(
    "caller_headers",
    [
        {},
        {"Accept-Encoding": "gzip"},
        {"accept-encoding": "gzip"},
        {"AcCePt-EnCoDiNg": "br"},
        {"ACCEPT-ENCODING": "deflate", "accept-encoding": "gzip"},
    ],
)
def test_transport_normalizes_accept_encoding_case_insensitively_without_duplicates(
    mock_http: dict[str, Any],
    caller_headers: dict[str, str],
) -> None:
    mock_http["handler"] = lambda req: httpx.Response(200, json={"ok": True})
    headers = {"X-Custom-Header": "keep-me", "Accept": "application/json"}
    headers.update(caller_headers)

    resp = provider_http_request(
        _FakeDb(),  # type: ignore[arg-type]
        provider="google",
        method="GET",
        url="https://example.test/headers",
        headers=headers,
        max_bytes=1024,
        timeout=5.0,
    )
    assert resp.payload == {"ok": True}
    sent = mock_http["requests"][0]
    assert sent.headers.get_list("accept-encoding") == ["identity"]
    assert sent.headers["x-custom-header"] == "keep-me"
    assert sent.headers["accept"] == "application/json"


def test_transport_enforces_exact_byte_cap_and_aborts_unbounded_stream(
    mock_http: dict[str, Any],
) -> None:
    cap = 16_384
    exact_payload = json.dumps({"pad": "x" * (cap - 11)}).encode("utf-8")
    assert len(exact_payload) == cap

    mock_http["handler"] = lambda req: httpx.Response(200, content=exact_payload)
    ok_resp = provider_http_request(
        _FakeDb(),  # type: ignore[arg-type]
        provider="github",
        method="GET",
        url="https://example.test/exact",
        headers={},
        max_bytes=cap,
        timeout=5.0,
    )
    assert "pad" in ok_resp.payload

    oversized_payload = b"{" + (b" " * (cap - 1)) + b"}"
    assert len(oversized_payload) == cap + 1
    mock_http["handler"] = lambda req: httpx.Response(200, content=oversized_payload)
    with pytest.raises(OAuthProviderError) as exc_over:
        provider_http_request(
            _FakeDb(),  # type: ignore[arg-type]
            provider="github",
            method="GET",
            url="https://example.test/over",
            headers={},
            max_bytes=cap,
            timeout=5.0,
        )
    assert exc_over.value.category == "response_too_large"

    stream = _CountingStream(chunk_size=8192, chunk_count=100)
    mock_http["handler"] = lambda req: httpx.Response(200, stream=stream)
    with pytest.raises(OAuthProviderError) as exc_stream:
        provider_http_request(
            _FakeDb(),  # type: ignore[arg-type]
            provider="github",
            method="GET",
            url="https://example.test/huge",
            headers={},
            max_bytes=cap,
            timeout=5.0,
        )
    assert exc_stream.value.category == "response_too_large"
    assert stream.chunks_read <= (cap // 8192) + 2


@pytest.mark.parametrize(
    "raw_bytes",
    [
        b"\xff\xfe\xfd",
        b'{"not_closed": ',
        b'{"num": NaN}',
        b'{"num": Infinity}',
    ],
)
def test_transport_rejects_malformed_utf8_json_and_constants(
    mock_http: dict[str, Any],
    raw_bytes: bytes,
) -> None:
    mock_http["handler"] = lambda req: httpx.Response(200, content=raw_bytes)
    with pytest.raises(OAuthProviderError) as exc_info:
        provider_http_request(
            _FakeDb(),  # type: ignore[arg-type]
            provider="google",
            method="GET",
            url="https://example.test/bad",
            headers={},
            max_bytes=1024,
            timeout=5.0,
        )
    assert exc_info.value.category == "malformed_json"
    assert exc_info.value.__cause__ is None


def test_transport_maps_timeout_and_transport_errors(
    mock_http: dict[str, Any],
) -> None:
    def _raise_timeout(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=req)

    mock_http["handler"] = _raise_timeout
    with pytest.raises(OAuthProviderError) as exc_to:
        provider_http_request(
            _FakeDb(),  # type: ignore[arg-type]
            provider="google",
            method="GET",
            url="https://example.test/timeout",
            headers={},
            max_bytes=1024,
            timeout=5.0,
        )
    assert exc_to.value.category == "timeout"
    assert exc_to.value.__cause__ is None

    def _raise_connect(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("dns fail", request=req)

    mock_http["handler"] = _raise_connect
    with pytest.raises(OAuthProviderError) as exc_tr:
        provider_http_request(
            _FakeDb(),  # type: ignore[arg-type]
            provider="github",
            method="GET",
            url="https://example.test/connect",
            headers={},
            max_bytes=1024,
            timeout=5.0,
        )
    assert exc_tr.value.category == "transport_error"
    assert exc_tr.value.__cause__ is None


# ---------------------------------------------------------------------------
# C. Google Token Exchange
# ---------------------------------------------------------------------------


def test_google_token_exchange_success_and_exact_form_fields(
    mock_http: dict[str, Any],
) -> None:
    settings = _build_oauth_settings()
    mock_http["handler"] = lambda req: httpx.Response(
        200, json={"id_token": "header.payload.sig", "access_token": "unused"}
    )

    id_token = exchange_google_authorization_code(
        _FakeDb(),  # type: ignore[arg-type]
        settings=settings,
        code=AUTH_CODE_SENTINEL,
        code_verifier=PKCE_VERIFIER_SENTINEL,
    )
    assert id_token == "header.payload.sig"
    req = mock_http["requests"][0]
    assert req.method == "POST"
    assert str(req.url) == GOOGLE_TOKEN_ENDPOINT
    assert req.headers["accept"] == "application/json"
    assert req.headers["accept-encoding"] == "identity"
    assert req.headers["content-type"] == "application/x-www-form-urlencoded"
    form = dict(parse_qsl(req.content.decode("utf-8"), keep_blank_values=True))
    assert form == {
        "grant_type": "authorization_code",
        "code": AUTH_CODE_SENTINEL,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_SECRET_SENTINEL,
        "redirect_uri": get_oauth_callback_url(settings, "google"),
        "code_verifier": PKCE_VERIFIER_SENTINEL,
    }


@pytest.mark.parametrize(
    "payload",
    [
        ["not", "a", "dict"],
        {},
        {"id_token": None},
        {"id_token": 123},
        {"id_token": "   "},
    ],
)
def test_google_token_exchange_rejects_malformed_payload(
    mock_http: dict[str, Any],
    payload: Any,
) -> None:
    settings = _build_oauth_settings()
    mock_http["handler"] = lambda req: httpx.Response(200, json=payload)

    with pytest.raises(OAuthProviderError) as exc_info:
        exchange_google_authorization_code(
            _FakeDb(),  # type: ignore[arg-type]
            settings=settings,
            code=AUTH_CODE_SENTINEL,
            code_verifier=PKCE_VERIFIER_SENTINEL,
        )
    assert exc_info.value.provider == "google"
    assert exc_info.value.category in {"malformed_token_response", "missing_id_token"}


def test_google_token_exchange_rejects_unconfigured_and_bad_inputs_pre_http(
    mock_http: dict[str, Any],
) -> None:
    unconfigured = _build_oauth_settings(
        GOOGLE_CLIENT_ID=None,
        GOOGLE_CLIENT_SECRET=None,
    )
    with pytest.raises(OAuthProviderError) as exc_unconf:
        exchange_google_authorization_code(
            _FakeDb(),  # type: ignore[arg-type]
            settings=unconfigured,
            code=AUTH_CODE_SENTINEL,
            code_verifier=PKCE_VERIFIER_SENTINEL,
        )
    assert exc_unconf.value.category == "not_configured"

    settings = _build_oauth_settings()
    with pytest.raises(OAuthProviderError) as exc_code:
        exchange_google_authorization_code(
            _FakeDb(),  # type: ignore[arg-type]
            settings=settings,
            code="bad code with space",
            code_verifier=PKCE_VERIFIER_SENTINEL,
        )
    assert exc_code.value.category == "invalid_authorization_code"

    with pytest.raises(OAuthProviderError) as exc_ver:
        exchange_google_authorization_code(
            _FakeDb(),  # type: ignore[arg-type]
            settings=settings,
            code=AUTH_CODE_SENTINEL,
            code_verifier="too-short",
        )
    assert exc_ver.value.category == "invalid_code_verifier"
    assert mock_http["requests"] == []


# ---------------------------------------------------------------------------
# D. Google JWKS Validation & Eligibility Filtering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("private_field", ["d", "p", "q", "dp", "dq", "qi", "oth"])
def test_jwks_prepass_rejects_any_private_key_field(
    rsa_keys: dict[str, Any],
    private_field: str,
) -> None:
    bad_key = dict(rsa_keys["jwk_2"], **{private_field: "secret"})
    # Even if placed after a valid RSA key or on a non-RSA key, pre-pass must reject entire JWKS
    payload = {"keys": [dict(rsa_keys["jwk_1"]), bad_key]}
    with pytest.raises(PyJWKClientError):
        build_eligible_google_jwk_set(payload)


@pytest.mark.parametrize(
    "bad_jwk_override",
    [
        {"kid": None},
        {"kid": 123},
        {"kid": ""},
        {"kid": "k" * 257},
        {"kid": " kid-1"},
        {"kid": "kid 1"},
        {"kid": "kid\x01"},
        {"kid": "kid\x7f"},
        {"kty": ""},
        {"kty": " RSA"},
        {"kty": 42},
        {"use": "invalid"},
        {"use": 1},
        {"key_ops": []},
        {"key_ops": "verify"},
        {"key_ops": [""]},
        {"key_ops": ["   "]},
        {"key_ops": [123]},
    ],
)
def test_jwks_prepass_rejects_metadata_defects_even_on_non_rsa_or_enc_keys(
    rsa_keys: dict[str, Any],
    bad_jwk_override: dict[str, Any],
) -> None:
    ec_jwk = {"kty": "EC", "crv": "P-256", "kid": "ec-1", "x": "aa", "y": "bb", "use": "sig"}
    ec_jwk.update(bad_jwk_override)
    payload = {"keys": [dict(rsa_keys["jwk_1"]), ec_jwk]}
    with pytest.raises(PyJWKClientError):
        build_eligible_google_jwk_set(payload)


def test_jwks_prepass_rejects_missing_kid_duplicate_kid_and_non_dict_entries(
    rsa_keys: dict[str, Any],
) -> None:
    no_kid = dict(rsa_keys["jwk_1"])
    del no_kid["kid"]
    with pytest.raises(PyJWKClientError):
        build_eligible_google_jwk_set({"keys": [no_kid]})

    dup_payload = {
        "keys": [
            dict(rsa_keys["jwk_1"]),
            dict(rsa_keys["jwk_2"], kid="kid-1"),
        ]
    }
    with pytest.raises(PyJWKClientError):
        build_eligible_google_jwk_set(dup_payload)

    with pytest.raises(PyJWKClientError):
        build_eligible_google_jwk_set({"keys": [dict(rsa_keys["jwk_1"]), "not-a-dict"]})

    with pytest.raises(PyJWKClientError):
        build_eligible_google_jwk_set({"keys": []})


def test_jwks_filtering_skips_ec_enc_rs512_small_rsa_and_requires_one_eligible(
    rsa_keys: dict[str, Any],
) -> None:
    ec_key = {"kty": "EC", "crv": "P-256", "kid": "ec-1", "x": "aa", "y": "bb", "use": "sig"}
    enc_rsa = dict(rsa_keys["jwk_2"], kid="enc-1", use="enc")
    rs512_rsa = dict(rsa_keys["jwk_2"], kid="rs512-1", alg="RS512")
    wrap_ops_rsa = dict(
        rsa_keys["jwk_2"], kid="wrap-1", key_ops=["verify", "decrypt"]
    )
    small_rsa = dict(rsa_keys["jwk_small"])

    # Ineligible-only JWKS fails
    with pytest.raises(PyJWKClientError):
        build_eligible_google_jwk_set({"keys": [ec_key, enc_rsa, rs512_rsa, wrap_ops_rsa, small_rsa]})

    # Mixed JWKS preserves only valid >=2048 RS256 signing keys
    valid_ops = dict(rsa_keys["jwk_2"], key_ops=["verify"])
    jwk_set = build_eligible_google_jwk_set(
        {"keys": [ec_key, enc_rsa, rs512_rsa, wrap_ops_rsa, small_rsa, dict(rsa_keys["jwk_1"]), valid_ops]}
    )
    assert [k.key_id for k in jwk_set.keys] == ["kid-1", "kid-2"]


def test_jwks_filtering_alg_absent_rs256_null_other_and_wrong_type(
    rsa_keys: dict[str, Any],
) -> None:
    alg_absent = dict(rsa_keys["jwk_1"])
    del alg_absent["alg"]
    alg_rs256 = dict(rsa_keys["jwk_2"], alg="RS256")

    # Both absent alg and exact "RS256" are eligible and retained
    retained = build_eligible_google_jwk_set({"keys": [alg_absent, alg_rs256]})
    assert [k.key_id for k in retained.keys] == ["kid-1", "kid-2"]

    # Explicit null, other algs, and non-str alg types are ineligible
    for bad_alg in (None, "RS384", 256, True, ["RS256"]):
        ineligible = dict(rsa_keys["jwk_2"], kid="bad-alg-kid", alg=bad_alg)
        with pytest.raises(PyJWKClientError):
            build_eligible_google_jwk_set({"keys": [ineligible]})

        mixed = build_eligible_google_jwk_set({"keys": [alg_absent, ineligible]})
        assert [k.key_id for k in mixed.keys] == ["kid-1"]


# ---------------------------------------------------------------------------
# E. HttpxJWKClient Split-Lock TTL, Single-Flight, Cooldown & Stale Fallback
# ---------------------------------------------------------------------------


def test_httpx_jwk_client_init_cache_disabled_and_bounded_fetch(
    mock_http: dict[str, Any],
    rsa_keys: dict[str, Any],
) -> None:
    client = HttpxJWKClient(timeout=4.0)
    assert client.jwk_set_cache is None

    mock_http["handler"] = lambda req: httpx.Response(
        200,
        content=b"{" + (b" " * GOOGLE_JWKS_MAX_BYTES) + b"}",
    )
    with pytest.raises(PyJWKClientError):
        client.get_jwk_set()

    mock_http["handler"] = lambda req: httpx.Response(
        200,
        json={"keys": [rsa_keys["jwk_1"]]},
    )
    # Wait beyond cooldown via custom client with clock
    clock = _FakeClock(initial=1000.0)
    timed_client = HttpxJWKClient(timeout=4.0, clock=clock)
    jwk_set = timed_client.get_jwk_set()
    assert [k.key_id for k in jwk_set.keys] == ["kid-1"]
    assert mock_http["requests"][0].headers["accept-encoding"] == "identity"


def test_httpx_jwk_client_ttl_cooldown_and_stale_fallback(
    monkeypatch: pytest.MonkeyPatch,
    rsa_keys: dict[str, Any],
) -> None:
    clock = _FakeClock(initial=1000.0)
    client = HttpxJWKClient(timeout=5.0, clock=clock)
    fetch_calls = 0
    mode = "ok_1"

    def _fake_fetch() -> dict[str, Any]:
        nonlocal fetch_calls
        fetch_calls += 1
        if mode == "fail":
            raise OAuthProviderError("google", "transport_error")
        if mode == "ok_2":
            return {"keys": [rsa_keys["jwk_2"]]}
        return {"keys": [rsa_keys["jwk_1"]]}

    monkeypatch.setattr(client, "fetch_data", _fake_fetch)

    # Cold-start failure sets cooldown; retry inside 30s does not hit fetch_data again
    mode = "fail"
    with pytest.raises(PyJWKClientError):
        client.get_jwk_set()
    assert fetch_calls == 1

    clock.now += JWKS_COOLDOWN_SECONDS - 1
    with pytest.raises(PyJWKClientError):
        client.get_jwk_set()
    assert fetch_calls == 1

    # Past cooldown -> succeeds (cached_at = 1031.0, last_refresh_attempt_at = 1031.0)
    clock.now += 2
    mode = "ok_1"
    s1 = client.get_jwk_set()
    assert [k.key_id for k in s1.keys] == ["kid-1"]
    assert fetch_calls == 2

    # Fresh (< 300s) and still inside 30s cooldown -> cached read + no refresh on missing kid
    clock.now += 5
    s2 = client.get_jwk_set(refresh=False)
    assert s2 is s1
    assert fetch_calls == 2
    with pytest.raises(PyJWKClientError):
        client.get_signing_key("unknown-kid")
    assert fetch_calls == 2

    # Still fresh (< 300s from 1031.0) but past 30s cooldown -> missing kid triggers 1 refresh, still raises
    clock.now = 1031.0 + JWKS_TTL_SECONDS - 5
    with pytest.raises(PyJWKClientError):
        client.get_signing_key("unknown-kid")
    assert fetch_calls == 3

    # Advance past TTL -> failure serves stale fallback up to MAX_JWKS_STALE_FALLBACK_SECONDS
    clock.now = 1031.0 + JWKS_TTL_SECONDS - 5 + JWKS_TTL_SECONDS + 5
    mode = "fail"
    stale_ok = client.get_jwk_set()
    assert [k.key_id for k in stale_ok.keys] == ["kid-1"]
    assert fetch_calls == 4

    # Exceed MAX_JWKS_STALE_FALLBACK_SECONDS -> raises after cooldown expires
    clock.now = 1031.0 + JWKS_TTL_SECONDS - 5 + MAX_JWKS_STALE_FALLBACK_SECONDS + 1
    with pytest.raises(PyJWKClientError):
        client.get_jwk_set()
    assert fetch_calls == 5

    # Recovery + key rotation via get_signing_key
    clock.now += JWKS_COOLDOWN_SECONDS + 1
    mode = "ok_1"
    assert client.get_signing_key("kid-1").key_id == "kid-1"
    assert fetch_calls == 6

    clock.now += JWKS_COOLDOWN_SECONDS + 1
    mode = "ok_2"
    assert client.get_signing_key("kid-2").key_id == "kid-2"
    assert fetch_calls == 7

    # Invalid kid rejected without fetch
    with pytest.raises(PyJWKClientError):
        client.get_signing_key("bad kid")
    assert fetch_calls == 7


def test_httpx_jwk_client_split_lock_concurrency_and_non_blocking_fresh_reads(
    monkeypatch: pytest.MonkeyPatch,
    rsa_keys: dict[str, Any],
) -> None:
    clock = _FakeClock(initial=1000.0)
    client = HttpxJWKClient(timeout=5.0, clock=clock)
    fetch_count = 0
    fetch_entered = threading.Event()
    release_fetch = threading.Event()

    def _blocking_fetch() -> dict[str, Any]:
        nonlocal fetch_count
        fetch_count += 1
        fetch_entered.set()
        release_fetch.wait(timeout=5.0)
        return {"keys": [rsa_keys["jwk_1"]]}

    monkeypatch.setattr(client, "fetch_data", _blocking_fetch)

    results: list[Any] = []
    errors: list[BaseException] = []

    def _worker() -> None:
        try:
            results.append(client.get_jwk_set(refresh=False))
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    t1 = threading.Thread(target=_worker)
    t2 = threading.Thread(target=_worker)
    t1.start()
    assert fetch_entered.wait(timeout=2.0)
    t2.start()
    time.sleep(0.05)
    release_fetch.set()
    t1.join(timeout=2.0)
    t2.join(timeout=2.0)

    assert not errors
    assert len(results) == 2
    assert fetch_count == 1  # single-flight cooldown/freshness deduplication

    # While another thread holds _refresh_lock, fresh read returns without blocking
    with client._refresh_lock:
        fresh = client.get_jwk_set(refresh=False)
        assert [k.key_id for k in fresh.keys] == ["kid-1"]


# ---------------------------------------------------------------------------
# F. verify_google_id_token & NumericDate Bounds
# ---------------------------------------------------------------------------


def test_parse_numeric_date_types_and_overflow_safety() -> None:
    assert parse_numeric_date(MIN_NUMERIC_DATE) == 1.0
    assert parse_numeric_date(MAX_NUMERIC_DATE) == float(MAX_NUMERIC_DATE)
    assert parse_numeric_date(1_700_000_000.5) == 1_700_000_000.5

    for invalid in (
        True,
        False,
        None,
        "1700000000",
        0,
        -100,
        MAX_NUMERIC_DATE + 1,
        10**400,  # would OverflowError if float(val) ran before bounds check
        math.nan,
        math.inf,
        -math.inf,
        {},
        [],
    ):
        with pytest.raises(OAuthProviderError) as exc_info:
            parse_numeric_date(invalid)
        assert exc_info.value.category == "invalid_numeric_date"


def test_verify_google_id_token_success_email_absent_and_unverified_allowed(
    monkeypatch: pytest.MonkeyPatch,
    rsa_keys: dict[str, Any],
) -> None:
    settings = _build_oauth_settings()
    now = 1_700_000_000.0
    jwk_client = build_google_jwk_client(settings)
    monkeypatch.setattr(jwk_client, "fetch_data", lambda: {"keys": [rsa_keys["jwk_1"]]})

    compare_calls = 0
    real_compare = oauth_providers.hmac.compare_digest

    def _spy_compare(a: Any, b: Any) -> bool:
        nonlocal compare_calls
        compare_calls += 1
        return real_compare(a, b)

    monkeypatch.setattr(oauth_providers.hmac, "compare_digest", _spy_compare)

    # Full verified identity with normalization preserved (+tag and dots kept)
    claims = _base_google_claims(settings, now=now)
    claims["email"] = "  First.Last+work@Example.COM  "
    token = jwt.encode(claims, rsa_keys["priv_1"], algorithm="RS256", headers={"kid": "kid-1"})

    ident = verify_google_id_token(
        _FakeDb(),  # type: ignore[arg-type]
        settings=settings,
        jwk_client=jwk_client,
        id_token=token,
        expected_nonce_hash=hash_opaque_token(NONCE_SENTINEL),
        now=now,
    )
    assert ident == GoogleIdentity(
        provider_user_id="google-sub-1234567890",
        email="first.last+work@example.com",
        email_verified=True,
    )
    assert compare_calls == 1

    # Absent email allowed -> (None, False)
    claims_no_email = _base_google_claims(settings, now=now)
    del claims_no_email["email"]
    claims_no_email["email_verified"] = True  # must become False because email is None
    token_no_email = jwt.encode(
        claims_no_email, rsa_keys["priv_1"], algorithm="RS256", headers={"kid": "kid-1"}
    )
    ident_no_email = verify_google_id_token(
        _FakeDb(),  # type: ignore[arg-type]
        settings=settings,
        jwk_client=jwk_client,
        id_token=token_no_email,
        expected_nonce_hash=hash_opaque_token(NONCE_SENTINEL),
        now=now,
    )
    assert ident_no_email == GoogleIdentity(
        provider_user_id="google-sub-1234567890",
        email=None,
        email_verified=False,
    )

    # email_verified=False allowed (locked refinement for returning Google accounts)
    claims_unverified = _base_google_claims(settings, now=now)
    claims_unverified["email_verified"] = False
    token_unverified = jwt.encode(
        claims_unverified, rsa_keys["priv_1"], algorithm="RS256", headers={"kid": "kid-1"}
    )
    ident_unverified = verify_google_id_token(
        _FakeDb(),  # type: ignore[arg-type]
        settings=settings,
        jwk_client=jwk_client,
        id_token=token_unverified,
        expected_nonce_hash=hash_opaque_token(NONCE_SENTINEL),
        now=now,
    )
    assert ident_unverified.email == "student.user@example.com"
    assert ident_unverified.email_verified is False


def test_verify_google_id_token_leeway_and_raw_edge_payloads(
    monkeypatch: pytest.MonkeyPatch,
    rsa_keys: dict[str, Any],
) -> None:
    settings = _build_oauth_settings()
    now = 1_700_000_000.0
    jwk_client = build_google_jwk_client(settings)
    monkeypatch.setattr(jwk_client, "fetch_data", lambda: {"keys": [rsa_keys["jwk_1"]]})
    nonce_hash = hash_opaque_token(NONCE_SENTINEL)

    # Exact +30s leeway allowed; +31s rejected for exp, iat, nbf
    for claim_updates, should_pass in [
        ({"exp": int(now) - CLOCK_SKEW_LEEWAY_SECONDS}, True),
        ({"exp": int(now) - CLOCK_SKEW_LEEWAY_SECONDS - 1}, False),
        ({"iat": int(now) + CLOCK_SKEW_LEEWAY_SECONDS}, True),
        ({"iat": int(now) + CLOCK_SKEW_LEEWAY_SECONDS + 1}, False),
        ({"nbf": int(now) + CLOCK_SKEW_LEEWAY_SECONDS}, True),
        ({"nbf": int(now) + CLOCK_SKEW_LEEWAY_SECONDS + 1}, False),
    ]:
        claims = _base_google_claims(settings, now=now)
        claims.update(claim_updates)
        tok = jwt.encode(claims, rsa_keys["priv_1"], algorithm="RS256", headers={"kid": "kid-1"})
        if should_pass:
            verify_google_id_token(
                _FakeDb(),  # type: ignore[arg-type]
                settings=settings,
                jwk_client=jwk_client,
                id_token=tok,
                expected_nonce_hash=nonce_hash,
                now=now,
            )
        else:
            with pytest.raises(OAuthProviderError):
                verify_google_id_token(
                    _FakeDb(),  # type: ignore[arg-type]
                    settings=settings,
                    jwk_client=jwk_client,
                    id_token=tok,
                    expected_nonce_hash=nonce_hash,
                    now=now,
                )

    # Massive integer exp (10**400) & bool exp rejected as OAuthProviderError (no OverflowError)
    huge_payload = (
        f'{{"iss":"https://accounts.google.com","sub":"sub1","aud":"{settings.GOOGLE_CLIENT_ID}",'
        f'"nonce":"{NONCE_SENTINEL}","iat":{int(now)},"exp":{"9" * 400}}}'
    )
    huge_tok = _sign_raw_jwt(rsa_keys["priv_1"], header={"alg": "RS256", "kid": "kid-1"}, payload_json=huge_payload)
    with pytest.raises(OAuthProviderError) as exc_huge:
        verify_google_id_token(
            _FakeDb(),  # type: ignore[arg-type]
            settings=settings,
            jwk_client=jwk_client,
            id_token=huge_tok,
            expected_nonce_hash=nonce_hash,
            now=now,
        )
    assert exc_huge.value.category == "invalid_numeric_date"

    bool_claims = _base_google_claims(settings, now=now)
    bool_claims["exp"] = True
    bool_tok = jwt.encode(bool_claims, rsa_keys["priv_1"], algorithm="RS256", headers={"kid": "kid-1"})
    with pytest.raises(OAuthProviderError) as exc_bool:
        verify_google_id_token(
            _FakeDb(),  # type: ignore[arg-type]
            settings=settings,
            jwk_client=jwk_client,
            id_token=bool_tok,
            expected_nonce_hash=nonce_hash,
            now=now,
        )
    assert exc_bool.value.category == "invalid_numeric_date"


@pytest.mark.parametrize(
    "bad_headers",
    [
        {"alg": "HS256", "kid": "kid-1"},
        {"alg": "none", "kid": "kid-1"},
        {"kid": "kid-1"},
        {"alg": "RS256"},
        {"alg": "RS256", "kid": ""},
        {"alg": "RS256", "kid": "bad kid"},
    ],
)
def test_verify_google_id_token_rejects_bad_headers_before_jwk_lookup(
    rsa_keys: dict[str, Any],
    bad_headers: dict[str, Any],
) -> None:
    settings = _build_oauth_settings()
    now = 1_700_000_000.0
    tok = _sign_raw_jwt(
        rsa_keys["priv_1"],
        header=bad_headers,
        payload_json=json.dumps(_base_google_claims(settings, now=now)),
    )

    class _SpyJWK:
        called = False

        def get_signing_key_from_jwt(self, token: str) -> Any:
            self.called = True
            raise AssertionError("Must not resolve JWK on rejected header")

    spy = _SpyJWK()
    with pytest.raises(OAuthProviderError):
        verify_google_id_token(
            _FakeDb(),  # type: ignore[arg-type]
            settings=settings,
            jwk_client=spy,  # type: ignore[arg-type]
            id_token=tok,
            expected_nonce_hash=hash_opaque_token(NONCE_SENTINEL),
            now=now,
        )
    assert spy.called is False


def test_verify_google_id_token_aud_azp_iss_nonce_sub_email_and_sig_cases(
    monkeypatch: pytest.MonkeyPatch,
    rsa_keys: dict[str, Any],
) -> None:
    settings = _build_oauth_settings(
        GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES=["ios-client-id.apps.googleusercontent.com"]
    )
    now = 1_700_000_000.0
    jwk_client = build_google_jwk_client(settings)
    monkeypatch.setattr(jwk_client, "fetch_data", lambda: {"keys": [rsa_keys["jwk_1"]]})
    nonce_hash = hash_opaque_token(NONCE_SENTINEL)

    # Multi-audience list with trusted additional aud + valid azp succeeds; bare "accounts.google.com" iss succeeds
    ok_multi = _base_google_claims(settings, now=now)
    ok_multi["iss"] = "accounts.google.com"
    ok_multi["aud"] = [settings.GOOGLE_CLIENT_ID, "ios-client-id.apps.googleusercontent.com"]
    ok_multi["azp"] = settings.GOOGLE_CLIENT_ID
    tok_multi = jwt.encode(ok_multi, rsa_keys["priv_1"], algorithm="RS256", headers={"kid": "kid-1"})
    verify_google_id_token(
        _FakeDb(),  # type: ignore[arg-type]
        settings=settings,
        jwk_client=jwk_client,
        id_token=tok_multi,
        expected_nonce_hash=nonce_hash,
        now=now,
    )

    bad_claim_mutations: list[Callable[[dict[str, Any]], None]] = [
        lambda c: c.__setitem__("iss", "https://evil.example.com"),
        lambda c: c.__setitem__("aud", "other-client"),
        lambda c: c.__setitem__("aud", [settings.GOOGLE_CLIENT_ID, "untrusted-client"]),
        lambda c: c.__setitem__("aud", [settings.GOOGLE_CLIENT_ID, settings.GOOGLE_CLIENT_ID]),
        lambda c: c.__setitem__("aud", []),
        lambda c: (c.__setitem__("aud", [settings.GOOGLE_CLIENT_ID, "ios-client-id.apps.googleusercontent.com"]), c.pop("azp", None)),
        lambda c: c.__setitem__("azp", "ios-client-id.apps.googleusercontent.com"),
        lambda c: c.__setitem__("nonce", "wrong-nonce"),
        lambda c: c.pop("nonce", None),
        lambda c: c.__setitem__("sub", ""),
        lambda c: c.__setitem__("sub", "a" * 256),
        lambda c: c.__setitem__("sub", " sub-space"),
        lambda c: c.__setitem__("email", "not-an-email"),
        lambda c: c.__setitem__("email", 12345),
        lambda c: c.__setitem__("email_verified", "true"),
    ]
    for mutate in bad_claim_mutations:
        claims = _base_google_claims(settings, now=now)
        mutate(claims)
        tok = jwt.encode(claims, rsa_keys["priv_1"], algorithm="RS256", headers={"kid": "kid-1"})
        with pytest.raises(OAuthProviderError):
            verify_google_id_token(
                _FakeDb(),  # type: ignore[arg-type]
                settings=settings,
                jwk_client=jwk_client,
                id_token=tok,
                expected_nonce_hash=nonce_hash,
                now=now,
            )

    # Signed with wrong private key under known kid-1 -> invalid_id_token
    wrong_sig_tok = jwt.encode(
        _base_google_claims(settings, now=now),
        rsa_keys["priv_2"],
        algorithm="RS256",
        headers={"kid": "kid-1"},
    )
    with pytest.raises(OAuthProviderError) as exc_sig:
        verify_google_id_token(
            _FakeDb(),  # type: ignore[arg-type]
            settings=settings,
            jwk_client=jwk_client,
            id_token=wrong_sig_tok,
            expected_nonce_hash=nonce_hash,
            now=now,
        )
    assert exc_sig.value.category == "invalid_id_token"

    # Unknown kid -> signing_key_unavailable
    unknown_kid_tok = jwt.encode(
        _base_google_claims(settings, now=now),
        rsa_keys["priv_1"],
        algorithm="RS256",
        headers={"kid": "unknown-kid"},
    )
    with pytest.raises(OAuthProviderError) as exc_kid:
        verify_google_id_token(
            _FakeDb(),  # type: ignore[arg-type]
            settings=settings,
            jwk_client=jwk_client,
            id_token=unknown_kid_tok,
            expected_nonce_hash=nonce_hash,
            now=now,
        )
    assert exc_kid.value.category == "signing_key_unavailable"


# ---------------------------------------------------------------------------
# G. GitHub Token Exchange & H. GitHub /user
# ---------------------------------------------------------------------------


def test_github_token_exchange_success_and_error_cases(
    mock_http: dict[str, Any],
) -> None:
    settings = _build_oauth_settings()
    mock_http["handler"] = lambda req: httpx.Response(
        200, json={"access_token": ACCESS_TOKEN_SENTINEL, "token_type": "bearer"}
    )

    token = exchange_github_authorization_code(
        _FakeDb(),  # type: ignore[arg-type]
        settings=settings,
        code=AUTH_CODE_SENTINEL,
        code_verifier=PKCE_VERIFIER_SENTINEL,
    )
    assert token == ACCESS_TOKEN_SENTINEL
    req = mock_http["requests"][0]
    assert req.method == "POST"
    assert str(req.url) == GITHUB_TOKEN_ENDPOINT
    assert req.headers["user-agent"] == f"{settings.APP_NAME}/{settings.APP_VERSION}"
    assert req.headers["accept"] == "application/json"
    form = dict(parse_qsl(req.content.decode("utf-8"), keep_blank_values=True))
    assert form == {
        "client_id": settings.GITHUB_CLIENT_ID,
        "client_secret": GITHUB_SECRET_SENTINEL,
        "code": AUTH_CODE_SENTINEL,
        "redirect_uri": get_oauth_callback_url(settings, "github"),
        "code_verifier": PKCE_VERIFIER_SENTINEL,
    }

    for bad_payload in (
        {"error": "bad_verification_code", "error_description": "expired"},
        {"access_token": ""},
        {"access_token": "   "},
        {"access_token": "tok with space"},
        {"access_token": 123},
        ["not-dict"],
    ):
        mock_http["handler"] = lambda req, p=bad_payload: httpx.Response(200, json=p)
        with pytest.raises(OAuthProviderError):
            exchange_github_authorization_code(
                _FakeDb(),  # type: ignore[arg-type]
                settings=settings,
                code=AUTH_CODE_SENTINEL,
                code_verifier=PKCE_VERIFIER_SENTINEL,
            )

    # Cap = 16_384 bytes -> 16_385 fails
    mock_http["handler"] = lambda req: httpx.Response(
        200, content=b"{" + (b" " * (GITHUB_TOKEN_MAX_BYTES - 1)) + b"}"
    )
    with pytest.raises(OAuthProviderError) as exc_cap:
        exchange_github_authorization_code(
            _FakeDb(),  # type: ignore[arg-type]
            settings=settings,
            code=AUTH_CODE_SENTINEL,
            code_verifier=PKCE_VERIFIER_SENTINEL,
        )
    assert exc_cap.value.category == "response_too_large"


def test_fetch_github_user_headers_immutable_id_and_ignores_email(
    mock_http: dict[str, Any],
) -> None:
    settings = _build_oauth_settings()
    mock_http["handler"] = lambda req: httpx.Response(
        200,
        json={"id": 12345, "login": "octocat", "email": "unverified@attacker.test"},
    )
    gh_user = fetch_github_user(
        _FakeDb(),  # type: ignore[arg-type]
        settings=settings,
        access_token=ACCESS_TOKEN_SENTINEL,
    )
    assert gh_user == GitHubUser(provider_user_id="12345")

    req = mock_http["requests"][0]
    assert str(req.url) == GITHUB_USER_ENDPOINT
    assert req.headers["authorization"] == f"Bearer {ACCESS_TOKEN_SENTINEL}"
    assert req.headers["accept"] == "application/vnd.github+json"
    assert req.headers["x-github-api-version"] == "2022-11-28"
    assert req.headers["user-agent"] == f"{settings.APP_NAME}/{settings.APP_VERSION}"

    for bad_id in (True, False, 0, -1, "123", 1.0, None):
        mock_http["handler"] = lambda req, val=bad_id: httpx.Response(
            200, json={"id": val} if val is not None else {}
        )
        with pytest.raises(OAuthProviderError) as exc_id:
            fetch_github_user(
                _FakeDb(),  # type: ignore[arg-type]
                settings=settings,
                access_token=ACCESS_TOKEN_SENTINEL,
            )
        assert exc_id.value.category == "invalid_user_id"


# ---------------------------------------------------------------------------
# I. Strict GitHub Pagination URL Validator (REV12-3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "valid_url",
    [
        "https://api.github.com/user/emails?per_page=100&page=2",
        "https://API.GITHUB.COM/user/emails?per_page=100&page=2",
        "https://api.github.com:443/user/emails?per_page=100&page=2",
        "https://api.github.com/user/emails?page=2&per_page=100",
    ],
)
def test_github_pagination_url_accepts_valid_urls(valid_url: str) -> None:
    assert (
        validate_github_emails_pagination_url(valid_url, expected_page=2, per_page=100)
        == valid_url
    )


@pytest.mark.parametrize(
    "bad_url",
    [
        "https://github.com/user/emails?per_page=100&page=2",
        "https://api.github.com.evil.com/user/emails?per_page=100&page=2",
        "https://api.github.com./user/emails?per_page=100&page=2",
        "http://api.github.com/user/emails?per_page=100&page=2",
        "https://api.github.com/user?per_page=100&page=2",
        "https://api.github.com/emails?per_page=100&page=2",
        "https://api.github.com/user/emails/extra?per_page=100&page=2",
        "https://api.github.com/user/emails/?per_page=100&page=2",
        "https://user:pass@api.github.com/user/emails?per_page=100&page=2",
        "https://api.github.com:8443/user/emails?per_page=100&page=2",
        "https://api.github.com:80/user/emails?per_page=100&page=2",
        "https://api.github.com:/user/emails?per_page=100&page=2",
        "https://api.github.com/user/emails?per_page=100&page=2#frag",
        "https://api.github.com/user/emails?per_page=100&page=2#",
        "https://api.github.com/user/emails?per_page=100&page=2&foo=bar",
        "https://api.github.com/user/emails?per_page=100&page=2&page=3",
        "https://api.github.com/user/emails?per_page=100&per_page=50&page=2",
        "https://api.github.com/user/emails?per_page=100",
        "https://api.github.com/user/emails?per_page=100&page=3",
        "https://api.github.com/user/emails?per_page=100&page=1",
        "https://api.github.com/user/emails?per_page=50&page=2",
        "https://api.github.com/user/emails?per_page=100&page=02",
        "https://api.github.com/user/emails?per_page=100&page=+2",
        "https://api.github.com/user/emails?per_page=100&page=%32",
        "https://api.github.com/user/emails?per_page=100&page=2 ",
    ],
)
def test_github_pagination_url_rejects_all_rev12_violations(bad_url: str) -> None:
    with pytest.raises(OAuthProviderError) as exc_info:
        validate_github_emails_pagination_url(bad_url, expected_page=2, per_page=100)
    assert exc_info.value.category == "invalid_pagination_url"


# ---------------------------------------------------------------------------
# J. GitHub Paginated Email Fetch & K. Selection & L. Unified Email Normalizer
# ---------------------------------------------------------------------------


def test_fetch_github_verified_email_multipage_and_bearer_host_restriction(
    mock_http: dict[str, Any],
) -> None:
    settings = _build_oauth_settings(GITHUB_EMAILS_PER_PAGE=100, GITHUB_EMAILS_MAX_PAGES=3)

    def _handler(req: httpx.Request) -> httpx.Response:
        if str(req.url).endswith("page=1"):
            return httpx.Response(
                200,
                headers={
                    "Link": (
                        '<https://api.github.com/user/emails?per_page=100&page=2>; rel="next", '
                        '<https://api.github.com/user/emails?per_page=100&page=2>; rel="last"'
                    )
                },
                json=[{"email": "123+octo@users.noreply.github.com", "verified": True, "primary": True}],
            )
        return httpx.Response(
            200,
            json=[{"email": "RealUser@Example.COM", "verified": True, "primary": False}],
        )

    mock_http["handler"] = _handler
    selected = fetch_github_verified_email(
        _FakeDb(),  # type: ignore[arg-type]
        settings=settings,
        access_token=ACCESS_TOKEN_SENTINEL,
    )
    assert selected == "realuser@example.com"
    assert [str(r.url) for r in mock_http["requests"]] == [
        "https://api.github.com/user/emails?per_page=100&page=1",
        "https://api.github.com/user/emails?per_page=100&page=2",
    ]

    # Evil next host must fail BEFORE making second request
    mock_http["requests"].clear()
    mock_http["handler"] = lambda req: httpx.Response(
        200,
        headers={"Link": '<https://evil.example/user/emails?per_page=100&page=2>; rel="next"'},
        json=[],
    )
    with pytest.raises(OAuthProviderError) as exc_evil:
        fetch_github_verified_email(
            _FakeDb(),  # type: ignore[arg-type]
            settings=settings,
            access_token=ACCESS_TOKEN_SENTINEL,
        )
    assert exc_evil.value.category == "invalid_pagination_url"
    assert len(mock_http["requests"]) == 1

    # Max pages truncation fails closed
    mock_http["requests"].clear()
    capped = _build_oauth_settings(GITHUB_EMAILS_PER_PAGE=100, GITHUB_EMAILS_MAX_PAGES=2)

    def _endless(req: httpx.Request) -> httpx.Response:
        page = 2 if "page=1" in str(req.url) else 3
        return httpx.Response(
            200,
            headers={"Link": f'<https://api.github.com/user/emails?per_page=100&page={page}>; rel="next"'},
            json=[{"email": f"u{page}@example.com", "verified": True, "primary": False}],
        )

    mock_http["handler"] = _endless
    with pytest.raises(OAuthProviderError) as exc_max:
        fetch_github_verified_email(
            _FakeDb(),  # type: ignore[arg-type]
            settings=capped,
            access_token=ACCESS_TOKEN_SENTINEL,
        )
    assert exc_max.value.category == "pagination_truncated"
    assert len(mock_http["requests"]) == 2


@pytest.mark.parametrize("redirect_code", [301, 302, 307, 308])
def test_fetch_github_verified_email_rejects_redirects_without_following(
    mock_http: dict[str, Any],
    redirect_code: int,
) -> None:
    settings = _build_oauth_settings()
    mock_http["handler"] = lambda req: httpx.Response(
        redirect_code,
        headers={"Location": "https://evil.example/steal"},
    )
    with pytest.raises(OAuthProviderError) as exc_info:
        fetch_github_verified_email(
            _FakeDb(),  # type: ignore[arg-type]
            settings=settings,
            access_token=ACCESS_TOKEN_SENTINEL,
        )
    assert exc_info.value.category == "unexpected_status"
    assert len(mock_http["requests"]) == 1


@pytest.mark.parametrize(
    ("headers", "payload"),
    [
        ({"Link": "not-a-valid-link"}, []),
        ({"Link": '<https://api.github.com/user/emails?per_page=100&page=2>; rel="next", <https://api.github.com/user/emails?per_page=100&page=2>; rel="next"'}, []),
        ({}, {"not": "a list"}),
        ({}, ["not-a-dict"]),
        ({}, [{"email": "a@b.com", "verified": "true", "primary": False}]),
        ({}, [{"email": "a@b.com", "verified": True}]),
    ],
)
def test_fetch_github_verified_email_rejects_malformed_links_or_entries(
    mock_http: dict[str, Any],
    headers: dict[str, str],
    payload: Any,
) -> None:
    settings = _build_oauth_settings()
    mock_http["handler"] = lambda req: httpx.Response(200, headers=headers, json=payload)
    with pytest.raises(OAuthProviderError):
        fetch_github_verified_email(
            _FakeDb(),  # type: ignore[arg-type]
            settings=settings,
            access_token=ACCESS_TOKEN_SENTINEL,
        )


def test_select_github_verified_email_rules() -> None:
    entries = [
        GitHubEmailEntry("unverified@example.com", verified=False, primary=True),
        GitHubEmailEntry("1234+u@users.noreply.github.com", verified=True, primary=True),
        GitHubEmailEntry("x@sub.users.noreply.github.com", verified=True, primary=True),
        GitHubEmailEntry("y@noreply.github.com", verified=True, primary=True),
        GitHubEmailEntry("A.B+tag@Example.com", verified=True, primary=False),
        GitHubEmailEntry("  a.b+tag@example.com ", verified=True, primary=True),
        GitHubEmailEntry("z@example.com", verified=True, primary=True),
        GitHubEmailEntry("allowed@noreply.github.com.example.org", verified=True, primary=False),
        GitHubEmailEntry("invalid-email-ignored", verified=True, primary=True),
    ]
    assert select_github_verified_email(entries) == "a.b+tag@example.com"

    # Without primary: lexicographically smallest non-noreply verified email
    no_primary = [
        GitHubEmailEntry("z@example.com", verified=True, primary=False),
        GitHubEmailEntry("a@noreply.github.com.example.org", verified=True, primary=False),
    ]
    assert select_github_verified_email(no_primary) == "a@noreply.github.com.example.org"

    with pytest.raises(GitHubVerifiedEmailRequiredError) as exc_req:
        select_github_verified_email(
            [
                GitHubEmailEntry("a@users.noreply.github.com", verified=True, primary=True),
                GitHubEmailEntry("b@example.com", verified=False, primary=True),
            ]
        )
    assert not isinstance(exc_req.value, OAuthProviderError)


def test_normalize_and_validate_oauth_email() -> None:
    assert (
        normalize_and_validate_oauth_email("  Alice.Smith+work@Example.COM ")
        == "alice.smith+work@example.com"
    )
    max_254 = ("a" * 64) + "@" + ("b" * 63) + "." + ("c" * 63) + "." + ("d" * 57) + ".com"
    assert len(max_254) == 254
    assert normalize_and_validate_oauth_email(max_254) == max_254

    over_255 = ("a" * 64) + "@" + ("b" * 63) + "." + ("c" * 63) + "." + ("d" * 58) + ".com"
    assert len(over_255) == 255
    over_321 = ("a" * 64) + "@" + ("b" * 63) + "." + ("c" * 63) + "." + ("d" * 63) + "." + ("e" * 64)
    assert len(over_321) == 321
    for bad in (123, None, "", "   ", "bad\n@example.com", "a b@example.com", "not-email", over_255, over_321):
        with pytest.raises(ValueError):
            normalize_and_validate_oauth_email(bad)


# ---------------------------------------------------------------------------
# M. Authorization URL Builders & N. Safe Logging & O. Isolation
# ---------------------------------------------------------------------------


def test_authorization_url_builders_and_validation() -> None:
    settings = _build_oauth_settings()
    verifier = generate_pkce_verifier()
    challenge = compute_pkce_s256_challenge(verifier)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    google_url = build_google_authorization_url(
        settings, state=state, nonce=nonce, code_challenge=challenge
    )
    g_parts = urlsplit(google_url)
    assert f"{g_parts.scheme}://{g_parts.netloc}{g_parts.path}" == GOOGLE_AUTHORIZATION_ENDPOINT
    assert parse_qsl(g_parts.query) == [
        ("client_id", settings.GOOGLE_CLIENT_ID),
        ("redirect_uri", get_oauth_callback_url(settings, "google")),
        ("response_type", "code"),
        ("scope", "openid email profile"),
        ("state", state),
        ("nonce", nonce),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ]

    github_url = build_github_authorization_url(
        settings, state=state, code_challenge=challenge
    )
    gh_parts = urlsplit(github_url)
    assert f"{gh_parts.scheme}://{gh_parts.netloc}{gh_parts.path}" == GITHUB_AUTHORIZATION_ENDPOINT
    assert parse_qsl(gh_parts.query) == [
        ("client_id", settings.GITHUB_CLIENT_ID),
        ("redirect_uri", get_oauth_callback_url(settings, "github")),
        ("scope", "read:user user:email"),
        ("state", state),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ]

    with pytest.raises(ValueError):
        build_google_authorization_url(settings, state="short", nonce=nonce, code_challenge=challenge)
    with pytest.raises(ValueError):
        build_google_authorization_url(settings, state=state, nonce="short", code_challenge=challenge)
    with pytest.raises(ValueError):
        build_github_authorization_url(settings, state=state, code_challenge="bad")


def test_safe_logging_and_repr_never_leak_secrets_or_emails(
    caplog: pytest.LogCaptureFixture,
    mock_http: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    rsa_keys: dict[str, Any],
) -> None:
    settings = _build_oauth_settings()
    refresh_token_sentinel = "rt-SENTINEL-6612"
    email_sentinel = "private.sentinel@example.com"
    wrong_nonce_sentinel = "wrong-nonce-SENTINEL-5501"
    now = 1_700_000_000.0
    claims = _base_google_claims(settings, now=now, nonce=wrong_nonce_sentinel)
    claims["email"] = email_sentinel
    id_token_sentinel = jwt.encode(
        claims, rsa_keys["priv_1"], algorithm="RS256", headers={"kid": "kid-1"}
    )

    sentinels = [
        GOOGLE_SECRET_SENTINEL,
        GITHUB_SECRET_SENTINEL,
        AUTH_CODE_SENTINEL,
        PKCE_VERIFIER_SENTINEL,
        ACCESS_TOKEN_SENTINEL,
        NONCE_SENTINEL,
        wrong_nonce_sentinel,
        id_token_sentinel,
        refresh_token_sentinel,
        email_sentinel,
    ]
    caplog.set_level("DEBUG")

    # 1. Token endpoint error with secrets inside body
    mock_http["handler"] = lambda req: httpx.Response(
        400,
        content=(
            f"error={GOOGLE_SECRET_SENTINEL}&code={AUTH_CODE_SENTINEL}"
            f"&refresh_token={refresh_token_sentinel}"
        ).encode("utf-8"),
    )
    with pytest.raises(OAuthProviderError) as exc1:
        exchange_google_authorization_code(
            _FakeDb(),  # type: ignore[arg-type]
            settings=settings,
            code=AUTH_CODE_SENTINEL,
            code_verifier=PKCE_VERIFIER_SENTINEL,
        )
    assert exc1.value.category == "unexpected_status"

    # 2. Malformed JSON containing fake access token & secret
    mock_http["handler"] = lambda req: httpx.Response(
        200,
        content=f"not-json-{ACCESS_TOKEN_SENTINEL}-{GITHUB_SECRET_SENTINEL}".encode("utf-8"),
    )
    with pytest.raises(OAuthProviderError) as exc2:
        exchange_github_authorization_code(
            _FakeDb(),  # type: ignore[arg-type]
            settings=settings,
            code=AUTH_CODE_SENTINEL,
            code_verifier=PKCE_VERIFIER_SENTINEL,
        )
    assert exc2.value.category == "malformed_json"

    # 3. Failing verify_google_id_token (nonce mismatch with email & id_token sentinels)
    jwk_client = build_google_jwk_client(settings)
    monkeypatch.setattr(jwk_client, "fetch_data", lambda: {"keys": [rsa_keys["jwk_1"]]})
    with pytest.raises(OAuthProviderError) as exc3:
        verify_google_id_token(
            _FakeDb(),  # type: ignore[arg-type]
            settings=settings,
            jwk_client=jwk_client,
            id_token=id_token_sentinel,
            expected_nonce_hash=hash_opaque_token(NONCE_SENTINEL),
            now=now,
        )
    assert exc3.value.category == "nonce_mismatch"

    # 4. Provider HTTP ReadTimeout during GitHub verified-email fetch
    def _raise_timeout(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout(
            f"timeout carrying {ACCESS_TOKEN_SENTINEL} {refresh_token_sentinel}",
            request=req,
        )

    mock_http["handler"] = _raise_timeout
    with pytest.raises(OAuthProviderError) as exc4:
        fetch_github_verified_email(
            _FakeDb(),  # type: ignore[arg-type]
            settings=settings,
            access_token=ACCESS_TOKEN_SENTINEL,
        )
    assert exc4.value.category == "timeout"
    assert exc4.value.__cause__ is None

    for exc in (exc1.value, exc2.value, exc3.value, exc4.value):
        for s in sentinels:
            assert s not in str(exc)
            assert s not in repr(exc)
    for s in sentinels:
        assert s not in caplog.text

    ident_repr = repr(
        GoogleIdentity(provider_user_id="sub-1", email=email_sentinel, email_verified=True)
    )
    assert email_sentinel not in ident_repr


def test_provider_module_isolation_and_3c1_compatibility() -> None:
    source = pathlib.Path(inspect.getfile(oauth_providers)).read_text(encoding="utf-8")
    for forbidden in ("app.models", "oauth_service", "auth_service", "select("):
        assert forbidden not in source

    empty_settings = Settings(_env_file=None)
    assert empty_settings.oauth_enabled is False
