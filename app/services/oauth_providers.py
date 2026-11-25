"""Isolated Stage 3C.4 OAuth provider clients (Google OIDC and GitHub OAuth 2.0).

This module implements provider-specific HTTP transport, database transaction-closure
guards, Google OIDC ID token & JWKS verification, and GitHub profile / strict
paginated verified-email retrieval per F360-S3C-SPEC-REV12 §4 and §5.

No database queries, OAuth state/exchange orchestration, FastAPI routes, or cookie
management belong in this module; those belong to Substages 3C.5 and 3C.6.
"""

from collections.abc import Callable
from dataclasses import dataclass, field, replace
import hashlib
import hmac
import json
import logging
import math
import re
import threading
import time
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
import httpx
import jwt
from jwt import PyJWK, PyJWKClient, PyJWKSet
from jwt.exceptions import PyJWKClientError, PyJWTError
from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy.orm import Session

from app.core.config import Settings, get_oauth_callback_url
from app.core.security import (
    hash_opaque_token,
    validate_pkce_s256_challenge,
    validate_provider_pkce_verifier,
)

logger = logging.getLogger("folio360.oauth.providers")

# ---------------------------------------------------------------------------
# Provider Endpoints, Caps & Protocol Constants (REV12 §4 / §5)
# ---------------------------------------------------------------------------

GOOGLE_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs"

GITHUB_AUTHORIZATION_ENDPOINT = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token"
GITHUB_USER_ENDPOINT = "https://api.github.com/user"
GITHUB_API_HOST = "api.github.com"
GITHUB_USER_EMAILS_PATH = "/user/emails"

GOOGLE_SCOPE = "openid email profile"
GOOGLE_ISSUERS: frozenset[str] = frozenset(
    {"https://accounts.google.com", "accounts.google.com"}
)
GITHUB_SCOPE = "read:user user:email"
GITHUB_API_VERSION = "2022-11-28"

# Raw response body caps (excluding headers)
GOOGLE_JWKS_MAX_BYTES = 65_536
GOOGLE_TOKEN_MAX_BYTES = 65_536
GITHUB_TOKEN_MAX_BYTES = 16_384
GITHUB_USER_MAX_BYTES = 65_536
GITHUB_EMAILS_PAGE_MAX_BYTES = 131_072
STREAM_CHUNK_SIZE = 8192

# Overflow-safe NumericDate bounds
MIN_NUMERIC_DATE = 1
MAX_NUMERIC_DATE = 4_102_444_800  # 2100-01-01T00:00:00Z
CLOCK_SKEW_LEEWAY_SECONDS = 30

# Google JWKS cache & refresh timings
JWKS_TTL_SECONDS = 300
JWKS_COOLDOWN_SECONDS = 30
MAX_JWKS_STALE_FALLBACK_SECONDS = 900

# Cryptographic key & claim bounds
MIN_RSA_KEY_BITS = 2048
MAX_KID_LENGTH = 256
MAX_SUBJECT_LENGTH = 255
MAX_OAUTH_EMAIL_LENGTH = 320
MAX_AUTHORIZATION_CODE_LENGTH = 2048

RSA_PRIVATE_JWK_FIELDS: frozenset[str] = frozenset(
    {"d", "p", "q", "dp", "dq", "qi", "oth"}
)
NON_SIGNING_KEY_OPS: frozenset[str] = frozenset(
    {"encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"}
)

GITHUB_NOREPLY_EXACT_DOMAINS: frozenset[str] = frozenset(
    {"users.noreply.github.com", "noreply.github.com"}
)
GITHUB_NOREPLY_SUFFIX = ".users.noreply.github.com"

_OPAQUE_TOKEN_43_RE = re.compile(r"\A[A-Za-z0-9_-]{43}\Z")
_SHA256_HEX_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_AUTH_CODE_RE = re.compile(rf"\A[!-~]{{1,{MAX_AUTHORIZATION_CODE_LENGTH}}}\Z")
_VISIBLE_ASCII_RE = re.compile(r"\A[!-~]+\Z")
_POSITIVE_INT_RE = re.compile(r"\A[1-9][0-9]{0,8}\Z")

_EMAIL_ADAPTER: TypeAdapter[EmailStr] = TypeAdapter(EmailStr)

_LINK_URL_RE = re.compile(r"\s*<([^<>]*)>\s*")
_LINK_PARAM_RE = re.compile(
    r';\s*([A-Za-z0-9!#$&+.^_`|~-]+)\s*=\s*(?:"([^"\\]*)"|([A-Za-z0-9!#$%&\'*+.^_`|~-]+))\s*'
)


def _has_forbidden_chars(value: str) -> bool:
    return any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


# ---------------------------------------------------------------------------
# Exceptions & Immutable Result Models
# ---------------------------------------------------------------------------


class OAuthProviderError(Exception):
    """Sanitized provider failure mapped to oauth_provider_error in Substage 3C.5."""

    def __init__(self, provider: str, category: str) -> None:
        self.provider = provider
        self.category = category
        super().__init__(f"OAuth provider error ({provider}): {category}")


class GitHubVerifiedEmailRequiredError(Exception):
    """Raised when GitHub returns zero eligible verified non-noreply emails (D02)."""

    def __init__(self) -> None:
        super().__init__("GitHub account has no eligible verified non-noreply email")


class OAuthTransactionGuardError(RuntimeError):
    """Raised when provider HTTP or JWKS resolution is attempted with an open DB transaction."""


def _provider_error(
    provider: str,
    category: str,
    *,
    status: int | None = None,
) -> OAuthProviderError:
    logger.warning(
        "OAuth provider request rejected: provider=%s category=%s status=%s",
        provider,
        category,
        status,
    )
    return OAuthProviderError(provider, category)


@dataclass(frozen=True, slots=True)
class ProviderHttpResponse:
    """Parsed JSON payload and raw Link headers from a bounded provider HTTP call."""

    payload: Any
    link_values: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GoogleIdentity:
    """Validated Google OIDC identity extracted from a verified ID token."""

    provider_user_id: str
    email: str | None = field(repr=False)
    email_verified: bool


@dataclass(frozen=True, slots=True)
class GitHubUser:
    """Validated immutable GitHub user identity from GET /user."""

    provider_user_id: str


@dataclass(frozen=True, slots=True)
class GitHubEmailEntry:
    """Single validated entry from GitHub GET /user/emails."""

    email: str = field(repr=False)
    verified: bool
    primary: bool


# ---------------------------------------------------------------------------
# Optimization-Safe Transaction Guard & Bounded Streaming Transport (REV12 §4)
# ---------------------------------------------------------------------------


def ensure_no_open_db_transaction(db: Session) -> None:
    """Enforce zero open SQLAlchemy transaction before outbound provider HTTP or JWKS work."""
    if db.in_transaction():
        raise OAuthTransactionGuardError(
            "Provider HTTP attempted while a database transaction is open"
        )


def _reject_json_constant(token: str) -> Any:
    raise ValueError(f"Forbidden JSON constant: {token}")


def _validate_content_encoding_header(
    provider: str,
    response: httpx.Response,
) -> None:
    encodings = response.headers.get_list("content-encoding")
    if len(encodings) > 1:
        raise _provider_error(provider, "unsupported_content_encoding") from None
    if len(encodings) == 1:
        value = encodings[0].strip().lower()
        if value not in ("", "identity"):
            raise _provider_error(provider, "unsupported_content_encoding") from None


def _stream_bounded_json(
    *,
    provider: str,
    method: str,
    url: str,
    headers: dict[str, str],
    max_bytes: int,
    timeout: float,
    data: dict[str, str] | None = None,
) -> ProviderHttpResponse:
    request_headers = {
        k: v for k, v in headers.items() if k.lower() != "accept-encoding"
    }
    request_headers["Accept-Encoding"] = "identity"

    body = bytearray()
    link_values: tuple[str, ...] = ()

    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            with client.stream(
                method,
                url,
                headers=request_headers,
                data=data,
            ) as response:
                if response.status_code != 200:
                    raise _provider_error(
                        provider,
                        "unexpected_status",
                        status=response.status_code,
                    ) from None

                _validate_content_encoding_header(provider, response)

                for chunk in response.iter_raw(chunk_size=STREAM_CHUNK_SIZE):
                    if len(body) + len(chunk) > max_bytes:
                        raise _provider_error(provider, "response_too_large") from None
                    body.extend(chunk)

                link_values = tuple(response.headers.get_list("link"))
    except OAuthProviderError:
        raise
    except httpx.TimeoutException:
        raise _provider_error(provider, "timeout") from None
    except (httpx.HTTPError, httpx.InvalidURL, httpx.StreamError):
        raise _provider_error(provider, "transport_error") from None

    try:
        decoded = bytes(body).decode("utf-8")
        payload = json.loads(decoded, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, ValueError):
        raise _provider_error(provider, "malformed_json") from None

    return ProviderHttpResponse(payload=payload, link_values=link_values)


def provider_http_request(
    db: Session,
    *,
    provider: str,
    method: str,
    url: str,
    headers: dict[str, str],
    max_bytes: int,
    timeout: float,
    data: dict[str, str] | None = None,
) -> ProviderHttpResponse:
    """Run a bounded JSON HTTP request after verifying no DB transaction is open."""
    ensure_no_open_db_transaction(db)
    return _stream_bounded_json(
        provider=provider,
        method=method,
        url=url,
        headers=headers,
        max_bytes=max_bytes,
        timeout=timeout,
        data=data,
    )


# ---------------------------------------------------------------------------
# Shared Helpers & Credential / Input Validators
# ---------------------------------------------------------------------------


def normalize_and_validate_oauth_email(raw_email: Any) -> str:
    """Normalize and validate an OAuth email strictly without dot or +tag aliasing (REV12 §5)."""
    if type(raw_email) is not str:
        raise ValueError("OAuth email must be a string")

    normalized = raw_email.strip().lower()
    if (
        not normalized
        or len(normalized) > MAX_OAUTH_EMAIL_LENGTH
        or _has_forbidden_chars(normalized)
    ):
        raise ValueError("Invalid OAuth email address format")

    try:
        validated = _EMAIL_ADAPTER.validate_python(normalized)
    except ValidationError:
        raise ValueError("Invalid OAuth email address format") from None

    if str(validated) != normalized:
        raise ValueError("OAuth email address did not preserve canonical form")

    return normalized


def _require_google_credentials(settings: Settings) -> tuple[str, str]:
    client_id = settings.GOOGLE_CLIENT_ID
    client_secret = settings.GOOGLE_CLIENT_SECRET
    if not client_id or client_secret is None:
        raise _provider_error("google", "not_configured") from None
    secret_value = client_secret.get_secret_value()
    if not secret_value:
        raise _provider_error("google", "not_configured") from None
    return client_id, secret_value


def _require_github_credentials(settings: Settings) -> tuple[str, str]:
    client_id = settings.GITHUB_CLIENT_ID
    client_secret = settings.GITHUB_CLIENT_SECRET
    if not client_id or client_secret is None:
        raise _provider_error("github", "not_configured") from None
    secret_value = client_secret.get_secret_value()
    if not secret_value:
        raise _provider_error("github", "not_configured") from None
    return client_id, secret_value


def _validate_authorization_code(provider: str, code: Any) -> str:
    if type(code) is not str or not _AUTH_CODE_RE.fullmatch(code):
        raise _provider_error(provider, "invalid_authorization_code") from None
    return code


def _validate_code_verifier(provider: str, code_verifier: Any) -> str:
    try:
        return validate_provider_pkce_verifier(code_verifier)
    except ValueError:
        raise _provider_error(provider, "invalid_code_verifier") from None


def _validate_access_token(access_token: Any) -> str:
    if (
        type(access_token) is not str
        or not access_token
        or not _VISIBLE_ASCII_RE.fullmatch(access_token)
    ):
        raise _provider_error("github", "malformed_access_token") from None
    return access_token


def _github_user_agent(settings: Settings) -> str:
    return f"{settings.APP_NAME}/{settings.APP_VERSION}"


def _github_api_headers(settings: Settings, access_token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "User-Agent": _github_user_agent(settings),
    }


def _is_valid_kid(kid: Any) -> bool:
    return (
        type(kid) is str
        and 1 <= len(kid) <= MAX_KID_LENGTH
        and kid == kid.strip()
        and not _has_forbidden_chars(kid)
    )


# ---------------------------------------------------------------------------
# Authorization URL Builders (REV12 §4)
# ---------------------------------------------------------------------------


def build_google_authorization_url(
    settings: Settings,
    *,
    state: str,
    nonce: str,
    code_challenge: str,
) -> str:
    """Build the Google OAuth 2.0 / OIDC authorization URL with server callback URI."""
    client_id = settings.GOOGLE_CLIENT_ID
    if not client_id or settings.GOOGLE_CLIENT_SECRET is None:
        raise ValueError("Google OAuth is not configured")
    if type(state) is not str or not _OPAQUE_TOKEN_43_RE.fullmatch(state):
        raise ValueError("Invalid OAuth state parameter")
    if type(nonce) is not str or not _OPAQUE_TOKEN_43_RE.fullmatch(nonce):
        raise ValueError("Invalid OIDC nonce parameter")
    validate_pkce_s256_challenge(code_challenge)

    redirect_uri = get_oauth_callback_url(settings, "google")
    params = [
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", GOOGLE_SCOPE),
        ("state", state),
        ("nonce", nonce),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
    ]
    return f"{GOOGLE_AUTHORIZATION_ENDPOINT}?{urlencode(params, quote_via=quote)}"


def build_github_authorization_url(
    settings: Settings,
    *,
    state: str,
    code_challenge: str,
) -> str:
    """Build the GitHub OAuth 2.0 authorization URL with server callback URI."""
    client_id = settings.GITHUB_CLIENT_ID
    if not client_id or settings.GITHUB_CLIENT_SECRET is None:
        raise ValueError("GitHub OAuth is not configured")
    if type(state) is not str or not _OPAQUE_TOKEN_43_RE.fullmatch(state):
        raise ValueError("Invalid OAuth state parameter")
    validate_pkce_s256_challenge(code_challenge)

    redirect_uri = get_oauth_callback_url(settings, "github")
    params = [
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("scope", GITHUB_SCOPE),
        ("state", state),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
    ]
    return f"{GITHUB_AUTHORIZATION_ENDPOINT}?{urlencode(params, quote_via=quote)}"


# ---------------------------------------------------------------------------
# Google Token Exchange, Raw JWKS Validation & HttpxJWKClient (REV12 §4 / §5)
# ---------------------------------------------------------------------------


def exchange_google_authorization_code(
    db: Session,
    *,
    settings: Settings,
    code: str,
    code_verifier: str,
) -> str:
    """Exchange a Google authorization code + PKCE verifier for the raw OIDC id_token."""
    client_id, client_secret = _require_google_credentials(settings)
    validated_code = _validate_authorization_code("google", code)
    validated_verifier = _validate_code_verifier("google", code_verifier)
    redirect_uri = get_oauth_callback_url(settings, "google")

    resp = provider_http_request(
        db,
        provider="google",
        method="POST",
        url=GOOGLE_TOKEN_ENDPOINT,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        max_bytes=GOOGLE_TOKEN_MAX_BYTES,
        timeout=settings.OAUTH_HTTP_TIMEOUT_SECONDS,
        data={
            "grant_type": "authorization_code",
            "code": validated_code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "code_verifier": validated_verifier,
        },
    )

    if type(resp.payload) is not dict:
        raise _provider_error("google", "malformed_token_response") from None

    id_token = resp.payload.get("id_token")
    if type(id_token) is not str or not id_token.strip():
        raise _provider_error("google", "missing_id_token") from None

    return id_token


def build_eligible_google_jwk_set(payload: Any) -> PyJWKSet:
    """Validate raw Google JWKS metadata deterministically and filter eligible RS256 keys."""
    if type(payload) is not dict:
        raise PyJWKClientError("Google JWKS payload must be a JSON object")

    keys = payload.get("keys")
    if type(keys) is not list or not keys:
        raise PyJWKClientError("Google JWKS payload must contain a non-empty keys list")

    # Stage 1: Unfiltered pre-pass over EVERY entry before any filtering.
    seen_kids: set[str] = set()
    for jwk in keys:
        if type(jwk) is not dict:
            raise PyJWKClientError("Google JWKS entry must be a JSON object")
        if any(field in jwk for field in RSA_PRIVATE_JWK_FIELDS):
            raise PyJWKClientError(
                "Google JWKS entry must not contain RSA private-key fields"
            )
        if "kid" not in jwk or not _is_valid_kid(jwk["kid"]):
            raise PyJWKClientError("Google JWKS entry has an invalid or missing kid")
        kid = jwk["kid"]
        if kid in seen_kids:
            raise PyJWKClientError("Google JWKS contains duplicate kid values")
        seen_kids.add(kid)

        kty = jwk.get("kty")
        if (
            type(kty) is not str
            or not kty
            or kty != kty.strip()
            or _has_forbidden_chars(kty)
        ):
            raise PyJWKClientError("Google JWKS entry has an invalid kty")

        if "use" in jwk:
            use_val = jwk["use"]
            if type(use_val) is not str or use_val not in {"sig", "enc"}:
                raise PyJWKClientError("Google JWKS entry has an invalid use field")

        if "key_ops" in jwk:
            key_ops = jwk["key_ops"]
            if (
                type(key_ops) is not list
                or not key_ops
                or any(type(op) is not str or not op.strip() for op in key_ops)
            ):
                raise PyJWKClientError("Google JWKS entry has an invalid key_ops field")

    # Stage 2: Filter eligible RS256 signing public keys (>= 2048-bit RSA).
    eligible_dicts: list[dict[str, Any]] = []
    for jwk in keys:
        if jwk["kty"] != "RSA":
            continue

        use_val = jwk.get("use")
        key_ops = jwk.get("key_ops")
        if use_val == "enc" and (
            key_ops is None or ("verify" not in key_ops and "sign" not in key_ops)
        ):
            continue

        if "alg" in jwk:
            alg = jwk["alg"]
            if type(alg) is not str or alg != "RS256":
                continue
        if use_val is not None and use_val != "sig":
            continue
        if key_ops is not None:
            if "verify" not in key_ops or any(
                op in NON_SIGNING_KEY_OPS for op in key_ops
            ):
                continue

        try:
            parsed = PyJWK.from_dict(jwk)
        except (PyJWTError, ValueError, TypeError, KeyError):
            continue

        if not isinstance(parsed.key, RSAPublicKey):
            continue
        if parsed.key.key_size < MIN_RSA_KEY_BITS:
            continue

        eligible_dicts.append(jwk)

    if not eligible_dicts:
        raise PyJWKClientError(
            "Google JWKS did not contain any eligible RSA signing keys"
        )

    jwk_set = PyJWKSet(eligible_dicts)
    if len(jwk_set.keys) != len(eligible_dicts):
        raise PyJWKClientError("Google JWKS failed eligible key-set verification")
    return jwk_set


@dataclass(frozen=True, slots=True)
class _JWKSnapshot:
    jwk_set: PyJWKSet | None
    cached_at: float | None
    last_refresh_attempt_at: float | None


class HttpxJWKClient(PyJWKClient):
    """Split-lock, bounded-streaming Google JWKS client overriding PyJWKClient caching."""

    def __init__(
        self,
        uri: str = GOOGLE_JWKS_URI,
        *,
        timeout: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(
            uri=uri,
            cache_jwk_set=False,
            cache_keys=False,
            timeout=timeout,
        )
        self._state_lock = threading.Lock()
        self._refresh_lock = threading.Lock()
        self._snapshot = _JWKSnapshot(None, None, None)
        self._clock = clock

    def _read_snapshot(self) -> _JWKSnapshot:
        with self._state_lock:
            return self._snapshot

    def _swap_snapshot(self, snapshot: _JWKSnapshot) -> None:
        with self._state_lock:
            self._snapshot = snapshot

    @staticmethod
    def _is_fresh(snapshot: _JWKSnapshot, now: float) -> bool:
        return (
            snapshot.jwk_set is not None
            and snapshot.cached_at is not None
            and (now - snapshot.cached_at) < JWKS_TTL_SECONDS
        )

    @staticmethod
    def _serve_cached_or_raise(snapshot: _JWKSnapshot, now: float) -> PyJWKSet:
        if (
            snapshot.jwk_set is not None
            and snapshot.cached_at is not None
            and (now - snapshot.cached_at) <= MAX_JWKS_STALE_FALLBACK_SECONDS
        ):
            return snapshot.jwk_set
        raise PyJWKClientError("Google JWKS is unavailable")

    def fetch_data(self) -> Any:
        """Fetch raw Google JWKS JSON via the shared bounded streaming HTTP transport."""
        return _stream_bounded_json(
            provider="google",
            method="GET",
            url=self.uri,
            headers={"Accept": "application/json"},
            max_bytes=GOOGLE_JWKS_MAX_BYTES,
            timeout=self.timeout,
        ).payload

    def get_jwk_set(self, refresh: bool = False) -> PyJWKSet:
        """Return an eligible PyJWKSet using split-lock single-flight refresh and cooldown."""
        if not refresh:
            snapshot = self._read_snapshot()
            if self._is_fresh(snapshot, self._clock()):
                assert snapshot.jwk_set is not None
                return snapshot.jwk_set

        with self._refresh_lock:
            snapshot = self._read_snapshot()
            now = self._clock()

            if not refresh and self._is_fresh(snapshot, now):
                assert snapshot.jwk_set is not None
                return snapshot.jwk_set

            if (
                snapshot.last_refresh_attempt_at is not None
                and (now - snapshot.last_refresh_attempt_at) < JWKS_COOLDOWN_SECONDS
            ):
                return self._serve_cached_or_raise(snapshot, now)

            self._swap_snapshot(replace(snapshot, last_refresh_attempt_at=now))

            try:
                raw_payload = self.fetch_data()
                new_jwk_set = build_eligible_google_jwk_set(raw_payload)
            except Exception:
                logger.warning("Google JWKS refresh failed; evaluating stale fallback")
                return self._serve_cached_or_raise(self._read_snapshot(), self._clock())

            refreshed_at = self._clock()
            self._swap_snapshot(
                _JWKSnapshot(
                    jwk_set=new_jwk_set,
                    cached_at=refreshed_at,
                    last_refresh_attempt_at=now,
                )
            )
            return new_jwk_set

    @staticmethod
    def _find_key(jwk_set: PyJWKSet, kid: str) -> PyJWK | None:
        for key in jwk_set.keys:
            if key.key_id == kid:
                return key
        return None

    def get_signing_key(self, kid: str) -> PyJWK:
        """Resolve an eligible signing key by kid, performing at most one forced refresh."""
        if not _is_valid_kid(kid):
            raise PyJWKClientError("Google ID token header contains an invalid kid")

        jwk_set = self.get_jwk_set(refresh=False)
        match = self._find_key(jwk_set, kid)
        if match is not None:
            return match

        refreshed_set = self.get_jwk_set(refresh=True)
        match = self._find_key(refreshed_set, kid)
        if match is not None:
            return match

        raise PyJWKClientError("No eligible Google signing key matches the JWT kid")


def build_google_jwk_client(settings: Settings) -> HttpxJWKClient:
    """Construct the bounded HttpxJWKClient configured for Google OIDC verification."""
    return HttpxJWKClient(
        GOOGLE_JWKS_URI,
        timeout=settings.OAUTH_HTTP_TIMEOUT_SECONDS,
    )


# ---------------------------------------------------------------------------
# Google OIDC Claims & Overflow-Safe NumericDate Verification (REV12 §5)
# ---------------------------------------------------------------------------


def parse_numeric_date(value: Any) -> float:
    """Parse an OIDC NumericDate safely without int->float overflow (REV12 §5)."""
    if type(value) is bool:
        raise _provider_error("google", "invalid_numeric_date") from None
    if type(value) is int:
        if value < MIN_NUMERIC_DATE or value > MAX_NUMERIC_DATE:
            raise _provider_error("google", "invalid_numeric_date") from None
        return float(value)
    if type(value) is float:
        if (
            not math.isfinite(value)
            or value < MIN_NUMERIC_DATE
            or value > MAX_NUMERIC_DATE
        ):
            raise _provider_error("google", "invalid_numeric_date") from None
        return value
    raise _provider_error("google", "invalid_numeric_date") from None


def verify_google_id_token(
    db: Session,
    *,
    settings: Settings,
    jwk_client: PyJWKClient,
    id_token: str,
    expected_nonce_hash: str,
    now: float | None = None,
) -> GoogleIdentity:
    """Verify Google ID token signature, NumericDate bounds, OIDC claims, and email."""
    client_id, _ = _require_google_credentials(settings)

    if type(id_token) is not str or not id_token.strip():
        raise _provider_error("google", "malformed_id_token") from None
    if type(expected_nonce_hash) is not str or not _SHA256_HEX_RE.fullmatch(
        expected_nonce_hash
    ):
        raise ValueError(
            "expected_nonce_hash must be a 64-character lowercase hex SHA-256 digest"
        )

    try:
        header = jwt.get_unverified_header(id_token)
    except PyJWTError:
        raise _provider_error("google", "malformed_id_token") from None

    if type(header) is not dict or header.get("alg") != "RS256":
        raise _provider_error("google", "invalid_id_token_header") from None
    if not _is_valid_kid(header.get("kid")):
        raise _provider_error("google", "invalid_id_token_header") from None

    # Mandatory pre-JWKS transaction-closure check (REV12 §4).
    ensure_no_open_db_transaction(db)
    try:
        signing_key = jwk_client.get_signing_key_from_jwt(id_token)
    except PyJWTError:
        raise _provider_error("google", "signing_key_unavailable") from None

    try:
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            options={
                "require": ["iss", "sub", "aud", "exp", "iat"],
                "verify_signature": True,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
    except PyJWTError:
        raise _provider_error("google", "invalid_id_token") from None

    if type(claims) is not dict:
        raise _provider_error("google", "invalid_id_token") from None

    current_time = time.time() if now is None else now
    exp = parse_numeric_date(claims.get("exp"))
    iat = parse_numeric_date(claims.get("iat"))
    if current_time > exp + CLOCK_SKEW_LEEWAY_SECONDS:
        raise _provider_error("google", "expired_id_token") from None
    if iat > current_time + CLOCK_SKEW_LEEWAY_SECONDS:
        raise _provider_error("google", "future_iat_id_token") from None
    if "nbf" in claims:
        nbf = parse_numeric_date(claims["nbf"])
        if nbf > current_time + CLOCK_SKEW_LEEWAY_SECONDS:
            raise _provider_error("google", "immature_id_token") from None

    iss = claims.get("iss")
    if type(iss) is not str or iss not in GOOGLE_ISSUERS:
        raise _provider_error("google", "invalid_issuer") from None

    raw_aud = claims.get("aud")
    if type(raw_aud) is str:
        if not raw_aud or raw_aud != raw_aud.strip() or _has_forbidden_chars(raw_aud):
            raise _provider_error("google", "invalid_audience") from None
        aud_list = [raw_aud]
    elif type(raw_aud) is list and raw_aud:
        aud_list = []
        seen_aud: set[str] = set()
        for entry in raw_aud:
            if (
                type(entry) is not str
                or not entry
                or entry != entry.strip()
                or _has_forbidden_chars(entry)
                or entry in seen_aud
            ):
                raise _provider_error("google", "invalid_audience") from None
            seen_aud.add(entry)
            aud_list.append(entry)
    else:
        raise _provider_error("google", "invalid_audience") from None

    trusted_audiences = frozenset({client_id}) | frozenset(
        settings.GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES
    )
    if client_id not in aud_list or any(
        entry not in trusted_audiences for entry in aud_list
    ):
        raise _provider_error("google", "invalid_audience") from None

    if len(aud_list) > 1 and "azp" not in claims:
        raise _provider_error("google", "missing_azp") from None
    if "azp" in claims:
        azp = claims["azp"]
        if type(azp) is not str or azp != client_id:
            raise _provider_error("google", "invalid_azp") from None

    raw_nonce = claims.get("nonce")
    if type(raw_nonce) is not str or not raw_nonce:
        raise _provider_error("google", "invalid_nonce") from None
    computed_nonce_hash = hash_opaque_token(raw_nonce)
    if not hmac.compare_digest(computed_nonce_hash, expected_nonce_hash):
        raise _provider_error("google", "nonce_mismatch") from None

    sub = claims.get("sub")
    if (
        type(sub) is not str
        or not (1 <= len(sub) <= MAX_SUBJECT_LENGTH)
        or sub != sub.strip()
        or _has_forbidden_chars(sub)
    ):
        raise _provider_error("google", "invalid_subject") from None

    normalized_email: str | None = None
    if "email" in claims:
        try:
            normalized_email = normalize_and_validate_oauth_email(claims["email"])
        except ValueError:
            raise _provider_error("google", "invalid_email") from None

    raw_email_verified = False
    if "email_verified" in claims:
        email_verified_claim = claims["email_verified"]
        if type(email_verified_claim) is not bool:
            raise _provider_error("google", "invalid_email_verified") from None
        raw_email_verified = email_verified_claim

    return GoogleIdentity(
        provider_user_id=sub,
        email=normalized_email,
        email_verified=(normalized_email is not None and raw_email_verified is True),
    )


# ---------------------------------------------------------------------------
# GitHub Token Exchange, Profile & Strict Paginated Emails (REV12 §4 / REV12-3)
# ---------------------------------------------------------------------------


def exchange_github_authorization_code(
    db: Session,
    *,
    settings: Settings,
    code: str,
    code_verifier: str,
) -> str:
    """Exchange a GitHub authorization code + PKCE verifier for an access token."""
    client_id, client_secret = _require_github_credentials(settings)
    validated_code = _validate_authorization_code("github", code)
    validated_verifier = _validate_code_verifier("github", code_verifier)
    redirect_uri = get_oauth_callback_url(settings, "github")

    resp = provider_http_request(
        db,
        provider="github",
        method="POST",
        url=GITHUB_TOKEN_ENDPOINT,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": _github_user_agent(settings),
        },
        max_bytes=GITHUB_TOKEN_MAX_BYTES,
        timeout=settings.OAUTH_HTTP_TIMEOUT_SECONDS,
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "code": validated_code,
            "redirect_uri": redirect_uri,
            "code_verifier": validated_verifier,
        },
    )

    if type(resp.payload) is not dict:
        raise _provider_error("github", "malformed_token_response") from None
    if resp.payload.get("error"):
        raise _provider_error("github", "token_error_response") from None

    return _validate_access_token(resp.payload.get("access_token"))


def fetch_github_user(
    db: Session,
    *,
    settings: Settings,
    access_token: str,
) -> GitHubUser:
    """Fetch immutable GitHub user id from GET /user (ignoring /user.email)."""
    validated_token = _validate_access_token(access_token)
    resp = provider_http_request(
        db,
        provider="github",
        method="GET",
        url=GITHUB_USER_ENDPOINT,
        headers=_github_api_headers(settings, validated_token),
        max_bytes=GITHUB_USER_MAX_BYTES,
        timeout=settings.OAUTH_HTTP_TIMEOUT_SECONDS,
    )

    if type(resp.payload) is not dict:
        raise _provider_error("github", "malformed_user_response") from None

    user_id = resp.payload.get("id")
    if type(user_id) is not int or user_id <= 0:
        raise _provider_error("github", "invalid_user_id") from None

    return GitHubUser(provider_user_id=str(user_id))


def validate_github_emails_pagination_url(
    url: str,
    *,
    expected_page: int,
    per_page: int,
) -> str:
    """Strictly validate every GitHub /user/emails pagination URL before HTTP (REV12-3)."""
    if (
        type(url) is not str
        or not url
        or not url.isascii()
        or _has_forbidden_chars(url)
        or any(ch in url for ch in ("\\", "#", "%"))
        or not url.startswith("https://")
    ):
        raise _provider_error("github", "invalid_pagination_url") from None

    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        raise _provider_error("github", "invalid_pagination_url") from None

    if (
        parts.scheme != "https"
        or parts.netloc.lower() not in {GITHUB_API_HOST, f"{GITHUB_API_HOST}:443"}
        or parts.hostname != GITHUB_API_HOST
        or parts.username is not None
        or parts.password is not None
        or port not in (None, 443)
        or parts.path != GITHUB_USER_EMAILS_PATH
        or parts.fragment != ""
    ):
        raise _provider_error("github", "invalid_pagination_url") from None

    try:
        query_pairs = parse_qsl(
            parts.query,
            keep_blank_values=True,
            strict_parsing=True,
        )
    except ValueError:
        raise _provider_error("github", "invalid_pagination_url") from None

    keys = [k for k, _ in query_pairs]
    if len(keys) != len(set(keys)) or set(keys) != {"per_page", "page"}:
        raise _provider_error("github", "invalid_pagination_url") from None

    query_map = dict(query_pairs)
    raw_per_page = query_map["per_page"]
    raw_page = query_map["page"]
    if not _POSITIVE_INT_RE.fullmatch(raw_per_page) or not _POSITIVE_INT_RE.fullmatch(
        raw_page
    ):
        raise _provider_error("github", "invalid_pagination_url") from None

    if int(raw_per_page) != per_page or int(raw_page) != expected_page:
        raise _provider_error("github", "invalid_pagination_url") from None

    return url


def _parse_link_next(link_values: tuple[str, ...]) -> str | None:
    if not link_values:
        return None

    next_urls: list[str] = []
    for raw_header in link_values:
        if not raw_header or not raw_header.strip():
            raise _provider_error("github", "malformed_link_header") from None

        pos = 0
        length = len(raw_header)
        while True:
            url_match = _LINK_URL_RE.match(raw_header, pos)
            if url_match is None:
                raise _provider_error("github", "malformed_link_header") from None
            target_url = url_match.group(1)
            pos = url_match.end()

            rels: list[str] = []
            while pos < length and raw_header[pos] == ";":
                param_match = _LINK_PARAM_RE.match(raw_header, pos)
                if param_match is None:
                    raise _provider_error("github", "malformed_link_header") from None
                param_name = param_match.group(1).lower()
                param_val = (
                    param_match.group(2)
                    if param_match.group(2) is not None
                    else param_match.group(3)
                )
                if param_name == "rel":
                    rels.append(param_val)
                pos = param_match.end()

            while pos < length and raw_header[pos].isspace():
                pos += 1

            if len(rels) > 1:
                raise _provider_error("github", "malformed_link_header") from None
            if len(rels) == 1 and "next" in rels[0].lower().split():
                next_urls.append(target_url)

            if pos == length:
                break
            if raw_header[pos] != ",":
                raise _provider_error("github", "malformed_link_header") from None
            pos += 1
            while pos < length and raw_header[pos].isspace():
                pos += 1
            if pos == length:
                raise _provider_error("github", "malformed_link_header") from None

    if len(next_urls) > 1:
        raise _provider_error("github", "ambiguous_link_header") from None
    return next_urls[0] if next_urls else None


def _parse_github_email_page(payload: Any) -> list[GitHubEmailEntry]:
    if type(payload) is not list:
        raise _provider_error("github", "malformed_emails_response") from None

    entries: list[GitHubEmailEntry] = []
    for item in payload:
        if type(item) is not dict:
            raise _provider_error("github", "malformed_emails_response") from None
        email = item.get("email")
        verified = item.get("verified")
        primary = item.get("primary")
        if (
            type(email) is not str
            or type(verified) is not bool
            or type(primary) is not bool
        ):
            raise _provider_error("github", "malformed_emails_response") from None
        entries.append(GitHubEmailEntry(email=email, verified=verified, primary=primary))
    return entries


def _is_github_noreply_email(normalized_email: str) -> bool:
    _, _, domain = normalized_email.rpartition("@")
    return domain in GITHUB_NOREPLY_EXACT_DOMAINS or domain.endswith(
        GITHUB_NOREPLY_SUFFIX
    )


def select_github_verified_email(entries: list[GitHubEmailEntry]) -> str:
    """Select canonical verified non-noreply GitHub email (primary else lexicographically smallest)."""
    deduped: dict[str, bool] = {}
    for entry in entries:
        if entry.verified is not True:
            continue
        try:
            normalized = normalize_and_validate_oauth_email(entry.email)
        except ValueError:
            continue
        if _is_github_noreply_email(normalized):
            continue
        deduped[normalized] = deduped.get(normalized, False) or entry.primary

    if not deduped:
        raise GitHubVerifiedEmailRequiredError()

    primary_emails = [email for email, is_primary in deduped.items() if is_primary]
    candidates = primary_emails if primary_emails else list(deduped.keys())
    return min(candidates)


def fetch_github_verified_email(
    db: Session,
    *,
    settings: Settings,
    access_token: str,
) -> str:
    """Fetch paginated GitHub /user/emails strictly validating every next URL before I/O."""
    validated_token = _validate_access_token(access_token)
    per_page = settings.GITHUB_EMAILS_PER_PAGE
    max_pages = settings.GITHUB_EMAILS_MAX_PAGES
    headers = _github_api_headers(settings, validated_token)

    next_url: str | None = (
        f"https://{GITHUB_API_HOST}{GITHUB_USER_EMAILS_PATH}"
        f"?per_page={per_page}&page=1"
    )
    page_number = 1
    visited_urls: set[str] = set()
    all_entries: list[GitHubEmailEntry] = []

    while next_url is not None:
        if page_number > max_pages:
            raise _provider_error("github", "pagination_truncated") from None

        validated_url = validate_github_emails_pagination_url(
            next_url,
            expected_page=page_number,
            per_page=per_page,
        )
        if validated_url in visited_urls:
            raise _provider_error("github", "pagination_loop") from None
        visited_urls.add(validated_url)

        resp = provider_http_request(
            db,
            provider="github",
            method="GET",
            url=validated_url,
            headers=headers,
            max_bytes=GITHUB_EMAILS_PAGE_MAX_BYTES,
            timeout=settings.OAUTH_HTTP_TIMEOUT_SECONDS,
        )
        all_entries.extend(_parse_github_email_page(resp.payload))
        next_url = _parse_link_next(resp.link_values)
        page_number += 1

    return select_github_verified_email(all_entries)
