"""Cryptographic, password, opaque-token, HS256 JWT, and Stage 3C PKCE/AES-GCM primitives."""

import base64
import binascii
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import re
import secrets
from typing import Any
import uuid

from argon2 import PasswordHasher, Type as Argon2Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import jwt
from jwt.exceptions import InvalidTokenError

from app.core.config import Settings
from app.core.crypto_keys import AES256_KEY_BYTES, decode_aes256_base64url_key

PASSWORD_HASHER = PasswordHasher(type=Argon2Type.ID)
DUMMY_PASSWORD_HASH: str = PASSWORD_HASHER.hash("Folio360-Dummy-Password-Do-Not-Use-000!")

MIN_PASSWORD_CHARS = 12
MAX_PASSWORD_CHARS = 128
MAX_PASSWORD_UTF8_BYTES = 128


def normalize_email(raw_email: str) -> str:
    """Normalize an email address to lowercase trimmed canonical form."""
    return raw_email.strip().lower()


def validate_password_policy(password: str, email: str | None = None) -> str:
    """
    Enforce Stage 3A password rules (Rev10 §9.3) without echoing password content.

    Rules:
      - 12..128 characters
      - <= 128 UTF-8 bytes
      - Must contain at least one non-whitespace character
      - Must not equal the normalized email address
    """
    if len(password) < MIN_PASSWORD_CHARS or len(password) > MAX_PASSWORD_CHARS:
        raise ValueError(
            f"Password must be between {MIN_PASSWORD_CHARS} and {MAX_PASSWORD_CHARS} characters"
        )
    if len(password.encode("utf-8")) > MAX_PASSWORD_UTF8_BYTES:
        raise ValueError(f"Password must not exceed {MAX_PASSWORD_UTF8_BYTES} UTF-8 bytes")
    if not password.strip():
        raise ValueError("Password must contain non-whitespace characters")
    if email is not None and password.strip().lower() == normalize_email(email):
        raise ValueError("Password must not match the account email address")
    return password


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return PASSWORD_HASHER.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verify a plaintext password against an Argon2id hash without raising on mismatch."""
    try:
        return bool(PASSWORD_HASHER.verify(password_hash, plain_password))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    """Return True if an Argon2id hash should be upgraded to current parameters."""
    try:
        return bool(PASSWORD_HASHER.check_needs_rehash(password_hash))
    except InvalidHashError:
        return False


def generate_opaque_token() -> str:
    """Generate a cryptographically random URL-safe opaque token."""
    return secrets.token_urlsafe(32)


def hash_opaque_token(raw_token: str) -> str:
    """Compute the lowercase 64-char hex SHA-256 digest of an opaque token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _require_jwt_secret(settings: Settings) -> str:
    if settings.JWT_SECRET_KEY is None:
        raise RuntimeError("JWT_SECRET_KEY must be configured to sign or verify access tokens")
    secret = settings.JWT_SECRET_KEY.get_secret_value().strip()
    if not secret:
        raise RuntimeError("JWT_SECRET_KEY must not be empty")
    return secret


def create_access_token(
    *,
    user_id: uuid.UUID,
    auth_version: int,
    settings: Settings,
    now: datetime | None = None,
) -> tuple[str, int]:
    """
    Mint a short-lived HS256 JWT access token with Rev10 §12.1 required claims.

    Returns (encoded_jwt, expires_in_seconds).
    """
    issued_at = now or datetime.now(timezone.utc)
    expires_in_seconds = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    expires_at = issued_at + timedelta(seconds=expires_in_seconds)

    payload: dict[str, Any] = {
        "sub": str(user_id),
        "ver": int(auth_version),
        "type": "access",
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    secret = _require_jwt_secret(settings)
    token = jwt.encode(payload, secret, algorithm="HS256")
    return token, expires_in_seconds


def decode_access_token(token: str, settings: Settings) -> tuple[uuid.UUID, int, dict[str, Any]]:
    """
    Decode and strictly validate an HS256 access JWT per Rev10 §12.1.

    Raises ValueError on any signature, claim, type, or format validation failure.
    """
    secret = _require_jwt_secret(settings)
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
            options={
                "require": ["sub", "ver", "type", "iss", "aud", "iat", "exp", "jti"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
    except InvalidTokenError as exc:
        raise ValueError("Invalid or expired access token") from exc

    if payload.get("type") != "access":
        raise ValueError("Invalid token type claim")

    ver = payload.get("ver")
    if type(ver) is not int or ver < 0:
        raise ValueError("Invalid auth_version claim type")

    raw_sub = payload.get("sub")
    if type(raw_sub) is not str:
        raise ValueError("Invalid sub claim")
    try:
        user_id = uuid.UUID(raw_sub)
    except ValueError as exc:
        raise ValueError("Invalid sub UUID") from exc

    raw_jti = payload.get("jti")
    if type(raw_jti) is not str or not raw_jti.strip():
        raise ValueError("Invalid jti claim")

    return user_id, ver, payload


# ---------------------------------------------------------------------------
# Stage 3C: RFC 7636 PKCE (S256 only) & AES-256-GCM Verifier Encryption (REV12)
# ---------------------------------------------------------------------------

PKCE_CODE_CHALLENGE_METHOD = "S256"
PKCE_VERIFIER_CONSUMED_MARKER = "[CONSUMED]"
PROVIDER_PKCE_VERIFIER_LENGTH = 86
PKCE_CIPHERTEXT_VERSION_PREFIX = "v1:"
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16
MIN_PKCE_DECODED_CIPHERTEXT_BYTES = AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES + 1
PKCE_KEY_ROTATION_SKEW_SECONDS = 30
MIN_PKCE_KEY_ROTATION_RETENTION_SECONDS = 900
SUPPORTED_OAUTH_PROVIDERS: frozenset[str] = frozenset({"google", "github"})

RFC7636_VERIFIER_RE = re.compile(r"\A[A-Za-z0-9._~-]{43,128}\Z")
PROVIDER_PKCE_VERIFIER_RE = re.compile(r"\A[A-Za-z0-9_-]{86}\Z")
PKCE_S256_CHALLENGE_RE = re.compile(r"\A[A-Za-z0-9_-]{43}\Z")
_CANONICAL_UNPADDED_B64URL_RE = re.compile(r"\A[A-Za-z0-9_-]+\Z")
_SHA256_HEX_RE = re.compile(r"\A[0-9a-f]{64}\Z")


class PKCEDecryptionError(ValueError):
    """Raised when an encrypted PKCE verifier cannot be parsed, authenticated, or decrypted."""


def validate_provider_pkce_verifier(verifier: str) -> str:
    """Validate the locked 86-character CSPRNG provider PKCE verifier format without mutation."""
    if type(verifier) is not str or not PROVIDER_PKCE_VERIFIER_RE.fullmatch(verifier):
        raise ValueError("Invalid provider PKCE code_verifier format")
    return verifier


def validate_pkce_verifier(verifier: str) -> str:
    """Validate an unmodified RFC 7636 PKCE code_verifier (43..128 unreserved chars)."""
    if type(verifier) is not str or not RFC7636_VERIFIER_RE.fullmatch(verifier):
        raise ValueError("Invalid RFC 7636 PKCE code_verifier")
    return verifier


def validate_pkce_challenge_method(method: str) -> str:
    """Enforce RFC 7636 S256 PKCE exclusively; reject 'plain' and all other methods."""
    if type(method) is not str or method != PKCE_CODE_CHALLENGE_METHOD:
        raise ValueError("PKCE code_challenge_method must be 'S256'")
    return method


def validate_pkce_s256_challenge(
    challenge: str,
    *,
    method: str = PKCE_CODE_CHALLENGE_METHOD,
) -> str:
    """Validate an unmodified 43-char unpadded Base64url PKCE S256 challenge and method."""
    validate_pkce_challenge_method(method)
    if type(challenge) is not str or not PKCE_S256_CHALLENGE_RE.fullmatch(challenge):
        raise ValueError("Invalid PKCE S256 code_challenge")
    return challenge


def generate_pkce_verifier() -> str:
    """Generate a 512-bit CSPRNG PKCE verifier (exact 86 URL-safe Base64 characters)."""
    return validate_provider_pkce_verifier(secrets.token_urlsafe(64))


def compute_pkce_s256_challenge(verifier: str) -> str:
    """Compute the RFC 7636 S256 code_challenge from an unmodified code_verifier."""
    validated = validate_pkce_verifier(verifier)
    digest = hashlib.sha256(validated.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify_pkce_s256(
    verifier: str,
    expected_challenge: str,
    *,
    method: str = PKCE_CODE_CHALLENGE_METHOD,
) -> bool:
    """Constant-time verification of an RFC 7636 verifier against an S256 challenge."""
    validated_challenge = validate_pkce_s256_challenge(expected_challenge, method=method)
    computed_challenge = compute_pkce_s256_challenge(verifier)
    return hmac.compare_digest(computed_challenge, validated_challenge)


def load_pkce_encryption_keys(settings: Settings) -> tuple[bytes, bytes | None]:
    """Decode configured primary and optional previous 32-byte AES-256 keys via crypto_keys."""
    if settings.OAUTH_PKCE_ENCRYPTION_KEY is None:
        raise RuntimeError("OAUTH_PKCE_ENCRYPTION_KEY must be configured")

    primary_key = decode_aes256_base64url_key(
        settings.OAUTH_PKCE_ENCRYPTION_KEY.get_secret_value(),
        field_name="OAUTH_PKCE_ENCRYPTION_KEY",
    )
    previous_key: bytes | None = None
    if settings.OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS is not None:
        previous_key = decode_aes256_base64url_key(
            settings.OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS.get_secret_value(),
            field_name="OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS",
        )
    return primary_key, previous_key


def get_pkce_previous_key_retention_seconds(
    settings: Settings,
    *,
    skew_seconds: int = PKCE_KEY_ROTATION_SKEW_SECONDS,
) -> int:
    """Return minimum previous-key retention covering OAUTH_STATE_EXPIRE_MINUTES plus clock skew."""
    if type(skew_seconds) is not int or skew_seconds < 0:
        raise ValueError("skew_seconds must be a non-negative integer")
    state_expire_minutes = settings.OAUTH_STATE_EXPIRE_MINUTES
    if type(state_expire_minutes) is not int or not (1 <= state_expire_minutes <= 30):
        raise ValueError("OAUTH_STATE_EXPIRE_MINUTES must be between 1 and 30")
    return max(
        state_expire_minutes * 60 + skew_seconds,
        MIN_PKCE_KEY_ROTATION_RETENTION_SECONDS,
    )


def is_within_pkce_rotation_window(
    *,
    state_created_at: datetime,
    now: datetime | None = None,
    state_expire_minutes: int = 10,
    skew_seconds: int = PKCE_KEY_ROTATION_SKEW_SECONDS,
) -> bool:
    """Return True iff state_created_at falls within the state-expiry-plus-skew previous-key window."""
    if not isinstance(state_created_at, datetime) or state_created_at.tzinfo is None or state_created_at.utcoffset() is None:
        raise ValueError("state_created_at must be a timezone-aware datetime")

    effective_now = now if now is not None else datetime.now(timezone.utc)
    if not isinstance(effective_now, datetime) or effective_now.tzinfo is None or effective_now.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime")

    if type(state_expire_minutes) is not int or not (1 <= state_expire_minutes <= 30):
        raise ValueError("state_expire_minutes must be between 1 and 30")
    if type(skew_seconds) is not int or skew_seconds < 0:
        raise ValueError("skew_seconds must be a non-negative integer")

    elapsed = effective_now - state_created_at
    return timedelta(seconds=-skew_seconds) <= elapsed <= timedelta(
        minutes=state_expire_minutes,
        seconds=skew_seconds,
    )


def _validate_aes256_raw_key(key: Any, *, name: str) -> bytes:
    if type(key) is not bytes or len(key) != AES256_KEY_BYTES:
        raise ValueError(f"{name} must be a {AES256_KEY_BYTES}-byte bytes object")
    return key


def _build_pkce_aad(provider: str, state_hash: str) -> bytes:
    if type(provider) is not str or provider not in SUPPORTED_OAUTH_PROVIDERS:
        raise ValueError("Invalid OAuth provider for PKCE AAD")
    if type(state_hash) is not str or not _SHA256_HEX_RE.fullmatch(state_hash):
        raise ValueError("Invalid OAuth state_hash for PKCE AAD")
    return f"{provider}:{state_hash}".encode("utf-8")


def encrypt_pkce_verifier(
    verifier: str,
    *,
    key: bytes,
    provider: str,
    state_hash: str,
) -> str:
    """Encrypt the 86-char provider PKCE verifier with AES-256-GCM and a fresh 12-byte nonce."""
    validated_verifier = validate_provider_pkce_verifier(verifier)
    raw_key = _validate_aes256_raw_key(key, name="key")
    aad = _build_pkce_aad(provider, state_hash)

    nonce = os.urandom(AES_GCM_NONCE_BYTES)
    ct_with_tag = AESGCM(raw_key).encrypt(nonce, validated_verifier.encode("ascii"), aad)
    encoded = base64.urlsafe_b64encode(nonce + ct_with_tag).rstrip(b"=").decode("ascii")
    return f"{PKCE_CIPHERTEXT_VERSION_PREFIX}{encoded}"


def decrypt_pkce_verifier(
    ciphertext: str,
    *,
    primary_key: bytes,
    previous_key: bytes | None = None,
    provider: str,
    state_hash: str,
    state_created_at: datetime | None = None,
    now: datetime | None = None,
    state_expire_minutes: int = 10,
    skew_seconds: int = PKCE_KEY_ROTATION_SKEW_SECONDS,
) -> str:
    """
    Decrypt a stored 'v1:' PKCE verifier using primary_key then previous_key (within rotation window).

    Rejects '[CONSUMED]', unsupported version prefixes, malformed Base64url, short payloads,
    tampered nonce/ciphertext/tag/AAD, and non-86-char plaintext without leaking secrets.
    """
    validated_primary = _validate_aes256_raw_key(primary_key, name="primary_key")
    validated_previous: bytes | None = None
    if previous_key is not None:
        validated_previous = _validate_aes256_raw_key(previous_key, name="previous_key")

    if state_created_at is not None:
        within_window = is_within_pkce_rotation_window(
            state_created_at=state_created_at,
            now=now,
            state_expire_minutes=state_expire_minutes,
            skew_seconds=skew_seconds,
        )
        allow_previous = validated_previous is not None and within_window
    else:
        allow_previous = validated_previous is not None

    try:
        aad = _build_pkce_aad(provider, state_hash)
    except ValueError:
        raise PKCEDecryptionError("Invalid PKCE AAD parameters") from None

    if type(ciphertext) is not str or not ciphertext:
        raise PKCEDecryptionError("PKCE verifier ciphertext must be a non-empty string")
    if ciphertext == PKCE_VERIFIER_CONSUMED_MARKER:
        raise PKCEDecryptionError("PKCE verifier has already been consumed")
    if not ciphertext.startswith(PKCE_CIPHERTEXT_VERSION_PREFIX):
        raise PKCEDecryptionError("Unsupported PKCE verifier ciphertext version")

    b64_payload = ciphertext[len(PKCE_CIPHERTEXT_VERSION_PREFIX) :]
    if (
        not b64_payload
        or not _CANONICAL_UNPADDED_B64URL_RE.fullmatch(b64_payload)
        or len(b64_payload) % 4 == 1
    ):
        raise PKCEDecryptionError("Malformed PKCE verifier ciphertext encoding")

    padding = "=" * (-len(b64_payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(f"{b64_payload}{padding}".encode("ascii"))
    except (binascii.Error, ValueError):
        raise PKCEDecryptionError("Invalid PKCE verifier ciphertext Base64url") from None

    canonical_b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    if canonical_b64 != b64_payload:
        raise PKCEDecryptionError("Non-canonical PKCE verifier ciphertext encoding")
    if len(raw) < MIN_PKCE_DECODED_CIPHERTEXT_BYTES:
        raise PKCEDecryptionError("PKCE verifier ciphertext payload is too short")

    nonce = raw[:AES_GCM_NONCE_BYTES]
    ct_with_tag = raw[AES_GCM_NONCE_BYTES:]

    try:
        plaintext_bytes = AESGCM(validated_primary).decrypt(nonce, ct_with_tag, aad)
    except InvalidTag:
        if (
            allow_previous
            and validated_previous is not None
            and validated_previous != validated_primary
        ):
            try:
                plaintext_bytes = AESGCM(validated_previous).decrypt(nonce, ct_with_tag, aad)
            except InvalidTag:
                raise PKCEDecryptionError("PKCE verifier decryption failed") from None
        else:
            raise PKCEDecryptionError("PKCE verifier decryption failed") from None

    try:
        plaintext = plaintext_bytes.decode("ascii")
    except UnicodeDecodeError:
        raise PKCEDecryptionError("Decrypted PKCE verifier is not valid ASCII") from None

    if not PROVIDER_PKCE_VERIFIER_RE.fullmatch(plaintext):
        raise PKCEDecryptionError("Decrypted PKCE verifier failed format check")

    return plaintext


def encrypt_pkce_verifier_for_settings(
    verifier: str,
    *,
    settings: Settings,
    provider: str,
    state_hash: str,
) -> str:
    """Encrypt a provider PKCE verifier using Settings.OAUTH_PKCE_ENCRYPTION_KEY."""
    primary_key, _ = load_pkce_encryption_keys(settings)
    return encrypt_pkce_verifier(
        verifier,
        key=primary_key,
        provider=provider,
        state_hash=state_hash,
    )


def decrypt_pkce_verifier_for_settings(
    ciphertext: str,
    *,
    settings: Settings,
    provider: str,
    state_hash: str,
    state_created_at: datetime | None = None,
    now: datetime | None = None,
) -> str:
    """Decrypt a provider PKCE verifier using primary and rotated previous Settings keys."""
    primary_key, previous_key = load_pkce_encryption_keys(settings)
    return decrypt_pkce_verifier(
        ciphertext,
        primary_key=primary_key,
        previous_key=previous_key,
        provider=provider,
        state_hash=state_hash,
        state_created_at=state_created_at,
        now=now,
        state_expire_minutes=settings.OAUTH_STATE_EXPIRE_MINUTES,
    )
