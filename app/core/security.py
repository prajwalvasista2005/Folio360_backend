"""Cryptographic, password, opaque-token, and HS256 JWT primitives for Stage 3A."""

from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import Any
import uuid

from argon2 import PasswordHasher, Type as Argon2Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
import jwt
from jwt.exceptions import InvalidTokenError

from app.core.config import Settings

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
