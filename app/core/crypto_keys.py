"""Pure standard-library Base64url AES-256 key decoder (zero internal app imports)."""

import base64
import binascii
import re

CANONICAL_AES256_B64URL_RE = re.compile(r"\A[A-Za-z0-9_-]{43}=?\Z")
AES256_KEY_BYTES = 32


def decode_aes256_base64url_key(raw_key: str, *, field_name: str) -> bytes:
    """
    Strictly decode a canonical 32-byte URL-safe Base64 key without exposing secret input.

    Accepted canonical forms:
      - Exactly 43 unpadded URL-safe Base64 characters, OR
      - Exactly 43 URL-safe Base64 characters followed by a single trailing '='.

    Rejects standard Base64 ('+' or '/'), whitespace, double padding ('=='), wrong lengths,
    non-canonical unused trailing bits, and decoded byte lengths != 32.
    """
    if type(raw_key) is not str:
        raise ValueError(f"{field_name} must be a string")

    if not CANONICAL_AES256_B64URL_RE.fullmatch(raw_key):
        raise ValueError(
            f"{field_name} must be a canonical 32-byte URL-safe Base64 string "
            "(43 chars or 43 chars + single '=')"
        )

    padded = f"{raw_key}=" if len(raw_key) == 43 else raw_key
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError):
        raise ValueError(f"{field_name} is not valid URL-safe Base64") from None

    if len(decoded) != AES256_KEY_BYTES:
        raise ValueError(f"{field_name} must decode to exactly {AES256_KEY_BYTES} bytes")

    canonical_unpadded = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical_unpadded != raw_key.rstrip("="):
        raise ValueError(f"{field_name} contains non-canonical unused trailing bits")

    return decoded


__all__ = [
    "AES256_KEY_BYTES",
    "CANONICAL_AES256_B64URL_RE",
    "decode_aes256_base64url_key",
]
