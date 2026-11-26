"""Centralized username/slug validation, normalization, activity keys, and avatar URL safety."""

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

SLUG_MIN_LENGTH = 3
SLUG_MAX_LENGTH = 30
SLUG_REGEX = re.compile(r"^[a-z0-9_]{3,30}$")

RESERVED_SLUGS: frozenset[str] = frozenset(
    {
        "api",
        "login",
        "register",
        "auth",
        "explore",
        "settings",
        "admin",
        "workspace",
        "onboarding",
        "share",
    }
)

ACTIVITY_KEYS: tuple[str, ...] = (
    "studying",
    "working",
    "interning",
    "freelancing",
    "job_seeking",
    "researching",
    "building_project",
    "learning_skills",
    "other",
)

AVATAR_URL_MAX_LENGTH = 512


def normalize_slug(raw_slug: str) -> str:
    """Normalize a username/slug by trimming surrounding whitespace and lowercasing."""
    return raw_slug.strip().lower()


def validate_slug_format(raw_slug: Any) -> str:
    """
    Normalize and validate username/slug format against ^[a-z0-9_]{3,30}$.

    Raises ValueError with a safe public message if invalid.
    """
    if not isinstance(raw_slug, str):
        raise ValueError("Username must be a string")

    normalized = normalize_slug(raw_slug)
    if len(normalized) < SLUG_MIN_LENGTH or len(normalized) > SLUG_MAX_LENGTH:
        raise ValueError(
            f"Username must be between {SLUG_MIN_LENGTH} and {SLUG_MAX_LENGTH} characters"
        )
    if not SLUG_REGEX.fullmatch(normalized):
        raise ValueError(
            "Username may only contain lowercase letters, numbers, and underscores"
        )
    return normalized


def is_reserved_slug(normalized_slug: str) -> bool:
    """Return True if the normalized slug is reserved for system routes."""
    return normalized_slug in RESERVED_SLUGS


def validate_assignable_slug(raw_slug: Any) -> str:
    """Validate both username/slug format and reserved-slug restrictions."""
    normalized = validate_slug_format(raw_slug)
    if is_reserved_slug(normalized):
        raise ValueError("This username is reserved and cannot be used")
    return normalized


def validate_safe_avatar_url(
    raw_url: Any,
    *,
    allow_localhost_http: bool = False,
) -> str | None:
    """
    Validate transitional Phase 1 avatar/profile picture URLs safely.

    Permits https:// URLs (and http://localhost / 127.0.0.1 / [::1] when
    allow_localhost_http=True) while rejecting non-HTTP schemes, embedded
    credentials, whitespace, control characters, and backslashes.
    """
    if raw_url is None:
        return None
    if not isinstance(raw_url, str):
        raise ValueError("Avatar URL must be a string")

    cleaned = raw_url.strip()
    if not cleaned:
        return None

    if len(cleaned) > AVATAR_URL_MAX_LENGTH:
        raise ValueError(
            f"Avatar URL must not exceed {AVATAR_URL_MAX_LENGTH} characters"
        )
    if "\\" in cleaned:
        raise ValueError("Avatar URL must not contain backslashes")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in cleaned):
        raise ValueError("Avatar URL must not contain whitespace or control characters")

    try:
        parts = urlsplit(cleaned)
    except ValueError:
        raise ValueError("Malformed avatar URL") from None

    scheme = parts.scheme.lower()
    if parts.username is not None or parts.password is not None:
        raise ValueError("Avatar URL must not contain embedded credentials")
    if not parts.hostname:
        raise ValueError("Avatar URL must include a valid host")

    if scheme == "https":
        return cleaned

    if scheme == "http" and allow_localhost_http:
        host_lower = parts.hostname.lower()
        if ":" in host_lower:
            try:
                normalized_host = f"[{ipaddress.IPv6Address(host_lower).compressed}]"
            except ValueError:
                raise ValueError("Avatar URL contains an invalid IPv6 host") from None
        else:
            normalized_host = host_lower
        if normalized_host in {"localhost", "127.0.0.1", "[::1]"}:
            return cleaned

    raise ValueError("Avatar URL must use https://")
