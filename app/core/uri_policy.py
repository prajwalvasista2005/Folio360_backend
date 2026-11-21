"""Deterministic environment and mobile-login URI policy validation (Rev10 §10.2.C)."""

from dataclasses import dataclass
import ipaddress
import re
from typing import Any, Literal, Sequence
from urllib.parse import urlsplit

ALLOWED_APP_ENVIRONMENTS: tuple[str, ...] = ("development", "testing", "production")
AppEnvironment = Literal["development", "testing", "production"]

LOOPBACK_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "[::1]"})

DANGEROUS_SCHEMES: frozenset[str] = frozenset(
    {
        "javascript",
        "data",
        "vbscript",
        "file",
        "blob",
        "about",
        "intent",
        "mailto",
        "tel",
        "ftp",
    }
)

CUSTOM_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*$")
ENCODED_TRAVERSAL_RE = re.compile(r"%(?:2f|5c|2e|00)", re.IGNORECASE)


@dataclass(frozen=True)
class ParsedMobileLoginUri:
    """Canonical representation and parsed components of an allowed mobile login URI."""

    scheme: str
    host: str
    port: int | None
    path: str
    canonical: str

    @property
    def as_tuple(self) -> tuple[str, str, int | None, str]:
        """Return canonical 4-tuple (scheme, host, port, path)."""
        return (self.scheme, self.host, self.port, self.path)


def validate_app_environment(value: Any, *, field_name: str = "ENVIRONMENT") -> AppEnvironment:
    """
    Validate an explicit closed-enum environment selector fail-closed.

    Rejects missing, non-string, whitespace-padded, differently cased, or unapproved values.
    """
    if type(value) is not str:
        raise ValueError(
            f"{field_name} must be one of {ALLOWED_APP_ENVIRONMENTS}, got {type(value).__name__}"
        )
    if value not in ALLOWED_APP_ENVIRONMENTS:
        raise ValueError(
            f"{field_name} must be strictly one of {ALLOWED_APP_ENVIRONMENTS}; got {value!r}"
        )
    return value  # type: ignore[return-value]


def _validate_raw_uri_string(candidate: Any) -> str:
    """Run Rev10 §10.2.C.5 Step 1 pre-parse raw rejection rules."""
    if type(candidate) is not str or len(candidate) == 0:
        raise ValueError("URI must be a non-empty string")

    if any(ch.isspace() for ch in candidate):
        raise ValueError("URI must not contain whitespace")

    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        raise ValueError("URI must not contain control characters")

    if not candidate.isascii():
        raise ValueError("URI must contain ASCII characters only")

    for forbidden_char in ("\\", "*", "@", "?", "#"):
        if forbidden_char in candidate:
            raise ValueError(f"URI contains forbidden character {forbidden_char!r}")

    if ENCODED_TRAVERSAL_RE.search(candidate):
        raise ValueError("URI contains forbidden percent-encoded traversal or null sequence")

    if "://" not in candidate:
        raise ValueError("URI must contain '://' scheme-authority separator")

    raw_scheme, rest = candidate.split("://", 1)
    if not raw_scheme:
        raise ValueError("URI must include a non-empty scheme")

    if "/" in rest:
        raw_authority, raw_path_part = rest.split("/", 1)
        raw_path = "/" + raw_path_part
    else:
        raw_authority = rest
        raw_path = ""

    if not raw_authority:
        raise ValueError("URI must include a non-empty authority")

    if raw_authority.endswith(":"):
        raise ValueError("URI authority must not end with an empty port ':'")

    scheme_lower = raw_scheme.lower()
    if scheme_lower == "https" and raw_authority.endswith(":443"):
        raise ValueError("URI must not specify redundant default port :443 on https://")
    if scheme_lower == "http" and raw_authority.endswith(":80"):
        raise ValueError("URI must not specify redundant default port :80 on http://")

    if "//" in raw_path:
        raise ValueError("URI path must not contain consecutive slashes '//'")

    if raw_path:
        for segment in raw_path.split("/")[1:]:
            if segment in {".", ".."}:
                raise ValueError("URI path must not contain dot segments")

    return candidate


def _normalize_host(raw_host: str | None) -> str:
    """Normalize IPv4/IPv6/ASCII hostnames identically across JS WHATWG URL and Python."""
    if not raw_host:
        raise ValueError("URI must include a non-empty host")

    host_lower = raw_host.lower()

    if ":" in host_lower:
        try:
            ipv6 = ipaddress.IPv6Address(host_lower)
        except ValueError as exc:
            raise ValueError(f"Invalid IPv6 host in URI: {exc}") from exc
        return f"[{ipv6.compressed}]"

    for label in host_lower.split("."):
        if label.startswith("xn--"):
            raise ValueError("URI host must not use punycode xn-- labels")

    return host_lower


def parse_and_canonicalize_mobile_login_uri(
    candidate: Any,
    *,
    environment: str,
) -> ParsedMobileLoginUri:
    """
    Parse, validate, and canonicalize a single mobile-login URI under Rev10 §10.2.C.4-5.
    """
    env = validate_app_environment(environment, field_name="ENVIRONMENT")
    raw = _validate_raw_uri_string(candidate)

    parts = urlsplit(raw)
    scheme = parts.scheme.lower()

    if scheme in DANGEROUS_SCHEMES:
        raise ValueError(f"URI scheme {scheme!r} is forbidden")

    if not CUSTOM_SCHEME_RE.fullmatch(scheme):
        raise ValueError(f"URI scheme {scheme!r} does not conform to RFC 3986")

    if parts.username is not None or parts.password is not None:
        raise ValueError("URI must not contain userinfo credentials")

    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("URI contains an invalid port") from exc

    canonical_host = _normalize_host(parts.hostname)

    # Environment-aware scheme & authority rules
    if scheme == "http":
        if env == "production":
            raise ValueError("http:// URIs are unconditionally rejected in production")
        if canonical_host not in LOOPBACK_HOSTS:
            raise ValueError(
                "External http:// URIs are rejected in all environments; "
                "only explicit loopback hosts (localhost, 127.0.0.1, [::1]) are permitted in dev/test"
            )
        if port == 80:
            raise ValueError("URI must not specify redundant default port :80 on http://")
    elif scheme == "https":
        if port == 443:
            raise ValueError("URI must not specify redundant default port :443 on https://")
    else:
        if port is not None:
            raise ValueError("Custom application scheme URIs must not specify a port")

    if port is not None and not (1 <= port <= 65535):
        raise ValueError("URI port must be between 1 and 65535")

    if parts.query != "" or parts.fragment != "":
        raise ValueError("URI must not contain query parameters or fragments")

    path = parts.path
    if not path or not path.startswith("/"):
        raise ValueError("URI must include a non-empty path starting with '/'")
    if "//" in path:
        raise ValueError("URI path must not contain consecutive slashes")
    if path != "/" and path.endswith("/"):
        raise ValueError("URI route path must not end with a trailing '/'")
    for segment in path.split("/")[1:]:
        if segment in {"", ".", ".."}:
            raise ValueError("URI path contains invalid empty or dot segment")

    authority = f"{canonical_host}:{port}" if port is not None else canonical_host
    canonical = f"{scheme}://{authority}{path}"
    return ParsedMobileLoginUri(
        scheme=scheme,
        host=canonical_host,
        port=port,
        path=path,
        canonical=canonical,
    )


def canonicalize_mobile_login_allowlist(
    uris: Sequence[str],
    *,
    environment: str,
) -> list[str]:
    """Validate and canonicalize an allowlist of mobile login URIs preserving deduplicated order."""
    env = validate_app_environment(environment, field_name="ENVIRONMENT")
    canonical_list: list[str] = []
    seen: set[str] = set()
    for raw_uri in uris:
        parsed = parse_and_canonicalize_mobile_login_uri(raw_uri, environment=env)
        if parsed.canonical not in seen:
            seen.add(parsed.canonical)
            canonical_list.append(parsed.canonical)
    return canonical_list


def match_mobile_login_uri(
    candidate: Any,
    allowlist: Sequence[str],
    *,
    environment: str,
) -> str | None:
    """
    Match a candidate URI strictly by canonical string and 4-tuple against an allowlist.

    Returns the canonical string if permitted, or None on any failure/mismatch (fail-safe).
    """
    try:
        env = validate_app_environment(environment, field_name="ENVIRONMENT")
        parsed_candidate = parse_and_canonicalize_mobile_login_uri(candidate, environment=env)
    except ValueError:
        return None

    for allowed_raw in allowlist:
        try:
            parsed_allowed = parse_and_canonicalize_mobile_login_uri(allowed_raw, environment=env)
        except ValueError:
            continue
        if (
            parsed_candidate.canonical == parsed_allowed.canonical
            and parsed_candidate.as_tuple == parsed_allowed.as_tuple
        ):
            return parsed_allowed.canonical

    return None


def validate_frontend_backend_parity(
    *,
    backend_environment: Any,
    frontend_environment: Any,
    backend_uris: Sequence[str],
    frontend_uris: Sequence[str],
) -> list[str]:
    """
    Execute the 4-gate deterministic CI/release parity check (Rev10 §10.2.C.3):
      1. Closed-enum validation of both ENVIRONMENT and VITE_APP_ENVIRONMENT.
      2. Exact 1-to-1 environment parity (VITE_APP_ENVIRONMENT == ENVIRONMENT).
      3. Per-environment URI validation on both allowlists.
      4. Canonical allowlist set equality across backend and frontend lists.
    """
    backend_env = validate_app_environment(backend_environment, field_name="ENVIRONMENT")
    frontend_env = validate_app_environment(
        frontend_environment, field_name="VITE_APP_ENVIRONMENT"
    )

    if frontend_env != backend_env:
        raise ValueError(
            f"Environment parity mismatch: VITE_APP_ENVIRONMENT={frontend_env!r} "
            f"!= ENVIRONMENT={backend_env!r}"
        )

    backend_parsed = [
        parse_and_canonicalize_mobile_login_uri(uri, environment=backend_env)
        for uri in backend_uris
    ]
    frontend_parsed = [
        parse_and_canonicalize_mobile_login_uri(uri, environment=frontend_env)
        for uri in frontend_uris
    ]

    backend_tuples = {item.as_tuple: item.canonical for item in backend_parsed}
    frontend_tuples = {item.as_tuple: item.canonical for item in frontend_parsed}

    if set(backend_tuples.keys()) != set(frontend_tuples.keys()) or set(
        backend_tuples.values()
    ) != set(frontend_tuples.values()):
        raise ValueError(
            "Canonical allowlist parity mismatch between "
            "EMAIL_VERIFICATION_MOBILE_LOGIN_URIS and VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS"
        )

    return sorted(backend_tuples.values())
