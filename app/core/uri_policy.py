"""Deterministic environment and mobile-login URI policy validation (Rev10 §10.2.C)."""

from collections.abc import Collection, Mapping
from dataclasses import dataclass
import ipaddress
import re
from typing import Any, Literal, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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


# ---------------------------------------------------------------------------
# Stage 3C: Web and Mobile OAuth Redirect URI Policies (F360-S3C-SPEC-REV12)
# ---------------------------------------------------------------------------

MALFORMED_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
OBFUSCATED_INT_LABEL_RE = re.compile(r"^(?:0x[0-9a-f]+|0[0-7]+|\d+)$", re.IGNORECASE)
OAUTH_DISALLOWED_MOBILE_SCHEMES: frozenset[str] = DANGEROUS_SCHEMES | frozenset({"ws", "wss"})
OAUTH_FORBIDDEN_ENCODED_RE = re.compile(
    r"%(?:[01][0-9a-f]|7f|23|25|2e|2f|3f|40|5c)",
    re.IGNORECASE,
)
OAUTH_FORBIDDEN_PATH_CHARS: frozenset[str] = frozenset(
    {'"', "'", "<", ">", "{", "}", "|", "^", "`"}
)
DNS_LABEL_RE = re.compile(r"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.IGNORECASE)
ALL_DIGITS_LABEL_RE = re.compile(r"\A\d+\Z")


@dataclass(frozen=True)
class ParsedOAuthRedirectUri:
    """Canonical representation and parsed components of an allowed OAuth redirect URI."""

    scheme: str
    host: str
    port: int | None
    path: str
    origin: str
    canonical: str


def _validate_oauth_raw_uri_string(candidate: Any) -> str:
    """Enforce strict Stage 3C pre-parse OAuth redirect URI rejection rules."""
    if type(candidate) is not str or len(candidate) == 0:
        raise ValueError("OAuth redirect URI must be a non-empty string")
    if any(ch.isspace() for ch in candidate):
        raise ValueError("OAuth redirect URI must not contain whitespace")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        raise ValueError("OAuth redirect URI must not contain control characters")
    if not candidate.isascii():
        raise ValueError("OAuth redirect URI must contain ASCII characters only")

    for forbidden_char in ("\\", "*", "@", "?", "#"):
        if forbidden_char in candidate:
            raise ValueError(
                f"OAuth redirect URI contains forbidden character {forbidden_char!r}"
            )

    if MALFORMED_PERCENT_RE.search(candidate):
        raise ValueError("OAuth redirect URI contains malformed percent encoding")
    if OAUTH_FORBIDDEN_ENCODED_RE.search(candidate):
        raise ValueError(
            "OAuth redirect URI contains forbidden percent-encoded control character, delimiter, or double-encoding"
        )

    if "://" not in candidate:
        raise ValueError("OAuth redirect URI must contain '://' scheme-authority separator")

    raw_scheme, rest = candidate.split("://", 1)
    if not raw_scheme:
        raise ValueError("OAuth redirect URI must include a non-empty scheme")

    if "/" in rest:
        raw_authority, raw_path_part = rest.split("/", 1)
        raw_path = "/" + raw_path_part
    else:
        raw_authority = rest
        raw_path = ""

    if not raw_authority:
        raise ValueError("OAuth redirect URI must include a non-empty authority")
    if "%" in raw_authority:
        raise ValueError("OAuth redirect URI authority must not contain percent-encoded sequences")
    if raw_authority.endswith(":"):
        raise ValueError("OAuth redirect URI authority must not end with an empty port ':'")

    validate_strict_authority(raw_authority, scheme_lower=raw_scheme.lower())

    if any(ch in OAUTH_FORBIDDEN_PATH_CHARS for ch in raw_path):
        raise ValueError("OAuth redirect URI path contains forbidden delimiter character")
    if "//" in raw_path:
        raise ValueError("OAuth redirect URI path must not contain consecutive slashes '//'")
    if raw_path:
        for segment in raw_path.split("/")[1:]:
            if segment in {".", ".."}:
                raise ValueError("OAuth redirect URI path must not contain dot segments")

    return candidate


def validate_strict_authority(raw_authority: str, *, scheme_lower: str) -> None:
    """Validate bracketed IPv6, hostname/IPv4 structure, and strict numeric port bounds."""
    if raw_authority.startswith("["):
        if "]" not in raw_authority:
            raise ValueError("OAuth redirect URI has unclosed IPv6 bracket in authority")
        bracketed_host, remainder = raw_authority.split("]", 1)
        inner_host = bracketed_host[1:]
        if not inner_host:
            raise ValueError("OAuth redirect URI has empty IPv6 host")
        try:
            ipaddress.IPv6Address(inner_host)
        except ValueError as exc:
            raise ValueError(f"Invalid IPv6 host in OAuth redirect URI: {exc}") from exc
        port_part = _extract_and_validate_port_suffix(remainder)
    else:
        if "[" in raw_authority or "]" in raw_authority:
            raise ValueError("OAuth redirect URI contains unexpected bracket in authority")
        if raw_authority.count(":") > 1:
            raise ValueError("OAuth redirect URI contains malformed authority with multiple ':'")
        if ":" in raw_authority:
            raw_host, raw_port = raw_authority.split(":", 1)
            port_part = _extract_and_validate_port_suffix(f":{raw_port}")
        else:
            raw_host = raw_authority
            port_part = None
        if not raw_host:
            raise ValueError("OAuth redirect URI must include a non-empty host")
        if raw_host.startswith(".") or raw_host.endswith(".") or ".." in raw_host:
            raise ValueError("OAuth redirect URI host contains empty or trailing DNS labels")
        if _is_obfuscated_ip_host(raw_host):
            raise ValueError("OAuth redirect URI host uses disallowed numeric/hex/octal IP notation")

        is_canonical_ipv4 = False
        try:
            ipaddress.IPv4Address(raw_host)
            is_canonical_ipv4 = True
        except ValueError:
            pass

        if not is_canonical_ipv4:
            if len(raw_host) > 253:
                raise ValueError("OAuth redirect URI host exceeds maximum DNS length")
            labels = raw_host.split(".")
            for label in labels:
                if not DNS_LABEL_RE.fullmatch(label):
                    raise ValueError(
                        "OAuth redirect URI host contains invalid DNS label characters"
                    )
                if label.lower().startswith("xn--"):
                    raise ValueError("OAuth redirect URI host must not use punycode xn-- labels")
            if len(labels) > 1 and ALL_DIGITS_LABEL_RE.fullmatch(labels[-1]):
                raise ValueError("OAuth redirect URI host must not end with an all-numeric label")

    if scheme_lower == "https" and port_part == 443:
        raise ValueError("OAuth redirect URI must not specify redundant default port :443 on https://")
    if scheme_lower == "http" and port_part == 80:
        raise ValueError("OAuth redirect URI must not specify redundant default port :80 on http://")


def _extract_and_validate_port_suffix(suffix: str) -> int | None:
    if not suffix:
        return None
    if not suffix.startswith(":"):
        raise ValueError("OAuth redirect URI has malformed authority after IPv6 host")
    raw_port = suffix[1:]
    if not raw_port or not raw_port.isdigit() or not raw_port.isascii():
        raise ValueError("OAuth redirect URI contains non-numeric port")
    if raw_port.startswith("0") and raw_port != "0":
        raise ValueError("OAuth redirect URI port must not contain leading zeroes")
    port = int(raw_port)
    if not (1 <= port <= 65535):
        raise ValueError("OAuth redirect URI port must be between 1 and 65535")
    return port


def _is_obfuscated_ip_host(raw_host: str) -> bool:
    """Reject integer, hex, or octal IPv4 obfuscations while allowing canonical dotted-quad IPv4."""
    try:
        canonical_ipv4 = str(ipaddress.IPv4Address(raw_host))
        return raw_host != canonical_ipv4
    except ValueError:
        pass
    labels = raw_host.split(".")
    return all(OBFUSCATED_INT_LABEL_RE.fullmatch(label) for label in labels)


def _parse_oauth_redirect_components(
    candidate: Any,
    *,
    environment: str,
) -> tuple[AppEnvironment, str, str, int | None, str]:
    env = validate_app_environment(environment, field_name="ENVIRONMENT")
    raw = _validate_oauth_raw_uri_string(candidate)

    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"Malformed OAuth redirect URI: {exc}") from exc

    scheme = parts.scheme.lower()
    if scheme in DANGEROUS_SCHEMES:
        raise ValueError(f"OAuth redirect URI scheme {scheme!r} is forbidden")
    if not CUSTOM_SCHEME_RE.fullmatch(scheme):
        raise ValueError(f"OAuth redirect URI scheme {scheme!r} does not conform to RFC 3986")
    if parts.username is not None or parts.password is not None:
        raise ValueError("OAuth redirect URI must not contain userinfo credentials")
    if parts.query != "" or parts.fragment != "":
        raise ValueError("OAuth redirect URI must not contain query parameters or fragments")

    canonical_host = _normalize_host(parts.hostname)
    path = parts.path
    if not path or not path.startswith("/"):
        raise ValueError("OAuth redirect URI must include a non-empty path starting with '/'")
    if "//" in path:
        raise ValueError("OAuth redirect URI path must not contain consecutive slashes")
    if path != "/" and path.endswith("/"):
        raise ValueError("OAuth redirect URI path must not end with a trailing '/'")
    for segment in path.split("/")[1:]:
        if segment in {"", ".", ".."}:
            raise ValueError("OAuth redirect URI path contains invalid empty or dot segment")

    return env, scheme, canonical_host, port, path


def parse_and_canonicalize_web_oauth_redirect_uri(
    candidate: Any,
    *,
    environment: str,
) -> ParsedOAuthRedirectUri:
    """Validate and canonicalize a Stage 3C web OAuth redirect URI."""
    env, scheme, canonical_host, port, path = _parse_oauth_redirect_components(
        candidate,
        environment=environment,
    )

    if scheme not in {"http", "https"}:
        raise ValueError("Web OAuth redirect URI must use https:// (or loopback http:// in dev/test)")
    if scheme == "http":
        if env == "production":
            raise ValueError("http:// web OAuth redirect URIs are forbidden in production")
        if canonical_host not in LOOPBACK_HOSTS:
            raise ValueError(
                "http:// web OAuth redirect URIs must target an explicit loopback host "
                "(localhost, 127.0.0.1, or [::1])"
            )
        if port == 80:
            raise ValueError("Web OAuth redirect URI must not specify redundant default port :80")
    elif port == 443:
        raise ValueError("Web OAuth redirect URI must not specify redundant default port :443")

    authority = f"{canonical_host}:{port}" if port is not None else canonical_host
    origin = f"{scheme}://{authority}"
    return ParsedOAuthRedirectUri(
        scheme=scheme,
        host=canonical_host,
        port=port,
        path=path,
        origin=origin,
        canonical=f"{origin}{path}",
    )


def parse_and_canonicalize_mobile_oauth_redirect_uri(
    candidate: Any,
    *,
    environment: str,
) -> ParsedOAuthRedirectUri:
    """
    Validate and canonicalize a Stage 3C mobile OAuth redirect URI.

    Per locked REV12 Decision #2:
      - In production: HTTPS Universal Links / App Links ONLY.
      - In development/testing: HTTPS or RFC 8252 custom scheme (no ports, no http://, no ws:///wss://).
    """
    env, scheme, canonical_host, port, path = _parse_oauth_redirect_components(
        candidate,
        environment=environment,
    )

    if scheme in OAUTH_DISALLOWED_MOBILE_SCHEMES:
        raise ValueError(f"Mobile OAuth redirect URI scheme {scheme!r} is forbidden")
    if scheme == "http":
        raise ValueError("http:// mobile OAuth redirect URIs are forbidden")
    if env == "production" and scheme != "https":
        raise ValueError(
            "Production mobile OAuth redirect URIs must use https:// Universal Links / App Links"
        )
    if scheme == "https":
        if port == 443:
            raise ValueError("Mobile OAuth redirect URI must not specify redundant default port :443")
    else:
        if port is not None:
            raise ValueError("Custom application scheme OAuth redirect URIs must not specify a port")

    authority = f"{canonical_host}:{port}" if port is not None else canonical_host
    origin = f"{scheme}://{authority}"
    return ParsedOAuthRedirectUri(
        scheme=scheme,
        host=canonical_host,
        port=port,
        path=path,
        origin=origin,
        canonical=f"{origin}{path}",
    )


def _canonicalize_oauth_allowlist(
    uris: Sequence[str],
    *,
    environment: str,
    parser: Any,
    label: str,
) -> list[str]:
    env = validate_app_environment(environment, field_name="ENVIRONMENT")
    canonical_list: list[str] = []
    seen: set[str] = set()
    for raw_uri in uris:
        parsed = parser(raw_uri, environment=env)
        if parsed.canonical in seen:
            raise ValueError(f"Duplicate {label} entry detected")
        seen.add(parsed.canonical)
        canonical_list.append(parsed.canonical)
    return canonical_list


def canonicalize_web_oauth_redirect_allowlist(
    uris: Sequence[str],
    *,
    environment: str,
) -> list[str]:
    """Validate, canonicalize, and reject duplicates in OAUTH_ALLOWED_WEB_REDIRECT_URIS."""
    return _canonicalize_oauth_allowlist(
        uris,
        environment=environment,
        parser=parse_and_canonicalize_web_oauth_redirect_uri,
        label="OAUTH_ALLOWED_WEB_REDIRECT_URIS",
    )


def canonicalize_mobile_oauth_redirect_allowlist(
    uris: Sequence[str],
    *,
    environment: str,
) -> list[str]:
    """Validate, canonicalize, and reject duplicates in OAUTH_ALLOWED_MOBILE_REDIRECT_URIS."""
    return _canonicalize_oauth_allowlist(
        uris,
        environment=environment,
        parser=parse_and_canonicalize_mobile_oauth_redirect_uri,
        label="OAUTH_ALLOWED_MOBILE_REDIRECT_URIS",
    )


def _validate_oauth_allowlist_collection(allowlist: Any) -> None:
    """Reject bare strings/bytes/mappings where a collection of complete redirect URIs is required."""
    if isinstance(allowlist, (str, bytes, bytearray, Mapping)) or not isinstance(
        allowlist, Collection
    ):
        raise ValueError(
            "OAuth redirect allowlist must be a collection of URI strings, not a bare string/bytes"
        )


def match_exact_oauth_redirect_uri(
    candidate: Any,
    allowlist: frozenset[str] | Sequence[str],
) -> str | None:
    """
    Match a caller-supplied OAuth redirect_uri using exact raw string equality only.

    Never normalizes or mutates candidate before allowlist comparison.
    """
    _validate_oauth_allowlist_collection(allowlist)
    if type(candidate) is not str or not candidate:
        return None
    if candidate in allowlist:
        return candidate
    return None


def build_oauth_redirect_url(
    redirect_uri: str,
    *,
    allowlist: frozenset[str] | Sequence[str],
    code: str | None = None,
    error: str | None = None,
) -> str:
    """
    Safely construct a final client OAuth redirect URL after re-verifying exact allowlist membership.

    Requires exactly one of `code` or `error` (non-empty string without whitespace/control chars),
    strips any pre-existing `code`/`error` keys case-insensitively, and appends the single
    encoded parameter via urllib.parse.
    """
    _validate_oauth_allowlist_collection(allowlist)
    if type(redirect_uri) is not str or not redirect_uri or redirect_uri not in allowlist:
        raise ValueError("OAuth redirect_uri is not an exact member of the configured allowlist")
    if (code is not None) == (error is not None):
        raise ValueError("Exactly one of code or error must be provided")

    param_key = "code" if code is not None else "error"
    param_val = code if code is not None else error
    if (
        type(param_val) is not str
        or not param_val
        or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in param_val)
    ):
        raise ValueError(
            f"OAuth redirect {param_key} must be a non-empty string without whitespace or control characters"
        )

    parts = urlsplit(redirect_uri)
    filtered_query = [
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k.lower() not in {"code", "error"}
    ]
    filtered_query.append((param_key, param_val))
    encoded_query = urlencode(filtered_query)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, encoded_query, ""))
