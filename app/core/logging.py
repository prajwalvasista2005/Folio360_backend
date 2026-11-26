"""Centralized logging configuration and security sanitization for Folio360."""

import logging
import re
import sys
from typing import Any, Iterable, Optional, Sequence, Union
from urllib.parse import unquote

REDACTED = "[REDACTED]"
REDACTED_SQL = "[REDACTED_SQL]"
REDACTED_CONN = "[REDACTED_CONNECTION_STRING]"
FAILSAFE_FALLBACK_MESSAGE = "[LOG_SANITIZATION_FAILED: Record content suppressed for security]"
FOLIO360_HANDLER_NAME = "folio360_console_handler"

# Heuristic patterns for sensitive credentials, connection strings, and SQL in text

# 1. Authorization header pattern:
# Captures scheme if present (e.g. "Bearer ", "Basic ") and redacts the credential value
AUTH_HEADER_PATTERN = re.compile(
    r'(?i)(["\']?authorization["\']?\s*[:=]\s*["\']?(?:(?:bearer|basic)\s+)?)(?!\[REDACTED\])(?:["\']([^"\']*)["\']|([^\s,;&"\']+))'
)

# 2. Standalone Bearer tokens (where "bearer" is present outside an authorization header)
BEARER_PATTERN = re.compile(
    r'(?i)\b(bearer\s+)(?!\[REDACTED\])(?:["\']([^"\']*)["\']|([^\s,;&"\']+))'
)

# 3. Cookie / Set-Cookie header and key-value assignments
COOKIE_PATTERN = re.compile(
    r'(?i)(["\']?(?:set-cookie|cookie)["\']?\s*[:=]\s*)(?!\[REDACTED\])(?:["\']([^"\']*)["\']|([^\r\n]+))'
)

# 4. Key-value credential assignments (passwords, secrets, API keys, tokens, PKCE verifiers, OIDC nonces)
# Ordered with longer composite names before shorter prefixes.
KEY_VALUE_PATTERN = re.compile(
    r'(?i)(["\']?(?:'
    r"new_password|current_password|password|"
    r"client_secret|jwt_secret_key|oauth_pkce_encryption_key_previous|oauth_pkce_encryption_key|secret|"
    r"access_token|refresh_token|verification_token|reset_token|id_token|token_hash|token|"
    r"ai_analyzer_api_key|x-goog-api-key|resend_api_key|api_key|"
    r"pkce_verifier_encrypted|pkce_verifier|exchange_code_verifier|code_verifier|"
    r"exchange_code|authorization_code|oauth_code|oauth_state|(?<![A-Za-z0-9_-])oauth_nonce|(?<![A-Za-z0-9_-])nonce|"
    r"folio360_oauth_binding|oauth_binding|folio360_oauth_exchange|oauth_exchange|folio360_refresh_token"
    r')["\']?\s*[:=]\s*)(?!\[REDACTED\])(?:["\']([^"\']*)["\']|([^\s,;&"\'#]+))'
)

_SENSITIVE_QUERY_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "code",
        "state",
        "nonce",
        "oauth_nonce",
        "token",
        "id_token",
        "access_token",
        "refresh_token",
        "error_description",
    }
)
_TRAILING_WRAPPER_RE = re.compile(r'''["'][,}\])]*\Z''')

# 4b. Sensitive URL query/matrix/fragment parameters (preserves status_code, error_code, client_type)
QUERY_SECRET_PARAM_PATTERN = re.compile(
    r"([?&;#])([A-Za-z0-9_%-]{1,64})(=)([^\s&#;]+)"
)
ENCODED_QUERY_SECRET_PARAM_PATTERN = re.compile(
    r"(?i)(%3f|%26|%23|%3b)((?:(?!%3d)[A-Za-z0-9_%-]){1,64})(%3d)((?:(?!%26|%23|%3b|%3f)[^\s&#;])+)"
)

_EXTRA_SENSITIVE_KEY_NAMES: frozenset[str] = frozenset()
_EXTRA_SENSITIVE_KEY_NAMES_LOWER: frozenset[str] = frozenset()
_EXTRA_SENSITIVE_KEY_PATTERN: Optional[re.Pattern[str]] = None

# 5. Standalone Resend API keys & JWTs
RESEND_API_KEY_PATTERN = re.compile(r"\bre_[A-Za-z0-9_]{16,}\b")
JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)

# 6. Connection string / URI credentials pattern
URI_CREDENTIAL_PATTERN = re.compile(
    r'(?i)([a-z][a-z0-9+.-]*://[^:\s/@]+:)(?!\[REDACTED\])([^@\s/]+)(@)'
)
CONNECTION_STRING_PATTERN = re.compile(
    r'(?i)\b(?:postgresql|postgres|mysql|sqlite|mariadb|oracle|mssql|mongodb|redis)(?:\+[a-z0-9_]+)?://[^\s\'"]+'
)

# 7. Raw SQL statements pattern (SELECT ... FROM, INSERT INTO, UPDATE ... SET, DELETE FROM, etc.)
# Heuristic pattern-based matching for standard SQL statements.
#
# SQL Redaction Limitations:
#   SQL detection is heuristic and regex-based. It detects common statement patterns
#   (SELECT, INSERT, UPDATE, DELETE, CREATE/DROP/ALTER/TRUNCATE TABLE) but does not
#   employ a SQL grammar or AST parser. As such, it is not a guarantee of universal
#   SQL detection across all conceivable SQL dialects, heavily obfuscated queries,
#   unusual line-breaks, nested subqueries, or non-standard syntax. Applications should
#   avoid logging raw query strings containing sensitive values directly.
SQL_PATTERN = re.compile(
    r'(?i)\b(?:'
    r'SELECT\s+[\s\S]+?\s+FROM\s+[\w\."\']+(?:\s+WHERE\s+[^;\n]+)?|'
    r'INSERT\s+INTO\s+[\w\."\']+(?:\s*\([^)]*\))?\s*VALUES\s*\([^;\n]+\)|'
    r'INSERT\s+INTO\s+[\w\."\']+|'
    r'UPDATE\s+[\w\."\']+\s+SET\s+[\s\S]+?(?:\s+WHERE\s+[^;\n]+)?|'
    r'DELETE\s+FROM\s+[\w\."\']+(?:\s+WHERE\s+[^;\n]+)?|'
    r'(?:CREATE|DROP|ALTER|TRUNCATE)\s+TABLE(?:\s+IF\s+(?:NOT\s+)?EXISTS)?\s+[\w\."\']+'
    r')'
)


def _replace_credential(match: re.Match[str]) -> str:
    prefix = match.group(1)
    quoted_val = match.group(2)
    if quoted_val is not None:
        return f'{prefix}"{REDACTED}"'
    return f"{prefix}{REDACTED}"


def _replace_uri_credential(match: re.Match[str]) -> str:
    return f"{match.group(1)}{REDACTED}{match.group(3)}"


def _compile_extra_key_pattern(names: frozenset[str]) -> Optional[re.Pattern[str]]:
    if not names:
        return None
    escaped = "|".join(re.escape(name) for name in sorted(names, key=len, reverse=True))
    return re.compile(
        rf'(?i)(["\']?(?<![A-Za-z0-9_-])(?:{escaped})["\']?\s*[:=]\s*)'
        rf'(?!\[REDACTED\])(?:["\']([^"\']*)["\']|([^\s,;&"\'#]+))'
    )


def _split_trailing_wrapper_suffix(raw_val: str, match: re.Match[str]) -> tuple[str, str]:
    """Preserve closing quote/JSON delimiters only when the match ends at whitespace or EOS."""
    at_boundary = match.end() == len(match.string) or match.string[match.end()].isspace()
    if at_boundary:
        wrapper_match = _TRAILING_WRAPPER_RE.search(raw_val)
        if wrapper_match is not None:
            suffix = wrapper_match.group(0)
            return raw_val[: len(raw_val) - len(suffix)], suffix
    return raw_val, ""


def _redact_query_secret_match(match: re.Match[str]) -> str:
    delim, raw_name, eq, raw_val = match.groups()
    decoded_name = (unquote(raw_name) if "%" in raw_name else raw_name).lower()
    if (
        decoded_name not in _SENSITIVE_QUERY_PARAM_NAMES
        and decoded_name not in _EXTRA_SENSITIVE_KEY_NAMES_LOWER
    ):
        return match.group(0)
    core_val, suffix = _split_trailing_wrapper_suffix(raw_val, match)
    if not core_val or core_val == REDACTED:
        return match.group(0)
    return f"{delim}{raw_name}{eq}{REDACTED}{suffix}"


def register_sensitive_key_names(
    names: Iterable[str],
    *,
    replace: bool = False,
) -> None:
    """Register extra key-value names (e.g., custom OAuth cookie names) for log redaction."""
    global _EXTRA_SENSITIVE_KEY_NAMES, _EXTRA_SENSITIVE_KEY_NAMES_LOWER, _EXTRA_SENSITIVE_KEY_PATTERN
    cleaned = {item.strip() for item in names if isinstance(item, str) and item.strip()}
    updated = frozenset(cleaned) if replace else (_EXTRA_SENSITIVE_KEY_NAMES | cleaned)
    _EXTRA_SENSITIVE_KEY_NAMES = updated
    _EXTRA_SENSITIVE_KEY_NAMES_LOWER = frozenset(item.lower() for item in updated)
    _EXTRA_SENSITIVE_KEY_PATTERN = _compile_extra_key_pattern(updated)


def sanitize_log_text(text: Any) -> str:
    """
    Sanitize sensitive credential values, connection strings, and SQL queries from a log string.

    Heuristically redacts passwords, client secrets, API keys, cookies, JWTs,
    access/refresh/verification tokens, token hashes, PKCE verifiers, authorization
    headers, URI credentials, connection strings, and raw SQL statements.
    """
    if not isinstance(text, str):
        text = str(text)

    # 1. Redact Authorization headers (preserves scheme, e.g. "Authorization: Bearer [REDACTED]")
    sanitized = AUTH_HEADER_PATTERN.sub(_replace_credential, text)

    # 2. Redact standalone Bearer tokens (e.g. "bearer [REDACTED]")
    sanitized = BEARER_PATTERN.sub(_replace_credential, sanitized)

    # 3. Redact cookie / set-cookie headers and fields
    sanitized = COOKIE_PATTERN.sub(_replace_credential, sanitized)

    # 4. Redact key-value assignments (JSON, query params, configuration, custom cookie keys)
    sanitized = KEY_VALUE_PATTERN.sub(_replace_credential, sanitized)
    if _EXTRA_SENSITIVE_KEY_PATTERN is not None:
        sanitized = _EXTRA_SENSITIVE_KEY_PATTERN.sub(_replace_credential, sanitized)

    # 4b. Redact sensitive URL query/matrix/fragment parameters and percent-encoded variants
    sanitized = QUERY_SECRET_PARAM_PATTERN.sub(_redact_query_secret_match, sanitized)
    sanitized = ENCODED_QUERY_SECRET_PARAM_PATTERN.sub(_redact_query_secret_match, sanitized)

    # 5. Redact standalone Resend API keys and 3-segment JWT tokens
    sanitized = RESEND_API_KEY_PATTERN.sub(REDACTED, sanitized)
    sanitized = JWT_PATTERN.sub(REDACTED, sanitized)

    # 6. Redact URI connection credentials and raw database connection strings
    sanitized = URI_CREDENTIAL_PATTERN.sub(_replace_uri_credential, sanitized)
    sanitized = CONNECTION_STRING_PATTERN.sub(REDACTED_CONN, sanitized)

    # 7. Redact raw SQL statements
    sanitized = SQL_PATTERN.sub(REDACTED_SQL, sanitized)

    return sanitized


def _is_uvicorn_access_logger_name(name: Any) -> bool:
    return isinstance(name, str) and (name == "uvicorn.access" or name.startswith("uvicorn.access."))


def _suppress_uvicorn_access_record(record: logging.LogRecord) -> bool:
    record.msg = FAILSAFE_FALLBACK_MESSAGE
    record.args = None
    record.exc_info = None
    record.exc_text = None
    record.stack_info = None
    return False


def _sanitize_uvicorn_access_record(record: logging.LogRecord) -> bool:
    try:
        if not (isinstance(record.args, tuple) and len(record.args) == 5):
            return _suppress_uvicorn_access_record(record)

        client_addr, method, full_path, http_version, status_code = record.args
        if type(status_code) is int:
            safe_status_code = status_code
        elif isinstance(status_code, str) and status_code.isascii() and status_code.isdigit():
            safe_status_code = int(status_code)
        else:
            return _suppress_uvicorn_access_record(record)

        record.args = (
            sanitize_log_text(client_addr),
            sanitize_log_text(method),
            sanitize_log_text(full_path),
            sanitize_log_text(http_version),
            safe_status_code,
        )
        record.msg = sanitize_log_text(
            record.msg if isinstance(record.msg, str) else str(record.msg)
        )
        if record.exc_info and not record.exc_text:
            record.exc_text = sanitize_log_text(
                logging.Formatter().formatException(record.exc_info)
            )
        elif record.exc_text:
            record.exc_text = sanitize_log_text(record.exc_text)
        if getattr(record, "stack_info", None):
            record.stack_info = sanitize_log_text(str(record.stack_info))
        return True
    except Exception:
        return _suppress_uvicorn_access_record(record)


class SecurityFilter(logging.Filter):
    """
    Log filter providing defense-in-depth protection against accidental credential exposure.

    Heuristically sanitizes log records, parameterized arguments, exception text,
    raw SQL statements, database connection strings, and stack_info across
    application-controlled handlers.

    For uvicorn.access records on shared handlers, preserves the 5-tuple AccessFormatter
    contract instead of collapsing record.args to None.

    Fail-Safe Behavior:
        If sanitization fails or encounters an unexpected exception, the original record
        content is suppressed and replaced with a safe fallback diagnostic message.
        Unsanitized content is never permitted through the security boundary.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if _is_uvicorn_access_logger_name(getattr(record, "name", "")):
                return _sanitize_uvicorn_access_record(record)

            if record.args:
                # Merge and sanitize parameterized arguments
                formatted = record.getMessage()
                record.msg = sanitize_log_text(formatted)
                record.args = None
            else:
                # Convert supported string or non-string values safely, then sanitize
                msg_str = record.msg if isinstance(record.msg, str) else str(record.msg)
                record.msg = sanitize_log_text(msg_str)

            # Pre-format and cache sanitized exception traceback if present
            if record.exc_info and not record.exc_text:
                default_formatter = logging.Formatter()
                raw_exc_text = default_formatter.formatException(record.exc_info)
                record.exc_text = sanitize_log_text(raw_exc_text)
            elif record.exc_text:
                record.exc_text = sanitize_log_text(record.exc_text)

            # Sanitize stack_info if present
            if getattr(record, "stack_info", None):
                stack_str = (
                    record.stack_info
                    if isinstance(record.stack_info, str)
                    else str(record.stack_info)
                )
                record.stack_info = sanitize_log_text(stack_str)

            return True
        except Exception:
            # Fail-safe: Never emit unsanitized record content; replace with safe diagnostic
            record.msg = FAILSAFE_FALLBACK_MESSAGE
            record.args = None
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
            return True


class SecurityFormatter(logging.Formatter):
    """Logging formatter that ensures final emitted log records (including tracebacks) are sanitized."""

    def format(self, record: logging.LogRecord) -> str:
        try:
            formatted = super().format(record)
            return sanitize_log_text(formatted)
        except Exception:
            return f"{record.levelname} - {FAILSAFE_FALLBACK_MESSAGE}"


def protect_handler(handler: logging.Handler) -> logging.Handler:
    """
    Attach SecurityFilter to a logging handler if not already present.

    Ensures application-controlled handlers (including child logger handlers)
    cannot bypass the intended sanitization policy.
    """
    if not any(isinstance(f, SecurityFilter) for f in handler.filters):
        handler.addFilter(SecurityFilter())
    return handler


class UvicornAccessSanitizingFilter(logging.Filter):
    """
    Sanitize Uvicorn access-log query parameters and strings while preserving the 5-tuple
    args contract expected by uvicorn.logging.AccessFormatter.

    Non-uvicorn.access records reaching a shared handler are delegated to SecurityFilter.
    Malformed or unfilterable uvicorn.access records fail closed (dropped by returning False)
    so AccessFormatter never crashes or emits unsanitized secrets.
    """

    def _suppress_record(self, record: logging.LogRecord) -> bool:
        return _suppress_uvicorn_access_record(record)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if not _is_uvicorn_access_logger_name(getattr(record, "name", "")):
                return SecurityFilter().filter(record)
            return _sanitize_uvicorn_access_record(record)
        except Exception:
            return _suppress_uvicorn_access_record(record)


def protect_uvicorn_access_handler(handler: logging.Handler) -> logging.Handler:
    """Attach UvicornAccessSanitizingFilter idempotently to a uvicorn.access handler."""
    if not any(isinstance(f, UvicornAccessSanitizingFilter) for f in handler.filters):
        handler.addFilter(UvicornAccessSanitizingFilter())
    return handler


def _resolve_logger(logger_or_name: Union[logging.Logger, str]) -> logging.Logger:
    if isinstance(logger_or_name, logging.Logger):
        return logger_or_name
    if isinstance(logger_or_name, str) and logger_or_name:
        return logging.getLogger(logger_or_name)
    raise ValueError("logger_or_name must be a logging.Logger or non-empty logger name")


def protect_logger_handlers(logger_or_name: Union[logging.Logger, str]) -> logging.Logger:
    """
    Attach the appropriate sanitizing filter idempotently to a logger and all of its handlers.
    """
    target = _resolve_logger(logger_or_name)
    if _is_uvicorn_access_logger_name(target.name):
        if not any(isinstance(f, UvicornAccessSanitizingFilter) for f in target.filters):
            target.addFilter(UvicornAccessSanitizingFilter())
        for handler in target.handlers:
            protect_uvicorn_access_handler(handler)
    else:
        if not any(isinstance(f, SecurityFilter) for f in target.filters):
            target.addFilter(SecurityFilter())
        for handler in target.handlers:
            protect_handler(handler)
    return target


def attach_protected_handler(
    logger_or_name: Union[logging.Logger, str],
    handler: logging.Handler,
) -> logging.Handler:
    """
    Protect a handler at the handler boundary and attach it idempotently to a logger.

    Using this helper (or calling protect_uvicorn_loggers() after attaching a late handler)
    ensures propagated child-logger records cannot bypass parent logger filters without
    monkey-patching stdlib logging.
    """
    target = _resolve_logger(logger_or_name)
    if _is_uvicorn_access_logger_name(target.name):
        protect_uvicorn_access_handler(handler)
    else:
        protect_handler(handler)
    if handler not in target.handlers:
        target.addHandler(handler)
    return handler


def protect_uvicorn_loggers() -> None:
    """
    Idempotently protect Uvicorn loggers, existing uvicorn.* child loggers, and all their handlers.
    """
    access_logger = logging.getLogger("uvicorn.access")
    access_logger.propagate = False
    protect_logger_handlers(access_logger)
    protect_logger_handlers("uvicorn")
    protect_logger_handlers("uvicorn.error")

    for logger_name, logger_obj in list(logging.Logger.manager.loggerDict.items()):
        if isinstance(logger_obj, logging.Logger) and logger_name.startswith("uvicorn."):
            protect_logger_handlers(logger_obj)


def setup_logging(
    log_level: Optional[str] = None,
    *,
    extra_sensitive_keys: Optional[Sequence[str]] = None,
) -> None:
    """
    Configure structured centralized logging for the application.

    Maintains predictable log formatting and configured log levels.
    Defines a clear sanitization boundary for application-controlled logging by:
      1. Attaching SecurityFilter directly to the root logger and the application logger ('folio360').
      2. Ensuring all handlers in the application logging pipeline (root and 'folio360')
         have security filtering attached via protect_handler() without destructively replacing them.
      3. Registering the dedicated Folio360 console handler idempotently.
    """
    if extra_sensitive_keys is not None:
        register_sensitive_key_names(extra_sensitive_keys, replace=True)

    level_name = (log_level or "INFO").upper()
    numeric_level = getattr(logging, level_name, logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    app_logger = logging.getLogger("folio360")
    app_logger.setLevel(numeric_level)

    # 1. Attach SecurityFilter to root logger and app_logger if not already present
    if not any(isinstance(f, SecurityFilter) for f in root_logger.filters):
        root_logger.addFilter(SecurityFilter())
    if not any(isinstance(f, SecurityFilter) for f in app_logger.filters):
        app_logger.addFilter(SecurityFilter())

    # 2. Attach SecurityFilter to all existing handlers on root and app_logger
    for handler in root_logger.handlers:
        protect_handler(handler)
    for handler in app_logger.handlers:
        protect_handler(handler)

    # 3. Locate or register the Folio360 console handler
    formatter = SecurityFormatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    folio_handler: Optional[logging.Handler] = None
    for handler in root_logger.handlers:
        if handler.get_name() == FOLIO360_HANDLER_NAME:
            folio_handler = handler
            break

    if folio_handler is not None:
        folio_handler.setLevel(numeric_level)
        folio_handler.setFormatter(formatter)
    else:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.set_name(FOLIO360_HANDLER_NAME)
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(SecurityFilter())
        root_logger.addHandler(console_handler)

    # Third-party Uvicorn loggers & child loggers: idempotent sanitization without duplicating access logs
    protect_uvicorn_loggers()
