"""Centralized logging configuration and security sanitization for Folio360."""

import logging
import re
import sys
from typing import Any, Optional

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

# 4. Key-value credential assignments (passwords, secrets, API keys, tokens, PKCE verifiers)
KEY_VALUE_PATTERN = re.compile(
    r'(?i)(["\']?(?:'
    r"new_password|current_password|password|"
    r"client_secret|jwt_secret_key|oauth_pkce_encryption_key|secret|"
    r"access_token|refresh_token|verification_token|reset_token|id_token|token_hash|token|"
    r"resend_api_key|api_key|"
    r"pkce_verifier_encrypted|pkce_verifier|code_verifier|"
    r"exchange_code|oauth_code|folio360_refresh_token"
    r')["\']?\s*[:=]\s*)(?!\[REDACTED\])(?:["\']([^"\']*)["\']|([^\s,;&"\']+))'
)

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

    # 4. Redact key-value assignments (JSON, query params, configuration)
    sanitized = KEY_VALUE_PATTERN.sub(_replace_credential, sanitized)

    # 5. Redact standalone Resend API keys and 3-segment JWT tokens
    sanitized = RESEND_API_KEY_PATTERN.sub(REDACTED, sanitized)
    sanitized = JWT_PATTERN.sub(REDACTED, sanitized)

    # 6. Redact URI connection credentials and raw database connection strings
    sanitized = URI_CREDENTIAL_PATTERN.sub(_replace_uri_credential, sanitized)
    sanitized = CONNECTION_STRING_PATTERN.sub(REDACTED_CONN, sanitized)

    # 7. Redact raw SQL statements
    sanitized = SQL_PATTERN.sub(REDACTED_SQL, sanitized)

    return sanitized


class SecurityFilter(logging.Filter):
    """
    Log filter providing defense-in-depth protection against accidental credential exposure.

    Heuristically sanitizes log records, parameterized arguments, exception text,
    raw SQL statements, database connection strings, and stack_info across
    application-controlled handlers.

    Fail-Safe Behavior:
        If sanitization fails or encounters an unexpected exception, the original record
        content is suppressed and replaced with a safe fallback diagnostic message.
        Unsanitized content is never permitted through the security boundary.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
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


def setup_logging(log_level: Optional[str] = None) -> None:
    """
    Configure structured centralized logging for the application.

    Maintains predictable log formatting and configured log levels.
    Defines a clear sanitization boundary for application-controlled logging by:
      1. Attaching SecurityFilter directly to the root logger and the application logger ('folio360').
      2. Ensuring all handlers in the application logging pipeline (root and 'folio360')
         have security filtering attached via protect_handler() without destructively replacing them.
      3. Registering the dedicated Folio360 console handler idempotently.
    """
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

    # Third-party noisy loggers control
    logging.getLogger("uvicorn.access").propagate = True
