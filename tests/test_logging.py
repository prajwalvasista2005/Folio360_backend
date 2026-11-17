"""Tests for logging security filtering, credential redaction, and handler lifecycle."""

import io
import logging
from unittest.mock import patch

from app.core.logging import (
    FAILSAFE_FALLBACK_MESSAGE,
    FOLIO360_HANDLER_NAME,
    REDACTED_CONN,
    REDACTED_SQL,
    SecurityFilter,
    SecurityFormatter,
    protect_handler,
    sanitize_log_text,
    setup_logging,
)


def test_sanitize_log_text_credentials() -> None:
    """Verify that sensitive credentials, connection strings, and SQL are redacted."""
    # Passwords (unquoted and quoted)
    assert sanitize_log_text("password=my_secret_123") == "password=[REDACTED]"
    assert sanitize_log_text('{"password": "secret_pass_456"}') == '{"password": "[REDACTED]"}'
    assert sanitize_log_text("password: 'single_quote_secret'") == 'password: "[REDACTED]"'

    # Client secrets and generic secrets
    assert sanitize_log_text("client_secret=super_secret_xyz") == "client_secret=[REDACTED]"
    assert sanitize_log_text('secret: "sensitive_val"') == 'secret: "[REDACTED]"'

    # Tokens
    assert sanitize_log_text("access_token=eyJhbGciOi...") == "access_token=[REDACTED]"
    assert sanitize_log_text("refresh_token=rt_987654321") == "refresh_token=[REDACTED]"
    assert sanitize_log_text("token_hash=$argon2id$v=19$...") == "token_hash=[REDACTED]"

    # Authorization headers & Bearer tokens
    assert sanitize_log_text("Authorization: Bearer my_jwt_token") == "Authorization: Bearer [REDACTED]"
    assert sanitize_log_text("bearer secret_bearer_token") == "bearer [REDACTED]"

    # Connection strings and URI credentials
    assert (
        sanitize_log_text("postgres://admin:super_secret_pw@localhost:5432/folio_db")
        == REDACTED_CONN
    )
    assert (
        sanitize_log_text("mysql://root:my_db_pass@127.0.0.1:3306/db")
        == REDACTED_CONN
    )
    assert (
        sanitize_log_text("https://user:pass123@api.example.com/v1")
        == "https://user:[REDACTED]@api.example.com/v1"
    )

    # Raw SQL queries
    assert (
        sanitize_log_text("Failed query: SELECT id, username, password_hash FROM users WHERE id = 123")
        == f"Failed query: {REDACTED_SQL}"
    )
    assert (
        sanitize_log_text("INSERT INTO account_credentials (email, secret) VALUES ('a@b.com', 'xyz')")
        == REDACTED_SQL
    )

    # Non-sensitive text preserved
    assert sanitize_log_text("User alice logged in successfully") == "User alice logged in successfully"


def test_security_filter_parameterized_logging() -> None:
    """Verify that SecurityFilter sanitizes records with parameterized arguments."""
    log_filter = SecurityFilter()
    record = logging.LogRecord(
        name="test.auth",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Login attempt for user %s with password=%s",
        args=("alice", "secret123"),
        exc_info=None,
    )

    log_filter.filter(record)
    assert record.args is None
    assert "secret123" not in record.msg
    assert "password=[REDACTED]" in record.msg


def test_security_formatter_exception_logging() -> None:
    """Verify that SecurityFormatter sanitizes exception tracebacks containing sensitive strings."""
    formatter = SecurityFormatter(fmt="%(levelname)s - %(message)s")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)

    test_logger = logging.getLogger("test.exceptions")
    original_handlers = list(test_logger.handlers)
    original_level = test_logger.level
    original_propagate = test_logger.propagate

    test_logger.handlers = [handler]
    test_logger.setLevel(logging.INFO)
    test_logger.propagate = False

    try:
        raise ValueError("Failed connecting with client_secret=very_confidential_key")
    except ValueError:
        test_logger.exception("An error occurred")
    finally:
        # Full isolation cleanup
        test_logger.handlers = original_handlers
        test_logger.setLevel(original_level)
        test_logger.propagate = original_propagate

    output = stream.getvalue()
    assert "very_confidential_key" not in output
    assert "client_secret=[REDACTED]" in output


def test_failsafe_sanitization_behavior_suppresses_content() -> None:
    """Verify fail-safe behavior when sanitizer fails: content is suppressed and does not crash."""
    log_filter = SecurityFilter()
    record = logging.LogRecord(
        name="test.failsafe",
        level=logging.ERROR,
        pathname="test.py",
        lineno=10,
        msg="Super confidential database password=top_secret_pw",
        args=None,
        exc_info=None,
    )

    # Deliberately simulate unexpected sanitization failure
    with patch("app.core.logging.sanitize_log_text", side_effect=RuntimeError("Simulated sanitizer failure")):
        # Must not raise an exception or crash application
        result = log_filter.filter(record)
        assert result is True

    # Sensitive content must be suppressed and replaced with safe fallback diagnostic
    assert "top_secret_pw" not in record.msg
    assert record.msg == FAILSAFE_FALLBACK_MESSAGE
    assert record.args is None
    assert record.exc_info is None


def test_child_logger_with_own_handler_and_propagation_disabled() -> None:
    """Verify that a child logger with propagation disabled and its own handler is protected."""
    child_logger = logging.getLogger("folio360.subservice")
    original_handlers = list(child_logger.handlers)
    original_level = child_logger.level
    original_propagate = child_logger.propagate

    stream = io.StringIO()
    child_handler = protect_handler(logging.StreamHandler(stream))
    child_handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))

    child_logger.handlers = [child_handler]
    child_logger.setLevel(logging.INFO)
    child_logger.propagate = False

    try:
        child_logger.info("Connecting with password=%s", "child_secret_123")
        output = stream.getvalue()
        assert "child_secret_123" not in output
        assert "password=[REDACTED]" in output
    finally:
        child_logger.handlers = original_handlers
        child_logger.setLevel(original_level)
        child_logger.propagate = original_propagate


def test_setup_logging_preserves_existing_handlers() -> None:
    """Verify that setup_logging does not delete unrelated logging handlers."""
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_filters = list(root_logger.filters)
    original_level = root_logger.level

    custom_handler = logging.StreamHandler()
    custom_handler.set_name("custom_external_handler")
    root_logger.addHandler(custom_handler)

    try:
        setup_logging(log_level="DEBUG")
        handler_names = [h.get_name() for h in root_logger.handlers]
        assert "custom_external_handler" in handler_names
        assert FOLIO360_HANDLER_NAME in handler_names
    finally:
        root_logger.handlers = original_handlers
        root_logger.filters = original_filters
        root_logger.setLevel(original_level)


def test_setup_logging_idempotent_no_duplicates() -> None:
    """Verify that calling setup_logging repeatedly does not register duplicate Folio360 handlers."""
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_filters = list(root_logger.filters)
    original_level = root_logger.level

    try:
        setup_logging(log_level="INFO")
        setup_logging(log_level="DEBUG")
        setup_logging(log_level="WARNING")

        folio_handlers = [
            h for h in root_logger.handlers if h.get_name() == FOLIO360_HANDLER_NAME
        ]
        assert len(folio_handlers) == 1
        assert folio_handlers[0].level == logging.WARNING
    finally:
        root_logger.handlers = original_handlers
        root_logger.filters = original_filters
        root_logger.setLevel(original_level)


def test_setup_logging_sanitizes_across_multiple_handlers() -> None:
    """Verify that multiple application-controlled handlers all receive sanitized records."""
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_filters = list(root_logger.filters)
    original_level = root_logger.level

    stream1 = io.StringIO()
    handler1 = logging.StreamHandler(stream1)
    handler1.set_name("multi_handler_1")
    handler1.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))

    stream2 = io.StringIO()
    handler2 = logging.StreamHandler(stream2)
    handler2.set_name("multi_handler_2")
    handler2.setFormatter(logging.Formatter("%(name)s: %(message)s"))

    root_logger.addHandler(handler1)
    root_logger.addHandler(handler2)

    try:
        setup_logging(log_level="INFO")

        # Test parameterized log record through multiple handlers
        app_logger = logging.getLogger("folio360.test.multi")
        app_logger.info("Connecting with password=%s and client_secret=%s", "secret_pwd_999", "secret_key_888")

        # Test exception traceback through multiple handlers
        try:
            raise RuntimeError("Database connection string postgres://user:super_secret_db_pass@db:5432/folio")
        except RuntimeError:
            app_logger.exception("An exception occurred")

        output1 = stream1.getvalue()
        output2 = stream2.getvalue()

        # Both handlers must receive sanitized text
        for out in (output1, output2):
            # Credentials must be redacted
            assert "secret_pwd_999" not in out
            assert "secret_key_888" not in out
            assert "super_secret_db_pass" not in out

            # Redacted placeholders must be present
            assert "password=[REDACTED]" in out
            assert "client_secret=[REDACTED]" in out
            assert REDACTED_CONN in out
    finally:
        root_logger.handlers = original_handlers
        root_logger.filters = original_filters
        root_logger.setLevel(original_level)


def test_stack_info_credentials_redacted() -> None:
    """Verify that sensitive credentials inside stack_info are redacted."""
    log_filter = SecurityFilter()
    stack_content = (
        '  File "/app/auth/service.py", line 55, in verify_token\n'
        '    validate(token="eyJhbGciOi_access_token_val", password="my_top_secret_123")\n'
        '  File "/app/core/security.py", line 12, in validate\n'
        '    check(client_secret="secret_client_xyz", auth_header="Bearer bearer_token_abc")'
    )
    record = logging.LogRecord(
        name="test.stack.creds",
        level=logging.ERROR,
        pathname="service.py",
        lineno=55,
        msg="Error during authentication execution",
        args=None,
        exc_info=None,
        sinfo=stack_content,
    )

    result = log_filter.filter(record)
    assert result is True
    assert record.stack_info is not None
    assert "my_top_secret_123" not in record.stack_info
    assert "eyJhbGciOi_access_token_val" not in record.stack_info
    assert "secret_client_xyz" not in record.stack_info
    assert "bearer_token_abc" not in record.stack_info
    assert 'password="[REDACTED]"' in record.stack_info
    assert 'client_secret="[REDACTED]"' in record.stack_info


def test_stack_info_raw_sql_and_connection_strings_redacted() -> None:
    """Verify that raw SQL and database connection strings inside stack_info are redacted."""
    log_filter = SecurityFilter()
    stack_content = (
        '  File "/app/db/session.py", line 80, in run_query\n'
        '    cursor.execute("SELECT id, secret_token FROM users WHERE email=\'admin@folio.com\'")\n'
        '  File "/app/db/engine.py", line 25, in connect\n'
        '    connect_raw("postgresql://postgres:db_super_pass@db.internal:5432/folio360")'
    )
    record = logging.LogRecord(
        name="test.stack.sql",
        level=logging.ERROR,
        pathname="session.py",
        lineno=80,
        msg="Database operational error",
        args=None,
        exc_info=None,
        sinfo=stack_content,
    )

    result = log_filter.filter(record)
    assert result is True
    assert record.stack_info is not None
    assert "db_super_pass" not in record.stack_info
    assert "SELECT id, secret_token FROM users" not in record.stack_info
    assert REDACTED_SQL in record.stack_info
    assert REDACTED_CONN in record.stack_info


def test_non_string_log_messages_cannot_bypass_sanitization() -> None:
    """Verify that non-string log messages (dicts, lists, exceptions, objects) are sanitized."""
    log_filter = SecurityFilter()

    # 1. Dictionary message containing credentials
    dict_record = logging.LogRecord(
        name="test.msg.dict",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg={"field": "password", "password": "confidential_pass_456", "status": "failed"},
        args=None,
        exc_info=None,
    )
    log_filter.filter(dict_record)
    assert isinstance(dict_record.msg, str)
    assert "confidential_pass_456" not in dict_record.msg
    assert "[REDACTED]" in dict_record.msg

    # 2. List message containing credentials and connection strings
    list_record = logging.LogRecord(
        name="test.msg.list",
        level=logging.INFO,
        pathname="test.py",
        lineno=12,
        msg=["access_token=secret_jwt_tok", "mysql://root:secret_mysql_pass@localhost/db"],
        args=None,
        exc_info=None,
    )
    log_filter.filter(list_record)
    assert isinstance(list_record.msg, str)
    assert "secret_jwt_tok" not in list_record.msg
    assert "secret_mysql_pass" not in list_record.msg
    assert "access_token=[REDACTED]" in list_record.msg
    assert REDACTED_CONN in list_record.msg

    # 3. Custom class with __str__ containing credentials
    class SensitivePayload:
        def __str__(self) -> str:
            return "SensitivePayload(client_secret=custom_class_secret_789)"

    obj_record = logging.LogRecord(
        name="test.msg.obj",
        level=logging.INFO,
        pathname="test.py",
        lineno=14,
        msg=SensitivePayload(),
        args=None,
        exc_info=None,
    )
    log_filter.filter(obj_record)
    assert isinstance(obj_record.msg, str)
    assert "custom_class_secret_789" not in obj_record.msg
    assert "client_secret=[REDACTED]" in obj_record.msg

    # 4. Exception instance as message
    exc_record = logging.LogRecord(
        name="test.msg.exc",
        level=logging.ERROR,
        pathname="test.py",
        lineno=16,
        msg=RuntimeError("Failure with token_hash=$argon2id$v=19$hash_val_123"),
        args=None,
        exc_info=None,
    )
    log_filter.filter(exc_record)
    assert isinstance(exc_record.msg, str)
    assert "$argon2id$v=19$hash_val_123" not in exc_record.msg
    assert "token_hash=[REDACTED]" in exc_record.msg


def test_failsafe_triggered_on_stack_info_or_non_string_failure() -> None:
    """Verify that a failure during stack_info or non-string processing triggers safe fallback."""
    log_filter = SecurityFilter()

    # 1. Broken non-string message whose __str__ raises an exception
    class BrokenStringify:
        def __str__(self) -> str:
            raise RuntimeError("String conversion catastrophic failure")

    record1 = logging.LogRecord(
        name="test.failsafe.msg",
        level=logging.ERROR,
        pathname="test.py",
        lineno=20,
        msg=BrokenStringify(),
        args=None,
        exc_info=None,
    )
    result1 = log_filter.filter(record1)
    assert result1 is True
    assert record1.msg == FAILSAFE_FALLBACK_MESSAGE
    assert record1.args is None
    assert record1.exc_info is None
    assert record1.stack_info is None

    # 2. Failure during stack_info sanitization
    record2 = logging.LogRecord(
        name="test.failsafe.stack",
        level=logging.ERROR,
        pathname="test.py",
        lineno=25,
        msg="Normal message",
        args=None,
        exc_info=None,
        sinfo='File "db.py", line 1\n  run(password="secret_pass")',
    )
    with patch("app.core.logging.sanitize_log_text", side_effect=RuntimeError("Sanitizer unexpected fault")):
        result2 = log_filter.filter(record2)
        assert result2 is True
        assert record2.msg == FAILSAFE_FALLBACK_MESSAGE
        assert record2.stack_info is None
        assert record2.args is None
        assert record2.exc_info is None


def test_standard_formatter_on_protected_handler_cannot_emit_unsanitized_content() -> None:
    """Verify that a standard logging.Formatter attached to a protected handler cannot emit unsanitized content."""
    test_logger = logging.getLogger("test.standard_formatter_protected")
    original_handlers = list(test_logger.handlers)
    original_level = test_logger.level
    original_propagate = test_logger.propagate

    stream = io.StringIO()
    # Explicitly use standard library logging.Formatter with stack_info format
    standard_formatter = logging.Formatter(fmt="%(levelname)s - %(message)s\n%(stack_info)s")
    handler = logging.StreamHandler(stream)
    handler.setFormatter(standard_formatter)
    protect_handler(handler)  # Attaches SecurityFilter to handler

    test_logger.handlers = [handler]
    test_logger.setLevel(logging.INFO)
    test_logger.propagate = False

    try:
        # 1. Non-string dict message with credentials and SQL
        test_logger.info({"password": "secret_dict_pass", "sql": "SELECT id FROM users WHERE secret='val'"})

        # 2. Record with stack_info containing credentials and SQL
        stack_content = (
            '  File "/app/auth.py", line 10, in auth_func\n'
            '    login(password="stack_secret_pass_123")\n'
            '  File "/app/query.py", line 20, in run\n'
            '    db.exec("INSERT INTO accounts (user, pass) VALUES (\'bob\', \'secret_bob_pw\')")'
        )
        record = test_logger.makeRecord(
            name=test_logger.name,
            level=logging.INFO,
            fn="test.py",
            lno=30,
            msg="Operational authentication event",
            args=(),
            exc_info=None,
            sinfo=stack_content,
        )
        test_logger.handle(record)

        emitted_output = stream.getvalue()

        # Verify no sensitive credentials or raw SQL were emitted
        assert "secret_dict_pass" not in emitted_output
        assert "stack_secret_pass_123" not in emitted_output
        assert "secret_bob_pw" not in emitted_output
        assert "SELECT id FROM users" not in emitted_output
        assert "INSERT INTO accounts" not in emitted_output

        # Verify redacted markers are present
        assert "[REDACTED]" in emitted_output
        assert REDACTED_SQL in emitted_output
    finally:
        test_logger.handlers = original_handlers
        test_logger.setLevel(original_level)
        test_logger.propagate = original_propagate
