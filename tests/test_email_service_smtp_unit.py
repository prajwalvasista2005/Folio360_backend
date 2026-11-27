"""Focused unit tests for SMTP email service migration (Stage 3A/3B)."""

from email.message import EmailMessage
import smtplib

import pytest

from app.core.config import Settings
from app.services.email_service import (
    build_password_reset_url,
    build_verification_url,
    send_email,
    send_password_reset_email,
    send_verification_email,
)


def _smtp_settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "_env_file": None,
        "ENVIRONMENT": "testing",
        "FRONTEND_BASE_URL": "http://localhost:5173",
    }
    base.update(overrides)
    return Settings(**base)


def test_smtp_settings_defaults_and_resend_removed() -> None:
    """Verify SMTP defaults target Gmail STARTTLS and RESEND_API_KEY is removed."""
    settings = _smtp_settings()
    assert settings.SMTP_HOST == "smtp.gmail.com"
    assert settings.SMTP_PORT == 587
    assert settings.SMTP_USER is None
    assert settings.SMTP_PASSWORD is None
    assert not hasattr(settings, "RESEND_API_KEY")


def test_send_verification_and_reset_skip_when_smtp_unconfigured(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Unconfigured SMTP_USER/SMTP_PASSWORD returns SmtpNotConfigured cleanly."""
    caplog.set_level("WARNING")
    settings = _smtp_settings()

    verify_res = send_verification_email(
        to_email="user@example.com",
        raw_token="raw-verify-secret-123",
        settings=settings,
    )
    reset_res = send_password_reset_email(
        to_email="user@example.com",
        raw_token="raw-reset-secret-456",
        settings=settings,
    )

    assert verify_res.sent is False
    assert verify_res.error_type == "SmtpNotConfigured"
    assert reset_res.sent is False
    assert reset_res.error_type == "SmtpNotConfigured"

    joined = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "user@example.com" not in joined
    assert "raw-verify-secret-123" not in joined
    assert "raw-reset-secret-456" not in joined


def test_send_email_starttls_flow_and_headers(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify STARTTLS handshake, login, Folio360 Admin sender, and zero log leaks."""
    events: list[tuple[str, object]] = []
    sent_messages: list[EmailMessage] = []

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
            events.append(("init", (host, port, timeout)))

        def __enter__(self) -> "FakeSMTP":
            return self

        def __exit__(self, *_args: object) -> bool:
            events.append(("quit", None))
            return False

        def ehlo(self) -> tuple[int, bytes]:
            events.append(("ehlo", None))
            return (250, b"ok")

        def starttls(self, context: object = None) -> tuple[int, bytes]:
            events.append(("starttls", context is not None))
            return (220, b"ready")

        def login(self, user: str, password: str) -> tuple[int, bytes]:
            events.append(("login", (user, password)))
            return (235, b"auth ok")

        def send_message(self, msg: EmailMessage) -> dict[str, object]:
            sent_messages.append(msg)
            return {}

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    caplog.set_level("INFO")

    secret_app_pw = "abcd efgh ijkl mnop"
    settings = _smtp_settings(
        SMTP_HOST="smtp.gmail.com",
        SMTP_PORT=587,
        SMTP_USER="folio360.mailer@gmail.com",
        SMTP_PASSWORD=secret_app_pw,
        EMAIL_FROM_ADDRESS="no-reply@folio360.local",
        EMAIL_SEND_TIMEOUT_SECONDS=7.0,
    )

    verify_res = send_verification_email(
        to_email="recipient@example.com",
        raw_token="verify-tok-xyz",
        settings=settings,
    )
    reset_res = send_password_reset_email(
        to_email="recipient@example.com",
        raw_token="reset-tok-uvw",
        settings=settings,
    )
    direct_res = send_email(
        to_email="recipient@example.com",
        subject="Custom Subject",
        html_content="<p>Hello</p>",
        settings=settings,
    )

    assert verify_res.sent is True and verify_res.provider_message_id
    assert reset_res.sent is True and reset_res.provider_message_id
    assert direct_res.sent is True and direct_res.provider_message_id
    assert len(sent_messages) == 3

    assert ("init", ("smtp.gmail.com", 587, 7.0)) in events
    assert ("starttls", True) in events
    assert ("login", ("folio360.mailer@gmail.com", secret_app_pw)) in events

    verify_msg, reset_msg, direct_msg = sent_messages
    assert "Folio360 Admin" in str(verify_msg["From"])
    assert "folio360.mailer@gmail.com" in str(verify_msg["From"])
    assert verify_msg["To"] == "recipient@example.com"
    assert verify_msg["Subject"] == "Verify your Folio360 email address"

    verify_plain = verify_msg.get_body(preferencelist=("plain",)).get_content()
    verify_html = verify_msg.get_body(preferencelist=("html",)).get_content()
    expected_verify_url = build_verification_url("http://localhost:5173", "verify-tok-xyz")
    assert expected_verify_url in verify_plain
    assert expected_verify_url in verify_html

    reset_plain = reset_msg.get_body(preferencelist=("plain",)).get_content()
    reset_html = reset_msg.get_body(preferencelist=("html",)).get_content()
    expected_reset_url = build_password_reset_url("http://localhost:5173", "reset-tok-uvw")
    assert expected_reset_url in reset_plain
    assert expected_reset_url in reset_html
    assert direct_msg["Subject"] == "Custom Subject"

    joined = "\n".join(rec.getMessage() for rec in caplog.records)
    assert secret_app_pw not in joined
    assert "verify-tok-xyz" not in joined
    assert "reset-tok-uvw" not in joined
    assert "recipient@example.com" not in joined


def test_send_email_handles_smtp_exception_without_leaking(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify SMTP failures return sanitized EmailSendResult without raising."""

    class FailingSMTP:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise smtplib.SMTPAuthenticationError(535, b"5.7.8 Bad credentials")

    monkeypatch.setattr(smtplib, "SMTP", FailingSMTP)
    caplog.set_level("WARNING")

    settings = _smtp_settings(
        SMTP_USER="folio360.mailer@gmail.com",
        SMTP_PASSWORD="super-secret-app-password",
    )
    res = send_verification_email(
        to_email="user@example.com",
        raw_token="secret-verify-token",
        settings=settings,
    )

    assert res.sent is False
    assert res.error_type == "SMTPAuthenticationError"

    joined = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "super-secret-app-password" not in joined
    assert "secret-verify-token" not in joined
    assert "user@example.com" not in joined
