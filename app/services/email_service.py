"""SMTP transactional email integration and verification/reset URL builders (Stage 3A/3B)."""

from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, make_msgid, parseaddr
from html import escape
import logging
import smtplib
import ssl
from urllib.parse import urlencode

from app.core.config import Settings

logger = logging.getLogger("folio360.email")

DEFAULT_SENDER_NAME = "Folio360 Admin"


@dataclass(frozen=True)
class EmailSendResult:
    """Sanitized result of attempting an external SMTP delivery."""

    sent: bool
    provider_message_id: str | None = None
    error_type: str | None = None


def build_verification_url(frontend_base_url: str, raw_token: str) -> str:
    """Build {FRONTEND_BASE_URL}/verify-email?token=<raw> strictly from FRONTEND_BASE_URL."""
    base = frontend_base_url.rstrip("/")
    query = urlencode({"token": raw_token})
    return f"{base}/verify-email?{query}"


def build_password_reset_url(frontend_base_url: str, raw_token: str) -> str:
    """Build {FRONTEND_BASE_URL}/reset-password?token=<raw> strictly from FRONTEND_BASE_URL."""
    base = frontend_base_url.rstrip("/")
    query = urlencode({"token": raw_token})
    return f"{base}/reset-password?{query}"


def build_email_change_confirm_url(frontend_base_url: str, raw_token: str) -> str:
    """Build {FRONTEND_BASE_URL}/workspace/settings?email_change_token=<raw>."""
    base = frontend_base_url.rstrip("/")
    query = urlencode({"email_change_token": raw_token})
    return f"{base}/workspace/settings?{query}"


def _resolve_sender_address(configured_from: str, smtp_user: str) -> str:
    """Resolve the RFC 5322 sender email address, falling back to SMTP_USER for dev defaults."""
    _, parsed_addr = parseaddr((configured_from or "").strip())
    normalized = parsed_addr.strip().lower()
    if (
        not normalized
        or "@" not in normalized
        or normalized.endswith(".local")
        or normalized == "onboarding@resend.dev"
    ):
        return smtp_user
    return parsed_addr.strip()


def send_email(
    *,
    to_email: str,
    subject: str,
    html_content: str,
    text_content: str | None = None,
    settings: Settings,
) -> EmailSendResult:
    """
    Deliver a transactional email via SMTP outside any DB transaction.

    Never raises or leaks SMTP credentials, raw tokens, or recipient emails to logs.
    """
    smtp_host = (settings.SMTP_HOST or "").strip()
    smtp_port = settings.SMTP_PORT
    smtp_user = (settings.SMTP_USER or "").strip()
    smtp_password = (
        settings.SMTP_PASSWORD.get_secret_value().strip()
        if settings.SMTP_PASSWORD is not None
        else ""
    )

    if not smtp_host or not smtp_user or not smtp_password:
        logger.warning(
            "SMTP delivery skipped: SMTP credentials are not configured; status=failed"
        )
        return EmailSendResult(sent=False, error_type="SmtpNotConfigured")

    sender_addr = _resolve_sender_address(settings.EMAIL_FROM_ADDRESS, smtp_user)
    domain = sender_addr.split("@", 1)[1] if "@" in sender_addr else "folio360.local"
    message_id = make_msgid(domain=domain)

    msg = EmailMessage()
    msg["From"] = formataddr((DEFAULT_SENDER_NAME, sender_addr))
    msg["To"] = to_email
    msg["Subject"] = subject
    msg["Message-ID"] = message_id
    msg.set_content(text_content or html_content)
    msg.add_alternative(html_content, subtype="html")

    timeout = float(settings.EMAIL_SEND_TIMEOUT_SECONDS)
    tls_context = ssl.create_default_context()

    try:
        if smtp_port == 465:
            with smtplib.SMTP_SSL(
                smtp_host,
                smtp_port,
                timeout=timeout,
                context=tls_context,
            ) as server:
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=timeout) as server:
                server.ehlo()
                server.starttls(context=tls_context)
                server.ehlo()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)

        logger.info("SMTP email accepted: message_id=%s", message_id)
        return EmailSendResult(sent=True, provider_message_id=message_id)
    except Exception as exc:
        logger.warning(
            "SMTP email delivery failed: exception=%s",
            type(exc).__name__,
        )
        return EmailSendResult(sent=False, error_type=type(exc).__name__)


def send_verification_email(
    *,
    to_email: str,
    raw_token: str,
    settings: Settings,
) -> EmailSendResult:
    """Deliver an account verification email via SMTP outside any DB transaction."""
    verification_url = build_verification_url(settings.FRONTEND_BASE_URL, raw_token)
    escaped_url = escape(verification_url, quote=True)
    expire_hours = settings.EMAIL_VERIFICATION_EXPIRE_HOURS

    html_content = (
        "<p>Welcome to Folio360.</p>"
        f'<p>Verify your email address by opening <a href="{escaped_url}">'
        "Verify Folio360 Email</a>.</p>"
        f"<p>This link expires in {expire_hours} hours.</p>"
    )
    text_content = (
        "Welcome to Folio360.\n\n"
        f"Verify your email address by opening:\n{verification_url}\n\n"
        f"This link expires in {expire_hours} hours."
    )

    return send_email(
        to_email=to_email,
        subject="Verify your Folio360 email address",
        html_content=html_content,
        text_content=text_content,
        settings=settings,
    )


def send_password_reset_email(
    *,
    to_email: str,
    raw_token: str,
    settings: Settings,
) -> EmailSendResult:
    """Deliver a password reset email via SMTP outside any DB transaction."""
    reset_url = build_password_reset_url(settings.FRONTEND_BASE_URL, raw_token)
    safe_reset_url = escape(reset_url, quote=True)
    expire_minutes = settings.PASSWORD_RESET_EXPIRE_MINUTES

    html_content = (
        "<p>We received a request to reset your Folio360 password.</p>"
        f'<p><a href="{safe_reset_url}">Reset your password</a></p>'
        f"<p>This link expires in {expire_minutes} minutes and can only be used once.</p>"
        "<p>If you did not request a password reset, you can safely ignore this email.</p>"
    )
    text_content = (
        "We received a request to reset your Folio360 password.\n\n"
        f"Reset your password: {reset_url}\n\n"
        f"This link expires in {expire_minutes} minutes and can only be used once.\n"
        "If you did not request a password reset, you can safely ignore this email."
    )

    return send_email(
        to_email=to_email,
        subject="Reset your Folio360 password",
        html_content=html_content,
        text_content=text_content,
        settings=settings,
    )


def send_email_change_verification_email(
    *,
    to_email: str,
    raw_token: str,
    settings: Settings,
) -> EmailSendResult:
    """Deliver an email-change confirmation link via SMTP outside any DB transaction."""
    confirm_url = build_email_change_confirm_url(settings.FRONTEND_BASE_URL, raw_token)
    escaped_url = escape(confirm_url, quote=True)

    html_content = (
        "<p>Confirm your new Folio360 email address.</p>"
        f'<p>Open <a href="{escaped_url}">Confirm Email Change</a> to verify this address.</p>'
        "<p>This link expires in 24 hours and can only be used once. "
        "If you did not request this change, you can safely ignore this email.</p>"
    )
    text_content = (
        "Confirm your new Folio360 email address.\n\n"
        f"Open:\n{confirm_url}\n\n"
        "This link expires in 24 hours and can only be used once."
    )

    return send_email(
        to_email=to_email,
        subject="Confirm your new Folio360 email address",
        html_content=html_content,
        text_content=text_content,
        settings=settings,
    )
