"""Resend transactional email integration and verification URL builder (Stage 3A)."""

from dataclasses import dataclass
from functools import lru_cache
from html import escape
import logging
from urllib.parse import urlencode

import resend

from app.core.config import Settings

logger = logging.getLogger("folio360.email")


@lru_cache(maxsize=16)
def get_resend_http_client(timeout: float) -> resend.RequestsClient:
    """Return a cached Resend RequestsClient keyed by timeout seconds."""
    return resend.RequestsClient(timeout=timeout)


@dataclass(frozen=True)
class EmailSendResult:
    """Sanitized result of attempting an external Resend delivery."""

    sent: bool
    provider_message_id: str | None = None
    error_type: str | None = None


def build_verification_url(frontend_base_url: str, raw_token: str) -> str:
    """Build {FRONTEND_BASE_URL}/verify-email?token=<raw> strictly from FRONTEND_BASE_URL."""
    base = frontend_base_url.rstrip("/")
    query = urlencode({"token": raw_token})
    return f"{base}/verify-email?{query}"


def send_verification_email(
    *,
    to_email: str,
    raw_token: str,
    settings: Settings,
) -> EmailSendResult:
    """
    Deliver an account verification email via Resend outside any DB transaction.

    Never raises or leaks API keys, raw tokens, or recipient secrets to logs.
    """
    api_key = (
        settings.RESEND_API_KEY.get_secret_value().strip()
        if settings.RESEND_API_KEY is not None
        else ""
    )
    if not api_key:
        logger.warning(
            "Resend delivery skipped: RESEND_API_KEY is not configured; status=failed"
        )
        return EmailSendResult(sent=False, error_type="ResendNotConfigured")

    verification_url = build_verification_url(settings.FRONTEND_BASE_URL, raw_token)
    escaped_url = escape(verification_url, quote=True)
    expire_hours = settings.EMAIL_VERIFICATION_EXPIRE_HOURS

    params: resend.Emails.SendParams = {
        "from": settings.EMAIL_FROM_ADDRESS,
        "to": [to_email],
        "subject": "Verify your Folio360 email address",
        "html": (
            "<p>Welcome to Folio360.</p>"
            f"<p>Verify your email address by opening <a href=\"{escaped_url}\">"
            "Verify Folio360 Email</a>.</p>"
            f"<p>This link expires in {expire_hours} hours.</p>"
        ),
        "text": (
            "Welcome to Folio360.\n\n"
            f"Verify your email address by opening:\n{verification_url}\n\n"
            f"This link expires in {expire_hours} hours."
        ),
    }

    try:
        resend.api_key = api_key
        resend.default_http_client = get_resend_http_client(
            float(settings.EMAIL_SEND_TIMEOUT_SECONDS)
        )
        response = resend.Emails.send(params)
        message_id = response.get("id") if isinstance(response, dict) else None
        logger.info("Resend verification email accepted: message_id=%s", message_id or "none")
        return EmailSendResult(
            sent=True,
            provider_message_id=str(message_id) if message_id else None,
        )
    except Exception as exc:
        logger.warning(
            "Resend verification email delivery failed: exception=%s",
            type(exc).__name__,
        )
        return EmailSendResult(sent=False, error_type=type(exc).__name__)
