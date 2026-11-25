"""Stage 3C.5 OAuth 2.0 / OIDC service orchestration, state machine, SAVEPOINT recovery & cleanup.

Implements F360-S3C-SPEC-REV12 §§1, 3, 4, 7, 8 service workflows while keeping HTTP
route handling, schemas, ASGI middleware, rate limiting, and cookie headers in 3C.6.
"""

import base64
from collections.abc import Collection, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import logging
import re
from typing import Literal
import uuid

from fastapi import status
from jwt import PyJWKClient
from sqlalchemy import delete, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import (
    OAUTH_EXCHANGE_CODE_EXPIRE_SECONDS,
    Settings,
    get_allowed_redirect_uris_snapshot,
)
from app.core.exceptions import AppException, ValidationAppError, auth_error
from app.core.security import (
    PKCE_CODE_CHALLENGE_METHOD,
    PKCE_VERIFIER_CONSUMED_MARKER,
    PKCEDecryptionError,
    compute_pkce_s256_challenge,
    decrypt_pkce_verifier_for_settings,
    encrypt_pkce_verifier_for_settings,
    generate_opaque_token,
    generate_pkce_verifier,
    hash_opaque_token,
)
from app.core.uri_policy import build_oauth_redirect_url, match_exact_oauth_redirect_uri
from app.models.oauth import OAuthAccount, OAuthExchangeCode, OAuthState
from app.models.user import User
from app.services.auth_service import (
    create_session_and_mint_tokens,
    get_constraint_name,
)
from app.services.oauth_providers import (
    GitHubVerifiedEmailRequiredError,
    OAuthProviderError,
    OAuthTransactionGuardError,
    build_github_authorization_url,
    build_google_authorization_url,
    ensure_no_open_db_transaction,
    exchange_github_authorization_code,
    exchange_google_authorization_code,
    fetch_github_user,
    fetch_github_verified_email,
    verify_google_id_token,
)

logger = logging.getLogger("folio360.oauth.service")

SUPPORTED_OAUTH_PROVIDERS: frozenset[str] = frozenset({"google", "github"})
SUPPORTED_CLIENT_TYPES: frozenset[str] = frozenset({"web", "mobile"})

MAX_CALLBACK_STATE_LENGTH = 256
MAX_CALLBACK_CODE_LENGTH = 2048
MAX_CALLBACK_ERROR_LENGTH = 128
MAX_EXCHANGE_CODE_LENGTH = 512

OAUTH_CLEANUP_BATCH_SIZE = 100
OAUTH_CLEANUP_GRACE_SECONDS = 60

_CALLBACK_CODE_RE = re.compile(rf"\A[!-~]{{1,{MAX_CALLBACK_CODE_LENGTH}}}\Z")
_EXCHANGE_CHALLENGE_RE = re.compile(r"\A[A-Za-z0-9_-]{43}\Z")
_EXCHANGE_VERIFIER_RE = re.compile(r"\A[A-Za-z0-9._~-]{43,128}\Z")


def _has_forbidden_chars(value: str) -> bool:
    return any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


@dataclass(frozen=True, slots=True)
class OAuthStartResult:
    """Service output for GET /auth/oauth/{provider}/start."""

    authorization_url: str
    client_type: Literal["web", "mobile"]
    binding_cookie_value: str | None = field(repr=False)


@dataclass(frozen=True, slots=True)
class OAuthCallbackResult:
    """Service output for GET /auth/oauth/{provider}/callback redirects."""

    redirect_url: str
    client_type: Literal["web", "mobile"]
    clear_binding_cookie: bool
    exchange_cookie_value: str | None = field(repr=False)


class OAuthCallbackJsonError(AppException):
    """JSON error raised by callback orders that must not redirect, carrying cookie directive."""

    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        public_message: str,
        clear_binding_cookie_mode: Literal["always", "if_present", "never"],
    ) -> None:
        self.clear_binding_cookie_mode = clear_binding_cookie_mode
        super().__init__(
            message=public_message,
            status_code=status_code,
            details={"code": code},
            public_message=public_message,
        )


def is_oauth_provider_configured(settings: Settings, provider: str) -> bool:
    """Return True if the specified provider has both client_id and client_secret configured (D18)."""
    if provider == "google":
        return bool(
            settings.GOOGLE_CLIENT_ID
            and settings.GOOGLE_CLIENT_SECRET is not None
            and settings.GOOGLE_CLIENT_SECRET.get_secret_value()
        )
    if provider == "github":
        return bool(
            settings.GITHUB_CLIENT_ID
            and settings.GITHUB_CLIENT_SECRET is not None
            and settings.GITHUB_CLIENT_SECRET.get_secret_value()
        )
    return False


def cleanup_expired_oauth_records(
    db: Session,
    *,
    now: datetime | None = None,
    batch_size: int = OAUTH_CLEANUP_BATCH_SIZE,
    grace_seconds: int = OAUTH_CLEANUP_GRACE_SECONDS,
) -> tuple[int, int]:
    """Bounded PostgreSQL SKIP LOCKED cleanup of expired/consumed OAuth states and exchange codes."""
    current_now = now if now is not None else datetime.now(timezone.utc)
    cutoff = current_now - timedelta(seconds=grace_seconds)
    effective_batch = max(1, batch_size)

    try:
        state_ids_subq = (
            select(OAuthState.id)
            .where(
                or_(
                    OAuthState.expires_at < cutoff,
                    OAuthState.consumed_at.is_not(None)
                    & (OAuthState.consumed_at < cutoff),
                )
            )
            .order_by(OAuthState.expires_at.asc())
            .limit(effective_batch)
            .with_for_update(skip_locked=True)
        )
        deleted_states = (
            db.execute(delete(OAuthState).where(OAuthState.id.in_(state_ids_subq))).rowcount
            or 0
        )

        code_ids_subq = (
            select(OAuthExchangeCode.id)
            .where(
                or_(
                    OAuthExchangeCode.expires_at < cutoff,
                    OAuthExchangeCode.consumed_at.is_not(None)
                    & (OAuthExchangeCode.consumed_at < cutoff),
                )
            )
            .order_by(OAuthExchangeCode.expires_at.asc())
            .limit(effective_batch)
            .with_for_update(skip_locked=True)
        )
        deleted_codes = (
            db.execute(
                delete(OAuthExchangeCode).where(OAuthExchangeCode.id.in_(code_ids_subq))
            ).rowcount
            or 0
        )

        db.commit()
        return int(deleted_states), int(deleted_codes)
    except Exception as exc:
        logger.warning(
            "Bounded OAuth cleanup skipped due to isolated error: exception=%s",
            type(exc).__name__,
        )
        try:
            db.rollback()
        except Exception:
            pass
        return 0, 0


def start_oauth_flow(
    db: Session,
    *,
    provider: str,
    client_type: str | None,
    redirect_uri: str | None,
    exchange_code_challenge: str | None,
    exchange_code_challenge_method: str | None = PKCE_CODE_CHALLENGE_METHOD,
    duplicate_params: Collection[str] = (),
    settings: Settings,
    now: datetime | None = None,
) -> OAuthStartResult:
    """Validate OAuth /start parameters in strict REV12 §8 order, persist state, and build auth URL."""
    # Step 1: Validate provider
    if provider not in SUPPORTED_OAUTH_PROVIDERS:
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_OAUTH_PROVIDER",
            public_message="Unsupported OAuth provider.",
        )

    # Step 2: Provider configuration check (D18)
    if not is_oauth_provider_configured(settings, provider):
        raise auth_error(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="SERVICE_UNAVAILABLE",
            public_message="OAuth authentication is currently unavailable for this provider.",
        )

    # Step 3: Duplicate query parameter rejection
    if "client_type" in duplicate_params:
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_CLIENT_TYPE",
            public_message="Duplicate client_type parameter.",
        )
    if "redirect_uri" in duplicate_params:
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_REDIRECT_URI",
            public_message="Duplicate redirect_uri parameter.",
        )
    if (
        "exchange_code_challenge" in duplicate_params
        or "exchange_code_challenge_method" in duplicate_params
    ):
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_EXCHANGE_CHALLENGE",
            public_message="Invalid OAuth exchange code challenge.",
        )

    # Step 4: Validate client_type
    if type(client_type) is not str or client_type not in SUPPORTED_CLIENT_TYPES:
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_CLIENT_TYPE",
            public_message="client_type must be 'web' or 'mobile'.",
        )
    typed_client_type: Literal["web", "mobile"] = (
        "web" if client_type == "web" else "mobile"
    )

    # Step 5: Exact unmodified redirect_uri allowlist match (D08)
    allowlist = get_allowed_redirect_uris_snapshot(settings, typed_client_type)
    matched_redirect = match_exact_oauth_redirect_uri(redirect_uri, allowlist)
    if matched_redirect is None:
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_REDIRECT_URI",
            public_message="Redirect URI is not allowed.",
        )

    # Step 6: Validate unmodified exchange_code_challenge + S256 method (D09)
    if (
        type(exchange_code_challenge_method) is not str
        or exchange_code_challenge_method != PKCE_CODE_CHALLENGE_METHOD
        or type(exchange_code_challenge) is not str
        or not _EXCHANGE_CHALLENGE_RE.fullmatch(exchange_code_challenge)
    ):
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_EXCHANGE_CHALLENGE",
            public_message="Invalid OAuth exchange code challenge.",
        )

    # Step 7: Mint CSPRNG secrets, encrypt PKCE verifier, persist state & run bounded cleanup
    current_now = now if now is not None else datetime.now(timezone.utc)
    raw_state = generate_opaque_token()
    state_hash = hash_opaque_token(raw_state)

    raw_nonce = generate_opaque_token() if provider == "google" else None
    nonce_hash = hash_opaque_token(raw_nonce) if raw_nonce is not None else None

    binding_cookie = generate_opaque_token() if typed_client_type == "web" else None
    client_binding_hash = (
        hash_opaque_token(binding_cookie) if binding_cookie is not None else None
    )

    pkce_verifier = generate_pkce_verifier()
    pkce_challenge = compute_pkce_s256_challenge(pkce_verifier)
    pkce_verifier_encrypted = encrypt_pkce_verifier_for_settings(
        pkce_verifier,
        settings=settings,
        provider=provider,
        state_hash=state_hash,
    )
    exchange_code_challenge_hash = hash_opaque_token(exchange_code_challenge)

    state_row = OAuthState(
        id=uuid.uuid4(),
        state_hash=state_hash,
        provider=provider,
        client_type=typed_client_type,
        pkce_verifier_encrypted=pkce_verifier_encrypted,
        nonce_hash=nonce_hash,
        redirect_uri=matched_redirect,
        client_binding_hash=client_binding_hash,
        exchange_code_challenge_hash=exchange_code_challenge_hash,
        expires_at=current_now + timedelta(minutes=settings.OAUTH_STATE_EXPIRE_MINUTES),
        consumed_at=None,
    )
    db.add(state_row)
    db.commit()

    cleanup_expired_oauth_records(db, now=current_now)

    if provider == "google":
        assert raw_nonce is not None
        authorization_url = build_google_authorization_url(
            settings,
            state=raw_state,
            nonce=raw_nonce,
            code_challenge=pkce_challenge,
        )
    else:
        authorization_url = build_github_authorization_url(
            settings,
            state=raw_state,
            code_challenge=pkce_challenge,
        )

    return OAuthStartResult(
        authorization_url=authorization_url,
        client_type=typed_client_type,
        binding_cookie_value=binding_cookie,
    )


def _consume_and_scrub_state(state_row: OAuthState, consumed_at: datetime) -> None:
    """Atomically pair consumed_at with '[CONSUMED]' scrub to satisfy DB CHECK invariant."""
    state_row.consumed_at = consumed_at
    state_row.pkce_verifier_encrypted = PKCE_VERIFIER_CONSUMED_MARKER


def _build_callback_error_redirect(
    *,
    redirect_uri: str,
    client_type: Literal["web", "mobile"],
    settings: Settings,
    error_code: str,
) -> OAuthCallbackResult:
    allowlist = get_allowed_redirect_uris_snapshot(settings, client_type)
    try:
        target = build_oauth_redirect_url(
            redirect_uri,
            allowlist=allowlist,
            error=error_code,
        )
    except ValueError:
        raise OAuthCallbackJsonError(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_REDIRECT_URI",
            public_message="Redirect URI is not allowed.",
            clear_binding_cookie_mode="always" if client_type == "web" else "never",
        ) from None
    return OAuthCallbackResult(
        redirect_url=target,
        client_type=client_type,
        clear_binding_cookie=(client_type == "web"),
        exchange_cookie_value=None,
    )


def handle_oauth_callback(
    db: Session,
    *,
    provider: str,
    state_values: Sequence[str] = (),
    code_values: Sequence[str] = (),
    error_values: Sequence[str] = (),
    binding_cookie: str | None = None,
    settings: Settings,
    jwk_client: PyJWKClient | None = None,
    now: datetime | None = None,
) -> OAuthCallbackResult:
    """
    Execute REV12 §8 callback state machine (Orders 1-12, 9a/9b, Checkpoints 1-3, Phases 1-3).

    Order 0 (rate limiting) is enforced at the FastAPI route boundary in Stage 3C.6.
    """
    current_now = now if now is not None else datetime.now(timezone.utc)

    # Order 1: Provider check
    if provider not in SUPPORTED_OAUTH_PROVIDERS:
        db.rollback()
        raise OAuthCallbackJsonError(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_OAUTH_PROVIDER",
            public_message="Unsupported OAuth provider.",
            clear_binding_cookie_mode="if_present",
        )

    # Order 2: Unmodified callback state validation (D16)
    if len(state_values) != 1:
        db.rollback()
        raise OAuthCallbackJsonError(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_OAUTH_STATE",
            public_message="Invalid or expired OAuth state.",
            clear_binding_cookie_mode="if_present",
        )
    raw_state = state_values[0]
    if (
        type(raw_state) is not str
        or not raw_state
        or not raw_state.strip()
        or len(raw_state) > MAX_CALLBACK_STATE_LENGTH
    ):
        db.rollback()
        raise OAuthCallbackJsonError(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_OAUTH_STATE",
            public_message="Invalid or expired OAuth state.",
            clear_binding_cookie_mode="if_present",
        )

    state_hash = hash_opaque_token(raw_state)

    # Order 3 + Phase 1 lock: lock state row FOR UPDATE with populate_existing=True
    state_row = db.execute(
        select(OAuthState)
        .where(OAuthState.state_hash == state_hash)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if state_row is None:
        db.rollback()
        raise OAuthCallbackJsonError(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_OAUTH_STATE",
            public_message="Invalid or expired OAuth state.",
            clear_binding_cookie_mode="if_present",
        )

    client_type: Literal["web", "mobile"] = (
        "web" if state_row.client_type == "web" else "mobile"
    )
    clear_mode: Literal["always", "never"] = "always" if client_type == "web" else "never"

    # Orders 4 & 5: Already-consumed or expired state rolls back untouched
    if state_row.consumed_at is not None or state_row.expires_at <= current_now:
        db.rollback()
        return _build_callback_error_redirect(
            redirect_uri=state_row.redirect_uri,
            client_type=client_type,
            settings=settings,
            error_code="invalid_oauth_state",
        )

    # Order 6: Provider mismatch consumes and scrubs active state
    if state_row.provider != provider:
        _consume_and_scrub_state(state_row, current_now)
        db.commit()
        return _build_callback_error_redirect(
            redirect_uri=state_row.redirect_uri,
            client_type=client_type,
            settings=settings,
            error_code="invalid_oauth_state",
        )

    # Order 7: Unconfigured provider returns 503 leaving state untouched
    if not is_oauth_provider_configured(settings, provider):
        db.rollback()
        raise OAuthCallbackJsonError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="SERVICE_UNAVAILABLE",
            public_message="OAuth authentication is currently unavailable for this provider.",
            clear_binding_cookie_mode=clear_mode,
        )

    # Order 8: Web binding cookie check (constant-time on unmodified cookie)
    if client_type == "web":
        binding_ok = (
            state_row.client_binding_hash is not None
            and type(binding_cookie) is str
            and len(binding_cookie) > 0
            and hmac.compare_digest(
                hash_opaque_token(binding_cookie),
                state_row.client_binding_hash,
            )
        )
        if not binding_ok:
            _consume_and_scrub_state(state_row, current_now)
            db.commit()
            return _build_callback_error_redirect(
                redirect_uri=state_row.redirect_uri,
                client_type=client_type,
                settings=settings,
                error_code="invalid_oauth_state",
            )

    # Orders 9a / 9b / 10: Provider callback parameters validation (skip PKCE decrypt)
    has_error = len(error_values) > 0
    has_code = len(code_values) > 0

    if (
        len(error_values) > 1
        or len(code_values) > 1
        or (has_error and has_code)
        or (
            has_error
            and (
                type(error_values[0]) is not str
                or not error_values[0]
                or not error_values[0].strip()
                or len(error_values[0]) > MAX_CALLBACK_ERROR_LENGTH
            )
        )
        or (
            has_code
            and (
                type(code_values[0]) is not str
                or not _CALLBACK_CODE_RE.fullmatch(code_values[0])
            )
        )
    ):
        _consume_and_scrub_state(state_row, current_now)
        db.commit()
        return _build_callback_error_redirect(
            redirect_uri=state_row.redirect_uri,
            client_type=client_type,
            settings=settings,
            error_code="oauth_provider_error",
        )

    if has_error and error_values[0] == "access_denied":
        _consume_and_scrub_state(state_row, current_now)
        db.commit()
        return _build_callback_error_redirect(
            redirect_uri=state_row.redirect_uri,
            client_type=client_type,
            settings=settings,
            error_code="oauth_cancelled",
        )

    if has_error or not has_code:
        _consume_and_scrub_state(state_row, current_now)
        db.commit()
        return _build_callback_error_redirect(
            redirect_uri=state_row.redirect_uri,
            client_type=client_type,
            settings=settings,
            error_code="oauth_provider_error",
        )

    raw_code = code_values[0]

    # Order 11 (S3C2-F1): Unconditionally pass state_row.created_at + now to PKCE decrypt
    try:
        pkce_verifier = decrypt_pkce_verifier_for_settings(
            state_row.pkce_verifier_encrypted,
            settings=settings,
            provider=provider,
            state_hash=state_hash,
            state_created_at=state_row.created_at,
            now=current_now,
        )
    except PKCEDecryptionError:
        _consume_and_scrub_state(state_row, current_now)
        db.commit()
        return _build_callback_error_redirect(
            redirect_uri=state_row.redirect_uri,
            client_type=client_type,
            settings=settings,
            error_code="oauth_provider_error",
        )

    # Order 12 Checkpoint 1: Re-verify exact redirect_uri allowlist before consuming for Phase 2
    redirect_uri = state_row.redirect_uri
    allowlist_cp1 = get_allowed_redirect_uris_snapshot(settings, client_type)
    if match_exact_oauth_redirect_uri(redirect_uri, allowlist_cp1) is None:
        _consume_and_scrub_state(state_row, current_now)
        db.commit()
        raise OAuthCallbackJsonError(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_REDIRECT_URI",
            public_message="Redirect URI is not allowed.",
            clear_binding_cookie_mode=clear_mode,
        )

    # Capture necessary values in local memory before Phase 1 commit closes the transaction
    nonce_hash = state_row.nonce_hash
    exchange_code_challenge_hash = state_row.exchange_code_challenge_hash

    _consume_and_scrub_state(state_row, current_now)
    db.commit()

    # -----------------------------------------------------------------------
    # Phase 2: Bounded Provider HTTP & JWKS with ZERO Open DB Transaction
    # -----------------------------------------------------------------------
    provider_email: str | None = None
    provider_email_verified = False
    provider_user_id: str

    try:
        ensure_no_open_db_transaction(db)
        if provider == "google":
            assert nonce_hash is not None
            id_token = exchange_google_authorization_code(
                db,
                settings=settings,
                code=raw_code,
                code_verifier=pkce_verifier,
            )
            if jwk_client is None:
                raise OAuthProviderError("google", "signing_key_unavailable")
            identity = verify_google_id_token(
                db,
                settings=settings,
                jwk_client=jwk_client,
                id_token=id_token,
                expected_nonce_hash=nonce_hash,
                now=now.timestamp() if now is not None else None,
            )
            provider_user_id = identity.provider_user_id
            provider_email = identity.email
            provider_email_verified = identity.email_verified
        else:
            access_token = exchange_github_authorization_code(
                db,
                settings=settings,
                code=raw_code,
                code_verifier=pkce_verifier,
            )
            gh_user = fetch_github_user(
                db,
                settings=settings,
                access_token=access_token,
            )
            provider_user_id = gh_user.provider_user_id

            # REV12-1: GitHub returning-user fast-path lookup + mandatory rollback on BOTH hit & miss
            matched_user_id = db.execute(
                select(OAuthAccount.user_id).where(
                    OAuthAccount.provider == "github",
                    OAuthAccount.provider_user_id == provider_user_id,
                )
            ).scalar_one_or_none()
            found_returning_github = matched_user_id is not None
            db.rollback()
            ensure_no_open_db_transaction(db)

            if not found_returning_github:
                provider_email = fetch_github_verified_email(
                    db,
                    settings=settings,
                    access_token=access_token,
                )
                provider_email_verified = True
    except OAuthTransactionGuardError as exc:
        logger.error("OAuth transaction-closure guard tripped during Phase 2")
        db.rollback()
        setattr(exc, "clear_binding_cookie_mode", clear_mode)
        raise
    except GitHubVerifiedEmailRequiredError:
        return _build_callback_error_redirect(
            redirect_uri=redirect_uri,
            client_type=client_type,
            settings=settings,
            error_code="verified_email_required",
        )
    except OAuthProviderError:
        return _build_callback_error_redirect(
            redirect_uri=redirect_uri,
            client_type=client_type,
            settings=settings,
            error_code="oauth_provider_error",
        )

    # Checkpoint 2 (Pre-Phase 3): allowlist check + guarantee zero open DB tx
    allowlist_cp2 = get_allowed_redirect_uris_snapshot(settings, client_type)
    if match_exact_oauth_redirect_uri(redirect_uri, allowlist_cp2) is None:
        raise OAuthCallbackJsonError(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_REDIRECT_URI",
            public_message="Redirect URI is not allowed.",
            clear_binding_cookie_mode=clear_mode,
        )

    try:
        ensure_no_open_db_transaction(db)
    except OAuthTransactionGuardError as exc:
        logger.error("OAuth transaction-closure guard tripped at Phase 3 entry")
        db.rollback()
        setattr(exc, "clear_binding_cookie_mode", clear_mode)
        raise

    # -----------------------------------------------------------------------
    # Phase 3: Single Outer Transaction for Account Resolution & Exchange Code
    # -----------------------------------------------------------------------
    phase3_now = now if now is not None else datetime.now(timezone.utc)
    verified_fresh_email = (
        provider_email
        if provider_email is not None and provider_email_verified is True
        else None
    )

    account = db.execute(
        select(OAuthAccount).where(
            OAuthAccount.provider == provider,
            OAuthAccount.provider_user_id == provider_user_id,
        )
    ).scalar_one_or_none()

    user: User | None = None
    if account is not None:
        user = db.execute(
            select(User)
            .where(User.id == account.user_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if user is None:
            db.rollback()
            return _build_callback_error_redirect(
                redirect_uri=redirect_uri,
                client_type=client_type,
                settings=settings,
                error_code="oauth_provider_error",
            )
        if not user.is_active:
            db.rollback()
            return _build_callback_error_redirect(
                redirect_uri=redirect_uri,
                client_type=client_type,
                settings=settings,
                error_code="account_inactive",
            )
        # D20: Refresh provider_email only from fresh verified data; never touch users.email
        if verified_fresh_email is not None:
            account.provider_email = verified_fresh_email
            account.provider_email_verified = True
    else:
        if verified_fresh_email is None:
            db.rollback()
            return _build_callback_error_redirect(
                redirect_uri=redirect_uri,
                client_type=client_type,
                settings=settings,
                error_code="verified_email_required",
            )

        try:
            with db.begin_nested():
                user = User(
                    id=uuid.uuid4(),
                    email=verified_fresh_email,
                    password_hash=None,
                    is_active=True,
                    is_email_verified=True,
                    email_verified_at=phase3_now,
                    auth_version=0,
                    password_changed_at=None,
                )
                db.add(user)
                db.flush()

                account = OAuthAccount(
                    id=uuid.uuid4(),
                    user_id=user.id,
                    provider=provider,
                    provider_user_id=provider_user_id,
                    provider_email=verified_fresh_email,
                    provider_email_verified=True,
                )
                db.add(account)
                db.flush()
        except IntegrityError as exc:
            constraint_name = get_constraint_name(exc)
            if constraint_name in {"uq_users_email", "uq_oauth_accounts_provider_subject"}:
                # Re-query by exact (provider, provider_user_id) only (D05: never merge by email alone);
                # handles both provider_subject race and same-email concurrent first-time signup race.
                account = db.execute(
                    select(OAuthAccount)
                    .where(
                        OAuthAccount.provider == provider,
                        OAuthAccount.provider_user_id == provider_user_id,
                    )
                    .execution_options(populate_existing=True)
                ).scalar_one_or_none()
                if account is None:
                    db.rollback()
                    error_code = (
                        "email_already_registered"
                        if constraint_name == "uq_users_email"
                        else "oauth_provider_error"
                    )
                    return _build_callback_error_redirect(
                        redirect_uri=redirect_uri,
                        client_type=client_type,
                        settings=settings,
                        error_code=error_code,
                    )
                user = db.execute(
                    select(User)
                    .where(User.id == account.user_id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                ).scalar_one_or_none()
                if user is None:
                    db.rollback()
                    return _build_callback_error_redirect(
                        redirect_uri=redirect_uri,
                        client_type=client_type,
                        settings=settings,
                        error_code="oauth_provider_error",
                    )
                if not user.is_active:
                    db.rollback()
                    return _build_callback_error_redirect(
                        redirect_uri=redirect_uri,
                        client_type=client_type,
                        settings=settings,
                        error_code="account_inactive",
                    )
                # D20: Refresh provider_email only; never modify users.email
                account.provider_email = verified_fresh_email
                account.provider_email_verified = True
            else:
                db.rollback()
                return _build_callback_error_redirect(
                    redirect_uri=redirect_uri,
                    client_type=client_type,
                    settings=settings,
                    error_code="oauth_provider_error",
                )

    raw_exchange_code = generate_opaque_token()
    exchange_cookie_value = (
        generate_opaque_token() if client_type == "web" else None
    )
    exchange_binding_hash = (
        hash_opaque_token(exchange_cookie_value)
        if exchange_cookie_value is not None
        else None
    )

    exchange_row = OAuthExchangeCode(
        id=uuid.uuid4(),
        user_id=user.id,
        code_hash=hash_opaque_token(raw_exchange_code),
        client_type=client_type,
        auth_version=user.auth_version,
        exchange_code_challenge_hash=exchange_code_challenge_hash,
        exchange_binding_hash=exchange_binding_hash,
        expires_at=phase3_now + timedelta(seconds=OAUTH_EXCHANGE_CODE_EXPIRE_SECONDS),
        consumed_at=None,
    )
    db.add(exchange_row)
    db.flush()

    # Checkpoint 3 (Pre-commit): build redirect URL before committing exchange code
    allowlist_cp3 = get_allowed_redirect_uris_snapshot(settings, client_type)
    try:
        final_redirect = build_oauth_redirect_url(
            redirect_uri,
            allowlist=allowlist_cp3,
            code=raw_exchange_code,
        )
    except ValueError:
        db.rollback()
        raise OAuthCallbackJsonError(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_REDIRECT_URI",
            public_message="Redirect URI is not allowed.",
            clear_binding_cookie_mode=clear_mode,
        ) from None

    db.commit()
    return OAuthCallbackResult(
        redirect_url=final_redirect,
        client_type=client_type,
        clear_binding_cookie=(client_type == "web"),
        exchange_cookie_value=exchange_cookie_value,
    )


def _validate_unmodified_exchange_inputs(
    code: str,
    exchange_code_verifier: str,
) -> None:
    if (
        type(code) is not str
        or not (1 <= len(code) <= MAX_EXCHANGE_CODE_LENGTH)
        or code != code.strip()
        or _has_forbidden_chars(code)
    ):
        raise ValidationAppError(
            message="Validation failed",
            details={
                "code": "VALIDATION_ERROR",
                "errors": [
                    {
                        "loc": ["body", "code"],
                        "msg": "Invalid OAuth exchange code format",
                        "type": "value_error",
                    }
                ],
            },
            public_message="Validation failed",
        )

    if type(exchange_code_verifier) is not str or not _EXCHANGE_VERIFIER_RE.fullmatch(
        exchange_code_verifier
    ):
        raise ValidationAppError(
            message="Validation failed",
            details={
                "code": "VALIDATION_ERROR",
                "errors": [
                    {
                        "loc": ["body", "exchange_code_verifier"],
                        "msg": "Invalid OAuth exchange_code_verifier format",
                        "type": "value_error",
                    }
                ],
            },
            public_message="Validation failed",
        )


def _invalid_exchange_code_error() -> AppException:
    return auth_error(
        status_code=status.HTTP_400_BAD_REQUEST,
        code="INVALID_OAUTH_EXCHANGE_CODE",
        public_message="OAuth exchange code is invalid or has expired.",
    )


def exchange_oauth_code(
    db: Session,
    *,
    code: str,
    exchange_code_verifier: str,
    client_type: Literal["web", "mobile"],
    exchange_cookie: str | None = None,
    user_agent: str | None = None,
    ip_address: str | None = None,
    settings: Settings,
    now: datetime | None = None,
) -> tuple[User, str, int, str, int]:
    """
    Atomically redeem a single-use OAuthExchangeCode per REV12 §8 Steps 1-8 & REV12-2.

    Enforces preliminary non-locking lookup, users-first FOR UPDATE locking, 5-step
    RFC 7636 S256 verifier proof via hmac.compare_digest, burn-on-proof-failure,
    unconsumed 403 rollback for inactive/unverified users, and single outer commit.
    """
    if client_type not in SUPPORTED_CLIENT_TYPES:
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_CLIENT_TYPE",
            public_message="client_type must be 'web' or 'mobile'.",
        )

    _validate_unmodified_exchange_inputs(code, exchange_code_verifier)

    # Step 1: Hash unmodified code
    code_hash = hash_opaque_token(code)

    # Step 2: Preliminary non-locking lookup
    prelim_user_id = db.execute(
        select(OAuthExchangeCode.user_id).where(OAuthExchangeCode.code_hash == code_hash)
    ).scalar_one_or_none()
    if prelim_user_id is None:
        db.rollback()
        raise _invalid_exchange_code_error()

    # Step 3: Lock users row FIRST
    user = db.execute(
        select(User)
        .where(User.id == prelim_user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if user is None:
        db.rollback()
        raise _invalid_exchange_code_error()

    # Step 4: Lock oauth_exchange_codes row SECOND
    code_row = db.execute(
        select(OAuthExchangeCode)
        .where(
            OAuthExchangeCode.code_hash == code_hash,
            OAuthExchangeCode.user_id == user.id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()

    current_now = now if now is not None else datetime.now(timezone.utc)

    # Step 5: Revalidate under locks
    if (
        code_row is None
        or code_row.user_id != user.id
        or code_row.consumed_at is not None
        or code_row.expires_at <= current_now
        or code_row.client_type != client_type
        or code_row.auth_version != user.auth_version
    ):
        db.rollback()
        raise _invalid_exchange_code_error()

    # Step 6 (REV12-2): Explicit 5-step RFC 7636 PKCE & web binding proof verification
    if not _EXCHANGE_VERIFIER_RE.fullmatch(exchange_code_verifier):
        code_row.consumed_at = current_now
        db.commit()
        raise _invalid_exchange_code_error()

    verifier_digest = hashlib.sha256(exchange_code_verifier.encode("utf-8")).digest()
    computed_challenge = (
        base64.urlsafe_b64encode(verifier_digest).rstrip(b"=").decode("ascii")
    )
    computed_challenge_hash = hashlib.sha256(
        computed_challenge.encode("utf-8")
    ).hexdigest()

    pkce_ok = hmac.compare_digest(
        computed_challenge_hash,
        code_row.exchange_code_challenge_hash,
    )

    binding_ok = True
    if client_type == "web":
        binding_ok = (
            code_row.exchange_binding_hash is not None
            and type(exchange_cookie) is str
            and len(exchange_cookie) > 0
            and hmac.compare_digest(
                hash_opaque_token(exchange_cookie),
                code_row.exchange_binding_hash,
            )
        )

    if not pkce_ok or not binding_ok:
        code_row.consumed_at = current_now
        db.commit()
        raise _invalid_exchange_code_error()

    # Step 7: Account status checks rollback WITHOUT consuming exchange code
    if not user.is_active:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="ACCOUNT_INACTIVE",
            public_message="Account is inactive.",
        )

    if not user.is_email_verified:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="EMAIL_NOT_VERIFIED",
            public_message="Email address must be verified before signing in.",
        )

    # Step 8: Atomic consumption + refresh session creation under single outer commit
    code_row.consumed_at = current_now
    user_out, access_token, expires_in, refresh_token, refresh_expires_in = (
        create_session_and_mint_tokens(
            db,
            user=user,
            client_type=client_type,
            user_agent=user_agent,
            ip_address=ip_address,
            now=current_now,
            settings=settings,
            commit=False,
        )
    )
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    return user_out, access_token, expires_in, refresh_token, refresh_expires_in


def list_user_oauth_providers(db: Session, *, user_id: uuid.UUID) -> list[str]:
    """Return sorted provider names linked to the user for GET /auth/me (D15)."""
    rows = (
        db.execute(
            select(OAuthAccount.provider)
            .where(OAuthAccount.user_id == user_id)
            .order_by(OAuthAccount.provider.asc())
        )
        .scalars()
        .all()
    )
    return list(rows)
