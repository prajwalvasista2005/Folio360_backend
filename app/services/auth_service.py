"""Stage 3A/3B authentication service implementing atomic PostgreSQL state machines."""

from datetime import datetime, timedelta, timezone
import logging
from typing import Callable, Type
import uuid

from fastapi import status
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import AppException, ValidationAppError, auth_error
from app.core.security import (
    DUMMY_PASSWORD_HASH,
    create_access_token,
    generate_opaque_token,
    hash_opaque_token,
    hash_password,
    normalize_email,
    password_needs_rehash,
    validate_password_policy,
    verify_password,
)
from app.models.email_verification_token import EmailVerificationToken
from app.models.password_reset_token import PasswordResetToken
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.services.email_service import (
    EmailSendResult,
    send_password_reset_email,
    send_verification_email,
)

logger = logging.getLogger("folio360.auth.service")


def _get_constraint_name(exc: IntegrityError) -> str | None:
    """Extract only the PostgreSQL constraint_name without exposing DETAIL values."""
    orig = getattr(exc, "orig", None)
    diag = getattr(orig, "diag", None)
    return getattr(diag, "constraint_name", None)


def register_user(
    db: Session,
    *,
    email: str,
    password: str,
    settings: Settings,
) -> tuple[User, bool]:
    """
    Register a new user in unverified state and send verification email via Resend.

    Executes Tx 1 (user + pending token) before calling Resend outside any DB transaction,
    then persists the delivery status in Tx 2.
    """
    canonical_email = normalize_email(email)
    password_hash = hash_password(password)
    raw_token = generate_opaque_token()
    token_hash = hash_opaque_token(raw_token)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=settings.EMAIL_VERIFICATION_EXPIRE_HOURS)

    user = User(
        id=uuid.uuid4(),
        email=canonical_email,
        password_hash=password_hash,
        is_active=True,
        is_email_verified=False,
        email_verified_at=None,
        auth_version=0,
        password_changed_at=None,
    )
    verification_token = EmailVerificationToken(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=token_hash,
        delivery_status="pending",
        delivery_attempted_at=None,
        expires_at=expires_at,
    )

    try:
        db.add(user)
        db.flush()
        db.add(verification_token)
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        constraint_name = _get_constraint_name(exc)
        if constraint_name == "uq_users_email":
            raise auth_error(
                status_code=status.HTTP_409_CONFLICT,
                code="EMAIL_ALREADY_REGISTERED",
                public_message="An account with this email address already exists.",
            ) from None
        logger.error(
            "Unexpected database constraint violation during registration: constraint=%s",
            constraint_name or "unknown",
        )
        raise AppException(
            message=f"Registration integrity failure: {constraint_name}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        ) from None

    # External HTTP request strictly outside DB transaction
    send_result = send_verification_email(
        to_email=user.email,
        raw_token=raw_token,
        settings=settings,
    )

    # Tx 2: persist delivery result without rolling back the committed unverified user
    verification_token.delivery_status = "sent" if send_result.sent else "failed"
    verification_token.delivery_attempted_at = datetime.now(timezone.utc)
    db.commit()

    return user, send_result.sent


def verify_email(
    db: Session,
    *,
    raw_token: str,
) -> None:
    """
    Consume a single-use email verification token without authenticating the user.

    Locks users row first, then email_verification_tokens row (deadlock-free ordering).
    """
    token_hash = hash_opaque_token(raw_token.strip())
    token_user_id = db.execute(
        select(EmailVerificationToken.user_id).where(
            EmailVerificationToken.token_hash == token_hash
        )
    ).scalar_one_or_none()
    if token_user_id is None:
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_VERIFICATION_TOKEN",
            public_message="Verification link is invalid or has expired.",
        )

    # Lock users first, then the token row
    user = db.execute(
        select(User)
        .where(User.id == token_user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if user is None:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_VERIFICATION_TOKEN",
            public_message="Verification link is invalid or has expired.",
        )

    if not user.is_active:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="ACCOUNT_INACTIVE",
            public_message="Account is inactive.",
        )

    token_row = db.execute(
        select(EmailVerificationToken)
        .where(
            EmailVerificationToken.token_hash == token_hash,
            EmailVerificationToken.user_id == user.id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()

    now = datetime.now(timezone.utc)
    if (
        token_row is None
        or token_row.consumed_at is not None
        or token_row.revoked_at is not None
        or token_row.expires_at <= now
    ):
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_VERIFICATION_TOKEN",
            public_message="Verification link is invalid or has expired.",
        )

    token_row.consumed_at = now
    if not user.is_email_verified:
        user.is_email_verified = True
        user.email_verified_at = now

    # Revoke any other active unconsumed verification tokens for this user
    db.execute(
        update(EmailVerificationToken)
        .where(
            EmailVerificationToken.user_id == user.id,
            EmailVerificationToken.id != token_row.id,
            EmailVerificationToken.consumed_at.is_(None),
            EmailVerificationToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    db.commit()


def _validate_new_password_or_raise(new_password: str, email: str) -> None:
    """Validate new password complexity and email-inequality without echoing secrets."""
    try:
        validate_password_policy(new_password, email=email)
    except ValueError as exc:
        raise ValidationAppError(
            message="Password does not satisfy security policy",
            details={
                "code": "VALIDATION_ERROR",
                "errors": [
                    {
                        "loc": ["body", "new_password"],
                        "msg": f"Value error, {exc}",
                        "type": "value_error",
                    }
                ],
            },
            public_message="Validation failed",
        ) from exc


def _create_session_and_mint_tokens(
    db: Session,
    *,
    user: User,
    client_type: str,
    user_agent: str | None,
    ip_address: str | None,
    now: datetime,
    settings: Settings,
) -> tuple[User, str, int, str, int]:
    """Create a fresh root RefreshSession, commit transaction, then mint an access JWT."""
    raw_refresh_token = generate_opaque_token()
    refresh_hash = hash_opaque_token(raw_refresh_token)
    rolling_ttl = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    absolute_ttl = timedelta(days=settings.REFRESH_TOKEN_ABSOLUTE_EXPIRE_DAYS)
    family_expires_at = now + absolute_ttl
    expires_at = min(now + rolling_ttl, family_expires_at)

    session_row = RefreshSession(
        id=uuid.uuid4(),
        user_id=user.id,
        family_id=uuid.uuid4(),
        token_hash=refresh_hash,
        parent_session_id=None,
        replaced_by_session_id=None,
        client_type=client_type,
        user_agent=user_agent[:512] if user_agent else None,
        ip_address=ip_address[:45] if ip_address else None,
        expires_at=expires_at,
        family_expires_at=family_expires_at,
        last_used_at=now,
    )
    db.add(session_row)
    user_id = user.id
    auth_version = user.auth_version
    db.commit()

    access_token, expires_in = create_access_token(
        user_id=user_id,
        auth_version=auth_version,
        settings=settings,
        now=now,
    )
    refresh_expires_in = max(1, int((expires_at - now).total_seconds()))
    return user, access_token, expires_in, raw_refresh_token, refresh_expires_in


def _normalize_persisted_ip(ip_address: str | None) -> str | None:
    """Return a clean client IP up to 45 chars, or None when absent/fallback-sentinel."""
    if ip_address is None:
        return None
    cleaned = ip_address.strip()
    if not cleaned or cleaned in {"unknown", "invalid-client-ip"}:
        return None
    return cleaned[:45]


def _issue_and_deliver_single_use_token(
    db: Session,
    *,
    email: str,
    token_model: Type[EmailVerificationToken] | Type[PasswordResetToken],
    eligibility_check: Callable[[User], bool],
    expires_delta: timedelta,
    email_sender: Callable[..., EmailSendResult],
    settings: Settings,
    requested_ip: str | None = None,
) -> bool:
    """
    Evaluate Rev10 §11.2 Resend retry/cooldown state machine and deliver if eligible.

    Tx 1 acquires the users FOR UPDATE lock, enforces cooldown/hourly/failure
    backoffs, revokes prior active tokens, and persists a pending hashed token
    before committing and executing external email I/O outside any lock/tx.
    """
    canonical_email = normalize_email(email)
    user_id = db.execute(
        select(User.id).where(User.email == canonical_email)
    ).scalar_one_or_none()
    if user_id is None:
        db.rollback()
        return False

    # Tx 1: serialized under users FOR UPDATE lock
    user = db.execute(
        select(User)
        .where(User.id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if user is None or not eligibility_check(user):
        db.rollback()
        return False

    now = datetime.now(timezone.utc)

    # 1. In-flight pending guard
    latest_non_revoked = db.execute(
        select(token_model)
        .where(
            token_model.user_id == user.id,
            token_model.revoked_at.is_(None),
        )
        .order_by(token_model.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    if (
        latest_non_revoked is not None
        and latest_non_revoked.delivery_status == "pending"
        and latest_non_revoked.created_at
        >= now - timedelta(seconds=settings.EMAIL_PENDING_STALE_SECONDS)
    ):
        db.rollback()
        return False

    # 2. Successful-send limits: <= 3 per rolling hour, >= 60s between sends
    sent_last_hour = db.execute(
        select(func.count())
        .select_from(token_model)
        .where(
            token_model.user_id == user.id,
            token_model.delivery_status == "sent",
            token_model.delivery_attempted_at > now - timedelta(minutes=60),
        )
    ).scalar_one()
    if sent_last_hour >= settings.EMAIL_MAX_PER_HOUR:
        db.rollback()
        return False

    latest_sent = db.execute(
        select(token_model)
        .where(
            token_model.user_id == user.id,
            token_model.delivery_status == "sent",
        )
        .order_by(
            token_model.delivery_attempted_at.desc().nulls_last(),
            token_model.created_at.desc(),
        )
        .limit(1)
    ).scalar_one_or_none()

    if (
        latest_sent is not None
        and latest_sent.delivery_attempted_at is not None
        and latest_sent.delivery_attempted_at
        > now - timedelta(seconds=settings.EMAIL_COOLDOWN_SECONDS)
    ):
        db.rollback()
        return False

    # 3. Consecutive-failure sequence (Rev10 §11.2)
    last_sent_created_at = (
        latest_sent.created_at
        if latest_sent is not None
        else datetime.min.replace(tzinfo=timezone.utc)
    )
    consecutive_failures = db.execute(
        select(func.count())
        .select_from(token_model)
        .where(
            token_model.user_id == user.id,
            token_model.delivery_status == "failed",
            token_model.created_at > last_sent_created_at,
        )
    ).scalar_one()

    if consecutive_failures >= 2:
        latest_failed = db.execute(
            select(token_model)
            .where(
                token_model.user_id == user.id,
                token_model.delivery_status == "failed",
                token_model.created_at > last_sent_created_at,
            )
            .order_by(token_model.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if (
            latest_failed is not None
            and latest_failed.delivery_attempted_at is not None
            and latest_failed.delivery_attempted_at
            > now - timedelta(seconds=settings.EMAIL_FAILED_RETRY_BACKOFF_SECONDS)
        ):
            db.rollback()
            return False

    # 4. Revoke prior unconsumed/unrevoked tokens & insert fresh pending token
    db.execute(
        update(token_model)
        .where(
            token_model.user_id == user.id,
            token_model.consumed_at.is_(None),
            token_model.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )

    raw_token = generate_opaque_token()
    target_email = user.email
    new_token = token_model(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=hash_opaque_token(raw_token),
        delivery_status="pending",
        delivery_attempted_at=None,
        expires_at=now + expires_delta,
    )
    if isinstance(new_token, PasswordResetToken):
        new_token.requested_ip = _normalize_persisted_ip(requested_ip)
    db.add(new_token)
    db.commit()

    # External HTTP call outside DB transaction & lock
    try:
        send_result = email_sender(
            to_email=target_email,
            raw_token=raw_token,
            settings=settings,
        )
    except Exception as exc:
        logger.warning(
            "Transactional email sender raised unexpectedly: exception=%s",
            type(exc).__name__,
        )
        send_result = EmailSendResult(sent=False, error_type=type(exc).__name__)

    # Tx 2: update final delivery status
    new_token.delivery_status = "sent" if send_result.sent else "failed"
    new_token.delivery_attempted_at = datetime.now(timezone.utc)
    db.commit()

    return send_result.sent


def resend_verification(
    db: Session,
    *,
    email: str,
    settings: Settings,
) -> bool:
    """
    Evaluate Rev10 §11.2 Resend retry/cooldown state machine and deliver if eligible.

    Returns True if a new email send was attempted and succeeded, False otherwise
    (caller always returns generic 202 Accepted).
    """
    return _issue_and_deliver_single_use_token(
        db,
        email=email,
        token_model=EmailVerificationToken,
        eligibility_check=lambda u: u.is_active and not u.is_email_verified,
        expires_delta=timedelta(hours=settings.EMAIL_VERIFICATION_EXPIRE_HOURS),
        email_sender=send_verification_email,
        settings=settings,
    )


def login_user(
    db: Session,
    *,
    email: str,
    password: str,
    client_type: str,
    user_agent: str | None,
    ip_address: str | None,
    settings: Settings,
) -> tuple[User, str, int, str, int]:
    """
    Authenticate email/password credentials and create a rotating refresh session.

    Always runs Argon2id verification before checking email verification or active status.
    """
    canonical_email = normalize_email(email)
    user = db.execute(select(User).where(User.email == canonical_email)).scalar_one_or_none()

    candidate_hash = (
        user.password_hash
        if user is not None and user.password_hash is not None
        else DUMMY_PASSWORD_HASH
    )
    password_matches = verify_password(password, candidate_hash)

    if user is None or user.password_hash is None or not password_matches:
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_CREDENTIALS",
            public_message="Invalid email or password.",
        )

    if not user.is_email_verified:
        raise auth_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="EMAIL_NOT_VERIFIED",
            public_message="Email address must be verified before logging in.",
        )

    if not user.is_active:
        raise auth_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="ACCOUNT_INACTIVE",
            public_message="Account is inactive.",
        )

    now = datetime.now(timezone.utc)
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    return _create_session_and_mint_tokens(
        db,
        user=user,
        client_type=client_type,
        user_agent=user_agent,
        ip_address=ip_address,
        now=now,
        settings=settings,
    )


def refresh_session_token(
    db: Session,
    *,
    raw_refresh_token: str | None,
    client_type: str,
    user_agent: str | None,
    ip_address: str | None,
    settings: Settings,
) -> tuple[User, str, int, str, int]:
    """
    Rotate a single-use opaque refresh token under users-first FOR UPDATE locking.

    Locks users first, then refresh_sessions (deadlock-free hierarchy). Replaying an
    already-rotated token revokes only the affected family_id and raises
    401 REFRESH_TOKEN_REUSE_DETECTED.
    """
    if not raw_refresh_token or not raw_refresh_token.strip():
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_REFRESH_TOKEN",
            public_message="Invalid or expired refresh token.",
        )

    token_hash = hash_opaque_token(raw_refresh_token.strip())
    session_user_id = db.execute(
        select(RefreshSession.user_id).where(RefreshSession.token_hash == token_hash)
    ).scalar_one_or_none()

    if session_user_id is None:
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_REFRESH_TOKEN",
            public_message="Invalid or expired refresh token.",
        )

    # Lock users first, then refresh_sessions, refreshing ORM identity-map state
    user = db.execute(
        select(User)
        .where(User.id == session_user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if user is None:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_REFRESH_TOKEN",
            public_message="Invalid or expired refresh token.",
        )

    session_row = db.execute(
        select(RefreshSession)
        .where(
            RefreshSession.token_hash == token_hash,
            RefreshSession.user_id == user.id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()

    if session_row is None:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_REFRESH_TOKEN",
            public_message="Invalid or expired refresh token.",
        )

    now = datetime.now(timezone.utc)

    if session_row.revoked_at is not None:
        if (
            session_row.revoke_reason == "rotated"
            or session_row.replaced_by_session_id is not None
        ):
            db.execute(
                update(RefreshSession)
                .where(
                    RefreshSession.family_id == session_row.family_id,
                    RefreshSession.revoked_at.is_(None),
                )
                .values(revoked_at=now, revoke_reason="reuse_detected")
            )
            db.commit()
            raise auth_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                code="REFRESH_TOKEN_REUSE_DETECTED",
                public_message="Refresh token reuse detected; session family revoked.",
            )

        db.rollback()
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_REFRESH_TOKEN",
            public_message="Invalid or expired refresh token.",
        )

    if session_row.client_type != client_type:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_REFRESH_TOKEN",
            public_message="Invalid or expired refresh token.",
        )

    if session_row.expires_at <= now or session_row.family_expires_at <= now:
        session_row.revoked_at = now
        session_row.revoke_reason = "expired"
        db.commit()
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_REFRESH_TOKEN",
            public_message="Invalid or expired refresh token.",
        )

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
            public_message="Email address must be verified before refreshing sessions.",
        )

    new_raw_token = generate_opaque_token()
    new_token_hash = hash_opaque_token(new_raw_token)
    new_expires_at = min(
        now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        session_row.family_expires_at,
    )

    child_session = RefreshSession(
        id=uuid.uuid4(),
        user_id=user.id,
        family_id=session_row.family_id,
        token_hash=new_token_hash,
        parent_session_id=session_row.id,
        replaced_by_session_id=None,
        client_type=client_type,
        user_agent=user_agent[:512] if user_agent else None,
        ip_address=ip_address[:45] if ip_address else None,
        expires_at=new_expires_at,
        family_expires_at=session_row.family_expires_at,
        last_used_at=now,
    )
    db.add(child_session)
    db.flush()

    session_row.revoked_at = now
    session_row.revoke_reason = "rotated"
    session_row.replaced_by_session_id = child_session.id
    session_row.last_used_at = now
    db.commit()

    access_token, expires_in = create_access_token(
        user_id=user.id,
        auth_version=user.auth_version,
        settings=settings,
        now=now,
    )
    refresh_expires_in = max(1, int((new_expires_at - now).total_seconds()))
    return user, access_token, expires_in, new_raw_token, refresh_expires_in


def logout_current_session(
    db: Session,
    *,
    raw_refresh_token: str | None,
    client_type: str,
) -> None:
    """Idempotently revoke the active refresh session using users-first locking."""
    if not raw_refresh_token or not raw_refresh_token.strip():
        return

    token_hash = hash_opaque_token(raw_refresh_token.strip())
    session_user_id = db.execute(
        select(RefreshSession.user_id).where(RefreshSession.token_hash == token_hash)
    ).scalar_one_or_none()
    if session_user_id is None:
        return

    locked_user_id = db.execute(
        select(User.id).where(User.id == session_user_id).with_for_update()
    ).scalar_one_or_none()
    if locked_user_id is None:
        db.rollback()
        return

    session_row = db.execute(
        select(RefreshSession)
        .where(
            RefreshSession.token_hash == token_hash,
            RefreshSession.user_id == locked_user_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()

    if (
        session_row is not None
        and session_row.client_type == client_type
        and session_row.revoked_at is None
    ):
        session_row.revoked_at = datetime.now(timezone.utc)
        session_row.revoke_reason = "logout"
        db.commit()
    else:
        db.rollback()


def logout_all_sessions(
    db: Session,
    *,
    user_id: uuid.UUID,
    expected_auth_version: int | None = None,
) -> None:
    """
    Atomically increment users.auth_version and revoke all active refresh sessions.

    Locks and refreshes the users row first, revalidates is_active unconditionally
    (and expected_auth_version when supplied) under the row lock, and only then
    updates users and refresh_sessions.
    """
    user = db.execute(
        select(User)
        .where(User.id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if user is None:
        db.rollback()
        if expected_auth_version is not None:
            raise auth_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                code="INVALID_ACCESS_TOKEN",
                public_message="Invalid or expired access token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return

    if expected_auth_version is not None and user.auth_version != expected_auth_version:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_ACCESS_TOKEN",
            public_message="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="ACCOUNT_INACTIVE",
            public_message="Account is inactive.",
        )

    now = datetime.now(timezone.utc)
    user.auth_version += 1

    db.execute(
        update(RefreshSession)
        .where(
            RefreshSession.user_id == user.id,
            RefreshSession.revoked_at.is_(None),
        )
        .values(revoked_at=now, revoke_reason="logout_all")
    )
    db.commit()


def request_password_reset(
    db: Session,
    *,
    email: str,
    requested_ip: str | None = None,
    settings: Settings,
) -> bool:
    """
    Evaluate Rev10 §11.2 Resend retry/cooldown state machine and deliver reset link if eligible.

    Eligible only for active, email-verified accounts with a local password_hash.
    Returns True if an email send was attempted and succeeded, False otherwise
    (caller always returns generic 202 Accepted).
    """
    return _issue_and_deliver_single_use_token(
        db,
        email=email,
        token_model=PasswordResetToken,
        eligibility_check=lambda u: (
            u.is_active and u.is_email_verified and u.password_hash is not None
        ),
        expires_delta=timedelta(minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES),
        email_sender=send_password_reset_email,
        settings=settings,
        requested_ip=requested_ip,
    )


def reset_password(
    db: Session,
    *,
    raw_token: str,
    new_password: str,
) -> None:
    """
    Consume a single-use password reset token, update credentials, and revoke all sessions.

    Follows strict deadlock-free lock hierarchy: users -> password_reset_tokens -> refresh_sessions.
    Never issues JWTs, refresh sessions, or cookies.
    """
    token_hash = hash_opaque_token(raw_token.strip())
    token_user_id = db.execute(
        select(PasswordResetToken.user_id).where(
            PasswordResetToken.token_hash == token_hash
        )
    ).scalar_one_or_none()
    if token_user_id is None:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_RESET_TOKEN",
            public_message="Password reset link is invalid or has expired.",
        )

    # Lock users row FIRST, then password_reset_tokens row
    user = db.execute(
        select(User)
        .where(User.id == token_user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if user is None:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_RESET_TOKEN",
            public_message="Password reset link is invalid or has expired.",
        )

    if not user.is_active:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="ACCOUNT_INACTIVE",
            public_message="Account is inactive.",
        )

    if not user.is_email_verified or user.password_hash is None:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_RESET_TOKEN",
            public_message="Password reset link is invalid or has expired.",
        )

    token_row = db.execute(
        select(PasswordResetToken)
        .where(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.user_id == user.id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()

    now = datetime.now(timezone.utc)
    if (
        token_row is None
        or token_row.consumed_at is not None
        or token_row.revoked_at is not None
        or token_row.expires_at <= now
    ):
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_RESET_TOKEN",
            public_message="Password reset link is invalid or has expired.",
        )

    try:
        _validate_new_password_or_raise(new_password, user.email)
    except ValidationAppError:
        db.rollback()
        raise

    user.password_hash = hash_password(new_password)
    user.password_changed_at = now
    user.auth_version += 1
    token_row.consumed_at = now

    # Revoke any sibling active reset tokens for this user
    db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.id != token_row.id,
            PasswordResetToken.consumed_at.is_(None),
            PasswordResetToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )

    # Revoke all active refresh sessions for this user
    db.execute(
        update(RefreshSession)
        .where(
            RefreshSession.user_id == user.id,
            RefreshSession.revoked_at.is_(None),
        )
        .values(revoked_at=now, revoke_reason="password_reset")
    )
    db.commit()


def change_password(
    db: Session,
    *,
    user_id: uuid.UUID,
    expected_auth_version: int,
    current_password: str,
    new_password: str,
    client_type: str,
    user_agent: str | None,
    ip_address: str | None,
    settings: Settings,
) -> tuple[User, str, int, str, int]:
    """
    Rotate authenticated user's password, revoke prior tokens/sessions, and issue one fresh session.

    Mandatory validation order after User FOR UPDATE lock + populate_existing=True:
      1. auth_version == expected_auth_version -> 401 INVALID_ACCESS_TOKEN
      2. is_active -> 403 ACCOUNT_INACTIVE
      3. password_hash is not None -> 400 PASSWORD_NOT_SET
      4. verify_password(current_password) -> 401 INVALID_CREDENTIALS
      5. new_password != current_password -> 400 SAME_PASSWORD_NOT_ALLOWED
      6. validate_password_policy(new_password, user.email) -> 422 VALIDATION_ERROR
    """
    user = db.execute(
        select(User)
        .where(User.id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if user is None or user.auth_version != expected_auth_version:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_ACCESS_TOKEN",
            public_message="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="ACCOUNT_INACTIVE",
            public_message="Account is inactive.",
        )

    if user.password_hash is None:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="PASSWORD_NOT_SET",
            public_message="Password login is not enabled for this account.",
        )

    if not verify_password(current_password, user.password_hash):
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_CREDENTIALS",
            public_message="Current password is incorrect.",
        )

    if new_password == current_password:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="SAME_PASSWORD_NOT_ALLOWED",
            public_message="New password must be different from your current password.",
        )

    try:
        _validate_new_password_or_raise(new_password, user.email)
    except ValidationAppError:
        db.rollback()
        raise

    now = datetime.now(timezone.utc)
    user.password_hash = hash_password(new_password)
    user.password_changed_at = now
    user.auth_version += 1

    # Revoke any active outstanding password reset tokens
    db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.consumed_at.is_(None),
            PasswordResetToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )

    # Revoke all prior active refresh sessions
    db.execute(
        update(RefreshSession)
        .where(
            RefreshSession.user_id == user.id,
            RefreshSession.revoked_at.is_(None),
        )
        .values(revoked_at=now, revoke_reason="password_changed")
    )

    return _create_session_and_mint_tokens(
        db,
        user=user,
        client_type=client_type,
        user_agent=user_agent,
        ip_address=ip_address,
        now=now,
        settings=settings,
    )
