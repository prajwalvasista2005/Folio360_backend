"""Owner-scoped account management, security audit log, email change, export, and deletion service."""

from datetime import datetime, timedelta, timezone
import logging
import math
import uuid

from fastapi import status
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core.config import Settings
from app.core.exceptions import AppException, ResourceNotFoundError, ValidationAppError, auth_error
from app.core.security import (
    generate_opaque_token,
    hash_opaque_token,
    normalize_email,
    verify_password,
)
from app.models.account import EmailChangeToken, SecurityAuditEvent
from app.models.certificate import Achievement, Certificate
from app.models.document import Document
from app.models.education import Education
from app.models.experience import Experience
from app.models.oauth import OAuthAccount
from app.models.profile import UserProfile
from app.models.project import Project, ProjectImage
from app.models.refresh_session import RefreshSession
from app.models.skill import Skill
from app.models.user import User
from app.services.email_service import send_email_change_verification_email
from app.services.storage_service import build_storage_backend

logger = logging.getLogger("folio360.account.service")

_EMAIL_CHANGE_EXPIRE_HOURS = 24


def _get_constraint_name(exc: IntegrityError) -> str | None:
    """Extract PostgreSQL constraint name from a SQLAlchemy IntegrityError."""
    orig = exc.orig
    if orig is None:
        return None
    diag = getattr(orig, "diag", None)
    if diag is not None:
        return getattr(diag, "constraint_name", None)
    return None


def format_device_label(user_agent: str | None, client_type: str = "web") -> str:
    """Derive a concise, non-sensitive browser/OS label from User-Agent."""
    if not user_agent or not user_agent.strip():
        return "Mobile app session" if client_type == "mobile" else "Web browser session"
    ua = user_agent.strip()
    browser = "Browser"
    if "Edg/" in ua:
        browser = "Edge"
    elif "Chrome/" in ua and "Chromium" not in ua:
        browser = "Chrome"
    elif "Firefox/" in ua:
        browser = "Firefox"
    elif "Safari/" in ua and "Chrome/" not in ua:
        browser = "Safari"
    elif "curl/" in ua.lower():
        browser = "curl"

    platform = "Unknown OS"
    if "Windows" in ua:
        platform = "Windows"
    elif "Mac OS X" in ua or "Macintosh" in ua:
        platform = "macOS"
    elif "Android" in ua:
        platform = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        platform = "iOS"
    elif "Linux" in ua:
        platform = "Linux"

    return f"{browser} on {platform}"


def record_security_event(
    db: Session,
    *,
    user_id: uuid.UUID,
    action: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
    client_type: str = "web",
) -> None:
    """Append a sanitized security audit event to the caller's active transaction."""
    clean_ip = ip_address[:45] if ip_address else None
    label = format_device_label(user_agent, client_type)[:120]
    db.add(
        SecurityAuditEvent(
            id=uuid.uuid4(),
            user_id=user_id,
            action=action.strip()[:64],
            ip_address=clean_ip,
            device_label=label,
        )
    )


def get_pending_email(db: Session, *, user_id: uuid.UUID) -> str | None:
    """Return the latest active, unexpired, unconsumed pending email change for user_id."""
    now = datetime.now(timezone.utc)
    return db.execute(
        select(EmailChangeToken.new_email)
        .where(
            EmailChangeToken.user_id == user_id,
            EmailChangeToken.consumed_at.is_(None),
            EmailChangeToken.revoked_at.is_(None),
            EmailChangeToken.expires_at > now,
        )
        .order_by(EmailChangeToken.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def get_account_summary(db: Session, *, user: User) -> dict:
    """Build sanitized account summary including active pending_email."""
    return {
        "id": user.id,
        "email": user.email,
        "email_verified": user.is_email_verified,
        "pending_email": get_pending_email(db, user_id=user.id),
        "has_password": user.password_hash is not None,
        "created_at": user.created_at,
    }


def list_security_log(
    db: Session,
    *,
    user_id: uuid.UUID,
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[SecurityAuditEvent], int, int]:
    """Return paginated security audit events strictly scoped to user_id."""
    total = int(
        db.execute(
            select(func.count())
            .select_from(SecurityAuditEvent)
            .where(SecurityAuditEvent.user_id == user_id)
        ).scalar_one()
    )
    total_pages = max(1, math.ceil(total / page_size)) if total > 0 else 1
    offset = (page - 1) * page_size
    items = list(
        db.execute(
            select(SecurityAuditEvent)
            .where(SecurityAuditEvent.user_id == user_id)
            .order_by(SecurityAuditEvent.created_at.desc())
            .offset(offset)
            .limit(page_size)
        )
        .scalars()
        .all()
    )
    return items, total, total_pages


def request_email_change(
    db: Session,
    *,
    user_id: uuid.UUID,
    new_email: str,
    current_password: str | None,
    ip_address: str | None,
    user_agent: str | None,
    settings: Settings,
) -> tuple[str, str | None]:
    """
    Validate credentials and create a pending verified email-change token.

    Preserves the existing verified email until the new address is confirmed.
    Rejects addresses linked to any existing account or active pending request
    without sending verification emails.
    """
    canonical_new_email = normalize_email(new_email)
    user = db.execute(
        select(User)
        .where(User.id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if user is None:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_ACCESS_TOKEN",
            public_message="Invalid or expired access token.",
        )

    if user.password_hash is not None:
        if not current_password or not verify_password(current_password, user.password_hash):
            db.rollback()
            raise auth_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                code="INVALID_CREDENTIALS",
                public_message="Current password is incorrect.",
            )

    if canonical_new_email == user.email:
        db.rollback()
        raise ValidationAppError(
            message="New email matches current email",
            public_message="New email must be different from your current email.",
            error_code="SAME_EMAIL",
        )

    existing_owner = db.execute(
        select(User.id).where(User.email == canonical_new_email)
    ).scalar_one_or_none()
    if existing_owner is not None:
        db.rollback()
        raise AppException(
            message="Email address is already linked to an existing account",
            status_code=status.HTTP_409_CONFLICT,
            public_message="This email address is already linked to an existing account.",
            error_code="EMAIL_TAKEN",
        )

    existing_oauth_owner = db.execute(
        select(OAuthAccount.user_id)
        .where(
            OAuthAccount.provider_email == canonical_new_email,
            OAuthAccount.user_id != user.id,
        )
        .limit(1)
    ).scalar_one_or_none()
    if existing_oauth_owner is not None:
        db.rollback()
        raise AppException(
            message="Email address is already linked to an existing account",
            status_code=status.HTTP_409_CONFLICT,
            public_message="This email address is already linked to an existing account.",
            error_code="EMAIL_TAKEN",
        )

    now = datetime.now(timezone.utc)
    # Revoke expired active tokens holding this email before uniqueness check
    db.execute(
        update(EmailChangeToken)
        .where(
            EmailChangeToken.new_email == canonical_new_email,
            EmailChangeToken.consumed_at.is_(None),
            EmailChangeToken.revoked_at.is_(None),
            EmailChangeToken.expires_at <= now,
        )
        .values(revoked_at=now)
    )

    active_claim = db.execute(
        select(EmailChangeToken)
        .where(
            EmailChangeToken.new_email == canonical_new_email,
            EmailChangeToken.consumed_at.is_(None),
            EmailChangeToken.revoked_at.is_(None),
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if active_claim is not None:
        same_user = active_claim.user_id == user.id
        db.rollback()
        if same_user:
            raise AppException(
                message="Verification email already pending for this email address",
                status_code=status.HTTP_409_CONFLICT,
                public_message=(
                    "A verification email is already pending for this email address. "
                    "Please check your inbox."
                ),
                error_code="EMAIL_CHANGE_ALREADY_PENDING",
            )
        raise AppException(
            message="Email address is already reserved by a pending request",
            status_code=status.HTTP_409_CONFLICT,
            public_message="This email address is already linked to an existing account.",
            error_code="EMAIL_TAKEN",
        )

    db.execute(
        update(EmailChangeToken)
        .where(
            EmailChangeToken.user_id == user.id,
            EmailChangeToken.consumed_at.is_(None),
            EmailChangeToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )

    raw_token = generate_opaque_token()
    token_row = EmailChangeToken(
        id=uuid.uuid4(),
        user_id=user.id,
        new_email=canonical_new_email,
        token_hash=hash_opaque_token(raw_token),
        expires_at=now + timedelta(hours=_EMAIL_CHANGE_EXPIRE_HOURS),
    )
    db.add(token_row)
    record_security_event(
        db,
        user_id=user.id,
        action="email_change_requested",
        ip_address=ip_address,
        user_agent=user_agent,
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        logger.info(
            "Email change request hit unique constraint (%s)",
            _get_constraint_name(exc),
        )
        raise AppException(
            message="Email address is unavailable due to an existing or concurrent request",
            status_code=status.HTTP_409_CONFLICT,
            public_message="This email address is already linked to an existing account.",
            error_code="EMAIL_TAKEN",
        ) from exc

    send_email_change_verification_email(
        to_email=canonical_new_email,
        raw_token=raw_token,
        settings=settings,
    )
    return (
        "Confirmation email sent. Your login email will update after verification.",
        canonical_new_email,
    )


def confirm_email_change(
    db: Session,
    *,
    raw_token: str,
    ip_address: str | None,
    user_agent: str | None,
) -> dict:
    """Confirm a single-use email-change token and atomically update user.email."""
    token_hash = hash_opaque_token(raw_token.strip())
    token_row = db.execute(
        select(EmailChangeToken).where(EmailChangeToken.token_hash == token_hash)
    ).scalar_one_or_none()
    if token_row is None:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_EMAIL_CHANGE_TOKEN",
            public_message="Email change link is invalid or has expired.",
        )

    user = db.execute(
        select(User)
        .where(User.id == token_row.user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    locked_token = db.execute(
        select(EmailChangeToken)
        .where(EmailChangeToken.id == token_row.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()

    now = datetime.now(timezone.utc)
    if (
        user is None
        or not user.is_active
        or locked_token is None
        or locked_token.consumed_at is not None
        or locked_token.revoked_at is not None
        or locked_token.expires_at <= now
    ):
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="INVALID_EMAIL_CHANGE_TOKEN",
            public_message="Email change link is invalid or has expired.",
        )

    conflict = db.execute(
        select(User.id).where(
            User.email == locked_token.new_email,
            User.id != user.id,
        )
    ).scalar_one_or_none()
    oauth_conflict = db.execute(
        select(OAuthAccount.user_id)
        .where(
            OAuthAccount.provider_email == locked_token.new_email,
            OAuthAccount.user_id != user.id,
        )
        .limit(1)
    ).scalar_one_or_none()
    if conflict is not None or oauth_conflict is not None:
        db.rollback()
        raise AppException(
            message="Email address is already taken",
            status_code=status.HTTP_409_CONFLICT,
            public_message="This email address is no longer available.",
            error_code="EMAIL_TAKEN",
        )

    user.email = locked_token.new_email
    user.is_email_verified = True
    if user.email_verified_at is None:
        user.email_verified_at = now
    locked_token.consumed_at = now
    record_security_event(
        db,
        user_id=user.id,
        action="email_changed",
        ip_address=ip_address,
        user_agent=user_agent,
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        logger.info(
            "Email change confirmation hit unique constraint (%s)",
            _get_constraint_name(exc),
        )
        raise AppException(
            message="Email address is already taken",
            status_code=status.HTTP_409_CONFLICT,
            public_message="This email address is no longer available.",
            error_code="EMAIL_TAKEN",
        ) from exc
    db.refresh(user)
    return get_account_summary(db, user=user)


def list_oauth_connections(db: Session, *, user_id: uuid.UUID) -> list[OAuthAccount]:
    """Return linked OAuth sign-in providers for user_id without exposing credentials."""
    return list(
        db.execute(
            select(OAuthAccount)
            .where(OAuthAccount.user_id == user_id)
            .order_by(OAuthAccount.created_at.asc())
        )
        .scalars()
        .all()
    )


def disconnect_oauth_provider(
    db: Session,
    *,
    user_id: uuid.UUID,
    provider: str,
    ip_address: str | None,
    user_agent: str | None,
) -> None:
    """Unlink an OAuth provider only if another usable sign-in method remains."""
    user = db.execute(
        select(User)
        .where(User.id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if user is None:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_ACCESS_TOKEN",
            public_message="Invalid or expired access token.",
        )

    linked = list(
        db.execute(
            select(OAuthAccount)
            .where(OAuthAccount.user_id == user.id)
            .with_for_update()
        )
        .scalars()
        .all()
    )
    target = next((row for row in linked if row.provider == provider), None)
    if target is None:
        db.rollback()
        raise ResourceNotFoundError(
            message="OAuth connection not found",
            public_message="Connected provider not found.",
            error_code="CONNECTION_NOT_FOUND",
        )

    if user.password_hash is None and len(linked) <= 1:
        db.rollback()
        raise AppException(
            message="Cannot unlink the only sign-in method",
            status_code=status.HTTP_400_BAD_REQUEST,
            public_message="Set a password or link another provider before disconnecting your only sign-in method.",
            error_code="LAST_AUTH_METHOD",
        )

    db.delete(target)
    record_security_event(
        db,
        user_id=user.id,
        action="oauth_disconnected",
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.commit()


def export_user_data(
    db: Session,
    *,
    user: User,
    ip_address: str | None,
    user_agent: str | None,
) -> dict:
    """Assemble a sanitized, strictly owner-scoped JSON export of user data."""
    from app.services import profile_service

    profile = db.execute(
        select(UserProfile)
        .options(selectinload(UserProfile.activities))
        .where(UserProfile.user_id == user.id)
    ).scalar_one_or_none()

    educations = list(
        db.execute(select(Education).where(Education.user_id == user.id)).scalars().all()
    )
    projects = list(
        db.execute(select(Project).where(Project.user_id == user.id)).scalars().all()
    )
    skills = list(
        db.execute(select(Skill).where(Skill.user_id == user.id)).scalars().all()
    )
    certificates = list(
        db.execute(select(Certificate).where(Certificate.user_id == user.id)).scalars().all()
    )
    achievements = list(
        db.execute(select(Achievement).where(Achievement.user_id == user.id)).scalars().all()
    )
    experiences = list(
        db.execute(select(Experience).where(Experience.user_id == user.id)).scalars().all()
    )
    documents = list(
        db.execute(select(Document).where(Document.user_id == user.id)).scalars().all()
    )
    oauth_accounts = list_oauth_connections(db, user_id=user.id)

    record_security_event(
        db,
        user_id=user.id,
        action="data_exported",
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.commit()

    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "account": {
            "id": str(user.id),
            "email": user.email,
            "email_verified": user.is_email_verified,
            "created_at": user.created_at.isoformat(),
        },
        "profile": (
            {
                "slug": profile.slug,
                "full_name": profile.full_name,
                "date_of_birth": profile.date_of_birth.isoformat()
                if profile.date_of_birth
                else None,
                "bio": profile.bio,
                "avatar_url": profile.profile_picture_url,
                "interests": list(profile.interests or []),
                "current_activities": [
                    {
                        "key": act.activity_key,
                        "label": act.custom_label,
                        "description": act.description,
                    }
                    for act in profile.activities
                ],
                "visibility_settings": profile_service.resolve_visibility_settings(
                    profile.visibility_settings
                ),
                "theme_preference": profile.theme_preference,
            }
            if profile is not None
            else None
        ),
        "education": [
            {
                "id": str(edu.id),
                "institution": edu.institution,
                "university_or_board": edu.university_or_board,
                "education_level": edu.education_level,
                "degree": edu.degree,
                "programme": edu.programme,
                "branch": edu.branch,
                "start_year": edu.start_year,
                "end_year": edu.end_year,
                "is_current": edu.is_current,
                "result_type": edu.result_type,
                "result_value": edu.result_value,
                "visibility": edu.visibility,
            }
            for edu in educations
        ],
        "projects": [
            {
                "id": str(proj.id),
                "title": proj.title,
                "summary": proj.summary,
                "description": proj.description,
                "category": proj.category,
                "technologies": list(proj.technologies or []),
                "github_url": proj.github_url,
                "live_url": proj.live_url,
                "start_date": proj.start_date.isoformat() if proj.start_date else None,
                "end_date": proj.end_date.isoformat() if proj.end_date else None,
                "is_ongoing": proj.is_ongoing,
                "visibility": proj.visibility,
            }
            for proj in projects
        ],
        "skills": [
            {
                "id": str(sk.id),
                "name": sk.name,
                "category": sk.category,
                "proficiency": sk.proficiency,
            }
            for sk in skills
        ],
        "certificates": [
            {
                "id": str(cert.id),
                "name": cert.name,
                "issuer": cert.issuer,
                "category": cert.category,
                "issue_date": cert.issue_date.isoformat() if cert.issue_date else None,
                "expiry_date": cert.expiry_date.isoformat() if cert.expiry_date else None,
                "credential_id": cert.credential_id,
                "verification_url": cert.verification_url,
                "visibility": cert.visibility,
            }
            for cert in certificates
        ],
        "achievements": [
            {
                "id": str(ach.id),
                "title": ach.title,
                "category": ach.category,
                "organization": ach.organization,
                "date": ach.date.isoformat() if ach.date else None,
                "description": ach.description,
                "visibility": ach.visibility,
            }
            for ach in achievements
        ],
        "experience": [
            {
                "id": str(exp.id),
                "type": exp.type,
                "organization": exp.organization,
                "role": exp.role,
                "location": exp.location,
                "is_remote": exp.is_remote,
                "start_date": exp.start_date.isoformat(),
                "end_date": exp.end_date.isoformat() if exp.end_date else None,
                "is_current": exp.is_current,
                "description": exp.description,
                "highlights": list(exp.highlights or []),
                "visibility": exp.visibility,
            }
            for exp in experiences
        ],
        "documents": [
            {
                "id": str(doc.id),
                "title": doc.title,
                "original_filename": doc.original_filename,
                "category": doc.category,
                "mime_type": doc.mime_type,
                "size_bytes": doc.size_bytes,
                "processing_status": doc.processing_status,
                "uploaded_at": doc.created_at.isoformat(),
            }
            for doc in documents
        ],
        "connected_providers": [
            {
                "provider": acc.provider,
                "provider_email": acc.provider_email,
                "linked_at": acc.created_at.isoformat(),
            }
            for acc in oauth_accounts
        ],
    }


def delete_user_account(
    db: Session,
    *,
    user_id: uuid.UUID,
    current_password: str | None,
    settings: Settings,
) -> None:
    """
    Verify identity, delete the user (cascading owned DB rows), and clean up stored objects.
    """
    user = db.execute(
        select(User)
        .where(User.id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if user is None:
        db.rollback()
        raise auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="INVALID_ACCESS_TOKEN",
            public_message="Invalid or expired access token.",
        )

    if user.password_hash is not None:
        if not current_password or not verify_password(current_password, user.password_hash):
            db.rollback()
            raise auth_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                code="INVALID_CREDENTIALS",
                public_message="Current password is incorrect.",
            )

    doc_keys = list(
        db.execute(
            select(Document.storage_key).where(
                Document.user_id == user.id,
                Document.storage_state != "deleted",
            )
        )
        .scalars()
        .all()
    )
    proj_img_keys = list(
        db.execute(
            select(ProjectImage.storage_key).where(ProjectImage.user_id == user.id)
        )
        .scalars()
        .all()
    )
    avatar_key = db.execute(
        select(UserProfile.avatar_storage_key).where(
            UserProfile.user_id == user.id,
            UserProfile.avatar_storage_key.is_not(None),
        )
    ).scalar_one_or_none()

    now = datetime.now(timezone.utc)
    user.auth_version += 1
    db.execute(
        update(RefreshSession)
        .where(
            RefreshSession.user_id == user.id,
            RefreshSession.revoked_at.is_(None),
        )
        .values(revoked_at=now, revoke_reason="account_deleted")
    )
    db.delete(user)
    db.commit()

    storage = build_storage_backend(settings)
    cleanup_keys = [*doc_keys, *proj_img_keys]
    if avatar_key:
        cleanup_keys.append(avatar_key)
    for key in cleanup_keys:
        try:
            storage.delete_object(storage_key=key)
        except Exception as exc:
            logger.warning(
                "Failed to delete stored object during account deletion: exception=%s",
                type(exc).__name__,
            )
