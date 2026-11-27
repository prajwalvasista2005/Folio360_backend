"""Synchronous Certificates & Achievements CRUD, Document Vault linking, and ownership service."""

import logging
import math
from typing import Any
import uuid

from fastapi import status
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core.exceptions import (
    AppException,
    ResourceNotFoundError,
    ValidationAppError,
)
from app.models.certificate import (
    Achievement,
    AchievementDocument,
    Certificate,
    CertificateSkill,
)
from app.models.document import Document
from app.models.skill import Skill
from app.schemas.certificate import (
    AchievementCreate,
    AchievementUpdate,
    CertificateCreate,
    CertificateUpdate,
    CredentialVisibility,
    compute_verification_status,
    validate_certificate_dates,
)
from app.services.auth_service import get_constraint_name

logger = logging.getLogger("folio360.certificate.service")

_CERT_NOT_FOUND_MESSAGE = "Certificate not found"
_CERT_NOT_FOUND_PUBLIC = "Certificate not found."
_CERT_NOT_FOUND_CODE = "CERTIFICATE_NOT_FOUND"

_ACH_NOT_FOUND_MESSAGE = "Achievement not found"
_ACH_NOT_FOUND_PUBLIC = "Achievement not found."
_ACH_NOT_FOUND_CODE = "ACHIEVEMENT_NOT_FOUND"


def _certificate_load_options() -> tuple[Any, ...]:
    return (
        selectinload(Certificate.document),
        selectinload(Certificate.skill_links).selectinload(CertificateSkill.skill),
    )


def _achievement_load_options() -> Any:
    return selectinload(Achievement.document_links).selectinload(
        AchievementDocument.document
    )


def _resolve_owned_documents(
    db: Session,
    *,
    user_id: uuid.UUID,
    document_ids: list[uuid.UUID],
    field_name: str,
) -> list[Document]:
    """Verify referenced documents exist, belong to user_id, and are scanned/trusted."""
    if not document_ids:
        return []
    docs = list(
        db.execute(
            select(Document).where(
                Document.id.in_(document_ids),
                Document.user_id == user_id,
            )
        )
        .scalars()
        .all()
    )
    by_id = {doc.id: doc for doc in docs}
    missing = [str(doc_id) for doc_id in document_ids if doc_id not in by_id]
    if missing:
        raise ValidationAppError(
            message="Invalid or unowned document reference",
            public_message="One or more referenced documents were not found.",
            details={"field": field_name},
            error_code="INVALID_REFERENCE",
        )
    ordered_docs = [by_id[doc_id] for doc_id in document_ids]
    for doc in ordered_docs:
        if doc.processing_status != "ready" or doc.storage_state != "trusted":
            raise ValidationAppError(
                message="Document is not ready for attachment",
                public_message="Only scanned and trusted documents can be attached as evidence.",
                details={"field": field_name},
                error_code="DOCUMENT_NOT_READY",
            )
    return ordered_docs


def _resolve_owned_skills(
    db: Session,
    *,
    user_id: uuid.UUID,
    skill_ids: list[uuid.UUID],
) -> list[Skill]:
    """Verify all referenced skills exist and belong to user_id."""
    if not skill_ids:
        return []
    skills = list(
        db.execute(
            select(Skill).where(
                Skill.id.in_(skill_ids),
                Skill.user_id == user_id,
            )
        )
        .scalars()
        .all()
    )
    by_id = {skill.id: skill for skill in skills}
    missing = [str(skill_id) for skill_id in skill_ids if skill_id not in by_id]
    if missing:
        raise ValidationAppError(
            message="Invalid or unowned skill reference",
            public_message="One or more referenced skills were not found.",
            details={"field": "skill_ids"},
            error_code="INVALID_REFERENCE",
        )
    return [by_id[skill_id] for skill_id in skill_ids]


def _certificate_order_by() -> tuple[Any, ...]:
    return (
        Certificate.featured.desc(),
        Certificate.display_order.asc(),
        Certificate.issue_date.desc().nulls_last(),
        Certificate.created_at.desc(),
        Certificate.id.desc(),
    )


def _achievement_order_by() -> tuple[Any, ...]:
    return (
        Achievement.featured.desc(),
        Achievement.display_order.asc(),
        Achievement.date.desc().nulls_last(),
        Achievement.created_at.desc(),
        Achievement.id.desc(),
    )


def _load_certificate(
    db: Session,
    *,
    user_id: uuid.UUID,
    certificate_id: uuid.UUID,
) -> Certificate | None:
    return (
        db.execute(
            select(Certificate)
            .options(*_certificate_load_options())
            .where(
                Certificate.id == certificate_id,
                Certificate.user_id == user_id,
            )
        )
        .scalar_one_or_none()
    )


def _load_achievement(
    db: Session,
    *,
    user_id: uuid.UUID,
    achievement_id: uuid.UUID,
) -> Achievement | None:
    return (
        db.execute(
            select(Achievement)
            .options(_achievement_load_options())
            .where(
                Achievement.id == achievement_id,
                Achievement.user_id == user_id,
            )
        )
        .scalar_one_or_none()
    )


def _handle_certificate_integrity_error(exc: IntegrityError) -> None:
    constraint = get_constraint_name(exc)
    if constraint == "ck_certificates_date_order_valid":
        raise ValidationAppError(
            message="Invalid certificate date range",
            public_message="Expiry date cannot be earlier than issue date.",
            details={"field": "expiry_date"},
        ) from None
    raise AppException(
        message="Unable to save certificate",
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        public_message="Invalid certificate payload.",
        error_code="VALIDATION_ERROR",
    ) from None


def _handle_achievement_integrity_error(exc: IntegrityError) -> None:
    constraint = get_constraint_name(exc)
    logger.warning("Achievement IntegrityError constraint=%s", constraint)
    raise AppException(
        message="Unable to save achievement",
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        public_message="Invalid achievement payload.",
        error_code="VALIDATION_ERROR",
    ) from None


# ---------------------------------------------------------------------------
# Certificates CRUD
# ---------------------------------------------------------------------------


def list_certificates(
    db: Session,
    *,
    user_id: uuid.UUID,
    page: int = 1,
    page_size: int = 100,
    q: str | None = None,
    category: str | None = None,
    visibility: CredentialVisibility | None = None,
    featured: bool | None = None,
) -> tuple[list[Certificate], int, int]:
    """List paginated certificates owned by user_id."""
    filters: list[Any] = [Certificate.user_id == user_id]
    if visibility is not None:
        filters.append(Certificate.visibility == visibility)
    if category is not None and category.strip():
        filters.append(Certificate.category == category.strip().lower())
    if featured is not None:
        filters.append(Certificate.featured.is_(featured))
    if q is not None and q.strip():
        term = f"%{q.strip()}%"
        filters.append(
            or_(
                Certificate.name.ilike(term),
                Certificate.issuer.ilike(term),
                Certificate.credential_id.ilike(term),
            )
        )

    total = int(
        db.execute(select(func.count(Certificate.id)).where(*filters)).scalar_one()
    )
    total_pages = max(1, math.ceil(total / page_size)) if total > 0 else 1
    offset = (page - 1) * page_size
    if total == 0 or offset >= total:
        return [], total, total_pages

    items = list(
        db.execute(
            select(Certificate)
            .options(*_certificate_load_options())
            .where(*filters)
            .order_by(*_certificate_order_by())
            .offset(offset)
            .limit(page_size)
        )
        .scalars()
        .all()
    )
    return items, total, total_pages


def get_certificate_by_id(
    db: Session,
    *,
    user_id: uuid.UUID,
    certificate_id: uuid.UUID,
) -> Certificate:
    """Fetch a single certificate owned by user_id or raise 404."""
    record = _load_certificate(db, user_id=user_id, certificate_id=certificate_id)
    if record is None:
        raise ResourceNotFoundError(
            message=_CERT_NOT_FOUND_MESSAGE,
            public_message=_CERT_NOT_FOUND_PUBLIC,
            error_code=_CERT_NOT_FOUND_CODE,
        )
    return record


def create_certificate(
    db: Session,
    *,
    user_id: uuid.UUID,
    payload: CertificateCreate,
) -> Certificate:
    """Create a certificate owned by user_id with optional validated evidence & skills."""
    if payload.document_id is not None:
        _resolve_owned_documents(
            db,
            user_id=user_id,
            document_ids=[payload.document_id],
            field_name="document_id",
        )
    resolved_skills = _resolve_owned_skills(
        db,
        user_id=user_id,
        skill_ids=payload.skill_ids,
    )

    record = Certificate(
        user_id=user_id,
        name=payload.name,
        issuer=payload.issuer,
        category=payload.category,
        issue_date=payload.issue_date,
        expiry_date=payload.expiry_date,
        credential_id=payload.credential_id,
        verification_url=payload.verification_url,
        verification_status=compute_verification_status(payload.verification_url),
        document_id=payload.document_id,
        featured=payload.featured,
        display_order=payload.order,
        visibility=payload.visibility,
    )
    for skill in resolved_skills:
        record.skill_links.append(CertificateSkill(skill_id=skill.id))

    db.add(record)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        _handle_certificate_integrity_error(exc)

    return get_certificate_by_id(db, user_id=user_id, certificate_id=record.id)


def update_certificate(
    db: Session,
    *,
    user_id: uuid.UUID,
    certificate_id: uuid.UUID,
    payload: CertificateUpdate,
) -> Certificate:
    """Partially update an owned certificate without overwriting omitted fields."""
    record = _load_certificate(db, user_id=user_id, certificate_id=certificate_id)
    if record is None:
        raise ResourceNotFoundError(
            message=_CERT_NOT_FOUND_MESSAGE,
            public_message=_CERT_NOT_FOUND_PUBLIC,
            error_code=_CERT_NOT_FOUND_CODE,
        )

    fields = payload.model_fields_set
    effective_issue = payload.issue_date if "issue_date" in fields else record.issue_date
    effective_expiry = payload.expiry_date if "expiry_date" in fields else record.expiry_date
    try:
        validate_certificate_dates(
            issue_date=effective_issue,
            expiry_date=effective_expiry,
        )
    except ValueError as exc:
        raise ValidationAppError(
            message=str(exc),
            public_message=str(exc),
            details={"field": "expiry_date"},
        ) from None

    if "document_id" in fields:
        if payload.document_id is not None:
            _resolve_owned_documents(
                db,
                user_id=user_id,
                document_ids=[payload.document_id],
                field_name="document_id",
            )
        record.document_id = payload.document_id

    if "skill_ids" in fields and payload.skill_ids is not None:
        resolved_skills = _resolve_owned_skills(
            db,
            user_id=user_id,
            skill_ids=payload.skill_ids,
        )
        record.skill_links.clear()
        db.flush()
        for skill in resolved_skills:
            record.skill_links.append(CertificateSkill(skill_id=skill.id))

    if "name" in fields and payload.name is not None:
        record.name = payload.name
    if "issuer" in fields and payload.issuer is not None:
        record.issuer = payload.issuer
    if "category" in fields and payload.category is not None:
        record.category = payload.category
    if "issue_date" in fields:
        record.issue_date = payload.issue_date
    if "expiry_date" in fields:
        record.expiry_date = payload.expiry_date
    if "credential_id" in fields:
        record.credential_id = payload.credential_id
    if "verification_url" in fields:
        record.verification_url = payload.verification_url
        record.verification_status = compute_verification_status(payload.verification_url)
    if "featured" in fields and payload.featured is not None:
        record.featured = payload.featured
    if "order" in fields and payload.order is not None:
        record.display_order = payload.order
    if "visibility" in fields and payload.visibility is not None:
        record.visibility = payload.visibility

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        _handle_certificate_integrity_error(exc)

    return get_certificate_by_id(db, user_id=user_id, certificate_id=record.id)


def delete_certificate(
    db: Session,
    *,
    user_id: uuid.UUID,
    certificate_id: uuid.UUID,
) -> None:
    """Delete an owned certificate (evidence document in Vault is preserved)."""
    record = db.execute(
        select(Certificate).where(
            Certificate.id == certificate_id,
            Certificate.user_id == user_id,
        )
    ).scalar_one_or_none()
    if record is None:
        raise ResourceNotFoundError(
            message=_CERT_NOT_FOUND_MESSAGE,
            public_message=_CERT_NOT_FOUND_PUBLIC,
            error_code=_CERT_NOT_FOUND_CODE,
        )
    db.delete(record)
    db.commit()


def list_public_certificates(
    db: Session,
    *,
    user_id: uuid.UUID,
    limit: int = 100,
) -> list[Certificate]:
    """Return strictly public certificates ordered by featured, display_order, and recency."""
    return list(
        db.execute(
            select(Certificate)
            .options(*_certificate_load_options())
            .where(
                Certificate.user_id == user_id,
                Certificate.visibility == "public",
            )
            .order_by(*_certificate_order_by())
            .limit(limit)
        )
        .scalars()
        .all()
    )


# ---------------------------------------------------------------------------
# Achievements CRUD
# ---------------------------------------------------------------------------


def list_achievements(
    db: Session,
    *,
    user_id: uuid.UUID,
    page: int = 1,
    page_size: int = 100,
    q: str | None = None,
    category: str | None = None,
    visibility: CredentialVisibility | None = None,
    featured: bool | None = None,
) -> tuple[list[Achievement], int, int]:
    """List paginated achievements owned by user_id."""
    filters: list[Any] = [Achievement.user_id == user_id]
    if visibility is not None:
        filters.append(Achievement.visibility == visibility)
    if category is not None and category.strip():
        filters.append(Achievement.category == category.strip().lower())
    if featured is not None:
        filters.append(Achievement.featured.is_(featured))
    if q is not None and q.strip():
        term = f"%{q.strip()}%"
        filters.append(
            or_(
                Achievement.title.ilike(term),
                Achievement.organization.ilike(term),
                Achievement.description.ilike(term),
            )
        )

    total = int(
        db.execute(select(func.count(Achievement.id)).where(*filters)).scalar_one()
    )
    total_pages = max(1, math.ceil(total / page_size)) if total > 0 else 1
    offset = (page - 1) * page_size
    if total == 0 or offset >= total:
        return [], total, total_pages

    items = list(
        db.execute(
            select(Achievement)
            .options(_achievement_load_options())
            .where(*filters)
            .order_by(*_achievement_order_by())
            .offset(offset)
            .limit(page_size)
        )
        .scalars()
        .all()
    )
    return items, total, total_pages


def get_achievement_by_id(
    db: Session,
    *,
    user_id: uuid.UUID,
    achievement_id: uuid.UUID,
) -> Achievement:
    """Fetch a single achievement owned by user_id or raise 404."""
    record = _load_achievement(db, user_id=user_id, achievement_id=achievement_id)
    if record is None:
        raise ResourceNotFoundError(
            message=_ACH_NOT_FOUND_MESSAGE,
            public_message=_ACH_NOT_FOUND_PUBLIC,
            error_code=_ACH_NOT_FOUND_CODE,
        )
    return record


def create_achievement(
    db: Session,
    *,
    user_id: uuid.UUID,
    payload: AchievementCreate,
) -> Achievement:
    """Create an achievement owned by user_id with optional validated evidence documents."""
    ordered_docs = _resolve_owned_documents(
        db,
        user_id=user_id,
        document_ids=payload.document_ids,
        field_name="document_ids",
    )

    record = Achievement(
        user_id=user_id,
        title=payload.title,
        category=payload.category,
        organization=payload.organization,
        date=payload.date,
        description=payload.description,
        featured=payload.featured,
        display_order=payload.order,
        visibility=payload.visibility,
    )
    for idx, doc in enumerate(ordered_docs):
        record.document_links.append(
            AchievementDocument(document_id=doc.id, display_order=idx)
        )

    db.add(record)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        _handle_achievement_integrity_error(exc)

    return get_achievement_by_id(db, user_id=user_id, achievement_id=record.id)


def update_achievement(
    db: Session,
    *,
    user_id: uuid.UUID,
    achievement_id: uuid.UUID,
    payload: AchievementUpdate,
) -> Achievement:
    """Partially update an owned achievement without overwriting omitted fields."""
    record = _load_achievement(db, user_id=user_id, achievement_id=achievement_id)
    if record is None:
        raise ResourceNotFoundError(
            message=_ACH_NOT_FOUND_MESSAGE,
            public_message=_ACH_NOT_FOUND_PUBLIC,
            error_code=_ACH_NOT_FOUND_CODE,
        )

    fields = payload.model_fields_set

    if "document_ids" in fields and payload.document_ids is not None:
        ordered_docs = _resolve_owned_documents(
            db,
            user_id=user_id,
            document_ids=payload.document_ids,
            field_name="document_ids",
        )
        record.document_links.clear()
        db.flush()
        for idx, doc in enumerate(ordered_docs):
            record.document_links.append(
                AchievementDocument(document_id=doc.id, display_order=idx)
            )

    if "title" in fields and payload.title is not None:
        record.title = payload.title
    if "category" in fields and payload.category is not None:
        record.category = payload.category
    if "organization" in fields:
        record.organization = payload.organization
    if "date" in fields:
        record.date = payload.date
    if "description" in fields:
        record.description = payload.description
    if "featured" in fields and payload.featured is not None:
        record.featured = payload.featured
    if "order" in fields and payload.order is not None:
        record.display_order = payload.order
    if "visibility" in fields and payload.visibility is not None:
        record.visibility = payload.visibility

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        _handle_achievement_integrity_error(exc)

    return get_achievement_by_id(db, user_id=user_id, achievement_id=record.id)


def delete_achievement(
    db: Session,
    *,
    user_id: uuid.UUID,
    achievement_id: uuid.UUID,
) -> None:
    """Delete an owned achievement (evidence documents in Vault are preserved)."""
    record = db.execute(
        select(Achievement).where(
            Achievement.id == achievement_id,
            Achievement.user_id == user_id,
        )
    ).scalar_one_or_none()
    if record is None:
        raise ResourceNotFoundError(
            message=_ACH_NOT_FOUND_MESSAGE,
            public_message=_ACH_NOT_FOUND_PUBLIC,
            error_code=_ACH_NOT_FOUND_CODE,
        )
    db.delete(record)
    db.commit()


def list_public_achievements(
    db: Session,
    *,
    user_id: uuid.UUID,
    limit: int = 100,
) -> list[Achievement]:
    """Return strictly public achievements ordered by featured, display_order, and recency."""
    return list(
        db.execute(
            select(Achievement)
            .options(_achievement_load_options())
            .where(
                Achievement.user_id == user_id,
                Achievement.visibility == "public",
            )
            .order_by(*_achievement_order_by())
            .limit(limit)
        )
        .scalars()
        .all()
    )
