"""Synchronous Experience CRUD, Skill & Document Vault linking, and ownership service."""

import logging
import math
from typing import Any
import uuid

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core.exceptions import ResourceNotFoundError, ValidationAppError
from app.models.document import Document
from app.models.experience import Experience, ExperienceDocument, ExperienceSkill
from app.models.skill import Skill
from app.schemas.experience import (
    ExperienceCreate,
    ExperienceType,
    ExperienceUpdate,
    ExperienceVisibility,
    validate_experience_dates,
)
from app.services.auth_service import get_constraint_name

logger = logging.getLogger("folio360.experience.service")

_EXP_NOT_FOUND_MESSAGE = "Experience not found"
_EXP_NOT_FOUND_PUBLIC = "Experience record not found."
_EXP_NOT_FOUND_CODE = "EXPERIENCE_NOT_FOUND"


def _experience_load_options() -> tuple[Any, ...]:
    return (
        selectinload(Experience.skill_links).selectinload(ExperienceSkill.skill),
        selectinload(Experience.document_links).selectinload(ExperienceDocument.document),
    )


def _resolve_owned_skills(
    db: Session,
    *,
    user_id: uuid.UUID,
    skill_ids: list[uuid.UUID],
) -> list[uuid.UUID]:
    if not skill_ids:
        return []
    rows = db.execute(
        select(Skill.id).where(Skill.user_id == user_id, Skill.id.in_(skill_ids))
    ).scalars().all()
    owned = set(rows)
    missing = [str(sid) for sid in skill_ids if sid not in owned]
    if missing:
        raise ValidationAppError(
            message="One or more selected skills do not exist for the user",
            public_message="One or more selected skills were not found in your workspace.",
            details={"missing_skill_ids": missing},
            error_code="EXPERIENCE_SKILL_INVALID",
        )
    return skill_ids


def _resolve_owned_documents(
    db: Session,
    *,
    user_id: uuid.UUID,
    document_ids: list[uuid.UUID],
) -> list[uuid.UUID]:
    if not document_ids:
        return []
    rows = db.execute(
        select(Document.id).where(
            Document.user_id == user_id,
            Document.id.in_(document_ids),
        )
    ).scalars().all()
    owned = set(rows)
    missing = [str(did) for did in document_ids if did not in owned]
    if missing:
        raise ValidationAppError(
            message="One or more selected documents do not exist for the user",
            public_message="One or more selected documents were not found in your Document Vault.",
            details={"missing_document_ids": missing},
            error_code="EXPERIENCE_DOCUMENT_INVALID",
        )
    return document_ids


def _replace_skill_links(
    db: Session,
    *,
    record: Experience,
    skill_ids: list[uuid.UUID],
) -> None:
    db.query(ExperienceSkill).filter(
        ExperienceSkill.experience_id == record.id
    ).delete(synchronize_session=False)
    for sid in skill_ids:
        db.add(ExperienceSkill(experience_id=record.id, skill_id=sid))


def _replace_document_links(
    db: Session,
    *,
    record: Experience,
    document_ids: list[uuid.UUID],
) -> None:
    db.query(ExperienceDocument).filter(
        ExperienceDocument.experience_id == record.id
    ).delete(synchronize_session=False)
    for idx, doc_id in enumerate(document_ids):
        db.add(
            ExperienceDocument(
                experience_id=record.id,
                document_id=doc_id,
                display_order=idx,
            )
        )


def _handle_integrity_error(db: Session, exc: IntegrityError) -> None:
    db.rollback()
    constraint = get_constraint_name(exc) or ""
    if "date_order" in constraint:
        raise ValidationAppError(
            message="Experience date order constraint failed",
            public_message="End date cannot be earlier than start date.",
            error_code="EXPERIENCE_DATE_INVALID",
        ) from exc
    if "current_no_end_date" in constraint:
        raise ValidationAppError(
            message="Current experience cannot have an end_date",
            public_message="A current role cannot also specify an end date.",
            error_code="EXPERIENCE_CURRENT_END_DATE",
        ) from exc
    raise ValidationAppError(
        message="Experience payload failed database validation",
        public_message="Invalid experience details provided.",
        details={"constraint": constraint} if constraint else None,
        error_code="EXPERIENCE_INVALID_INPUT",
    ) from exc


def get_owned_experience(
    db: Session,
    *,
    experience_id: uuid.UUID,
    user_id: uuid.UUID,
) -> Experience:
    """Return an owned Experience record with skills and documents eager-loaded."""
    record = db.execute(
        select(Experience)
        .options(*_experience_load_options())
        .execution_options(populate_existing=True)
        .where(Experience.id == experience_id, Experience.user_id == user_id)
    ).scalar_one_or_none()
    if record is None:
        raise ResourceNotFoundError(
            message=_EXP_NOT_FOUND_MESSAGE,
            public_message=_EXP_NOT_FOUND_PUBLIC,
            error_code=_EXP_NOT_FOUND_CODE,
        )
    return record


def list_experiences(
    db: Session,
    *,
    user_id: uuid.UUID,
    experience_type: ExperienceType | None = None,
    visibility: ExperienceVisibility | None = None,
    featured: bool | None = None,
    query_text: str | None = None,
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[Experience], int, int]:
    """List paginated Experience entries for a user with optional filters."""
    conditions = [Experience.user_id == user_id]
    if experience_type is not None:
        conditions.append(Experience.type == experience_type)
    if visibility is not None:
        conditions.append(Experience.visibility == visibility)
    if featured is not None:
        conditions.append(Experience.featured == featured)
    if query_text:
        pattern = f"%{query_text.strip()}%"
        conditions.append(
            or_(
                Experience.role.ilike(pattern),
                Experience.organization.ilike(pattern),
                Experience.location.ilike(pattern),
                Experience.description.ilike(pattern),
            )
        )

    total = int(
        db.execute(select(func.count(Experience.id)).where(*conditions)).scalar_one()
    )
    total_pages = math.ceil(total / page_size) if total > 0 else 0
    offset = (page - 1) * page_size
    if total == 0 or offset >= total:
        return [], total, total_pages

    stmt = (
        select(Experience)
        .options(*_experience_load_options())
        .where(*conditions)
        .order_by(
            Experience.featured.desc(),
            Experience.is_current.desc(),
            Experience.display_order.asc(),
            Experience.start_date.desc(),
            Experience.created_at.desc(),
            Experience.id.asc(),
        )
        .offset(offset)
        .limit(page_size)
    )
    items = list(db.execute(stmt).scalars().all())
    return items, total, total_pages


def list_public_experiences(db: Session, *, user_id: uuid.UUID) -> list[Experience]:
    """Return public Experience records ordered for the user's public portfolio."""
    stmt = (
        select(Experience)
        .options(*_experience_load_options())
        .where(
            Experience.user_id == user_id,
            Experience.visibility == "public",
        )
        .order_by(
            Experience.featured.desc(),
            Experience.is_current.desc(),
            Experience.display_order.asc(),
            Experience.start_date.desc(),
            Experience.created_at.desc(),
            Experience.id.asc(),
        )
    )
    return list(db.execute(stmt).scalars().all())


def create_experience(
    db: Session,
    *,
    user_id: uuid.UUID,
    payload: ExperienceCreate,
) -> Experience:
    """Create a user-owned Experience record with Skill and Document Vault links."""
    skill_ids = _resolve_owned_skills(db, user_id=user_id, skill_ids=payload.skill_ids)
    document_ids = _resolve_owned_documents(
        db,
        user_id=user_id,
        document_ids=payload.document_ids,
    )

    record = Experience(
        user_id=user_id,
        type=payload.type,
        organization=payload.organization,
        role=payload.role,
        location=payload.location,
        is_remote=payload.is_remote,
        organization_url=payload.organization_url,
        start_date=payload.start_date,
        end_date=payload.end_date,
        is_current=payload.is_current,
        description=payload.description,
        highlights=payload.highlights,
        featured=payload.featured,
        display_order=payload.order,
        visibility=payload.visibility,
    )
    db.add(record)
    try:
        db.flush()
        for sid in skill_ids:
            db.add(ExperienceSkill(experience_id=record.id, skill_id=sid))
        for idx, doc_id in enumerate(document_ids):
            db.add(
                ExperienceDocument(
                    experience_id=record.id,
                    document_id=doc_id,
                    display_order=idx,
                )
            )
        db.commit()
    except IntegrityError as exc:
        _handle_integrity_error(db, exc)

    logger.info("Created experience %s for user %s", record.id, user_id)
    return get_owned_experience(db, experience_id=record.id, user_id=user_id)


def update_experience(
    db: Session,
    *,
    experience_id: uuid.UUID,
    user_id: uuid.UUID,
    payload: ExperienceUpdate,
) -> Experience:
    """Partially update an owned Experience record."""
    record = get_owned_experience(db, experience_id=experience_id, user_id=user_id)
    fields = payload.model_fields_set

    next_start_date = payload.start_date if "start_date" in fields else record.start_date
    next_is_current = payload.is_current if "is_current" in fields else record.is_current
    if "end_date" in fields:
        next_end_date = payload.end_date
    elif "is_current" in fields and payload.is_current is True:
        # Marking an existing experience as current automatically clears any previous end_date.
        next_end_date = None
    else:
        next_end_date = record.end_date

    if next_start_date is None:
        raise ValidationAppError(
            message="start_date cannot be null",
            public_message="Start date is required.",
            error_code="EXPERIENCE_DATE_INVALID",
        )

    try:
        validate_experience_dates(
            start_date=next_start_date,
            end_date=next_end_date,
            is_current=bool(next_is_current),
        )
    except ValueError as exc:
        raise ValidationAppError(
            message=str(exc),
            public_message=str(exc),
            error_code="EXPERIENCE_DATE_INVALID",
        ) from exc

    skill_ids: list[uuid.UUID] | None = None
    if "skill_ids" in fields:
        skill_ids = _resolve_owned_skills(
            db,
            user_id=user_id,
            skill_ids=payload.skill_ids or [],
        )

    document_ids: list[uuid.UUID] | None = None
    if "document_ids" in fields:
        document_ids = _resolve_owned_documents(
            db,
            user_id=user_id,
            document_ids=payload.document_ids or [],
        )

    if "type" in fields and payload.type is not None:
        record.type = payload.type
    if "organization" in fields and payload.organization is not None:
        record.organization = payload.organization
    if "role" in fields and payload.role is not None:
        record.role = payload.role
    if "location" in fields:
        record.location = payload.location
    if "is_remote" in fields and payload.is_remote is not None:
        record.is_remote = payload.is_remote
    if "organization_url" in fields:
        record.organization_url = payload.organization_url
    record.start_date = next_start_date
    record.end_date = next_end_date
    record.is_current = bool(next_is_current)
    if "description" in fields:
        record.description = payload.description
    if "highlights" in fields and payload.highlights is not None:
        record.highlights = payload.highlights
    if "featured" in fields and payload.featured is not None:
        record.featured = payload.featured
    if "order" in fields and payload.order is not None:
        record.display_order = payload.order
    if "visibility" in fields and payload.visibility is not None:
        record.visibility = payload.visibility

    try:
        db.flush()
        if skill_ids is not None:
            _replace_skill_links(db, record=record, skill_ids=skill_ids)
        if document_ids is not None:
            _replace_document_links(db, record=record, document_ids=document_ids)
        db.commit()
        db.expire_all()
    except IntegrityError as exc:
        _handle_integrity_error(db, exc)

    logger.info("Updated experience %s for user %s", record.id, user_id)
    return get_owned_experience(db, experience_id=record.id, user_id=user_id)


def delete_experience(
    db: Session,
    *,
    experience_id: uuid.UUID,
    user_id: uuid.UUID,
) -> None:
    """Delete an owned Experience record without deleting linked Vault documents."""
    record = get_owned_experience(db, experience_id=experience_id, user_id=user_id)
    db.delete(record)
    db.commit()
    logger.info("Deleted experience %s for user %s", experience_id, user_id)
