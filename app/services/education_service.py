"""Phase 2 synchronous Education CRUD, canonical sorting, and ownership service."""

import logging
import math
from typing import Any
import uuid

from fastapi import status
from sqlalchemy import case, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core.exceptions import (
    AppException,
    ResourceNotFoundError,
    ValidationAppError,
)
from app.models.document import Document, EducationDocument
from app.models.education import Education
from app.schemas.education import (
    EducationCreate,
    EducationUpdate,
    validate_education_dates,
    validate_education_result,
)
from app.services.auth_service import get_constraint_name

logger = logging.getLogger("folio360.education.service")

_NOT_FOUND_MESSAGE = "Education record not found"
_NOT_FOUND_PUBLIC = "Education record not found."
_NOT_FOUND_CODE = "EDUCATION_NOT_FOUND"


def _education_load_options():
    return selectinload(Education.document_links).selectinload(
        EducationDocument.document
    )


def _resolve_owned_documents(
    db: Session,
    *,
    user_id: uuid.UUID,
    document_ids: list[uuid.UUID],
) -> list[Document]:
    """Verify all referenced documents exist and belong to user_id."""
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
            details={"field": "document_ids"},
            error_code="INVALID_REFERENCE",
        )
    ordered_docs = [by_id[doc_id] for doc_id in document_ids]
    for doc in ordered_docs:
        if doc.processing_status != "ready" or doc.storage_state != "trusted":
            raise ValidationAppError(
                message="Document is not ready for attachment",
                public_message="Only scanned and verified documents can be attached to education records.",
                details={"field": "document_ids"},
                error_code="DOCUMENT_NOT_READY",
            )
    return ordered_docs


def _load_education_with_documents(
    db: Session,
    *,
    user_id: uuid.UUID,
    education_id: uuid.UUID,
) -> Education | None:
    stmt = (
        select(Education)
        .options(_education_load_options())
        .where(
            Education.id == education_id,
            Education.user_id == user_id,
        )
    )
    return db.execute(stmt).scalar_one_or_none()


def _canonical_order_by() -> tuple[Any, ...]:
    """
    Canonical education sort order:
      1. Ongoing education first (is_current=True).
      2. Ongoing records: latest start date first.
      3. Completed records: latest end date first.
      4. Missing end date falls back to start date.
      5. Deterministic tie-breakers (start date, created_at desc, id desc).
    """
    primary_year = case(
        (Education.is_current.is_(True), Education.start_year),
        else_=func.coalesce(Education.end_year, Education.start_year),
    )
    primary_month = case(
        (Education.is_current.is_(True), Education.start_month),
        (Education.end_year.is_not(None), Education.end_month),
        else_=Education.start_month,
    )
    return (
        Education.is_current.desc(),
        primary_year.desc().nulls_last(),
        primary_month.desc().nulls_last(),
        Education.start_year.desc().nulls_last(),
        Education.start_month.desc().nulls_last(),
        Education.created_at.desc(),
        Education.id.desc(),
    )


def list_educations(
    db: Session,
    *,
    user_id: uuid.UUID,
    page: int,
    page_size: int,
) -> tuple[list[Education], int, int]:
    """Return a canonically sorted page of the authenticated user's education records."""
    total = int(
        db.execute(
            select(func.count(Education.id)).where(Education.user_id == user_id)
        ).scalar_one()
    )
    total_pages = math.ceil(total / page_size) if total > 0 else 0
    offset = (page - 1) * page_size

    if total == 0 or offset >= total:
        return [], total, total_pages

    stmt = (
        select(Education)
        .options(_education_load_options())
        .where(Education.user_id == user_id)
        .order_by(*_canonical_order_by())
        .offset(offset)
        .limit(page_size)
    )
    items = list(db.execute(stmt).scalars().all())
    return items, total, total_pages


def get_education_by_id(
    db: Session,
    *,
    user_id: uuid.UUID,
    education_id: uuid.UUID,
) -> Education:
    """Retrieve one education record owned by user_id or raise 404 EDUCATION_NOT_FOUND."""
    record = _load_education_with_documents(
        db,
        user_id=user_id,
        education_id=education_id,
    )
    if record is None:
        raise ResourceNotFoundError(
            message=_NOT_FOUND_MESSAGE,
            public_message=_NOT_FOUND_PUBLIC,
            error_code=_NOT_FOUND_CODE,
        )
    return record


def create_education(
    db: Session,
    *,
    user_id: uuid.UUID,
    payload: EducationCreate,
) -> Education:
    """Create a new education record owned by the authenticated user with optional document links."""
    owned_docs = _resolve_owned_documents(
        db,
        user_id=user_id,
        document_ids=payload.document_ids,
    )
    record = Education(
        id=uuid.uuid4(),
        user_id=user_id,
        institution=payload.institution,
        university_or_board=payload.university_or_board,
        education_level=payload.education_level,
        degree=payload.degree,
        programme=payload.programme,
        branch=payload.branch,
        specialization=payload.specialization,
        country=payload.country,
        state=payload.state,
        start_month=payload.start_month,
        start_year=payload.start_year,
        end_month=payload.end_month,
        end_year=payload.end_year,
        is_current=payload.is_current,
        description=payload.description,
        scheme_id=payload.scheme_id,
        result_type=payload.result_type,
        result_value=payload.result_value,
        result_source="manual",
        computed_cgpa=None,
        show_result_publicly=payload.show_result_publicly,
        achievements=list(payload.achievements),
        visibility=payload.visibility,
    )
    for idx, doc in enumerate(owned_docs):
        record.document_links.append(
            EducationDocument(
                document_id=doc.id,
                display_order=idx,
            )
        )
    db.add(record)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        constraint = get_constraint_name(exc)
        logger.error(
            "Unexpected database constraint violation during education create: constraint=%s",
            constraint or "unknown",
        )
        raise AppException(
            message=f"Education creation integrity failure: {constraint}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        ) from None

    loaded = _load_education_with_documents(
        db,
        user_id=user_id,
        education_id=record.id,
    )
    if loaded is None:
        raise AppException(
            message="Education record disappeared immediately after commit",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    return loaded


def update_education(
    db: Session,
    *,
    user_id: uuid.UUID,
    education_id: uuid.UUID,
    payload: EducationUpdate,
) -> Education:
    """Partially update an education record owned by user_id with merged invariant checks."""
    record = db.execute(
        select(Education)
        .options(selectinload(Education.document_links))
        .where(
            Education.id == education_id,
            Education.user_id == user_id,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if record is None:
        raise ResourceNotFoundError(
            message=_NOT_FOUND_MESSAGE,
            public_message=_NOT_FOUND_PUBLIC,
            error_code=_NOT_FOUND_CODE,
        )

    fields = payload.model_fields_set

    merged_start_month = payload.start_month if "start_month" in fields else record.start_month
    merged_start_year = payload.start_year if "start_year" in fields else record.start_year
    merged_end_month = payload.end_month if "end_month" in fields else record.end_month
    merged_end_year = payload.end_year if "end_year" in fields else record.end_year
    merged_is_current = (
        bool(payload.is_current) if "is_current" in fields else record.is_current
    )
    merged_result_type = payload.result_type if "result_type" in fields else record.result_type
    merged_result_value = payload.result_value if "result_value" in fields else record.result_value

    try:
        validate_education_dates(
            start_month=merged_start_month,
            start_year=merged_start_year,
            end_month=merged_end_month,
            end_year=merged_end_year,
            is_current=merged_is_current,
        )
        validate_education_result(
            result_type=merged_result_type,
            result_value=merged_result_value,
        )
    except ValueError as exc:
        db.rollback()
        raise ValidationAppError(
            message="Invalid merged education state",
            public_message=str(exc),
            error_code="VALIDATION_ERROR",
        ) from None

    owned_docs: list[Document] | None = None
    if "document_ids" in fields:
        try:
            owned_docs = _resolve_owned_documents(
                db,
                user_id=user_id,
                document_ids=payload.document_ids or [],
            )
        except ValidationAppError:
            db.rollback()
            raise

    scalar_fields = (
        "institution",
        "university_or_board",
        "education_level",
        "degree",
        "programme",
        "branch",
        "specialization",
        "country",
        "state",
        "start_month",
        "start_year",
        "end_month",
        "end_year",
        "is_current",
        "description",
        "scheme_id",
        "result_type",
        "result_value",
        "show_result_publicly",
        "visibility",
    )
    for field_name in scalar_fields:
        if field_name in fields:
            setattr(record, field_name, getattr(payload, field_name))

    if "achievements" in fields and payload.achievements is not None:
        record.achievements = list(payload.achievements)

    if owned_docs is not None:
        record.document_links.clear()
        db.flush()
        for idx, doc in enumerate(owned_docs):
            record.document_links.append(
                EducationDocument(
                    document_id=doc.id,
                    display_order=idx,
                )
            )

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        constraint = get_constraint_name(exc)
        logger.error(
            "Unexpected database constraint violation during education update: constraint=%s",
            constraint or "unknown",
        )
        raise AppException(
            message=f"Education update integrity failure: {constraint}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        ) from None

    loaded = _load_education_with_documents(
        db,
        user_id=user_id,
        education_id=education_id,
    )
    if loaded is None:
        raise ResourceNotFoundError(
            message=_NOT_FOUND_MESSAGE,
            public_message=_NOT_FOUND_PUBLIC,
            error_code=_NOT_FOUND_CODE,
        )
    return loaded


def delete_education(
    db: Session,
    *,
    user_id: uuid.UUID,
    education_id: uuid.UUID,
) -> None:
    """Delete an education record owned by user_id or raise 404 EDUCATION_NOT_FOUND."""
    record = db.execute(
        select(Education)
        .where(
            Education.id == education_id,
            Education.user_id == user_id,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if record is None:
        raise ResourceNotFoundError(
            message=_NOT_FOUND_MESSAGE,
            public_message=_NOT_FOUND_PUBLIC,
            error_code=_NOT_FOUND_CODE,
        )

    db.delete(record)
    db.commit()
