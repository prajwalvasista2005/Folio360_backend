"""Phase 2 synchronous Education CRUD routes under /api/v1/education."""

import uuid

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.orm import Session

from app.api.deps.auth import get_current_verified_user, rate_limit_dependency
from app.db.session import get_db
from app.models.education import Education
from app.models.user import User
from app.schemas.document import DocumentRef
from app.schemas.education import (
    EducationCreate,
    EducationListResponse,
    EducationResponse,
    EducationUpdate,
)
from app.services import education_service

router = APIRouter(prefix="/education", tags=["Education"])


def _to_education_response(record: Education) -> EducationResponse:
    linked_docs = [
        link.document
        for link in record.document_links
        if link.document is not None
    ]
    return EducationResponse(
        id=record.id,
        user_id=record.user_id,
        institution=record.institution,
        university_or_board=record.university_or_board,
        education_level=record.education_level,
        degree=record.degree,
        programme=record.programme,
        branch=record.branch,
        specialization=record.specialization,
        country=record.country,
        state=record.state,
        start_month=record.start_month,
        start_year=record.start_year,
        end_month=record.end_month,
        end_year=record.end_year,
        is_current=record.is_current,
        description=record.description,
        scheme_id=record.scheme_id,
        result_type=record.result_type,
        result_value=record.result_value,
        result_source=record.result_source,  # type: ignore[arg-type]
        computed_cgpa=(
            float(record.computed_cgpa) if record.computed_cgpa is not None else None
        ),
        show_result_publicly=record.show_result_publicly,
        achievements=list(record.achievements or []),
        document_ids=[doc.id for doc in linked_docs],
        documents=[
            DocumentRef(
                id=doc.id,
                title=doc.title,
                category=doc.category,  # type: ignore[arg-type]
                mime_type=doc.mime_type,  # type: ignore[arg-type]
            )
            for doc in linked_docs
        ],
        visibility=record.visibility,  # type: ignore[arg-type]
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.get(
    "",
    response_model=EducationListResponse,
    status_code=status.HTTP_200_OK,
    summary="List the authenticated user's education records",
)
def list_my_educations(
    page: int = Query(default=1, ge=1, description="1-based page number."),
    page_size: int = Query(
        default=100,
        ge=1,
        le=200,
        description="Number of education records per page (max 200).",
    ),
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> EducationListResponse:
    """List canonically sorted education records owned by the authenticated user."""
    items, total, total_pages = education_service.list_educations(
        db,
        user_id=current_user.id,
        page=page,
        page_size=page_size,
    )
    return EducationListResponse(
        items=[_to_education_response(item) for item in items],
        page=page,
        page_size=page_size,
        total=total,
        total_pages=total_pages,
    )


@router.post(
    "",
    response_model=EducationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            rate_limit_dependency(
                "education:create",
                limit=30,
                window_seconds=900,
            )
        )
    ],
    summary="Create an education record for the authenticated user",
)
def create_my_education(
    payload: EducationCreate,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> EducationResponse:
    """Create a new education record scoped to the authenticated user."""
    record = education_service.create_education(
        db,
        user_id=current_user.id,
        payload=payload,
    )
    return _to_education_response(record)


@router.get(
    "/{education_id}",
    response_model=EducationResponse,
    status_code=status.HTTP_200_OK,
    summary="Get one education record owned by the authenticated user",
)
def get_my_education(
    education_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> EducationResponse:
    """Return a single education record owned by the authenticated user."""
    record = education_service.get_education_by_id(
        db,
        user_id=current_user.id,
        education_id=education_id,
    )
    return _to_education_response(record)


@router.patch(
    "/{education_id}",
    response_model=EducationResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            rate_limit_dependency(
                "education:update",
                limit=60,
                window_seconds=900,
            )
        )
    ],
    summary="Partially update an education record owned by the authenticated user",
)
def update_my_education(
    education_id: uuid.UUID,
    payload: EducationUpdate,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> EducationResponse:
    """Partially update an owned education record without overwriting omitted fields."""
    record = education_service.update_education(
        db,
        user_id=current_user.id,
        education_id=education_id,
        payload=payload,
    )
    return _to_education_response(record)


@router.delete(
    "/{education_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(
            rate_limit_dependency(
                "education:delete",
                limit=30,
                window_seconds=900,
            )
        )
    ],
    summary="Delete an education record owned by the authenticated user",
)
def delete_my_education(
    education_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> Response:
    """Delete an owned education record and return 204 No Content."""
    education_service.delete_education(
        db,
        user_id=current_user.id,
        education_id=education_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
