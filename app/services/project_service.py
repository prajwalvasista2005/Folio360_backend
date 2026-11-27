"""Phase 3 synchronous Projects Portfolio CRUD, cover image storage, and public filtering."""

from datetime import datetime, timedelta, timezone
import math
from urllib.parse import quote
import uuid

from fastapi import UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.core.config import Settings, normalize_api_v1_prefix
from app.core.exceptions import (
    AppException,
    ResourceNotFoundError,
    ValidationAppError,
)
from app.models.project import Project, ProjectImage
from app.schemas.project import (
    ProjectCreate,
    ProjectImageUpdate,
    ProjectUpdate,
    validate_project_dates,
)
from app.services.file_validation import sniff_and_validate_project_image_bytes
from app.services.storage_service import (
    build_storage_backend,
    generate_scoped_content_token,
    verify_scoped_content_token,
)

PROJECT_IMAGE_NAMESPACE = "project_images"
PROJECT_IMAGE_TOKEN_SCOPE = "project_image"
PROJECT_IMAGE_URL_TTL_SECONDS = 3600


def _project_load_options():
    return selectinload(Project.images)


def _load_owned_project(
    db: Session,
    *,
    user_id: uuid.UUID,
    project_id: uuid.UUID,
) -> Project:
    stmt = (
        select(Project)
        .options(_project_load_options())
        .where(Project.id == project_id, Project.user_id == user_id)
    )
    record = db.execute(stmt).scalar_one_or_none()
    if record is None:
        raise ResourceNotFoundError(
            message="Project not found",
            public_message="Project not found.",
            error_code="PROJECT_NOT_FOUND",
        )
    return record


def build_project_image_url(
    image: ProjectImage,
    *,
    is_public_project: bool,
    settings: Settings,
) -> str:
    """Build a relative API content URL (signed for private projects, direct for public)."""
    prefix = normalize_api_v1_prefix(settings.API_V1_PREFIX)
    base_url = f"{prefix}/projects/{image.project_id}/images/{image.id}/content"
    if is_public_project:
        return base_url
    expires_at_ts = int((datetime.now(timezone.utc) + timedelta(seconds=PROJECT_IMAGE_URL_TTL_SECONDS)).timestamp())
    token = generate_scoped_content_token(
        scope=PROJECT_IMAGE_TOKEN_SCOPE,
        resource_id=image.id,
        expires_at_ts=expires_at_ts,
        settings=settings,
    )
    return f"{base_url}?token={quote(token, safe='.')}"


def list_projects(
    db: Session,
    *,
    user_id: uuid.UUID,
    page: int = 1,
    page_size: int = 100,
    visibility: str | None = None,
    category: str | None = None,
    q: str | None = None,
) -> tuple[list[Project], int, int]:
    """List owned projects ordered by featured desc, display_order asc, updated_at desc."""
    filters = [Project.user_id == user_id]
    if visibility in {"private", "public"}:
        filters.append(Project.visibility == visibility)
    if category and category.strip():
        filters.append(func.lower(Project.category) == category.strip().lower())
    if q and q.strip():
        pattern = f"%{q.strip()}%"
        filters.append(
            Project.title.ilike(pattern)
            | Project.summary.ilike(pattern)
            | Project.category.ilike(pattern)
        )

    total = int(
        db.execute(select(func.count()).select_from(Project).where(*filters)).scalar_one()
    )
    total_pages = max(1, math.ceil(total / page_size)) if total > 0 else 1
    offset = (page - 1) * page_size
    stmt = (
        select(Project)
        .options(_project_load_options())
        .where(*filters)
        .order_by(
            Project.featured.desc(),
            Project.display_order.asc(),
            Project.created_at.desc(),
            Project.id.desc(),
        )
        .offset(offset)
        .limit(page_size)
    )
    items = list(db.execute(stmt).scalars().all())
    return items, total, total_pages


def list_public_projects(
    db: Session,
    *,
    user_id: uuid.UUID,
) -> list[Project]:
    """Return strictly public projects for public profile rendering."""
    stmt = (
        select(Project)
        .options(_project_load_options())
        .where(Project.user_id == user_id, Project.visibility == "public")
        .order_by(
            Project.featured.desc(),
            Project.display_order.asc(),
            Project.created_at.desc(),
        )
    )
    return list(db.execute(stmt).scalars().all())


def create_project(
    db: Session,
    *,
    user_id: uuid.UUID,
    payload: ProjectCreate,
) -> Project:
    """Create a manual portfolio project owned by user_id."""
    record = Project(
        user_id=user_id,
        title=payload.title,
        summary=payload.summary,
        description=payload.description,
        category=payload.category,
        technologies=list(payload.technologies),
        github_url=payload.github_url,
        live_url=payload.live_url,
        start_date=payload.start_date,
        end_date=payload.end_date,
        is_ongoing=payload.is_ongoing,
        featured=payload.featured,
        display_order=payload.order,
        visibility=payload.visibility,
    )
    db.add(record)
    db.commit()
    return _load_owned_project(db, user_id=user_id, project_id=record.id)


def get_project_by_id(
    db: Session,
    *,
    user_id: uuid.UUID,
    project_id: uuid.UUID,
) -> Project:
    """Return a single project owned by user_id."""
    return _load_owned_project(db, user_id=user_id, project_id=project_id)


def update_project(
    db: Session,
    *,
    user_id: uuid.UUID,
    project_id: uuid.UUID,
    payload: ProjectUpdate,
) -> Project:
    """Partially update an owned project while preserving cross-field date invariants."""
    record = _load_owned_project(db, user_id=user_id, project_id=project_id)
    fields_set = payload.model_fields_set

    next_is_ongoing = payload.is_ongoing if "is_ongoing" in fields_set else record.is_ongoing
    assert next_is_ongoing is not None
    next_start_date = payload.start_date if "start_date" in fields_set else record.start_date
    if "is_ongoing" in fields_set and next_is_ongoing and "end_date" not in fields_set:
        next_end_date = None
    else:
        next_end_date = payload.end_date if "end_date" in fields_set else record.end_date

    try:
        validate_project_dates(
            start_date=next_start_date,
            end_date=next_end_date,
            is_ongoing=next_is_ongoing,
        )
    except ValueError as exc:
        raise ValidationAppError(
            message=str(exc),
            public_message=str(exc),
            error_code="VALIDATION_ERROR",
        ) from None

    simple_fields = (
        "title",
        "summary",
        "description",
        "category",
        "technologies",
        "github_url",
        "live_url",
        "featured",
        "visibility",
    )
    for field_name in simple_fields:
        if field_name in fields_set:
            setattr(record, field_name, getattr(payload, field_name))

    if "order" in fields_set and payload.order is not None:
        record.display_order = payload.order
    record.start_date = next_start_date
    record.end_date = next_end_date
    record.is_ongoing = next_is_ongoing

    db.commit()
    return _load_owned_project(db, user_id=user_id, project_id=record.id)


def delete_project(
    db: Session,
    *,
    user_id: uuid.UUID,
    project_id: uuid.UUID,
    settings: Settings,
) -> None:
    """Delete an owned project and clean up any stored cover image blobs."""
    record = _load_owned_project(db, user_id=user_id, project_id=project_id)
    storage_keys = [img.storage_key for img in record.images]
    db.delete(record)
    db.commit()

    if storage_keys:
        backend = build_storage_backend(settings)
        for key in storage_keys:
            backend.delete_object(storage_key=key)


def upload_project_image(
    db: Session,
    *,
    user_id: uuid.UUID,
    project_id: uuid.UUID,
    upload_file: UploadFile,
    alt: str | None,
    settings: Settings,
) -> ProjectImage:
    """Validate and persist a cover/showcase image for an owned project."""
    project = _load_owned_project(db, user_id=user_id, project_id=project_id)
    raw_bytes = upload_file.file.read(settings.PROJECT_IMAGE_MAX_SIZE_BYTES + 1)
    if not raw_bytes:
        raise ValidationAppError(
            message="Uploaded project image is empty",
            public_message="Uploaded image file is empty.",
            error_code="MALFORMED_FILE",
        )
    if len(raw_bytes) > settings.PROJECT_IMAGE_MAX_SIZE_BYTES:
        max_mb = max(1, settings.PROJECT_IMAGE_MAX_SIZE_BYTES // (1024 * 1024))
        raise AppException(
            message="Project image exceeds maximum allowed size",
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            public_message=f"Project image must not exceed {max_mb} MB.",
            error_code="FILE_TOO_LARGE",
        )

    mime_type = sniff_and_validate_project_image_bytes(raw_bytes)
    cleaned_alt = alt.strip()[:255] if alt and alt.strip() else None
    image_id = uuid.uuid4()
    storage_key = f"{PROJECT_IMAGE_NAMESPACE}/{user_id}/{image_id}"
    next_order = max((img.display_order for img in project.images), default=-1) + 1

    backend = build_storage_backend(settings)
    backend.put_object(
        storage_key=storage_key,
        data=raw_bytes,
        content_type=mime_type,
    )

    image = ProjectImage(
        id=image_id,
        project_id=project.id,
        user_id=user_id,
        storage_backend=backend.backend_name,
        storage_key=storage_key,
        mime_type=mime_type,
        size_bytes=len(raw_bytes),
        alt=cleaned_alt,
        display_order=next_order,
    )
    db.add(image)
    try:
        db.commit()
    except Exception:
        backend.delete_object(storage_key=storage_key)
        raise
    db.refresh(image)
    return image


def update_project_image(
    db: Session,
    *,
    user_id: uuid.UUID,
    project_id: uuid.UUID,
    image_id: uuid.UUID,
    payload: ProjectImageUpdate,
) -> ProjectImage:
    """Update alt text or display order for an owned project image."""
    image = db.execute(
        select(ProjectImage).where(
            ProjectImage.id == image_id,
            ProjectImage.project_id == project_id,
            ProjectImage.user_id == user_id,
        )
    ).scalar_one_or_none()
    if image is None:
        raise ResourceNotFoundError(
            message="Project image not found",
            public_message="Project image not found.",
            error_code="NOT_FOUND",
        )
    if "alt" in payload.model_fields_set:
        image.alt = payload.alt
    if "order" in payload.model_fields_set and payload.order is not None:
        image.display_order = payload.order
    db.commit()
    db.refresh(image)
    return image


def delete_project_image(
    db: Session,
    *,
    user_id: uuid.UUID,
    project_id: uuid.UUID,
    image_id: uuid.UUID,
    settings: Settings,
) -> None:
    """Delete an owned project image and remove its stored object."""
    image = db.execute(
        select(ProjectImage).where(
            ProjectImage.id == image_id,
            ProjectImage.project_id == project_id,
            ProjectImage.user_id == user_id,
        )
    ).scalar_one_or_none()
    if image is None:
        raise ResourceNotFoundError(
            message="Project image not found",
            public_message="Project image not found.",
            error_code="NOT_FOUND",
        )
    storage_key = image.storage_key
    db.delete(image)
    db.commit()
    build_storage_backend(settings).delete_object(storage_key=storage_key)


def get_project_image_content(
    db: Session,
    *,
    project_id: uuid.UUID,
    image_id: uuid.UUID,
    token: str | None,
    settings: Settings,
) -> tuple[ProjectImage, bytes]:
    """Read image bytes for public projects directly, or private projects with a valid HMAC token."""
    row = db.execute(
        select(ProjectImage, Project.visibility)
        .join(Project, Project.id == ProjectImage.project_id)
        .where(ProjectImage.id == image_id, ProjectImage.project_id == project_id)
    ).one_or_none()
    if row is None:
        raise ResourceNotFoundError(
            message="Project image not found",
            public_message="Project image not found.",
            error_code="NOT_FOUND",
        )
    image, project_visibility = row
    if project_visibility != "public":
        if not token or not verify_scoped_content_token(
            token,
            scope=PROJECT_IMAGE_TOKEN_SCOPE,
            resource_id=image.id,
            settings=settings,
        ):
            raise AppException(
                message="Invalid or missing project image access token",
                status_code=status.HTTP_403_FORBIDDEN,
                public_message="Invalid or expired project image access token.",
                error_code="FORBIDDEN",
            )
    data = build_storage_backend(settings).read_bytes(storage_key=image.storage_key)
    return image, data
