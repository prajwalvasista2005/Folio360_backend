"""Phase 3 synchronous Projects Portfolio routes under /api/v1/projects."""

import uuid

from fastapi import APIRouter, Depends, File, Form, Query, Response, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps.auth import (
    get_current_settings,
    get_current_verified_user,
    rate_limit_dependency,
)
from app.core.config import Settings
from app.db.session import get_db
from app.models.project import Project, ProjectImage
from app.models.user import User
from app.schemas.project import (
    ProjectCreate,
    ProjectGitHubImportMeta,
    ProjectImageResponse,
    ProjectImageUpdate,
    ProjectListResponse,
    ProjectResponse,
    ProjectUpdate,
    ProjectVisibility,
)
from app.services import project_service

router = APIRouter(prefix="/projects", tags=["Projects"])


def to_project_image_response(
    image: ProjectImage,
    *,
    is_public_project: bool,
    settings: Settings,
) -> ProjectImageResponse:
    """Serialize a ProjectImage ORM record with its resolved content URL."""
    return ProjectImageResponse(
        id=image.id,
        url=project_service.build_project_image_url(
            image,
            is_public_project=is_public_project,
            settings=settings,
        ),
        alt=image.alt,
        order=image.display_order,
    )


def to_project_response(record: Project, *, settings: Settings) -> ProjectResponse:
    """Serialize a Project ORM record to ProjectResponse."""
    is_public = record.visibility == "public"
    github_import = (
        ProjectGitHubImportMeta(
            repo_full_name=record.github_repo_full_name,
            imported_at=record.github_imported_at,
        )
        if record.github_repo_full_name and record.github_imported_at
        else None
    )
    return ProjectResponse(
        id=record.id,
        title=record.title,
        summary=record.summary,
        description=record.description,
        category=record.category,
        technologies=list(record.technologies or []),
        github_url=record.github_url,
        live_url=record.live_url,
        start_date=record.start_date,
        end_date=record.end_date,
        is_ongoing=record.is_ongoing,
        featured=record.featured,
        order=record.display_order,
        visibility=record.visibility,  # type: ignore[arg-type]
        images=[
            to_project_image_response(img, is_public_project=is_public, settings=settings)
            for img in record.images
        ],
        skills=[],
        report_document=None,
        github_import=github_import,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.get(
    "",
    response_model=ProjectListResponse,
    status_code=status.HTTP_200_OK,
    summary="List projects owned by the authenticated user",
)
def list_my_projects(
    page: int = Query(default=1, ge=1, description="1-based page number."),
    page_size: int = Query(default=100, ge=1, le=200, description="Items per page."),
    visibility: ProjectVisibility | None = Query(default=None),
    category: str | None = Query(default=None, max_length=80),
    q: str | None = Query(default=None, max_length=120),
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> ProjectListResponse:
    """List projects scoped to the authenticated owner."""
    items, total, total_pages = project_service.list_projects(
        db,
        user_id=current_user.id,
        page=page,
        page_size=page_size,
        visibility=visibility,
        category=category,
        q=q,
    )
    return ProjectListResponse(
        items=[to_project_response(item, settings=settings) for item in items],
        page=page,
        page_size=page_size,
        total=total,
        total_pages=total_pages,
    )


@router.post(
    "",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(rate_limit_dependency("projects:create", limit=30, window_seconds=900))
    ],
    summary="Create a manual portfolio project",
)
def create_my_project(
    payload: ProjectCreate,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> ProjectResponse:
    """Create a project record owned by the authenticated user."""
    record = project_service.create_project(db, user_id=current_user.id, payload=payload)
    return to_project_response(record, settings=settings)


@router.get(
    "/{project_id}",
    response_model=ProjectResponse,
    status_code=status.HTTP_200_OK,
    summary="Get one project owned by the authenticated user",
)
def get_my_project(
    project_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> ProjectResponse:
    """Return a single project owned by the authenticated user."""
    record = project_service.get_project_by_id(
        db,
        user_id=current_user.id,
        project_id=project_id,
    )
    return to_project_response(record, settings=settings)


@router.patch(
    "/{project_id}",
    response_model=ProjectResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(rate_limit_dependency("projects:update", limit=60, window_seconds=900))
    ],
    summary="Partially update an owned project",
)
def update_my_project(
    project_id: uuid.UUID,
    payload: ProjectUpdate,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> ProjectResponse:
    """Partially update an owned project without overwriting omitted fields."""
    record = project_service.update_project(
        db,
        user_id=current_user.id,
        project_id=project_id,
        payload=payload,
    )
    return to_project_response(record, settings=settings)


@router.delete(
    "/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(rate_limit_dependency("projects:delete", limit=30, window_seconds=900))
    ],
    summary="Delete an owned project",
)
def delete_my_project(
    project_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> Response:
    """Delete an owned project and its stored cover images."""
    project_service.delete_project(
        db,
        user_id=current_user.id,
        project_id=project_id,
        settings=settings,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{project_id}/images",
    response_model=ProjectImageResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(rate_limit_dependency("projects:upload-image", limit=30, window_seconds=900))
    ],
    summary="Upload a cover or showcase image for an owned project",
)
def upload_my_project_image(
    project_id: uuid.UUID,
    file: UploadFile = File(...),
    alt: str | None = Form(default=None),
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> ProjectImageResponse:
    """Upload and attach a validated JPEG/PNG/WebP image to an owned project."""
    project = project_service.get_project_by_id(
        db,
        user_id=current_user.id,
        project_id=project_id,
    )
    image = project_service.upload_project_image(
        db,
        user_id=current_user.id,
        project_id=project.id,
        upload_file=file,
        alt=alt,
        settings=settings,
    )
    return to_project_image_response(
        image,
        is_public_project=project.visibility == "public",
        settings=settings,
    )


@router.patch(
    "/{project_id}/images/{image_id}",
    response_model=ProjectImageResponse,
    status_code=status.HTTP_200_OK,
    summary="Update metadata for an owned project image",
)
def update_my_project_image(
    project_id: uuid.UUID,
    image_id: uuid.UUID,
    payload: ProjectImageUpdate,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> ProjectImageResponse:
    """Update alt text or display order of an owned project image."""
    project = project_service.get_project_by_id(
        db,
        user_id=current_user.id,
        project_id=project_id,
    )
    image = project_service.update_project_image(
        db,
        user_id=current_user.id,
        project_id=project.id,
        image_id=image_id,
        payload=payload,
    )
    return to_project_image_response(
        image,
        is_public_project=project.visibility == "public",
        settings=settings,
    )


@router.delete(
    "/{project_id}/images/{image_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an owned project image",
)
def delete_my_project_image(
    project_id: uuid.UUID,
    image_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> Response:
    """Delete an owned project image and remove its stored object."""
    project_service.delete_project_image(
        db,
        user_id=current_user.id,
        project_id=project_id,
        image_id=image_id,
        settings=settings,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{project_id}/images/{image_id}/content",
    status_code=status.HTTP_200_OK,
    summary="Serve project cover image bytes (public projects directly, private via HMAC token)",
)
def serve_project_image_content(
    project_id: uuid.UUID,
    image_id: uuid.UUID,
    token: str | None = Query(default=None, max_length=256),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> Response:
    """Stream project cover image bytes."""
    image, content = project_service.get_project_image_content(
        db,
        project_id=project_id,
        image_id=image_id,
        token=token,
        settings=settings,
    )
    return Response(
        content=content,
        media_type=image.mime_type,
        headers={
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, max-age=300",
        },
    )
