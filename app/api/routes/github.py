"""Phase 3 separate GitHub portfolio connection and repository import routes under /api/v1/github."""

from fastapi import APIRouter, Depends, Query, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps.auth import (
    get_current_settings,
    get_current_verified_user,
    rate_limit_dependency,
)
from app.api.routes.projects import to_project_response
from app.core.config import Settings
from app.db.session import get_db
from app.models.user import User
from app.schemas.github import (
    GitHubConnectionResponse,
    GitHubConnectRequest,
    GitHubConnectResponse,
    GitHubImportRequest,
    GitHubImportResultResponse,
    GitHubImportSkippedItem,
    GitHubRepoListResponse,
    GitHubRepoResponse,
)
from app.services import github_service

router = APIRouter(prefix="/github", tags=["GitHub Integration"])


@router.post(
    "/connect",
    response_model=GitHubConnectResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(rate_limit_dependency("github:connect", limit=20, window_seconds=900))
    ],
    summary="Initiate a separate GitHub OAuth connection for repository browsing",
)
def connect_github(
    payload: GitHubConnectRequest,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> GitHubConnectResponse:
    """Create a user-bound GitHub OAuth state and return the GitHub authorization URL."""
    del payload.client_type
    authorization_url = github_service.start_github_connect(
        db,
        user_id=current_user.id,
        redirect_uri=payload.redirect_uri,
        settings=settings,
    )
    return GitHubConnectResponse(authorization_url=authorization_url)


@router.get(
    "/callback",
    status_code=status.HTTP_302_FOUND,
    dependencies=[
        Depends(rate_limit_dependency("github:callback", limit=30, window_seconds=900))
    ],
    summary="Handle GitHub OAuth callback for portfolio repository connection",
)
def github_connect_callback(
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> RedirectResponse:
    """Validate state, store encrypted GitHub token server-side, and redirect to frontend."""
    redirect_url = github_service.handle_github_callback(
        db,
        code=code,
        state=state,
        error=error,
        settings=settings,
    )
    return RedirectResponse(
        url=redirect_url,
        status_code=status.HTTP_302_FOUND,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Referrer-Policy": "no-referrer",
        },
    )


@router.get(
    "/connection",
    response_model=GitHubConnectionResponse,
    status_code=status.HTTP_200_OK,
    summary="Get the authenticated user's GitHub portfolio connection status",
)
def get_github_connection(
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> GitHubConnectionResponse:
    """Return GitHub connection status without exposing any token."""
    conn = github_service.get_connection(db, user_id=current_user.id)
    if conn is None:
        return GitHubConnectionResponse(connected=False)
    return GitHubConnectionResponse(
        connected=True,
        username=conn.username,
        avatar_url=conn.avatar_url,
        connected_at=conn.connected_at,
    )


@router.delete(
    "/connection",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Disconnect the authenticated user's GitHub portfolio connection",
)
def disconnect_github(
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> Response:
    """Remove the user's GitHub portfolio connection while keeping imported projects."""
    github_service.disconnect(db, user_id=current_user.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/repositories",
    response_model=GitHubRepoListResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(rate_limit_dependency("github:repos", limit=60, window_seconds=900))
    ],
    summary="List accessible GitHub repositories for import",
)
def list_github_repositories(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    q: str | None = Query(default=None, max_length=120),
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> GitHubRepoListResponse:
    """Browse the authenticated user's accessible GitHub repositories."""
    items, total, total_pages = github_service.list_repositories(
        db,
        user_id=current_user.id,
        page=page,
        page_size=page_size,
        q=q,
        settings=settings,
    )
    return GitHubRepoListResponse(
        items=[
            GitHubRepoResponse(
                full_name=repo.full_name,
                name=repo.name,
                description=repo.description,
                html_url=repo.html_url,
                homepage=repo.homepage,
                languages=repo.languages,
                topics=repo.topics,
                stars=repo.stars,
                private=repo.private,
                updated_at=repo.updated_at,
                already_imported=already_imported,
            )
            for repo, already_imported in items
        ],
        page=page,
        page_size=page_size,
        total=total,
        total_pages=total_pages,
    )


@router.post(
    "/repositories/import",
    response_model=GitHubImportResultResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(rate_limit_dependency("github:import", limit=30, window_seconds=900))
    ],
    summary="Import selected GitHub repositories as private Folio360 projects",
)
def import_github_repositories(
    payload: GitHubImportRequest,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> GitHubImportResultResponse:
    """Import selected repositories as private projects, skipping duplicates."""
    created, skipped = github_service.import_repositories(
        db,
        user_id=current_user.id,
        full_names=[item.full_name for item in payload.repos],
        settings=settings,
    )
    return GitHubImportResultResponse(
        created=[to_project_response(proj, settings=settings) for proj in created],
        skipped=[
            GitHubImportSkippedItem(full_name=name, reason=reason)
            for name, reason in skipped
        ],
    )
