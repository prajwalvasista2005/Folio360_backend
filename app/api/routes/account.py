"""Owner-scoped account management, security log, email change, export, and deletion routes."""

from typing import Literal

from fastapi import APIRouter, Depends, Query, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.api.deps.auth import (
    get_current_settings,
    get_current_verified_user,
    rate_limit_dependency,
    resolve_client_ip,
)
from app.api.routes.auth import _clear_refresh_cookie
from app.core.config import Settings
from app.db.session import get_db
from app.models.user import User
from app.schemas.account import (
    AccountDeleteRequest,
    AccountResponse,
    AuditEventListResponse,
    AuditEventResponse,
    EmailChangeConfirmRequest,
    EmailChangeRequest,
    EmailChangeRequestedResponse,
    OAuthConnectionItem,
    OAuthConnectionListResponse,
)
from app.services import account_service

router = APIRouter(prefix="/account", tags=["Account"])


@router.get(
    "",
    response_model=AccountResponse,
    status_code=status.HTTP_200_OK,
    summary="Get authenticated account summary",
)
def get_account(
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> AccountResponse:
    """Return owner-scoped account metadata and any pending email change."""
    summary = account_service.get_account_summary(db, user=current_user)
    return AccountResponse(**summary)


@router.post(
    "/email",
    response_model=EmailChangeRequestedResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(rate_limit_dependency("account:email-change", limit=10, window_seconds=900))
    ],
    summary="Request an email address change with verification",
)
def request_email_change(
    request: Request,
    payload: EmailChangeRequest,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> EmailChangeRequestedResponse:
    """Verify credentials and send a single-use verification link to the new email."""
    message, pending_email = account_service.request_email_change(
        db,
        user_id=current_user.id,
        new_email=str(payload.new_email),
        current_password=payload.current_password,
        ip_address=resolve_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        settings=settings,
    )
    return EmailChangeRequestedResponse(message=message, pending_email=pending_email)


@router.post(
    "/email/confirm",
    response_model=AccountResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(rate_limit_dependency("account:email-confirm", limit=20, window_seconds=900))
    ],
    summary="Confirm a pending email address change using a single-use token",
)
def confirm_email_change(
    request: Request,
    payload: EmailChangeConfirmRequest,
    db: Session = Depends(get_db),
) -> AccountResponse:
    """Consume an email-change token and update the account's verified login email."""
    summary = account_service.confirm_email_change(
        db,
        raw_token=payload.token,
        ip_address=resolve_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return AccountResponse(**summary)


@router.get(
    "/security-log",
    response_model=AuditEventListResponse,
    status_code=status.HTTP_200_OK,
    summary="List paginated security audit events for the authenticated user",
)
def list_security_log(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> AuditEventListResponse:
    """Return owner-scoped security audit events ordered newest first."""
    items, total, total_pages = account_service.list_security_log(
        db,
        user_id=current_user.id,
        page=page,
        page_size=page_size,
    )
    return AuditEventListResponse(
        items=[
            AuditEventResponse(
                id=item.id,
                action=item.action,
                ip_address=item.ip_address,
                device_label=item.device_label,
                created_at=item.created_at,
            )
            for item in items
        ],
        page=page,
        page_size=page_size,
        total=total,
        total_pages=total_pages,
    )


@router.get(
    "/connections",
    response_model=OAuthConnectionListResponse,
    status_code=status.HTTP_200_OK,
    summary="List linked OAuth sign-in providers for the authenticated user",
)
def list_connections(
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> OAuthConnectionListResponse:
    """Return linked OAuth providers without exposing tokens or secrets."""
    rows = account_service.list_oauth_connections(db, user_id=current_user.id)
    return OAuthConnectionListResponse(
        items=[
            OAuthConnectionItem(
                provider=row.provider,  # type: ignore[arg-type]
                provider_email=row.provider_email,
                linked_at=row.created_at,
            )
            for row in rows
        ]
    )


@router.delete(
    "/connections/{provider}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Disconnect a linked OAuth sign-in provider",
)
def disconnect_connection(
    request: Request,
    provider: Literal["google", "github"],
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> Response:
    """Unlink an OAuth provider while preventing account lockout."""
    account_service.disconnect_oauth_provider(
        db,
        user_id=current_user.id,
        provider=provider,
        ip_address=resolve_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/export",
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(rate_limit_dependency("account:export", limit=10, window_seconds=900))
    ],
    summary="Export authenticated user's profile and portfolio data as JSON",
)
def export_account_data(
    request: Request,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Return a sanitized JSON export of all records owned by the authenticated user."""
    payload = account_service.export_user_data(
        db,
        user=current_user,
        ip_address=resolve_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=payload,
        headers={
            "Content-Disposition": 'attachment; filename="folio360-data-export.json"',
            "Cache-Control": "no-store",
        },
    )


@router.delete(
    "",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[
        Depends(rate_limit_dependency("account:delete", limit=5, window_seconds=900))
    ],
    summary="Permanently delete the authenticated user's account and owned records",
)
def delete_account(
    payload: AccountDeleteRequest,
    response: Response,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> Response:
    """Verify confirmation/password, delete user records and files, and clear session cookie."""
    del payload.confirm
    account_service.delete_user_account(
        db,
        user_id=current_user.id,
        current_password=payload.current_password,
        settings=settings,
    )
    _clear_refresh_cookie(response, settings=settings)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
