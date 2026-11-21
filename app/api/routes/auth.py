"""Stage 3A synchronous authentication routes under /api/v1/auth/*."""

from typing import Optional

from fastapi import APIRouter, Body, Depends, Request, Response, status
from sqlalchemy.orm import Session

from app.api.deps.auth import (
    AuthenticatedUser,
    ClientType,
    enforce_web_origin_if_web,
    get_current_auth_context,
    get_current_settings,
    get_current_user,
    optional_client_type,
    rate_limit_dependency,
    require_client_type,
    resolve_client_ip,
)
from app.core.config import Settings
from app.core.exceptions import AppException
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import (
    GenericAcceptedResponse,
    LoginRequest,
    LogoutRequest,
    LogoutResponse,
    MeResponse,
    MobileAuthTokenResponse,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    ResendVerificationRequest,
    UserPublicResponse,
    VerifyEmailRequest,
    VerifyEmailResponse,
    WebAuthTokenResponse,
)
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _get_refresh_cookie_path(settings: Settings) -> str:
    """Derive the refresh cookie Path attribute from settings.API_V1_PREFIX."""
    prefix = settings.API_V1_PREFIX.strip().rstrip("/")
    if not prefix:
        return "/auth"
    if not prefix.startswith("/"):
        prefix = f"/{prefix}"
    return f"{prefix}/auth"


def _to_user_public(user: User) -> UserPublicResponse:
    return UserPublicResponse(
        id=user.id,
        email=user.email,
        is_active=user.is_active,
        is_email_verified=user.is_email_verified,
        has_password=user.password_hash is not None,
        created_at=user.created_at,
    )


def _set_refresh_cookie(
    response: Response,
    *,
    raw_refresh_token: str,
    max_age_seconds: int,
    settings: Settings,
) -> None:
    response.set_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        value=raw_refresh_token,
        max_age=max_age_seconds,
        path=_get_refresh_cookie_path(settings),
        domain=settings.REFRESH_COOKIE_DOMAIN,
        secure=settings.REFRESH_COOKIE_SECURE,
        httponly=True,
        samesite=settings.REFRESH_COOKIE_SAMESITE,
    )


def _clear_refresh_cookie(response: Response, *, settings: Settings) -> None:
    response.delete_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        path=_get_refresh_cookie_path(settings),
        domain=settings.REFRESH_COOKIE_DOMAIN,
        secure=settings.REFRESH_COOKIE_SECURE,
        httponly=True,
        samesite=settings.REFRESH_COOKIE_SAMESITE,
    )


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_dependency("auth:register", limit=5, window_seconds=900))],
    summary="Register a new user account",
)
def register(
    payload: RegisterRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> RegisterResponse:
    """Create an unverified account and initiate verification email delivery."""
    user, verification_sent = auth_service.register_user(
        db,
        email=str(payload.email),
        password=payload.password,
        settings=settings,
    )
    message = (
        "Registration successful. Please check your email to verify your account."
        if verification_sent
        else "Registration successful, but the verification email could not be sent right now. "
        "Please request a verification resend."
    )
    return RegisterResponse(
        message=message,
        user=_to_user_public(user),
        verification_email_sent=verification_sent,
    )


@router.post(
    "/verify-email",
    response_model=VerifyEmailResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_dependency("auth:verify-email", limit=10, window_seconds=900))],
    summary="Verify user email address",
)
def verify_email(
    payload: VerifyEmailRequest,
    db: Session = Depends(get_db),
) -> VerifyEmailResponse:
    """Consume an email verification token without creating any session or issuing tokens."""
    auth_service.verify_email(db, raw_token=payload.token)
    return VerifyEmailResponse(
        message="Email verified successfully.",
        email_verified=True,
    )


@router.post(
    "/resend-verification",
    response_model=GenericAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[
        Depends(rate_limit_dependency("auth:resend-verification", limit=5, window_seconds=900))
    ],
    summary="Resend account verification email",
)
def resend_verification(
    payload: ResendVerificationRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> GenericAcceptedResponse:
    """Always return generic 202 Accepted while enforcing Rev10 §11.2 cooldowns/retries."""
    auth_service.resend_verification(
        db,
        email=str(payload.email),
        settings=settings,
    )
    return GenericAcceptedResponse(
        message="If an unverified account exists for this email, a verification link has been sent."
    )


@router.post(
    "/login",
    response_model=WebAuthTokenResponse | MobileAuthTokenResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_dependency("auth:login", limit=10, window_seconds=900))],
    summary="Authenticate with email and password",
)
def login(
    request: Request,
    response: Response,
    payload: LoginRequest,
    client_type: ClientType = Depends(require_client_type),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> WebAuthTokenResponse | MobileAuthTokenResponse:
    """Authenticate a verified user and issue client-appropriate access/refresh credentials."""
    enforce_web_origin_if_web(request, client_type, settings)

    user, access_token, expires_in, raw_refresh, refresh_expires_in = auth_service.login_user(
        db,
        email=str(payload.email),
        password=payload.password,
        client_type=client_type,
        user_agent=request.headers.get("user-agent"),
        ip_address=resolve_client_ip(request),
        settings=settings,
    )
    user_public = _to_user_public(user)

    if client_type == "web":
        _set_refresh_cookie(
            response,
            raw_refresh_token=raw_refresh,
            max_age_seconds=refresh_expires_in,
            settings=settings,
        )
        return WebAuthTokenResponse(
            access_token=access_token,
            expires_in=expires_in,
            user=user_public,
        )

    return MobileAuthTokenResponse(
        access_token=access_token,
        expires_in=expires_in,
        refresh_token=raw_refresh,
        refresh_expires_in=refresh_expires_in,
        user=user_public,
    )


@router.post(
    "/refresh",
    response_model=WebAuthTokenResponse | MobileAuthTokenResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_dependency("auth:refresh", limit=30, window_seconds=900))],
    summary="Rotate refresh session and issue fresh access JWT",
)
def refresh(
    request: Request,
    response: Response,
    payload: Optional[RefreshRequest] = Body(default=None),
    client_type: ClientType = Depends(require_client_type),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> WebAuthTokenResponse | MobileAuthTokenResponse:
    """Rotate a single-use refresh token and detect replay across session families."""
    enforce_web_origin_if_web(request, client_type, settings)

    if client_type == "web":
        raw_refresh_token = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    else:
        raw_refresh_token = payload.refresh_token if payload is not None else None

    try:
        user, access_token, expires_in, new_refresh, refresh_expires_in = (
            auth_service.refresh_session_token(
                db,
                raw_refresh_token=raw_refresh_token,
                client_type=client_type,
                user_agent=request.headers.get("user-agent"),
                ip_address=resolve_client_ip(request),
                settings=settings,
            )
        )
    except AppException as exc:
        if client_type == "web" and exc.status_code == status.HTTP_401_UNAUTHORIZED:
            # Clear stale/replayed web cookie on any 401 refresh error
            tmp_resp = Response()
            _clear_refresh_cookie(tmp_resp, settings=settings)
            headers = dict(exc.headers or {})
            set_cookie_header = tmp_resp.headers.get("set-cookie")
            if set_cookie_header is not None:
                headers["set-cookie"] = set_cookie_header
            exc.headers = headers
        raise

    user_public = _to_user_public(user)
    if client_type == "web":
        _set_refresh_cookie(
            response,
            raw_refresh_token=new_refresh,
            max_age_seconds=refresh_expires_in,
            settings=settings,
        )
        return WebAuthTokenResponse(
            access_token=access_token,
            expires_in=expires_in,
            user=user_public,
        )

    return MobileAuthTokenResponse(
        access_token=access_token,
        expires_in=expires_in,
        refresh_token=new_refresh,
        refresh_expires_in=refresh_expires_in,
        user=user_public,
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    status_code=status.HTTP_200_OK,
    summary="Logout current refresh session",
)
def logout(
    request: Request,
    response: Response,
    payload: Optional[LogoutRequest] = Body(default=None),
    client_type: ClientType = Depends(require_client_type),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> LogoutResponse:
    """Idempotently revoke the active refresh session and clear web refresh cookie."""
    enforce_web_origin_if_web(request, client_type, settings)

    if client_type == "web":
        raw_refresh_token = request.cookies.get(settings.REFRESH_COOKIE_NAME)
        _clear_refresh_cookie(response, settings=settings)
    else:
        raw_refresh_token = payload.refresh_token if payload is not None else None

    auth_service.logout_current_session(
        db,
        raw_refresh_token=raw_refresh_token,
        client_type=client_type,
    )
    return LogoutResponse(message="Logged out successfully.")


@router.post(
    "/logout-all",
    response_model=LogoutResponse,
    status_code=status.HTTP_200_OK,
    summary="Logout all active sessions and invalidate existing access JWTs",
)
def logout_all(
    request: Request,
    response: Response,
    auth_ctx: AuthenticatedUser = Depends(get_current_auth_context),
    client_type: ClientType | None = Depends(optional_client_type),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> LogoutResponse:
    """Increment auth_version and revoke all active refresh sessions for the user."""
    if client_type == "web":
        enforce_web_origin_if_web(request, "web", settings)

    auth_service.logout_all_sessions(
        db,
        user_id=auth_ctx.user.id,
        expected_auth_version=auth_ctx.token_ver,
    )

    if client_type == "web":
        _clear_refresh_cookie(response, settings=settings)

    return LogoutResponse(message="Logged out from all sessions.")


@router.get(
    "/me",
    response_model=MeResponse,
    status_code=status.HTTP_200_OK,
    summary="Get authenticated user profile",
)
def get_me(
    current_user: User = Depends(get_current_user),
) -> MeResponse:
    """Return the authenticated user's Stage 3A profile information."""
    return MeResponse(
        id=current_user.id,
        email=current_user.email,
        is_active=current_user.is_active,
        is_email_verified=current_user.is_email_verified,
        has_password=current_user.password_hash is not None,
        created_at=current_user.created_at,
        updated_at=current_user.updated_at,
    )
