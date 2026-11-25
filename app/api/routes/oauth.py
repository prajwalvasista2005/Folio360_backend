"""Stage 3C.6 synchronous OAuth 2.0 / OIDC HTTP routes under /api/v1/auth/oauth/* (REV12)."""

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps.auth import (
    ClientType,
    enforce_web_origin_if_web,
    get_current_settings,
    rate_limit_dependency,
    require_client_type,
    resolve_client_ip,
)
from app.api.routes.auth import _set_refresh_cookie, _to_user_public
from app.core.config import OAUTH_EXCHANGE_CODE_EXPIRE_SECONDS, Settings
from app.core.exceptions import AppException
from app.core.oauth_middleware import (
    build_clear_binding_cookie_header,
    build_clear_exchange_cookie_header,
    get_oauth_binding_cookie_path,
    get_oauth_exchange_cookie_path,
)
from app.db.session import get_db
from app.schemas.auth import (
    MobileAuthTokenResponse,
    OAuthExchangeRequest,
    WebAuthTokenResponse,
)
from app.services import oauth_service
from app.services.oauth_service import OAuthCallbackJsonError

router = APIRouter(prefix="/auth/oauth", tags=["OAuth"])

_START_PARAM_KEYS = (
    "client_type",
    "redirect_uri",
    "exchange_code_challenge",
    "exchange_code_challenge_method",
)


def _attach_set_cookie(exc: AppException, set_cookie_header: str) -> None:
    headers = dict(exc.headers or {})
    headers["set-cookie"] = set_cookie_header
    exc.headers = headers


@router.get(
    "/{provider}/start",
    status_code=status.HTTP_302_FOUND,
    dependencies=[Depends(rate_limit_dependency("auth:oauth-start", limit=20, window_seconds=900))],
    summary="Initiate OAuth 2.0 authorization redirect with PKCE S256",
)
def oauth_start(
    provider: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> RedirectResponse:
    """Validate /start query params strictly, persist OAuth state, and redirect to provider."""
    query = request.query_params
    duplicate_params: list[str] = []
    values: dict[str, str | None] = {}

    for key in _START_PARAM_KEYS:
        raw_list = query.getlist(key)
        if len(raw_list) > 1:
            duplicate_params.append(key)
            values[key] = raw_list[0]
        elif len(raw_list) == 1:
            values[key] = raw_list[0]
        else:
            values[key] = None

    # Preserve default 'S256' only when exchange_code_challenge_method is omitted (REV12 §8);
    # actually pass explicit None if absent? REV12 §8 Step 6: default on query if omitted?
    # Keep None if absent -> service requires exact "S256" if omitted, or wait:
    challenge_method = (
        values["exchange_code_challenge_method"]
        if "exchange_code_challenge_method" in query
        else "S256"
    )

    result = oauth_service.start_oauth_flow(
        db,
        provider=provider,
        client_type=values["client_type"],
        redirect_uri=values["redirect_uri"],
        exchange_code_challenge=values["exchange_code_challenge"],
        exchange_code_challenge_method=challenge_method,
        duplicate_params=duplicate_params,
        settings=settings,
    )

    response = RedirectResponse(
        url=result.authorization_url,
        status_code=status.HTTP_302_FOUND,
    )
    if result.client_type == "web" and result.binding_cookie_value is not None:
        response.set_cookie(
            key=settings.OAUTH_BINDING_COOKIE_NAME,
            value=result.binding_cookie_value,
            max_age=settings.OAUTH_STATE_EXPIRE_MINUTES * 60,
            path=get_oauth_binding_cookie_path(settings),
            domain=None,
            secure=settings.REFRESH_COOKIE_SECURE,
            httponly=True,
            samesite="lax",
        )
    return response


@router.get(
    "/{provider}/callback",
    status_code=status.HTTP_302_FOUND,
    dependencies=[
        Depends(rate_limit_dependency("auth:oauth-callback", limit=20, window_seconds=900))
    ],
    summary="Handle OAuth provider callback redirect",
)
def oauth_callback(
    provider: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> RedirectResponse:
    """Process OAuth provider callback, resolve/provision user, and issue exchange code."""
    query = request.query_params
    state_values = query.getlist("state")
    code_values = query.getlist("code")
    error_values = query.getlist("error")
    binding_cookie = request.cookies.get(settings.OAUTH_BINDING_COOKIE_NAME)
    binding_cookie_present = settings.OAUTH_BINDING_COOKIE_NAME in request.cookies
    jwk_client = getattr(request.app.state, "google_jwk_client", None)

    try:
        result = oauth_service.handle_oauth_callback(
            db,
            provider=provider,
            state_values=state_values,
            code_values=code_values,
            error_values=error_values,
            binding_cookie=binding_cookie,
            settings=settings,
            jwk_client=jwk_client,
        )
    except OAuthCallbackJsonError as exc:
        if exc.clear_binding_cookie_mode == "always" or (
            exc.clear_binding_cookie_mode == "if_present" and binding_cookie_present
        ):
            _attach_set_cookie(exc, build_clear_binding_cookie_header(settings))
        raise

    response = RedirectResponse(
        url=result.redirect_url,
        status_code=status.HTTP_302_FOUND,
    )
    if result.clear_binding_cookie:
        response.delete_cookie(
            key=settings.OAUTH_BINDING_COOKIE_NAME,
            path=get_oauth_binding_cookie_path(settings),
            domain=None,
            secure=settings.REFRESH_COOKIE_SECURE,
            httponly=True,
            samesite="lax",
        )
    if result.exchange_cookie_value is not None:
        response.set_cookie(
            key=settings.OAUTH_EXCHANGE_COOKIE_NAME,
            value=result.exchange_cookie_value,
            max_age=OAUTH_EXCHANGE_CODE_EXPIRE_SECONDS,
            path=get_oauth_exchange_cookie_path(settings),
            domain=None,
            secure=settings.REFRESH_COOKIE_SECURE,
            httponly=True,
            samesite=settings.REFRESH_COOKIE_SAMESITE,
        )
    return response


@router.post(
    "/exchange",
    response_model=WebAuthTokenResponse | MobileAuthTokenResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(rate_limit_dependency("auth:oauth-exchange", limit=10, window_seconds=900))
    ],
    summary="Exchange single-use OAuth code with PKCE verifier for JWT and refresh session",
)
def oauth_exchange(
    request: Request,
    response: Response,
    payload: OAuthExchangeRequest,
    client_type: ClientType = Depends(require_client_type),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_current_settings),
) -> WebAuthTokenResponse | MobileAuthTokenResponse:
    """Exchange a single-use OAuth exchange code + RFC 7636 verifier (+ cookie on web)."""
    # Must precede any cookie mutation so 403 CSRF_ORIGIN_MISMATCH never clears web cookie
    enforce_web_origin_if_web(request, client_type, settings)

    exchange_cookie = (
        request.cookies.get(settings.OAUTH_EXCHANGE_COOKIE_NAME)
        if client_type == "web"
        else None
    )

    try:
        user, access_token, expires_in, raw_refresh, refresh_expires_in = (
            oauth_service.exchange_oauth_code(
                db,
                code=payload.code,
                exchange_code_verifier=payload.exchange_code_verifier,
                client_type=client_type,
                exchange_cookie=exchange_cookie,
                user_agent=request.headers.get("user-agent"),
                ip_address=resolve_client_ip(request),
                settings=settings,
            )
        )
    except AppException as exc:
        if client_type == "web":
            _attach_set_cookie(exc, build_clear_exchange_cookie_header(settings))
        raise

    user_public = _to_user_public(user)
    if client_type == "web":
        response.delete_cookie(
            key=settings.OAUTH_EXCHANGE_COOKIE_NAME,
            path=get_oauth_exchange_cookie_path(settings),
            domain=None,
            secure=settings.REFRESH_COOKIE_SECURE,
            httponly=True,
            samesite=settings.REFRESH_COOKIE_SAMESITE,
        )
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
