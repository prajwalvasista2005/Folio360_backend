"""Pure ASGI3 security header and OAuth cookie middleware for Stage 3C.6 (REV12 §4, §7)."""

from email.utils import formatdate
import logging
from typing import Literal
from urllib.parse import quote

from fastapi import status
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import Settings
from app.core.exceptions import DEFAULT_SERVER_ERROR_MESSAGE

logger = logging.getLogger("folio360.oauth.middleware")


def get_normalized_api_v1_prefix(settings: Settings) -> str:
    """Return normalized leading-slash API prefix with no trailing slash (or '')."""
    cleaned = settings.API_V1_PREFIX.strip("/")
    return f"/{cleaned}" if cleaned else ""


def get_oauth_binding_cookie_path(settings: Settings) -> str:
    """Return the host-only Path attribute for folio360_oauth_binding."""
    prefix = get_normalized_api_v1_prefix(settings)
    return f"{prefix}/auth/oauth"


def get_oauth_exchange_cookie_path(settings: Settings) -> str:
    """Return the host-only Path attribute for folio360_oauth_exchange."""
    prefix = get_normalized_api_v1_prefix(settings)
    return f"{prefix}/auth/oauth/exchange"


def _build_delete_cookie_header(
    *,
    key: str,
    path: str,
    secure: bool,
    samesite: Literal["lax", "strict", "none"],
) -> str:
    resp = Response()
    resp.delete_cookie(
        key=key,
        path=path,
        domain=None,
        secure=secure,
        httponly=True,
        samesite=samesite,
    )
    header_val = resp.headers.get("set-cookie")
    if header_val is not None:  # pragma: no branch
        return header_val
    # Fallback identical to Starlette delete_cookie formatting
    expires = formatdate(0, usegmt=True)
    return f"{quote(key)}=''; Expires={expires}; HttpOnly; Max-Age=0; Path={path}; SameSite={samesite}"


def build_clear_binding_cookie_header(settings: Settings) -> str:
    """Build Set-Cookie deletion header for folio360_oauth_binding."""
    return _build_delete_cookie_header(
        key=settings.OAUTH_BINDING_COOKIE_NAME,
        path=get_oauth_binding_cookie_path(settings),
        secure=settings.REFRESH_COOKIE_SECURE,
        samesite="lax",
    )


def build_clear_exchange_cookie_header(settings: Settings) -> str:
    """Build Set-Cookie deletion header for folio360_oauth_exchange."""
    return _build_delete_cookie_header(
        key=settings.OAUTH_EXCHANGE_COOKIE_NAME,
        path=get_oauth_exchange_cookie_path(settings),
        secure=settings.REFRESH_COOKIE_SECURE,
        samesite=settings.REFRESH_COOKIE_SAMESITE,
    )


def _extract_cookie_names(headers: Headers) -> set[str]:
    names: set[str] = set()
    for raw_cookie in headers.getlist("cookie"):
        for segment in raw_cookie.split(";"):
            part = segment.strip()
            if "=" in part:
                name, _ = part.split("=", 1)
                stripped = name.strip()
                if stripped:
                    names.add(stripped)
    return names


def _has_set_cookie_for(raw_headers: list[tuple[bytes, bytes]], cookie_name: str) -> bool:
    prefix = f"{cookie_name}=".encode("latin-1")
    for k, v in raw_headers:
        if k.lower() == b"set-cookie" and v.startswith(prefix):
            return True
    return False


class OAuthSecurityResponseMiddleware:
    """
    Pure ASGI3 middleware scoped to {prefix}/auth/oauth/* enforcing REV12 §7:
    - Always sets Cache-Control: no-store, Pragma: no-cache, Referrer-Policy: no-referrer.
    - Catches unhandled exceptions inside CORSMiddleware to emit sanitized JSON 500
      with OAuth security headers, conditional cookie clearing, and CORS headers.
    - Enforces if-present cookie clearing on pre-route 429 / 422 / 500 OAuth responses.
    """

    def __init__(self, app: ASGIApp, *, settings: Settings) -> None:
        self.app = app
        self.settings = settings
        self._oauth_base = f"{get_normalized_api_v1_prefix(settings)}/auth/oauth"
        self._exchange_path = f"{self._oauth_base}/exchange"

    def _is_oauth_path(self, path: str) -> bool:
        return path == self._oauth_base or path.startswith(f"{self._oauth_base}/")

    def _is_callback_path(self, path: str) -> bool:
        return path.startswith(f"{self._oauth_base}/") and path.endswith("/callback")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path", ""))
        if not self._is_oauth_path(path):
            await self.app(scope, receive, send)
            return

        req_headers = Headers(scope=scope)
        cookie_names = _extract_cookie_names(req_headers)
        origin = req_headers.get("origin")
        trusted_origin = (
            origin is not None
            and bool(origin)
            and origin.lower() != "null"
            and origin in self.settings.CORS_ORIGINS
        )
        raw_client_type = (req_headers.get("x-client-type") or "").strip()

        is_callback = self._is_callback_path(path)
        is_exchange = path == self._exchange_path
        binding_present = self.settings.OAUTH_BINDING_COOKIE_NAME in cookie_names
        exchange_present = self.settings.OAUTH_EXCHANGE_COOKIE_NAME in cookie_names

        response_started = False

        async def wrapped_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                status_code = int(message.get("status", 200))
                filtered_headers = [
                    (k, v)
                    for k, v in message.get("headers", [])
                    if k.lower() not in {b"cache-control", b"pragma", b"referrer-policy"}
                ]
                filtered_headers.extend(
                    [
                        (b"cache-control", b"no-store"),
                        (b"pragma", b"no-cache"),
                        (b"referrer-policy", b"no-referrer"),
                    ]
                )

                if (
                    is_callback
                    and status_code == status.HTTP_429_TOO_MANY_REQUESTS
                    and binding_present
                    and not _has_set_cookie_for(
                        filtered_headers, self.settings.OAUTH_BINDING_COOKIE_NAME
                    )
                ):
                    filtered_headers.append(
                        (
                            b"set-cookie",
                            build_clear_binding_cookie_header(self.settings).encode("latin-1"),
                        )
                    )

                if (
                    is_exchange
                    and raw_client_type != "mobile"
                    and status_code in {422, status.HTTP_429_TOO_MANY_REQUESTS}
                    and trusted_origin
                    and exchange_present
                    and not _has_set_cookie_for(
                        filtered_headers, self.settings.OAUTH_EXCHANGE_COOKIE_NAME
                    )
                ):
                    filtered_headers.append(
                        (
                            b"set-cookie",
                            build_clear_exchange_cookie_header(self.settings).encode("latin-1"),
                        )
                    )

                message["headers"] = filtered_headers

            await send(message)

        try:
            await self.app(scope, receive, wrapped_send)
        except Exception as exc:
            if response_started:
                raise

            method = str(scope.get("method", "?"))
            logger.error(
                "Unhandled OAuth server error on %s %s: exception=%s",
                method,
                path,
                type(exc).__name__,
            )

            error_response = JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "error": {
                        "message": DEFAULT_SERVER_ERROR_MESSAGE,
                        "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                        "details": None,
                    }
                },
                headers={
                    "Cache-Control": "no-store",
                    "Pragma": "no-cache",
                    "Referrer-Policy": "no-referrer",
                },
            )

            if is_callback:
                clear_mode = getattr(exc, "clear_binding_cookie_mode", "if_present")
                if clear_mode == "always" or (clear_mode == "if_present" and binding_present):
                    error_response.delete_cookie(
                        key=self.settings.OAUTH_BINDING_COOKIE_NAME,
                        path=get_oauth_binding_cookie_path(self.settings),
                        domain=None,
                        secure=self.settings.REFRESH_COOKIE_SECURE,
                        httponly=True,
                        samesite="lax",
                    )

            if (
                is_exchange
                and raw_client_type != "mobile"
                and trusted_origin
                and exchange_present
            ):
                error_response.delete_cookie(
                    key=self.settings.OAUTH_EXCHANGE_COOKIE_NAME,
                    path=get_oauth_exchange_cookie_path(self.settings),
                    domain=None,
                    secure=self.settings.REFRESH_COOKIE_SECURE,
                    httponly=True,
                    samesite=self.settings.REFRESH_COOKIE_SAMESITE,
                )

            await error_response(scope, receive, send)
