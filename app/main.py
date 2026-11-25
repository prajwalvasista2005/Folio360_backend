"""FastAPI application entry point, ASGI3 trust-boundary subclass, and factory for Folio360."""

from contextlib import asynccontextmanager
import inspect
import logging
import sys
from typing import Any, AsyncGenerator

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import Engine
from starlette.types import Receive, Scope, Send
import uvicorn.config

from app.api.routes import auth, health, oauth
from app.core.config import Settings, get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import setup_logging
from app.core.oauth_middleware import OAuthSecurityResponseMiddleware
from app.core.rate_limit import SlidingWindowRateLimiter
from app.services.oauth_providers import build_google_jwk_client
from app.db.session import (
    build_engine,
    build_readiness_engine,
    build_readiness_semaphore,
    build_sessionmaker,
)
from app.server import (
    _ACTIVE_VERIFIED_CONFIG_LOAD,
    assert_production_lifespan_verified,
    verify_production_asgi_trust_boundary,
)

logger = logging.getLogger("folio360.main")


class Folio360FastAPI(FastAPI):
    """FastAPI subclass enforcing pre-socket Config.load() and ASGI3 lifespan gates."""

    @inspect.markcoroutinefunction
    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        # 1. Zero-argument Uvicorn Config.load() probe (uvicorn/config.py)
        if not args and not kwargs:
            settings: Settings = getattr(self.state, "settings", None) or get_settings()
            if (
                settings.ENVIRONMENT == "production"
                and _ACTIVE_VERIFIED_CONFIG_LOAD.get() is None
            ):
                raise RuntimeError(
                    "Unverified Uvicorn Config.load() rejected in production: "
                    "launch via app.server (VerifiedUvicornConfig)."
                )
            raise TypeError("Folio360FastAPI instance is not a factory")

        # 2. Strict ASGI3 (scope, receive, send) invocation
        if len(args) != 3 or kwargs:
            raise TypeError(
                "Folio360FastAPI requires ASGI3 (scope, receive, send) invocation."
            )
        scope, receive, send = args
        return self._dispatch_asgi(scope, receive, send)

    async def _dispatch_asgi(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope.get("type") in {"http", "websocket"}:
            settings: Settings = getattr(self.state, "settings", None) or get_settings()
            if settings.ENVIRONMENT == "production":
                assert_production_lifespan_verified(self)
        await super().__call__(scope, receive, send)


def _reset_db_state(app: FastAPI) -> None:
    """Reset all database-related attributes on app.state to None."""
    app.state.db_engine = None
    app.state.db_sessionmaker = None
    app.state.db_readiness_engine = None
    app.state.db_readiness_semaphore = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager with exception-safe database resource cleanup."""
    settings: Settings = getattr(app.state, "settings", None) or get_settings()
    setup_logging(
        log_level=settings.LOG_LEVEL,
        extra_sensitive_keys=(
            settings.OAUTH_BINDING_COOKIE_NAME,
            settings.OAUTH_EXCHANGE_COOKIE_NAME,
            settings.REFRESH_COOKIE_NAME,
        ),
    )
    _reset_db_state(app)

    db_engine: Engine | None = None
    readiness_engine: Engine | None = None
    startup_completed = False

    try:
        settings.validate_runtime_requirements()
        verify_production_asgi_trust_boundary(app, settings)

        if settings.DATABASE_URL is not None:
            db_engine = build_engine(settings)
            db_sessionmaker = build_sessionmaker(db_engine)
            readiness_engine = build_readiness_engine(settings)
            readiness_semaphore = build_readiness_semaphore(settings)

            app.state.db_engine = db_engine
            app.state.db_sessionmaker = db_sessionmaker
            app.state.db_readiness_engine = readiness_engine
            app.state.db_readiness_semaphore = readiness_semaphore
        else:
            logger.info(
                "Database is not configured (DATABASE_URL is unset); starting without database engine"
            )

        logger.info(
            "Starting %s v%s in %s mode",
            settings.APP_NAME,
            settings.APP_VERSION,
            settings.ENVIRONMENT,
        )
        startup_completed = True
        yield
    finally:
        if startup_completed:
            logger.info("Shutting down %s", settings.APP_NAME)
        _reset_db_state(app)

        for engine_label, engine_instance in (
            ("db_readiness_engine", readiness_engine),
            ("db_engine", db_engine),
        ):
            if engine_instance is not None:
                try:
                    engine_instance.dispose()
                except Exception as dispose_exc:
                    logger.error(
                        "Error disposing %s during lifespan cleanup: exception=%s",
                        engine_label,
                        type(dispose_exc).__name__,
                    )


def create_app(settings: Settings | None = None) -> Folio360FastAPI:
    """FastAPI application factory (never self-certifies Uvicorn proxy/ASGI state)."""
    active_config = _ACTIVE_VERIFIED_CONFIG_LOAD.get()
    if settings is None:
        if active_config is not None and active_config._bound_settings is not None:
            settings = active_config._bound_settings
        else:
            settings = get_settings()

    # Guard 1: Block direct factory invocation from raw uvicorn.config.Config.load() in production
    if settings.ENVIRONMENT == "production" and active_config is None:
        caller_frame = sys._getframe(1)
        if caller_frame.f_code is uvicorn.config.Config.load.__code__:
            raise RuntimeError(
                "Unverified Uvicorn Config.load() factory invocation rejected in production: "
                "launch via app.server (VerifiedUvicornConfig)."
            )

    application = Folio360FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=settings.APP_DESCRIPTION,
        docs_url=settings.DOCS_URL,
        openapi_url=settings.OPENAPI_URL,
        lifespan=lifespan,
    )

    # Attach settings instance, rate limiter, and JWKS client without startup network/DB side effects
    application.state.settings = settings
    application.state.rate_limiter = SlidingWindowRateLimiter()
    application.state.google_jwk_client = build_google_jwk_client(settings)
    _reset_db_state(application)

    # Centralized exception handling
    register_exception_handlers(application)

    # OAuth security middleware registered inside CORSMiddleware (Starlette applies last-added outermost)
    application.add_middleware(
        OAuthSecurityResponseMiddleware,
        settings=settings,
    )

    # CORS configuration
    if settings.CORS_ORIGINS:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=settings.CORS_ORIGINS,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Register API v1 routes
    api_v1_router = APIRouter(prefix=settings.API_V1_PREFIX)
    api_v1_router.include_router(health.router)
    api_v1_router.include_router(auth.router)
    api_v1_router.include_router(oauth.router)
    application.include_router(api_v1_router)

    return application


app = create_app()
