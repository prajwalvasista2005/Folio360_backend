"""FastAPI application entry point and factory for Folio360."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
import logging

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import Engine

from app.api.routes import health
from app.core.config import Settings, get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import setup_logging
from app.db.session import (
    build_engine,
    build_readiness_engine,
    build_readiness_semaphore,
    build_sessionmaker,
)

logger = logging.getLogger("folio360.main")


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
    setup_logging(log_level=settings.LOG_LEVEL)
    _reset_db_state(app)

    db_engine: Engine | None = None
    readiness_engine: Engine | None = None
    startup_completed = False

    try:
        settings.validate_runtime_requirements()
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


def create_app(settings: Settings | None = None) -> FastAPI:
    """FastAPI application factory."""
    if settings is None:
        settings = get_settings()

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=settings.APP_DESCRIPTION,
        docs_url=settings.DOCS_URL,
        openapi_url=settings.OPENAPI_URL,
        lifespan=lifespan,
    )

    # Attach settings instance and initialize DB state placeholders without side effects
    app.state.settings = settings
    _reset_db_state(app)

    # Centralized exception handling
    register_exception_handlers(app)

    # CORS configuration
    if settings.CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.CORS_ORIGINS,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Register API v1 routes
    api_v1_router = APIRouter(prefix=settings.API_V1_PREFIX)
    api_v1_router.include_router(health.router)
    app.include_router(api_v1_router)

    return app


app = create_app()
