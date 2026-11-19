"""Synchronous SQLAlchemy engine, session factory, readiness probe, and FastAPI dependency."""

from collections.abc import Generator
import logging
import threading
from typing import Any, Optional

from fastapi import Request, status
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.core.exceptions import AppException

logger = logging.getLogger("folio360.db")


class DatabaseUnavailableError(AppException):
    """Raised when the database session factory is unavailable."""

    def __init__(
        self,
        message: str = "Database service is unavailable",
        details: Optional[Any] = None,
        public_message: Optional[str] = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            details=details,
            public_message=public_message,
        )


def _require_database_url(settings: Settings) -> str:
    """Return the configured database URL string or raise ValueError without leaking secrets."""
    if settings.DATABASE_URL is None:
        raise ValueError("DATABASE_URL must be configured")
    database_url = settings.DATABASE_URL.get_secret_value().strip()
    if not database_url:
        raise ValueError("DATABASE_URL must be configured")
    return database_url


def build_engine(settings: Settings) -> Engine:
    """Create the primary synchronous pooled SQLAlchemy engine."""
    database_url = _require_database_url(settings)
    return create_engine(
        database_url,
        pool_pre_ping=True,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT,
        echo=settings.DB_ECHO,
        hide_parameters=True,
        connect_args={"connect_timeout": settings.DB_CONNECT_TIMEOUT},
    )


def build_sessionmaker(engine: Engine) -> sessionmaker[Session]:
    """Create a synchronous SQLAlchemy sessionmaker bound to the given engine."""
    return sessionmaker(
        bind=engine,
        class_=Session,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )


def build_readiness_engine(settings: Settings) -> Engine:
    """Create a dedicated NullPool SQLAlchemy engine for readiness probes."""
    database_url = _require_database_url(settings)
    return create_engine(
        database_url,
        poolclass=NullPool,
        echo=False,
        hide_parameters=True,
        connect_args={"connect_timeout": settings.DB_READINESS_CONNECT_TIMEOUT},
    )


def build_readiness_semaphore(settings: Settings) -> threading.BoundedSemaphore:
    """Create a bounded semaphore capping concurrent database readiness probes."""
    return threading.BoundedSemaphore(settings.DB_READINESS_MAX_CONCURRENCY)


def check_database_readiness(
    readiness_engine: Optional[Engine],
    readiness_semaphore: Optional[threading.BoundedSemaphore],
    settings: Settings,
) -> bool:
    """
    Perform a bounded, non-blocking synchronous database readiness check.

    Returns False if readiness resources are uninitialized, concurrency permits are
    exhausted, or the probe fails/times out. Logs only exception type names on failure.
    """
    if readiness_engine is None or readiness_semaphore is None:
        return False

    acquired = readiness_semaphore.acquire(blocking=False)
    if not acquired:
        logger.warning("Database readiness check skipped: concurrency limit reached")
        return False

    try:
        raw_timeout = settings.DB_READINESS_QUERY_TIMEOUT_MS
        if isinstance(raw_timeout, bool):
            raise ValueError("DB_READINESS_QUERY_TIMEOUT_MS must be a positive integer")
        timeout_ms = int(raw_timeout)
        if timeout_ms <= 0:
            raise ValueError("DB_READINESS_QUERY_TIMEOUT_MS must be a positive integer")

        with readiness_engine.connect() as conn:
            with conn.begin():
                conn.execute(text(f"SET LOCAL statement_timeout = {timeout_ms}"))
                conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.warning(
            "Database readiness check failed: %s",
            type(exc).__name__,
        )
        return False
    finally:
        if acquired:
            readiness_semaphore.release()


def get_db(request: Request) -> Generator[Session, None, None]:
    """Yield a synchronous SQLAlchemy Session for the request without auto-commit."""
    db_sessionmaker = getattr(request.app.state, "db_sessionmaker", None)
    if db_sessionmaker is None:
        raise DatabaseUnavailableError("Database session factory is not initialized")

    session: Session = db_sessionmaker()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
