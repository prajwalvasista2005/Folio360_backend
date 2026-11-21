"""Shared pytest fixtures and two-stage database safety guards for Folio360."""

from collections.abc import Generator
import os
from pathlib import Path

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.core.config import Settings, get_settings
from app.db.session import build_engine, build_sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALEMBIC_INI_PATH = PROJECT_ROOT / "alembic.ini"

FORBIDDEN_DB_NAMES = {"folio360_dev", "postgres", "template0", "template1"}


def verify_test_database_identity(
    raw_url: str,
    engine: Engine | None = None,
    *,
    allow_migrator: bool = False,
) -> tuple[str, str]:
    """
    Verify both statically and against the live PostgreSQL server that tests
    target a disposable `_test` database with an expected non-privileged test role.
    """
    cleaned = raw_url.strip()
    if not cleaned:
        raise RuntimeError("Database URL must not be empty")

    try:
        url = make_url(cleaned)
    except (ArgumentError, ValueError):
        raise RuntimeError("Invalid test database URL format") from None

    if url.drivername != "postgresql+psycopg":
        raise RuntimeError("Test database URL must use the 'postgresql+psycopg' driver")

    db_name = (url.database or "").strip()
    if not db_name or not db_name.endswith("_test") or db_name in FORBIDDEN_DB_NAMES:
        raise RuntimeError(
            "Refusing to run tests: database name must end with '_test' and not be a dev/system DB"
        )

    username = (url.username or "").strip()
    if (
        not username
        or username == "postgres"
        or username.startswith("folio360_dev")
        or username.endswith("_admin")
    ):
        raise RuntimeError(
            "Refusing to run tests: database role must be a non-admin, non-dev test role"
        )

    if allow_migrator:
        if not username.endswith("_migrator"):
            raise RuntimeError(
                "Refusing to run migrations: migration role must end with '_migrator'"
            )
    elif username.endswith("_migrator"):
        raise RuntimeError(
            "Refusing to run application tests: TEST_DATABASE_URL must not use the migrator role"
        )

    # Stage B: Live server identity verification
    check_engine = engine
    owns_engine = False
    if check_engine is None:
        check_engine = create_engine(
            cleaned,
            poolclass=NullPool,
            hide_parameters=True,
            connect_args={"connect_timeout": 5},
        )
        owns_engine = True

    try:
        with check_engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT current_database(), current_user, current_setting('is_superuser')"
                )
            ).one()
            live_db, live_user, is_superuser = str(row[0]), str(row[1]), str(row[2])

        if live_db != db_name or not live_db.endswith("_test") or live_db in FORBIDDEN_DB_NAMES:
            raise RuntimeError(
                f"Live DB identity check failed: unexpected current_database '{live_db}'"
            )
        if (
            live_user != username
            or live_user == "postgres"
            or live_user.startswith("folio360_dev")
            or live_user.endswith("_admin")
        ):
            raise RuntimeError(
                f"Live DB role check failed: unexpected current_user '{live_user}'"
            )
        if allow_migrator and not live_user.endswith("_migrator"):
            raise RuntimeError(
                f"Live DB migration role check failed: unexpected current_user '{live_user}'"
            )
        if not allow_migrator and live_user.endswith("_migrator"):
            raise RuntimeError(
                f"Live DB app role check failed: unexpected migrator user '{live_user}'"
            )
        if is_superuser.lower() != "off":
            raise RuntimeError(
                "Refusing to run tests: test database role must not have superuser privileges"
            )
        return live_db, live_user
    finally:
        if owns_engine:
            check_engine.dispose()


def build_alembic_config(database_url: str) -> Config:
    """Create an Alembic Config scoped to the project root."""
    del database_url  # Resolved cleanly through Settings.MIGRATION_DATABASE_URL inside alembic/env.py
    cfg = Config(str(ALEMBIC_INI_PATH))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "alembic"))
    return cfg


def run_alembic_with_database_url(database_url: str, action: str, target: str = "head") -> None:
    """Run an Alembic command using the `_test` migrator URL without mutating global caches."""
    verify_test_database_identity(database_url, allow_migrator=True)
    previous_migration_url = os.environ.get("MIGRATION_DATABASE_URL")
    os.environ["MIGRATION_DATABASE_URL"] = database_url
    get_settings.cache_clear()
    try:
        cfg = build_alembic_config(database_url)
        if action == "upgrade":
            command.upgrade(cfg, target)
        elif action == "downgrade":
            command.downgrade(cfg, target)
        elif action == "check":
            command.check(cfg)
        else:
            raise ValueError(f"Unsupported Alembic action: {action}")
    finally:
        if previous_migration_url is None:
            os.environ.pop("MIGRATION_DATABASE_URL", None)
        else:
            os.environ["MIGRATION_DATABASE_URL"] = previous_migration_url
        get_settings.cache_clear()


@pytest.fixture(scope="session")
def test_database_url() -> str:
    """Return validated DML-only TEST_DATABASE_URL or fail loudly."""
    raw_url = os.environ.get("TEST_DATABASE_URL", "").strip()
    if not raw_url:
        raise RuntimeError(
            "TEST_DATABASE_URL environment variable is required to execute @pytest.mark.db tests. "
            "To run unit tests without a database, pass: -m 'not db and not migration'"
        )
    verify_test_database_identity(raw_url, allow_migrator=False)
    return raw_url


@pytest.fixture(scope="session")
def test_migration_database_url() -> str:
    """Return validated migrator TEST_MIGRATION_DATABASE_URL or fail loudly."""
    raw_url = os.environ.get("TEST_MIGRATION_DATABASE_URL", "").strip()
    if not raw_url:
        raise RuntimeError(
            "TEST_MIGRATION_DATABASE_URL environment variable is required to run database migrations in tests."
        )
    verify_test_database_identity(raw_url, allow_migrator=True)
    return raw_url


@pytest.fixture(scope="session")
def db_engine(
    test_database_url: str,
    test_migration_database_url: str,
) -> Generator[Engine, None, None]:
    """Migrate _test DB with the migrator role, then yield a DML-only runtime Engine."""
    run_alembic_with_database_url(test_migration_database_url, action="upgrade", target="head")

    engine = build_engine(Settings(DATABASE_URL=test_database_url))
    try:
        verify_test_database_identity(test_database_url, engine=engine, allow_migrator=False)
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Generator[Session, None, None]:
    """Provide a per-test Session wrapped in an outer transaction with SAVEPOINT rollback."""
    connection = db_engine.connect()
    outer_tx = connection.begin()
    session = Session(
        bind=connection,
        join_transaction_mode="create_savepoint",
        expire_on_commit=False,
    )
    try:
        yield session
    finally:
        session.close()
        outer_tx.rollback()
        connection.close()


@pytest.fixture
def committed_db_session(
    test_database_url: str,
    db_engine: Engine,
) -> Generator[Session, None, None]:
    """Provide a real-commit Session for multi-connection visibility tests with guaranteed table cleanup."""
    verify_test_database_identity(test_database_url, engine=db_engine, allow_migrator=False)
    session_factory = build_sessionmaker(db_engine)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
        with db_engine.begin() as conn:
            conn.execute(text("DELETE FROM users"))
