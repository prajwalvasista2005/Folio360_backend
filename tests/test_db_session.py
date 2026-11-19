"""Tests for Stage 2 DB config, URL redaction, session lifecycle, and partial-startup cleanup."""

from unittest.mock import MagicMock

from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import sanitize_log_text
from app.db.session import (
    DatabaseUnavailableError,
    build_engine,
    build_readiness_engine,
    build_readiness_semaphore,
    build_sessionmaker,
    get_db,
)
import app.main as main_module
from tests.conftest import verify_test_database_identity


def test_database_url_validation_and_secret_masking() -> None:
    """Validate postgresql+psycopg URL rules and SecretStr masking."""
    settings = Settings(
        _env_file=None,
        DATABASE_URL="  postgresql+psycopg://folio360_dev_user:super_secret_pw@127.0.0.1:5433/folio360_dev  ",
    )
    assert settings.DATABASE_URL is not None
    assert (
        settings.DATABASE_URL.get_secret_value()
        == "postgresql+psycopg://folio360_dev_user:super_secret_pw@127.0.0.1:5433/folio360_dev"
    )
    assert "super_secret_pw" not in repr(settings)
    assert "super_secret_pw" not in str(settings)

    for bad_url in (
        "",
        "   ",
        "postgresql://user:super_secret_pw@localhost:5432/folio360",
        "sqlite:///tmp/test.db",
        "not_a_valid_url",
        "postgresql+psycopg://user:super_secret_pw@/folio360",
        "postgresql+psycopg://user:super_secret_pw@localhost:5432/",
    ):
        with pytest.raises(ValidationError) as exc_info:
            Settings(_env_file=None, DATABASE_URL=bad_url)
        assert "super_secret_pw" not in str(exc_info.value)


def test_readiness_budget_and_pool_bounds_validation() -> None:
    """Enforce pool bounds and combined readiness timeout budget <= 5.0 seconds."""
    # Valid boundary: 4 + 1000/1000.0 == 5.0
    valid = Settings(
        _env_file=None,
        DB_READINESS_CONNECT_TIMEOUT=4,
        DB_READINESS_QUERY_TIMEOUT_MS=1000,
    )
    assert valid.DB_READINESS_CONNECT_TIMEOUT == 4
    assert valid.DB_POOL_TIMEOUT == 30
    assert valid.DB_CONNECT_TIMEOUT == 5

    # Exceeding 5.0 seconds must fail validation (4 + 1500/1000 = 5.5 > 5.0)
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            _env_file=None,
            DB_READINESS_CONNECT_TIMEOUT=4,
            DB_READINESS_QUERY_TIMEOUT_MS=1500,
        )
    assert "5.0 seconds" in str(exc_info.value)

    with pytest.raises(ValidationError):
        Settings(_env_file=None, DB_POOL_SIZE=0)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, DB_POOL_TIMEOUT=121)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, DB_READINESS_MAX_CONCURRENCY=11)


def test_production_runtime_validation_and_import_safety() -> None:
    """
    Create_app with ENVIRONMENT=production and no DATABASE_URL must not fail at
    app construction time, but must fail fast during lifespan startup.
    """
    prod_missing_db = Settings(_env_file=None, ENVIRONMENT="production", DATABASE_URL=None)
    prod_app = main_module.create_app(settings=prod_missing_db)
    assert prod_app.state.db_engine is None
    assert prod_app.state.db_sessionmaker is None
    assert prod_app.state.db_readiness_engine is None
    assert prod_app.state.db_readiness_semaphore is None

    with pytest.raises(RuntimeError, match="DATABASE_URL must be configured"):
        with TestClient(prod_app):
            pass

    prod_echo_true = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        DATABASE_URL="postgresql+psycopg://u:p@db:5432/folio",
        DB_ECHO=True,
    )
    echo_app = main_module.create_app(settings=prod_echo_true)
    with pytest.raises(RuntimeError, match="DB_ECHO must be False"):
        with TestClient(echo_app):
            pass

    # Development and testing allow unconfigured DATABASE_URL cleanly
    dev_settings = Settings(_env_file=None, ENVIRONMENT="development", DATABASE_URL=None)
    dev_settings.validate_runtime_requirements()


def test_logging_redacts_sqlalchemy_driver_connection_strings() -> None:
    """Verify +driver URLs redact completely to [REDACTED_CONNECTION_STRING]."""
    assert (
        sanitize_log_text("Failed connecting to postgresql+psycopg://u:secret_pw@db:5432/folio360")
        == "Failed connecting to [REDACTED_CONNECTION_STRING]"
    )
    assert (
        sanitize_log_text("DSN=postgres+asyncpg://admin:pw@db.internal/app")
        == "DSN=[REDACTED_CONNECTION_STRING]"
    )
    assert (
        sanitize_log_text("mysql+pymysql://root:pw@localhost:3306/db")
        == "[REDACTED_CONNECTION_STRING]"
    )


def test_build_engine_and_sessionmaker_configuration() -> None:
    """Verify engine pool options, hide_parameters=True, and sessionmaker flags."""
    settings = Settings(
        _env_file=None,
        DATABASE_URL="postgresql+psycopg://u:p@127.0.0.1:5434/folio360_test",
        DB_POOL_SIZE=7,
        DB_MAX_OVERFLOW=3,
        DB_POOL_TIMEOUT=45,
        DB_CONNECT_TIMEOUT=6,
    )
    engine = build_engine(settings)
    try:
        assert engine.hide_parameters is True
        assert engine.pool._pre_ping is True
        assert engine.pool.size() == 7
        assert engine.pool._max_overflow == 3
        assert engine.pool._timeout == 45

        factory = build_sessionmaker(engine)
        assert factory.kw["autocommit"] is False
        assert factory.kw["autoflush"] is False
        assert factory.kw["expire_on_commit"] is False
    finally:
        engine.dispose()

    readiness_engine = build_readiness_engine(settings)
    try:
        assert readiness_engine.hide_parameters is True
    finally:
        readiness_engine.dispose()


def test_get_db_raises_when_uninitialized_and_manages_commit_rollback_close() -> None:
    """Verify get_db behavior when uninitialized, on success, and on exception."""
    mock_request = MagicMock(spec=Request)
    mock_request.app = FastAPI()
    mock_request.app.state.db_sessionmaker = None

    gen = get_db(mock_request)
    with pytest.raises(DatabaseUnavailableError) as exc_info:
        next(gen)
    assert exc_info.value.status_code == 503

    mock_session = MagicMock(spec=Session)
    mock_factory = MagicMock(return_value=mock_session)
    mock_request.app.state.db_sessionmaker = mock_factory

    # Normal exit closes without committing or rolling back
    gen_ok = get_db(mock_request)
    yielded = next(gen_ok)
    assert yielded is mock_session
    with pytest.raises(StopIteration):
        next(gen_ok)
    mock_session.commit.assert_not_called()
    mock_session.rollback.assert_not_called()
    mock_session.close.assert_called_once()

    # Exception triggers rollback and close
    mock_session.reset_mock()
    gen_err = get_db(mock_request)
    next(gen_err)
    with pytest.raises(ValueError, match="boom"):
        gen_err.throw(ValueError("boom"))
    mock_session.commit.assert_not_called()
    mock_session.rollback.assert_called_once()
    mock_session.close.assert_called_once()


def test_sessionmaker_initialization_failure_disposes_engine_and_resets_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Mandatory Stage 2 test:
    Simulate build_engine() succeeding and build_sessionmaker() raising an error.
    Verify app engine is disposed once, all 4 app.state attrs reset to None,
    and original exception propagates unmasked.
    """
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL="postgresql+psycopg://u:p@127.0.0.1:5434/folio360_test",
    )
    mock_db_engine = MagicMock(spec=Engine)
    mock_build_engine = MagicMock(return_value=mock_db_engine)
    mock_build_readiness_engine = MagicMock()
    mock_build_semaphore = MagicMock()

    def failing_sessionmaker(engine: Engine) -> None:
        raise RuntimeError("sessionmaker_init_failed")

    monkeypatch.setattr(main_module, "build_engine", mock_build_engine)
    monkeypatch.setattr(main_module, "build_sessionmaker", failing_sessionmaker)
    monkeypatch.setattr(main_module, "build_readiness_engine", mock_build_readiness_engine)
    monkeypatch.setattr(main_module, "build_readiness_semaphore", mock_build_semaphore)

    app = main_module.create_app(settings=settings)
    with pytest.raises(RuntimeError, match="sessionmaker_init_failed"):
        with TestClient(app):
            pass

    mock_build_engine.assert_called_once_with(settings)
    mock_db_engine.dispose.assert_called_once()
    mock_build_readiness_engine.assert_not_called()
    mock_build_semaphore.assert_not_called()
    assert app.state.db_engine is None
    assert app.state.db_sessionmaker is None
    assert app.state.db_readiness_engine is None
    assert app.state.db_readiness_semaphore is None


def test_readiness_engine_failure_disposes_db_engine_and_resets_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If build_readiness_engine fails after build_engine succeeds, dispose db_engine once."""
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL="postgresql+psycopg://u:p@127.0.0.1:5434/folio360_test",
    )
    mock_db_engine = MagicMock(spec=Engine)
    mock_sessionmaker = MagicMock()
    mock_build_semaphore = MagicMock()

    monkeypatch.setattr(main_module, "build_engine", MagicMock(return_value=mock_db_engine))
    monkeypatch.setattr(main_module, "build_sessionmaker", MagicMock(return_value=mock_sessionmaker))
    monkeypatch.setattr(
        main_module,
        "build_readiness_engine",
        MagicMock(side_effect=RuntimeError("readiness_init_failed")),
    )
    monkeypatch.setattr(main_module, "build_readiness_semaphore", mock_build_semaphore)

    app = main_module.create_app(settings=settings)
    with pytest.raises(RuntimeError, match="readiness_init_failed"):
        with TestClient(app):
            pass

    mock_db_engine.dispose.assert_called_once()
    mock_build_semaphore.assert_not_called()
    assert app.state.db_engine is None
    assert app.state.db_sessionmaker is None
    assert app.state.db_readiness_engine is None
    assert app.state.db_readiness_semaphore is None


def test_semaphore_failure_disposes_both_engines_without_masking_original_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    If build_readiness_semaphore fails after both engines are built, both engines
    are disposed once and even a disposal error does not mask the startup exception.
    """
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL="postgresql+psycopg://u:p@127.0.0.1:5434/folio360_test",
    )
    mock_db_engine = MagicMock(spec=Engine)
    mock_readiness_engine = MagicMock(spec=Engine)
    mock_readiness_engine.dispose.side_effect = RuntimeError("cleanup_dispose_error")

    monkeypatch.setattr(main_module, "build_engine", MagicMock(return_value=mock_db_engine))
    monkeypatch.setattr(main_module, "build_sessionmaker", MagicMock(return_value=MagicMock()))
    monkeypatch.setattr(
        main_module, "build_readiness_engine", MagicMock(return_value=mock_readiness_engine)
    )
    monkeypatch.setattr(
        main_module,
        "build_readiness_semaphore",
        MagicMock(side_effect=RuntimeError("semaphore_init_failed")),
    )

    app = main_module.create_app(settings=settings)
    with pytest.raises(RuntimeError, match="semaphore_init_failed"):
        with TestClient(app):
            pass

    mock_readiness_engine.dispose.assert_called_once()
    mock_db_engine.dispose.assert_called_once()
    assert app.state.db_engine is None
    assert app.state.db_sessionmaker is None
    assert app.state.db_readiness_engine is None
    assert app.state.db_readiness_semaphore is None


def test_verify_test_database_identity_rejects_dev_and_admin_urls() -> None:
    """Confirm test guard blocks non-_test DBs, dev roles, and admin roles before connecting."""
    for unsafe_url in (
        "",
        "sqlite:///tmp.db",
        "postgresql+psycopg://folio360_test_user:pw@127.0.0.1:5433/folio360_dev",
        "postgresql+psycopg://folio360_test_user:pw@127.0.0.1:5433/postgres",
        "postgresql+psycopg://folio360_dev_user:pw@127.0.0.1:5434/folio360_test",
        "postgresql+psycopg://folio360_test_admin:pw@127.0.0.1:5434/folio360_test",
        "postgresql+psycopg://postgres:pw@127.0.0.1:5434/folio360_test",
    ):
        with pytest.raises(RuntimeError):
            verify_test_database_identity(unsafe_url)


@pytest.mark.db
def test_lifespan_initializes_disposes_and_supports_get_db_dependency(
    test_database_url: str,
    db_session: Session,
) -> None:
    """Verify real lifespan startup/shutdown resource disposal and get_db dependency usage."""
    settings = Settings(_env_file=None, ENVIRONMENT="testing", DATABASE_URL=test_database_url)
    app = main_module.create_app(settings=settings)

    @app.get("/_test-db-ping")
    def _ping(session: Session = Depends(get_db)) -> dict[str, int]:
        val = session.execute(text("SELECT 1")).scalar_one()
        return {"ok": int(val)}

    assert app.state.db_engine is None
    with TestClient(app) as client:
        assert app.state.db_engine is not None
        assert app.state.db_sessionmaker is not None
        assert app.state.db_readiness_engine is not None
        assert app.state.db_readiness_semaphore is not None

        res = client.get("/_test-db-ping")
        assert res.status_code == 200
        assert res.json() == {"ok": 1}

        # Verify dependency override works cleanly with db_session fixture
        app.dependency_overrides[get_db] = lambda: db_session
        res_override = client.get("/_test-db-ping")
        assert res_override.status_code == 200
        assert res_override.json() == {"ok": 1}
        app.dependency_overrides.clear()

    assert app.state.db_engine is None
    assert app.state.db_sessionmaker is None
    assert app.state.db_readiness_engine is None
    assert app.state.db_readiness_semaphore is None
