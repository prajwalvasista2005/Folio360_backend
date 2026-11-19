"""Tests for synchronous GET /api/v1/health/ready, Option B concurrency, and resource cleanup."""

from concurrent.futures import ThreadPoolExecutor
import inspect
import logging
import threading
import time

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import event, text

from app.api.routes.health import readiness_check
from app.core.config import Settings
from app.db.session import (
    build_readiness_engine,
    build_readiness_semaphore,
    check_database_readiness,
)
from app.main import create_app


def assert_all_permits_restored(
    semaphore: threading.BoundedSemaphore,
    max_concurrency: int,
) -> None:
    """Verify full semaphore restoration using strictly public acquire/release APIs."""
    acquired = 0
    try:
        for _ in range(max_concurrency):
            assert semaphore.acquire(blocking=False) is True
            acquired += 1
        assert semaphore.acquire(blocking=False) is False
    finally:
        for _ in range(acquired):
            semaphore.release()


def test_readiness_route_and_probe_are_synchronous() -> None:
    """Verify readiness_check and check_database_readiness are plain synchronous functions."""
    assert inspect.iscoroutinefunction(readiness_check) is False
    assert inspect.iscoroutinefunction(check_database_readiness) is False


def test_health_ready_returns_503_when_database_unconfigured() -> None:
    """When DATABASE_URL is unset, /health stays 200 and /health/ready returns 503 unavailable."""
    settings = Settings(_env_file=None, ENVIRONMENT="testing", DATABASE_URL=None)
    custom_app = create_app(settings=settings)

    with TestClient(custom_app) as client:
        liveness = client.get("/api/v1/health")
        assert liveness.status_code == 200

        readiness = client.get("/api/v1/health/ready")
        assert readiness.status_code == 503
        assert readiness.json() == {"status": "unavailable"}


def test_health_ready_unreachable_database_within_budget_without_leaking_secrets(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Closed localhost port must return 503 quickly without leaking host, port, or credentials."""
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL="postgresql+psycopg://folio360_test_user:secret_probe_pw@127.0.0.1:59999/folio360_test",
        DB_READINESS_CONNECT_TIMEOUT=1,
        DB_READINESS_QUERY_TIMEOUT_MS=500,
    )
    custom_app = create_app(settings=settings)

    with caplog.at_level(logging.WARNING, logger="folio360.db"):
        with TestClient(custom_app) as client:
            started = time.monotonic()
            response = client.get("/api/v1/health/ready")
            elapsed = time.monotonic() - started

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}
    assert elapsed <= 6.0
    assert "secret_probe_pw" not in response.text
    assert "59999" not in response.text
    assert "127.0.0.1" not in response.text
    assert "secret_probe_pw" not in caplog.text
    assert "59999" not in caplog.text


@pytest.mark.db
def test_health_ready_healthy_database(test_database_url: str) -> None:
    """Healthy PostgreSQL test database yields 200 {"status": "ready"}."""
    settings = Settings(_env_file=None, ENVIRONMENT="testing", DATABASE_URL=test_database_url)
    custom_app = create_app(settings=settings)

    with TestClient(custom_app) as client:
        response = client.get("/api/v1/health/ready")
        assert response.status_code == 200
        assert response.json() == {"status": "ready"}


@pytest.mark.db
def test_health_ready_non_blocking_concurrency_limit_reached(
    test_database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    When all semaphore permits are held, /health/ready fails immediately with 503
    without waiting or calling readiness_engine.connect().
    """
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL=test_database_url,
        DB_READINESS_MAX_CONCURRENCY=1,
    )
    custom_app = create_app(settings=settings)

    with TestClient(custom_app) as client:
        semaphore = custom_app.state.db_readiness_semaphore
        readiness_engine = custom_app.state.db_readiness_engine

        connect_calls = 0
        original_connect = readiness_engine.connect

        def counted_connect(*args, **kwargs):
            nonlocal connect_calls
            connect_calls += 1
            return original_connect(*args, **kwargs)

        monkeypatch.setattr(readiness_engine, "connect", counted_connect)

        assert semaphore.acquire(blocking=False) is True
        try:
            started = time.monotonic()
            response = client.get("/api/v1/health/ready")
            elapsed = time.monotonic() - started
        finally:
            semaphore.release()

        assert response.status_code == 503
        assert response.json() == {"status": "unavailable"}
        assert elapsed < 0.5
        assert connect_calls == 0
        assert_all_permits_restored(semaphore, max_concurrency=1)


@pytest.mark.db
def test_multiple_concurrent_readiness_probes_bounded_to_per_process_limit(
    test_database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Dispatch 6 concurrent probes with DB_READINESS_MAX_CONCURRENCY=2 while holding
    the first 2 active probes at a barrier: peak active probes never exceeds 2,
    the 2 active probes succeed (200), and the excess 4 immediately return 503.
    """
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL=test_database_url,
        DB_READINESS_MAX_CONCURRENCY=2,
    )
    custom_app = create_app(settings=settings)

    with TestClient(custom_app) as client:
        readiness_engine = custom_app.state.db_readiness_engine
        original_connect = readiness_engine.connect

        lock = threading.Lock()
        active = 0
        peak_active = 0
        two_active = threading.Barrier(2, timeout=5.0)
        release_probes = threading.Event()

        class TrackedConnectionContext:
            def __init__(self, inner_ctx):
                self._inner = inner_ctx

            def __enter__(self):
                nonlocal active, peak_active
                with lock:
                    active += 1
                    peak_active = max(peak_active, active)
                two_active.wait()
                # Hold deterministically until the 4 burst requests have all shed with 503
                assert release_probes.wait(timeout=5.0) is True
                return self._inner.__enter__()

            def __exit__(self, exc_type, exc_val, exc_tb):
                nonlocal active
                try:
                    return self._inner.__exit__(exc_type, exc_val, exc_tb)
                finally:
                    with lock:
                        active -= 1

        monkeypatch.setattr(
            readiness_engine,
            "connect",
            lambda *args, **kwargs: TrackedConnectionContext(original_connect(*args, **kwargs)),
        )

        results: list[int] = []
        with ThreadPoolExecutor(max_workers=6) as executor:
            first_two = [
                executor.submit(lambda: client.get("/api/v1/health/ready").status_code)
                for _ in range(2)
            ]
            while True:
                with lock:
                    if active == 2:
                        break
                time.sleep(0.01)

            burst_four = [
                executor.submit(lambda: client.get("/api/v1/health/ready").status_code)
                for _ in range(4)
            ]
            try:
                for fut in burst_four:
                    results.append(fut.result(timeout=5.0))
            finally:
                release_probes.set()

            for fut in first_two:
                results.append(fut.result(timeout=5.0))

        assert peak_active == 2
        assert results.count(200) == 2
        assert results.count(503) == 4
        assert_all_permits_restored(custom_app.state.db_readiness_semaphore, max_concurrency=2)


@pytest.mark.db
def test_health_ready_hung_query_aborts_on_statement_timeout(
    test_database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Slow PostgreSQL query is aborted by SET LOCAL statement_timeout and returns 503 fast."""
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL=test_database_url,
        DB_READINESS_MAX_CONCURRENCY=1,
        DB_READINESS_CONNECT_TIMEOUT=3,
        DB_READINESS_QUERY_TIMEOUT_MS=200,
    )
    custom_app = create_app(settings=settings)

    with TestClient(custom_app) as client:
        readiness_engine = custom_app.state.db_readiness_engine
        original_connect = readiness_engine.connect

        class DelayedQueryConnection:
            def __init__(self, conn):
                self._conn = conn

            def __enter__(self):
                real_conn = self._conn.__enter__()
                orig_execute = real_conn.execute

                def patched_execute(statement, *args, **kwargs):
                    if "SELECT 1" in str(statement):
                        return orig_execute(text("SELECT pg_sleep(2)"), *args, **kwargs)
                    return orig_execute(statement, *args, **kwargs)

                monkeypatch.setattr(real_conn, "execute", patched_execute)
                return real_conn

            def __exit__(self, exc_type, exc_val, exc_tb):
                return self._conn.__exit__(exc_type, exc_val, exc_tb)

        monkeypatch.setattr(
            readiness_engine,
            "connect",
            lambda *args, **kwargs: DelayedQueryConnection(original_connect(*args, **kwargs)),
        )

        started = time.monotonic()
        response = client.get("/api/v1/health/ready")
        elapsed = time.monotonic() - started

        assert response.status_code == 503
        assert response.json() == {"status": "unavailable"}
        assert elapsed < 2.0
        assert_all_permits_restored(custom_app.state.db_readiness_semaphore, max_concurrency=1)


@pytest.mark.db
def test_health_ready_demonstrates_semantics_under_normal_pool_exhaustion(
    test_database_url: str,
) -> None:
    """
    Verify documented semantics: normal app pool exhaustion (holding all DB_POOL_SIZE=1,
    DB_MAX_OVERFLOW=0 slots while DB_POOL_TIMEOUT=30) does NOT block /health/ready for 30s;
    /health/ready reports 200 because Postgres and probe capacity remain healthy.
    """
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL=test_database_url,
        DB_POOL_SIZE=1,
        DB_MAX_OVERFLOW=0,
        DB_POOL_TIMEOUT=30,
    )
    custom_app = create_app(settings=settings)

    with TestClient(custom_app) as client:
        assert custom_app.state.settings.DB_POOL_TIMEOUT == 30
        held_session = custom_app.state.db_sessionmaker()
        try:
            # Force actual checkout of the sole normal pool connection
            held_session.execute(text("SELECT 1"))

            started = time.monotonic()
            response = client.get("/api/v1/health/ready")
            elapsed = time.monotonic() - started

            assert response.status_code == 200
            assert response.json() == {"status": "ready"}
            assert elapsed < 2.0
        finally:
            held_session.close()


@pytest.mark.db
def test_semaphore_restored_across_repeated_failures_and_subsequent_recovery(
    test_database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Confirm repeated connection/query failures never leak semaphore permits and a
    subsequent healthy probe recovers cleanly with 200.
    """
    healthy_settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL=test_database_url,
        DB_READINESS_MAX_CONCURRENCY=2,
    )
    readiness_engine = build_readiness_engine(healthy_settings)
    semaphore = build_readiness_semaphore(healthy_settings)

    try:
        # 1. Successful probe restores all permits
        assert check_database_readiness(readiness_engine, semaphore, healthy_settings) is True
        assert_all_permits_restored(semaphore, 2)

        # 2. 20 repeated consecutive failures restore all permits
        bad_settings = Settings(
            _env_file=None,
            ENVIRONMENT="testing",
            DATABASE_URL="postgresql+psycopg://folio360_test_user:pw@127.0.0.1:59999/folio360_test",
            DB_READINESS_MAX_CONCURRENCY=2,
            DB_READINESS_CONNECT_TIMEOUT=1,
        )
        bad_engine = build_readiness_engine(bad_settings)
        try:
            for _ in range(20):
                assert check_database_readiness(bad_engine, semaphore, bad_settings) is False
                assert_all_permits_restored(semaphore, 2)
        finally:
            bad_engine.dispose()

        # 3. Healthy probe immediately recovers
        assert check_database_readiness(readiness_engine, semaphore, healthy_settings) is True
        assert_all_permits_restored(semaphore, 2)
    finally:
        readiness_engine.dispose()


@pytest.mark.db
def test_readiness_probe_closes_connections_deterministically_via_pool_events(
    test_database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Authoritative SQLAlchemy NullPool connect/close event verification:
    opened_count == closed_count after both successful and failed probes.
    """
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL=test_database_url,
        DB_READINESS_MAX_CONCURRENCY=2,
        DB_READINESS_QUERY_TIMEOUT_MS=200,
    )
    readiness_engine = build_readiness_engine(settings)
    semaphore = build_readiness_semaphore(settings)

    counts = {"opened": 0, "closed": 0}

    def on_connect(dbapi_conn, conn_record) -> None:
        counts["opened"] += 1

    def on_close(dbapi_conn, conn_record) -> None:
        counts["closed"] += 1

    event.listen(readiness_engine.pool, "connect", on_connect)
    event.listen(readiness_engine.pool, "close", on_close)

    try:
        # Path 1: Successful probe opens and closes exactly 1 DBAPI connection
        assert check_database_readiness(readiness_engine, semaphore, settings) is True
        assert counts["opened"] == 1
        assert counts["closed"] == 1

        # Path 2: Failed post-connect query (statement_timeout) also closes its DBAPI connection
        original_connect = readiness_engine.connect

        class TimedOutConn:
            def __init__(self, ctx):
                self._ctx = ctx

            def __enter__(self):
                conn = self._ctx.__enter__()
                orig_execute = conn.execute

                def slow_execute(stmt, *args, **kwargs):
                    if "SELECT 1" in str(stmt):
                        return orig_execute(text("SELECT pg_sleep(2)"), *args, **kwargs)
                    return orig_execute(stmt, *args, **kwargs)

                monkeypatch.setattr(conn, "execute", slow_execute)
                return conn

            def __exit__(self, exc_type, exc_val, exc_tb):
                return self._ctx.__exit__(exc_type, exc_val, exc_tb)

        monkeypatch.setattr(
            readiness_engine,
            "connect",
            lambda *args, **kwargs: TimedOutConn(original_connect(*args, **kwargs)),
        )

        assert check_database_readiness(readiness_engine, semaphore, settings) is False
        assert counts["opened"] == 2
        assert counts["closed"] == 2
    finally:
        event.remove(readiness_engine.pool, "connect", on_connect)
        event.remove(readiness_engine.pool, "close", on_close)
        readiness_engine.dispose()


@pytest.mark.db
def test_readiness_probe_creates_zero_threads(
    test_database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify check_database_readiness executes synchronously and spawns zero Python threads."""
    settings = Settings(_env_file=None, ENVIRONMENT="testing", DATABASE_URL=test_database_url)
    readiness_engine = build_readiness_engine(settings)
    semaphore = build_readiness_semaphore(settings)

    thread_creations = 0
    original_thread_init = threading.Thread.__init__

    def tracked_thread_init(self, *args, **kwargs):
        nonlocal thread_creations
        thread_creations += 1
        return original_thread_init(self, *args, **kwargs)

    monkeypatch.setattr(threading.Thread, "__init__", tracked_thread_init)

    try:
        assert check_database_readiness(readiness_engine, semaphore, settings) is True
        assert thread_creations == 0
    finally:
        readiness_engine.dispose()
