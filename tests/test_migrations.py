"""Isolated destructive Alembic migration round-trip tests restricted strictly to _test DBs."""

import os

from alembic import command
import pytest
from sqlalchemy import Engine, create_engine, inspect
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from tests.conftest import build_alembic_config, verify_test_database_identity


@pytest.mark.db
@pytest.mark.migration
def test_alembic_downgrade_upgrade_round_trip_and_schema_check(
    test_database_url: str,
    db_engine: Engine,
) -> None:
    """
    Verify upgrade -> downgrade base -> upgrade head -> alembic check exclusively
    on the disposable `_test` database, always restoring head in finally.
    """
    verify_test_database_identity(test_database_url)

    # Release any pooled sessions from earlier tests so DDL locks cannot stall.
    db_engine.dispose()

    previous_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = test_database_url
    get_settings.cache_clear()

    inspect_engine = create_engine(
        test_database_url,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"connect_timeout": 5},
    )

    try:
        cfg = build_alembic_config(test_database_url)

        # 1. Downgrade to base drops the users table
        command.downgrade(cfg, "base")
        assert inspect(inspect_engine).has_table("users") is False

        # 2. Upgrade back to head recreates users with exact columns and constraints
        command.upgrade(cfg, "head")
        inspector = inspect(inspect_engine)
        assert inspector.has_table("users") is True

        columns = {col["name"]: col for col in inspector.get_columns("users")}
        assert set(columns.keys()) == {"id", "email", "is_active", "created_at", "updated_at"}
        assert columns["email"]["nullable"] is False
        assert columns["is_active"]["nullable"] is False

        pk = inspector.get_pk_constraint("users")
        assert pk["name"] == "pk_users"
        assert pk["constrained_columns"] == ["id"]

        uniques = {uc["name"]: uc for uc in inspector.get_unique_constraints("users")}
        assert "uq_users_email" in uniques
        assert uniques["uq_users_email"]["column_names"] == ["email"]

        checks = {cc["name"]: cc["sqltext"] for cc in inspector.get_check_constraints("users")}
        assert "ck_users_email_lowercase_trimmed" in checks
        assert "ck_users_email_not_empty" in checks
        assert "ck_users_email_no_whitespace" in checks

        # 3. Verify live schema matches SQLAlchemy ORM metadata with zero drift
        command.check(cfg)
    finally:
        try:
            command.upgrade(build_alembic_config(test_database_url), "head")
        finally:
            inspect_engine.dispose()
            if previous_url is None:
                os.environ.pop("DATABASE_URL", None)
            else:
                os.environ["DATABASE_URL"] = previous_url
            get_settings.cache_clear()
