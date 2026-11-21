"""Isolated destructive Alembic migration and split-role privilege tests on _test DBs."""

import os

from alembic import command
import pytest
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from tests.conftest import build_alembic_config, verify_test_database_identity


@pytest.mark.db
@pytest.mark.migration
def test_alembic_0001_populated_upgrade_to_head_reversibility_and_schema_check(
    test_database_url: str,
    test_migration_database_url: str,
    db_engine: Engine,
) -> None:
    """
    Verify:
      1. Downgrade to base drops all tables.
      2. Upgrade to 0001_create_users preserves exact original 5-column users schema without auth tables.
      3. Populated 0001_create_users row upgrades cleanly to head (0002_add_core_auth_tables) with defaults.
      4. Full Stage 3A schema (users, email_verification_tokens, refresh_sessions) and absence of 3B/3C tables.
      5. Round-trip downgrade 0001 -> upgrade head -> downgrade base -> upgrade head -> alembic check.
    """
    verify_test_database_identity(test_database_url, allow_migrator=False)
    verify_test_database_identity(test_migration_database_url, allow_migrator=True)

    # Release any pooled app connections so DDL locks cannot stall.
    db_engine.dispose()

    previous_migration_url = os.environ.get("MIGRATION_DATABASE_URL")
    os.environ["MIGRATION_DATABASE_URL"] = test_migration_database_url
    get_settings.cache_clear()

    migrator_inspect_engine = create_engine(
        test_migration_database_url,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"connect_timeout": 5},
    )

    try:
        cfg = build_alembic_config(test_migration_database_url)

        # 1. Downgrade to base drops all tables
        command.downgrade(cfg, "base")
        base_inspector = inspect(migrator_inspect_engine)
        assert base_inspector.has_table("users") is False
        assert base_inspector.has_table("email_verification_tokens") is False
        assert base_inspector.has_table("refresh_sessions") is False

        # 2. Upgrade to original Stage 2 baseline 0001_create_users
        command.upgrade(cfg, "0001_create_users")
        v1_inspector = inspect(migrator_inspect_engine)
        assert v1_inspector.has_table("users") is True
        assert v1_inspector.has_table("email_verification_tokens") is False
        assert v1_inspector.has_table("refresh_sessions") is False

        v1_columns = {col["name"]: col for col in v1_inspector.get_columns("users")}
        assert set(v1_columns.keys()) == {"id", "email", "is_active", "created_at", "updated_at"}
        assert v1_columns["email"]["nullable"] is False
        assert v1_columns["is_active"]["nullable"] is False

        v1_pk = v1_inspector.get_pk_constraint("users")
        assert v1_pk["name"] == "pk_users"
        assert v1_pk["constrained_columns"] == ["id"]

        v1_uniques = {uc["name"]: uc for uc in v1_inspector.get_unique_constraints("users")}
        assert "uq_users_email" in v1_uniques
        assert v1_uniques["uq_users_email"]["column_names"] == ["email"]

        v1_checks = {cc["name"]: cc["sqltext"] for cc in v1_inspector.get_check_constraints("users")}
        assert set(v1_checks.keys()) == {
            "ck_users_email_lowercase_trimmed",
            "ck_users_email_not_empty",
            "ck_users_email_no_whitespace",
        }

        # Populate a legacy user row at 0001_create_users before upgrading to head
        with migrator_inspect_engine.begin() as conn:
            conn.execute(
                text("INSERT INTO users (email) VALUES (:email)"),
                {"email": "legacy.stage2@example.com"},
            )

        # 3. Upgrade populated 0001 DB to head (0002_add_core_auth_tables)
        command.upgrade(cfg, "head")
        head_inspector = inspect(migrator_inspect_engine)
        assert head_inspector.has_table("users") is True
        assert head_inspector.has_table("email_verification_tokens") is True
        assert head_inspector.has_table("refresh_sessions") is True

        # Ensure Stage 3B/3C tables are NOT present
        for excluded_table in (
            "password_reset_tokens",
            "oauth_accounts",
            "oauth_states",
            "oauth_exchange_codes",
        ):
            assert head_inspector.has_table(excluded_table) is False

        # Verify legacy populated user received exact Rev10 defaults
        with migrator_inspect_engine.connect() as conn:
            legacy_row = conn.execute(
                text(
                    "SELECT password_hash, is_email_verified, email_verified_at, "
                    "auth_version, password_changed_at "
                    "FROM users WHERE email = :email"
                ),
                {"email": "legacy.stage2@example.com"},
            ).mappings().one()
            assert legacy_row["password_hash"] is None
            assert legacy_row["is_email_verified"] is False
            assert legacy_row["email_verified_at"] is None
            assert legacy_row["auth_version"] == 0
            assert legacy_row["password_changed_at"] is None

        # 4. Verify complete Stage 3A users columns & constraints
        users_cols = {col["name"]: col for col in head_inspector.get_columns("users")}
        assert set(users_cols.keys()) == {
            "id",
            "email",
            "password_hash",
            "is_active",
            "is_email_verified",
            "email_verified_at",
            "auth_version",
            "password_changed_at",
            "created_at",
            "updated_at",
        }
        assert users_cols["password_hash"]["nullable"] is True
        assert users_cols["is_email_verified"]["nullable"] is False
        assert users_cols["email_verified_at"]["nullable"] is True
        assert users_cols["auth_version"]["nullable"] is False
        assert users_cols["password_changed_at"]["nullable"] is True

        users_checks = {cc["name"] for cc in head_inspector.get_check_constraints("users")}
        assert users_checks == {
            "ck_users_email_lowercase_trimmed",
            "ck_users_email_not_empty",
            "ck_users_email_no_whitespace",
            "ck_users_email_verified_at_consistency",
            "ck_users_auth_version_non_negative",
        }

        # Verify email_verification_tokens schema
        evt_cols = {
            col["name"]: col for col in head_inspector.get_columns("email_verification_tokens")
        }
        assert set(evt_cols.keys()) == {
            "id",
            "user_id",
            "token_hash",
            "delivery_status",
            "delivery_attempted_at",
            "expires_at",
            "consumed_at",
            "revoked_at",
            "created_at",
            "updated_at",
        }
        assert evt_cols["user_id"]["nullable"] is False
        assert evt_cols["token_hash"]["nullable"] is False
        assert evt_cols["delivery_status"]["nullable"] is False
        assert evt_cols["expires_at"]["nullable"] is False
        assert head_inspector.get_pk_constraint("email_verification_tokens")["name"] == (
            "pk_email_verification_tokens"
        )
        evt_uniques = {
            uc["name"] for uc in head_inspector.get_unique_constraints("email_verification_tokens")
        }
        assert "uq_email_verification_tokens_token_hash" in evt_uniques
        evt_checks = {
            cc["name"] for cc in head_inspector.get_check_constraints("email_verification_tokens")
        }
        assert evt_checks == {
            "ck_email_verification_tokens_delivery_status",
            "ck_email_verification_tokens_hash_hex",
            "ck_email_verification_tokens_not_both_consumed_revoked",
        }
        evt_indexes = {
            idx["name"] for idx in head_inspector.get_indexes("email_verification_tokens")
        }
        assert {
            "ix_email_verification_tokens_user_created",
            "ix_email_verification_tokens_expires_at",
        }.issubset(evt_indexes)
        evt_fks = head_inspector.get_foreign_keys("email_verification_tokens")
        assert len(evt_fks) == 1
        assert evt_fks[0]["referred_table"] == "users"
        assert evt_fks[0]["options"].get("ondelete") == "CASCADE"

        # Verify refresh_sessions schema
        rs_cols = {col["name"]: col for col in head_inspector.get_columns("refresh_sessions")}
        assert set(rs_cols.keys()) == {
            "id",
            "user_id",
            "family_id",
            "token_hash",
            "parent_session_id",
            "replaced_by_session_id",
            "client_type",
            "user_agent",
            "ip_address",
            "expires_at",
            "family_expires_at",
            "last_used_at",
            "revoked_at",
            "revoke_reason",
            "created_at",
            "updated_at",
        }
        assert head_inspector.get_pk_constraint("refresh_sessions")["name"] == "pk_refresh_sessions"
        rs_uniques = {
            uc["name"] for uc in head_inspector.get_unique_constraints("refresh_sessions")
        }
        assert "uq_refresh_sessions_token_hash" in rs_uniques
        rs_checks = {
            cc["name"] for cc in head_inspector.get_check_constraints("refresh_sessions")
        }
        assert rs_checks == {
            "ck_refresh_sessions_client_type",
            "ck_refresh_sessions_hash_hex",
            "ck_refresh_sessions_expiry_bounds",
            "ck_refresh_sessions_revoke_reason_consistency",
        }
        rs_indexes = {idx["name"] for idx in head_inspector.get_indexes("refresh_sessions")}
        assert {
            "ix_refresh_sessions_user_active",
            "ix_refresh_sessions_family_id",
            "ix_refresh_sessions_expires_at",
        }.issubset(rs_indexes)
        rs_fks = {tuple(fk["constrained_columns"]): fk for fk in head_inspector.get_foreign_keys("refresh_sessions")}
        assert rs_fks[("user_id",)]["referred_table"] == "users"
        assert rs_fks[("user_id",)]["options"].get("ondelete") == "CASCADE"
        assert rs_fks[("parent_session_id",)]["referred_table"] == "refresh_sessions"
        assert rs_fks[("parent_session_id",)]["options"].get("ondelete") == "SET NULL"
        assert rs_fks[("replaced_by_session_id",)]["referred_table"] == "refresh_sessions"
        assert rs_fks[("replaced_by_session_id",)]["options"].get("ondelete") == "SET NULL"

        # 5. Reversibility: head -> 0001_create_users -> head -> base -> head -> alembic check
        command.downgrade(cfg, "0001_create_users")
        mid_inspector = inspect(migrator_inspect_engine)
        assert mid_inspector.has_table("users") is True
        assert mid_inspector.has_table("email_verification_tokens") is False
        assert mid_inspector.has_table("refresh_sessions") is False
        assert set(col["name"] for col in mid_inspector.get_columns("users")) == {
            "id",
            "email",
            "is_active",
            "created_at",
            "updated_at",
        }

        command.upgrade(cfg, "head")
        command.downgrade(cfg, "base")
        command.upgrade(cfg, "head")
        command.check(cfg)
    finally:
        try:
            command.upgrade(build_alembic_config(test_migration_database_url), "head")
            with migrator_inspect_engine.begin() as conn:
                conn.execute(text("DELETE FROM users"))
        finally:
            migrator_inspect_engine.dispose()
            if previous_migration_url is None:
                os.environ.pop("MIGRATION_DATABASE_URL", None)
            else:
                os.environ["MIGRATION_DATABASE_URL"] = previous_migration_url
            get_settings.cache_clear()


@pytest.mark.db
@pytest.mark.migration
def test_split_roles_enforce_dml_only_for_app_and_ddl_for_migrator(
    test_database_url: str,
    test_migration_database_url: str,
    db_engine: Engine,
) -> None:
    """
    Verify Rev10 §8 rule 5 & §20.2 least-privilege split-role isolation:
      - Application role owns neither schema nor migrated tables.
      - Application role can SELECT/INSERT/UPDATE/DELETE on all Stage 3A tables.
      - Application role is denied CREATE/ALTER/DROP/TRUNCATE DDL operations.
      - Migrator role owns migrated tables and holds DDL privileges.
    """
    _, app_role = verify_test_database_identity(test_database_url, allow_migrator=False)
    _, migrator_role = verify_test_database_identity(
        test_migration_database_url, allow_migrator=True
    )
    assert app_role != migrator_role

    migrator_engine = create_engine(
        test_migration_database_url,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"connect_timeout": 5},
    )
    try:
        with migrator_engine.connect() as conn:
            owners = conn.execute(
                text(
                    "SELECT tablename, tableowner FROM pg_tables "
                    "WHERE schemaname = 'public' "
                    "AND tablename IN ('users', 'email_verification_tokens', 'refresh_sessions')"
                )
            ).all()
            assert dict(owners) == {
                "users": migrator_role,
                "email_verification_tokens": migrator_role,
                "refresh_sessions": migrator_role,
            }
    finally:
        migrator_engine.dispose()

    # App role DML succeeds across all Stage 3A tables
    with db_engine.begin() as conn:
        user_id = conn.execute(
            text(
                "INSERT INTO users (email, is_email_verified, auth_version) "
                "VALUES ('dml.check@example.com', false, 0) RETURNING id"
            )
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO email_verification_tokens "
                "(user_id, token_hash, expires_at) "
                "VALUES (:uid, repeat('a', 64), now() + interval '1 hour')"
            ),
            {"uid": user_id},
        )
        conn.execute(
            text(
                "INSERT INTO refresh_sessions "
                "(user_id, family_id, token_hash, client_type, expires_at, family_expires_at) "
                "VALUES (:uid, gen_random_uuid(), repeat('b', 64), 'mobile', "
                "now() + interval '1 day', now() + interval '7 days')"
            ),
            {"uid": user_id},
        )
        cnt = conn.execute(
            text("SELECT COUNT(*) FROM users WHERE id = :uid"),
            {"uid": user_id},
        ).scalar_one()
        assert cnt == 1
        conn.execute(
            text("UPDATE users SET is_active = false WHERE id = :uid"),
            {"uid": user_id},
        )
        conn.execute(text("DELETE FROM users WHERE id = :uid"), {"uid": user_id})

    # App role DDL and TRUNCATE must be denied with InsufficientPrivilege
    for ddl_stmt in (
        "CREATE TABLE public.unauthorized_ddl_probe (id integer)",
        "ALTER TABLE public.users ADD COLUMN unauthorized_col text",
        "DROP TABLE public.refresh_sessions",
        "TRUNCATE TABLE public.users CASCADE",
    ):
        with pytest.raises(ProgrammingError):
            with db_engine.begin() as conn:
                conn.execute(text(ddl_stmt))
