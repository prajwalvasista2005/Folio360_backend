"""Isolated destructive Alembic migration and split-role privilege tests on _test DBs."""

import os
import uuid

from alembic import command
import pytest
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from tests.conftest import build_alembic_config, verify_test_database_identity

ALL_MIGRATED_TABLES: tuple[str, ...] = (
    "users",
    "email_verification_tokens",
    "refresh_sessions",
    "password_reset_tokens",
    "oauth_accounts",
    "oauth_states",
    "oauth_exchange_codes",
    "user_profiles",
    "user_profile_activities",
    "educations",
    "documents",
    "education_documents",
    "document_analyses",
    "projects",
    "project_images",
    "github_connections",
    "github_oauth_states",
)


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
      3. Populated 0001_create_users row upgrades to 0003_add_password_reset_tokens without Stage 3C tables,
         and then upgrades to head (0004_add_oauth_tables) with defaults and full OAuth schema.
      4. Full Stage 3A+3B+3C.3 schema (users, email_verification_tokens, password_reset_tokens,
         refresh_sessions, oauth_accounts, oauth_states, oauth_exchange_codes).
      5. Round-trip downgrade 0003 -> 0002 -> 0001 -> head -> downgrade base -> upgrade head -> alembic check.
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
        for tbl in ALL_MIGRATED_TABLES:
            assert base_inspector.has_table(tbl) is False

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

        # 3. Upgrade populated 0001 DB first to 0003_add_password_reset_tokens (pre-Stage 3C)
        command.upgrade(cfg, "0003_add_password_reset_tokens")
        stage3b_inspector = inspect(migrator_inspect_engine)
        assert stage3b_inspector.has_table("users") is True
        assert stage3b_inspector.has_table("email_verification_tokens") is True
        assert stage3b_inspector.has_table("password_reset_tokens") is True
        assert stage3b_inspector.has_table("refresh_sessions") is True

        # Ensure Stage 3C tables are NOT present at 0003_add_password_reset_tokens
        for excluded_table in (
            "oauth_accounts",
            "oauth_states",
            "oauth_exchange_codes",
        ):
            assert stage3b_inspector.has_table(excluded_table) is False

        # Upgrade populated DB to 0004_add_oauth_tables (pre-Phase 1 profiles)
        command.upgrade(cfg, "0004_add_oauth_tables")
        stage3c_inspector = inspect(migrator_inspect_engine)
        assert stage3c_inspector.has_table("oauth_accounts") is True
        assert stage3c_inspector.has_table("user_profiles") is False
        assert stage3c_inspector.has_table("user_profile_activities") is False

        # Upgrade populated DB to 0005_add_user_profiles (pre-Phase 2 educations)
        command.upgrade(cfg, "0005_add_user_profiles")
        phase1_inspector = inspect(migrator_inspect_engine)
        assert phase1_inspector.has_table("user_profiles") is True
        assert phase1_inspector.has_table("user_profile_activities") is True
        assert phase1_inspector.has_table("educations") is False

        # Upgrade populated DB to 0006_add_educations (pre-Stage 4 documents)
        command.upgrade(cfg, "0006_add_educations")
        phase2_edu_inspector = inspect(migrator_inspect_engine)
        assert phase2_edu_inspector.has_table("educations") is True
        assert phase2_edu_inspector.has_table("documents") is False
        assert phase2_edu_inspector.has_table("education_documents") is False

        # Upgrade populated DB to 0007_add_documents (Stage 4 baseline)
        command.upgrade(cfg, "0007_add_documents")
        stage4_inspector = inspect(migrator_inspect_engine)
        assert stage4_inspector.has_table("documents") is True
        assert stage4_inspector.has_table("education_documents") is True
        assert "storage_state" not in {
            col["name"] for col in stage4_inspector.get_columns("documents")
        }

        # Upgrade populated DB to 0008_document_quarantine_scan (pre-Stage 6 AI analyses)
        command.upgrade(cfg, "0008_document_quarantine_scan")
        stage5_inspector = inspect(migrator_inspect_engine)
        assert stage5_inspector.has_table("documents") is True
        assert stage5_inspector.has_table("document_analyses") is False

        # Upgrade populated DB to head (0009_add_document_analyses)
        command.upgrade(cfg, "head")
        head_inspector = inspect(migrator_inspect_engine)
        assert head_inspector.has_table("users") is True
        assert head_inspector.has_table("email_verification_tokens") is True
        assert head_inspector.has_table("password_reset_tokens") is True
        assert head_inspector.has_table("refresh_sessions") is True
        assert head_inspector.has_table("oauth_accounts") is True
        assert head_inspector.has_table("oauth_states") is True
        assert head_inspector.has_table("oauth_exchange_codes") is True
        assert head_inspector.has_table("user_profiles") is True
        assert head_inspector.has_table("user_profile_activities") is True
        assert head_inspector.has_table("educations") is True
        assert head_inspector.has_table("documents") is True
        assert head_inspector.has_table("education_documents") is True
        assert head_inspector.get_table_names() is not None
        for tbl in ALL_MIGRATED_TABLES:
            assert head_inspector.has_table(tbl) is True

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

        # Verify password_reset_tokens schema (Stage 3B)
        prt_cols = {col["name"]: col for col in head_inspector.get_columns("password_reset_tokens")}
        assert set(prt_cols.keys()) == {
            "id",
            "user_id",
            "token_hash",
            "delivery_status",
            "delivery_attempted_at",
            "requested_ip",
            "expires_at",
            "consumed_at",
            "revoked_at",
            "created_at",
            "updated_at",
        }
        assert prt_cols["user_id"]["nullable"] is False
        assert prt_cols["token_hash"]["nullable"] is False
        assert prt_cols["delivery_status"]["nullable"] is False
        assert prt_cols["requested_ip"]["nullable"] is True
        assert getattr(prt_cols["requested_ip"]["type"], "length", None) == 45
        assert prt_cols["expires_at"]["nullable"] is False
        assert head_inspector.get_pk_constraint("password_reset_tokens")["name"] == (
            "pk_password_reset_tokens"
        )
        prt_uniques = {
            uc["name"] for uc in head_inspector.get_unique_constraints("password_reset_tokens")
        }
        assert "uq_password_reset_tokens_token_hash" in prt_uniques
        prt_checks = {
            cc["name"] for cc in head_inspector.get_check_constraints("password_reset_tokens")
        }
        assert prt_checks == {
            "ck_password_reset_tokens_delivery_status",
            "ck_password_reset_tokens_hash_hex",
            "ck_password_reset_tokens_not_both_consumed_revoked",
        }
        prt_indexes = {
            idx["name"] for idx in head_inspector.get_indexes("password_reset_tokens")
        }
        assert {
            "ix_password_reset_tokens_user_created",
            "ix_password_reset_tokens_expires_at",
        }.issubset(prt_indexes)
        prt_fks = head_inspector.get_foreign_keys("password_reset_tokens")
        assert len(prt_fks) == 1
        assert prt_fks[0]["referred_table"] == "users"
        assert prt_fks[0]["options"].get("ondelete") == "CASCADE"

        # Verify oauth_accounts schema (Stage 3C.3)
        oa_cols = {col["name"]: col for col in head_inspector.get_columns("oauth_accounts")}
        assert set(oa_cols.keys()) == {
            "id",
            "user_id",
            "provider",
            "provider_user_id",
            "provider_email",
            "provider_email_verified",
            "created_at",
            "updated_at",
        }
        assert oa_cols["user_id"]["nullable"] is False
        assert oa_cols["provider"]["nullable"] is False
        assert getattr(oa_cols["provider"]["type"], "length", None) == 32
        assert oa_cols["provider_user_id"]["nullable"] is False
        assert getattr(oa_cols["provider_user_id"]["type"], "length", None) == 255
        assert oa_cols["provider_email"]["nullable"] is True
        assert getattr(oa_cols["provider_email"]["type"], "length", None) == 320
        assert oa_cols["provider_email_verified"]["nullable"] is False
        assert head_inspector.get_pk_constraint("oauth_accounts")["name"] == "pk_oauth_accounts"
        oa_uniques = {
            uc["name"]: uc["column_names"]
            for uc in head_inspector.get_unique_constraints("oauth_accounts")
        }
        assert oa_uniques == {
            "uq_oauth_accounts_provider_subject": ["provider", "provider_user_id"],
            "uq_oauth_accounts_user_provider": ["user_id", "provider"],
        }
        oa_checks = {
            cc["name"] for cc in head_inspector.get_check_constraints("oauth_accounts")
        }
        assert oa_checks == {
            "ck_oauth_accounts_provider",
            "ck_oauth_accounts_provider_user_id_valid",
            "ck_oauth_accounts_provider_email_canonical",
            "ck_oauth_accounts_email_verified_consistency",
        }
        oa_indexes = {idx["name"] for idx in head_inspector.get_indexes("oauth_accounts")}
        assert "ix_oauth_accounts_user_id" in oa_indexes
        oa_fks = head_inspector.get_foreign_keys("oauth_accounts")
        assert len(oa_fks) == 1
        assert oa_fks[0]["referred_table"] == "users"
        assert oa_fks[0]["options"].get("ondelete") == "CASCADE"

        # Verify oauth_states schema (Stage 3C.3)
        os_cols = {col["name"]: col for col in head_inspector.get_columns("oauth_states")}
        assert set(os_cols.keys()) == {
            "id",
            "state_hash",
            "provider",
            "client_type",
            "pkce_verifier_encrypted",
            "nonce_hash",
            "redirect_uri",
            "client_binding_hash",
            "exchange_code_challenge_hash",
            "expires_at",
            "consumed_at",
            "created_at",
            "updated_at",
        }
        assert os_cols["state_hash"]["nullable"] is False
        assert getattr(os_cols["state_hash"]["type"], "length", None) == 64
        assert os_cols["provider"]["nullable"] is False
        assert getattr(os_cols["provider"]["type"], "length", None) == 32
        assert os_cols["client_type"]["nullable"] is False
        assert getattr(os_cols["client_type"]["type"], "length", None) == 16
        assert os_cols["pkce_verifier_encrypted"]["nullable"] is False
        assert getattr(os_cols["pkce_verifier_encrypted"]["type"], "length", None) == 512
        assert os_cols["nonce_hash"]["nullable"] is True
        assert getattr(os_cols["nonce_hash"]["type"], "length", None) == 64
        assert os_cols["redirect_uri"]["nullable"] is False
        assert getattr(os_cols["redirect_uri"]["type"], "length", None) == 512
        assert os_cols["client_binding_hash"]["nullable"] is True
        assert getattr(os_cols["client_binding_hash"]["type"], "length", None) == 64
        assert os_cols["exchange_code_challenge_hash"]["nullable"] is False
        assert getattr(os_cols["exchange_code_challenge_hash"]["type"], "length", None) == 64
        assert os_cols["expires_at"]["nullable"] is False
        assert os_cols["consumed_at"]["nullable"] is True
        assert head_inspector.get_pk_constraint("oauth_states")["name"] == "pk_oauth_states"
        assert head_inspector.get_foreign_keys("oauth_states") == []
        os_uniques = {
            uc["name"]: uc["column_names"]
            for uc in head_inspector.get_unique_constraints("oauth_states")
        }
        assert os_uniques == {"uq_oauth_states_state_hash": ["state_hash"]}
        os_checks = {
            cc["name"] for cc in head_inspector.get_check_constraints("oauth_states")
        }
        assert os_checks == {
            "ck_oauth_states_provider",
            "ck_oauth_states_client_type",
            "ck_oauth_states_state_hash_hex",
            "ck_oauth_states_exchange_code_challenge_hash_hex",
            "ck_oauth_states_pkce_not_empty",
            "ck_oauth_states_redirect_uri_valid",
            "ck_oauth_states_nonce_hash_consistency",
            "ck_oauth_states_client_binding_consistency",
            "ck_oauth_states_consumed_pkce_scrubbed",
        }
        os_indexes = {idx["name"] for idx in head_inspector.get_indexes("oauth_states")}
        assert "ix_oauth_states_expires_at" in os_indexes

        # Verify oauth_exchange_codes schema (Stage 3C.3)
        oec_cols = {
            col["name"]: col for col in head_inspector.get_columns("oauth_exchange_codes")
        }
        assert set(oec_cols.keys()) == {
            "id",
            "user_id",
            "code_hash",
            "client_type",
            "auth_version",
            "exchange_code_challenge_hash",
            "exchange_binding_hash",
            "expires_at",
            "consumed_at",
            "created_at",
            "updated_at",
        }
        assert oec_cols["user_id"]["nullable"] is False
        assert oec_cols["code_hash"]["nullable"] is False
        assert getattr(oec_cols["code_hash"]["type"], "length", None) == 64
        assert oec_cols["client_type"]["nullable"] is False
        assert getattr(oec_cols["client_type"]["type"], "length", None) == 16
        assert oec_cols["auth_version"]["nullable"] is False
        assert oec_cols["exchange_code_challenge_hash"]["nullable"] is False
        assert getattr(oec_cols["exchange_code_challenge_hash"]["type"], "length", None) == 64
        assert oec_cols["exchange_binding_hash"]["nullable"] is True
        assert getattr(oec_cols["exchange_binding_hash"]["type"], "length", None) == 64
        assert oec_cols["expires_at"]["nullable"] is False
        assert oec_cols["consumed_at"]["nullable"] is True
        assert (
            head_inspector.get_pk_constraint("oauth_exchange_codes")["name"]
            == "pk_oauth_exchange_codes"
        )
        oec_uniques = {
            uc["name"]: uc["column_names"]
            for uc in head_inspector.get_unique_constraints("oauth_exchange_codes")
        }
        assert oec_uniques == {"uq_oauth_exchange_codes_code_hash": ["code_hash"]}
        oec_checks = {
            cc["name"]
            for cc in head_inspector.get_check_constraints("oauth_exchange_codes")
        }
        assert oec_checks == {
            "ck_oauth_exchange_codes_hash_hex",
            "ck_oauth_exchange_codes_client_type",
            "ck_oauth_exchange_codes_auth_version_non_negative",
            "ck_oauth_exchange_codes_exchange_code_challenge_hash_hex",
            "ck_oauth_exchange_codes_exchange_binding_consistency",
        }
        oec_indexes = {
            idx["name"] for idx in head_inspector.get_indexes("oauth_exchange_codes")
        }
        assert {
            "ix_oauth_exchange_codes_user_id",
            "ix_oauth_exchange_codes_expires_at",
        }.issubset(oec_indexes)
        oec_fks = head_inspector.get_foreign_keys("oauth_exchange_codes")
        assert len(oec_fks) == 1
        assert oec_fks[0]["referred_table"] == "users"
        assert oec_fks[0]["options"].get("ondelete") == "CASCADE"

        # Verify user_profiles schema (Phase 1)
        up_cols = {col["name"]: col for col in head_inspector.get_columns("user_profiles")}
        assert set(up_cols.keys()) == {
            "id",
            "user_id",
            "slug",
            "full_name",
            "date_of_birth",
            "bio",
            "profile_picture_url",
            "interests",
            "profile_completed",
            "profile_completed_at",
            "created_at",
            "updated_at",
        }
        assert up_cols["user_id"]["nullable"] is False
        assert up_cols["slug"]["nullable"] is True
        assert getattr(up_cols["slug"]["type"], "length", None) == 30
        assert up_cols["full_name"]["nullable"] is True
        assert getattr(up_cols["full_name"]["type"], "length", None) == 150
        assert up_cols["date_of_birth"]["nullable"] is True
        assert up_cols["bio"]["nullable"] is True
        assert getattr(up_cols["bio"]["type"], "length", None) == 500
        assert up_cols["profile_picture_url"]["nullable"] is True
        assert getattr(up_cols["profile_picture_url"]["type"], "length", None) == 512
        assert up_cols["interests"]["nullable"] is False
        assert up_cols["profile_completed"]["nullable"] is False
        assert up_cols["profile_completed_at"]["nullable"] is True
        assert head_inspector.get_pk_constraint("user_profiles")["name"] == "pk_user_profiles"
        up_uniques = {
            uc["name"]: uc["column_names"]
            for uc in head_inspector.get_unique_constraints("user_profiles")
        }
        assert up_uniques == {
            "uq_user_profiles_user_id": ["user_id"],
            "uq_user_profiles_slug": ["slug"],
        }
        up_checks = {
            cc["name"] for cc in head_inspector.get_check_constraints("user_profiles")
        }
        assert up_checks == {
            "ck_user_profiles_slug_canonical",
            "ck_user_profiles_full_name_valid",
            "ck_user_profiles_bio_valid",
            "ck_user_profiles_picture_url_valid",
            "ck_user_profiles_interests_array",
            "ck_user_profiles_completion_consistency",
        }
        up_fks = head_inspector.get_foreign_keys("user_profiles")
        assert len(up_fks) == 1
        assert up_fks[0]["referred_table"] == "users"
        assert up_fks[0]["options"].get("ondelete") == "CASCADE"

        # Verify user_profile_activities schema (Phase 1)
        upa_cols = {
            col["name"]: col
            for col in head_inspector.get_columns("user_profile_activities")
        }
        assert set(upa_cols.keys()) == {
            "id",
            "profile_id",
            "activity_key",
            "custom_label",
            "description",
            "display_order",
            "created_at",
            "updated_at",
        }
        assert upa_cols["profile_id"]["nullable"] is False
        assert upa_cols["activity_key"]["nullable"] is False
        assert getattr(upa_cols["activity_key"]["type"], "length", None) == 32
        assert upa_cols["custom_label"]["nullable"] is True
        assert getattr(upa_cols["custom_label"]["type"], "length", None) == 80
        assert upa_cols["description"]["nullable"] is True
        assert getattr(upa_cols["description"]["type"], "length", None) == 200
        assert upa_cols["display_order"]["nullable"] is False
        assert (
            head_inspector.get_pk_constraint("user_profile_activities")["name"]
            == "pk_user_profile_activities"
        )
        upa_uniques = {
            uc["name"]: uc["column_names"]
            for uc in head_inspector.get_unique_constraints("user_profile_activities")
        }
        assert upa_uniques == {
            "uq_user_profile_activities_profile_key": ["profile_id", "activity_key"],
        }
        upa_checks = {
            cc["name"]
            for cc in head_inspector.get_check_constraints("user_profile_activities")
        }
        assert upa_checks == {
            "ck_user_profile_activities_activity_key",
            "ck_user_profile_activities_custom_label_consistency",
            "ck_user_profile_activities_description_valid",
            "ck_user_profile_activities_display_order_non_negative",
        }
        upa_indexes = {
            idx["name"] for idx in head_inspector.get_indexes("user_profile_activities")
        }
        assert "ix_user_profile_activities_profile_id" in upa_indexes
        upa_fks = head_inspector.get_foreign_keys("user_profile_activities")
        assert len(upa_fks) == 1
        assert upa_fks[0]["referred_table"] == "user_profiles"
        assert upa_fks[0]["options"].get("ondelete") == "CASCADE"

        # Verify educations schema (Phase 2)
        edu_cols = {col["name"]: col for col in head_inspector.get_columns("educations")}
        assert set(edu_cols.keys()) == {
            "id",
            "user_id",
            "institution",
            "university_or_board",
            "education_level",
            "degree",
            "programme",
            "branch",
            "specialization",
            "country",
            "state",
            "start_month",
            "start_year",
            "end_month",
            "end_year",
            "is_current",
            "description",
            "scheme_id",
            "result_type",
            "result_value",
            "result_source",
            "computed_cgpa",
            "show_result_publicly",
            "achievements",
            "visibility",
            "created_at",
            "updated_at",
        }
        assert edu_cols["user_id"]["nullable"] is False
        assert edu_cols["institution"]["nullable"] is False
        assert edu_cols["degree"]["nullable"] is False
        assert edu_cols["is_current"]["nullable"] is False
        assert edu_cols["result_source"]["nullable"] is False
        assert edu_cols["show_result_publicly"]["nullable"] is False
        assert edu_cols["achievements"]["nullable"] is False
        assert edu_cols["visibility"]["nullable"] is False
        assert head_inspector.get_pk_constraint("educations")["name"] == "pk_educations"
        edu_checks = {
            cc["name"] for cc in head_inspector.get_check_constraints("educations")
        }
        assert edu_checks == {
            "ck_educations_institution_valid",
            "ck_educations_degree_valid",
            "ck_educations_start_month_range",
            "ck_educations_end_month_range",
            "ck_educations_start_year_range",
            "ck_educations_end_year_range",
            "ck_educations_start_month_requires_year",
            "ck_educations_end_month_requires_year",
            "ck_educations_current_no_end_date",
            "ck_educations_date_order_valid",
            "ck_educations_result_source_valid",
            "ck_educations_visibility_valid",
            "ck_educations_achievements_array",
            "ck_educations_computed_cgpa_range",
        }
        edu_indexes = {idx["name"] for idx in head_inspector.get_indexes("educations")}
        assert "ix_educations_user_id" in edu_indexes
        edu_fks = head_inspector.get_foreign_keys("educations")
        assert len(edu_fks) == 1
        assert edu_fks[0]["referred_table"] == "users"
        assert edu_fks[0]["options"].get("ondelete") == "CASCADE"

        # Verify documents schema (Phase 2 Stage 4 + Stage 5)
        doc_cols = {col["name"]: col for col in head_inspector.get_columns("documents")}
        assert set(doc_cols.keys()) == {
            "id",
            "user_id",
            "title",
            "original_filename",
            "category",
            "mime_type",
            "size_bytes",
            "page_count",
            "sha256",
            "storage_backend",
            "storage_key",
            "storage_state",
            "notes",
            "processing_status",
            "scan_attempts",
            "scan_started_at",
            "scanned_at",
            "failure_reason",
            "show_in_education",
            "created_at",
            "updated_at",
        }
        assert doc_cols["storage_state"]["nullable"] is False
        assert doc_cols["scan_attempts"]["nullable"] is False
        assert doc_cols["scan_started_at"]["nullable"] is True
        assert doc_cols["scanned_at"]["nullable"] is True
        assert doc_cols["failure_reason"]["nullable"] is True
        assert head_inspector.get_pk_constraint("documents")["name"] == "pk_documents"
        doc_uniques = {uc["name"] for uc in head_inspector.get_unique_constraints("documents")}
        assert "uq_documents_storage_key" in doc_uniques
        doc_checks = {cc["name"] for cc in head_inspector.get_check_constraints("documents")}
        assert doc_checks == {
            "ck_documents_title_valid",
            "ck_documents_original_filename_valid",
            "ck_documents_category_valid",
            "ck_documents_mime_type_valid",
            "ck_documents_size_bytes_positive",
            "ck_documents_page_count_positive",
            "ck_documents_sha256_hex",
            "ck_documents_storage_backend_valid",
            "ck_documents_storage_key_valid",
            "ck_documents_processing_status_valid",
            "ck_documents_storage_state_valid",
            "ck_documents_scan_attempts_non_negative",
            "ck_documents_failure_reason_valid",
            "ck_documents_status_storage_consistency",
        }
        doc_indexes = {idx["name"] for idx in head_inspector.get_indexes("documents")}
        assert {
            "ix_documents_user_id",
            "ix_documents_user_created",
            "ix_documents_processing_status",
        }.issubset(doc_indexes)
        doc_fks = head_inspector.get_foreign_keys("documents")
        assert len(doc_fks) == 1
        assert doc_fks[0]["referred_table"] == "users"
        assert doc_fks[0]["options"].get("ondelete") == "CASCADE"

        # Verify education_documents schema (Phase 2 Stage 4)
        ed_cols = {col["name"]: col for col in head_inspector.get_columns("education_documents")}
        assert set(ed_cols.keys()) == {"education_id", "document_id", "display_order", "created_at"}
        ed_pk = head_inspector.get_pk_constraint("education_documents")
        assert ed_pk["name"] == "pk_education_documents"
        assert ed_pk["constrained_columns"] == ["education_id", "document_id"]
        ed_checks = {
            cc["name"] for cc in head_inspector.get_check_constraints("education_documents")
        }
        assert ed_checks == {"ck_education_documents_display_order_non_negative"}
        ed_indexes = {idx["name"] for idx in head_inspector.get_indexes("education_documents")}
        assert "ix_education_documents_document_id" in ed_indexes
        ed_fks = {
            tuple(fk["constrained_columns"]): fk
            for fk in head_inspector.get_foreign_keys("education_documents")
        }
        assert ed_fks[("education_id",)]["referred_table"] == "educations"
        assert ed_fks[("education_id",)]["options"].get("ondelete") == "CASCADE"
        assert ed_fks[("document_id",)]["referred_table"] == "documents"
        assert ed_fks[("document_id",)]["options"].get("ondelete") == "CASCADE"

        # Verify document_analyses schema (Phase 2 Stage 6)
        da_cols = {col["name"]: col for col in head_inspector.get_columns("document_analyses")}
        assert set(da_cols.keys()) == {
            "id",
            "document_id",
            "user_id",
            "status",
            "document_type",
            "provider_name",
            "model_name",
            "analyzer_version",
            "attempts",
            "started_at",
            "completed_at",
            "summary",
            "extracted_data",
            "confidence",
            "uncertain_fields",
            "failure_reason",
            "created_at",
            "updated_at",
        }
        assert head_inspector.get_pk_constraint("document_analyses")["name"] == "pk_document_analyses"
        da_uniques = {uc["name"] for uc in head_inspector.get_unique_constraints("document_analyses")}
        assert "uq_document_analyses_document_id" in da_uniques
        da_checks = {cc["name"] for cc in head_inspector.get_check_constraints("document_analyses")}
        assert da_checks == {
            "ck_document_analyses_status_valid",
            "ck_document_analyses_document_type_valid",
            "ck_document_analyses_attempts_non_negative",
            "ck_document_analyses_confidence_range",
            "ck_document_analyses_uncertain_fields_array",
            "ck_document_analyses_failure_reason_valid",
            "ck_document_analyses_status_result_consistency",
        }
        da_indexes = {idx["name"] for idx in head_inspector.get_indexes("document_analyses")}
        assert {
            "ix_document_analyses_user_id",
            "ix_document_analyses_status_updated",
        }.issubset(da_indexes)
        da_fks = {
            tuple(fk["constrained_columns"]): fk
            for fk in head_inspector.get_foreign_keys("document_analyses")
        }
        assert da_fks[("document_id",)]["referred_table"] == "documents"
        assert da_fks[("document_id",)]["options"].get("ondelete") == "CASCADE"
        assert da_fks[("user_id",)]["referred_table"] == "users"
        assert da_fks[("user_id",)]["options"].get("ondelete") == "CASCADE"

        # 5. Reversibility: head -> 0008 -> 0007 -> 0006 -> 0005 -> 0004 -> 0003 -> 0002 -> 0001 -> head -> base -> head -> alembic check
        command.downgrade(cfg, "0008_document_quarantine_scan")
        stage5_post_downgrade = inspect(migrator_inspect_engine)
        assert stage5_post_downgrade.has_table("documents") is True
        assert stage5_post_downgrade.has_table("document_analyses") is False

        command.downgrade(cfg, "0007_add_documents")
        stage4_post_downgrade = inspect(migrator_inspect_engine)
        assert stage4_post_downgrade.has_table("documents") is True
        assert "storage_state" not in {
            col["name"] for col in stage4_post_downgrade.get_columns("documents")
        }
        assert "ix_documents_processing_status" not in {
            idx["name"] for idx in stage4_post_downgrade.get_indexes("documents")
        }

        command.downgrade(cfg, "0006_add_educations")
        phase2_edu_post_downgrade = inspect(migrator_inspect_engine)
        assert phase2_edu_post_downgrade.has_table("educations") is True
        assert phase2_edu_post_downgrade.has_table("documents") is False
        assert phase2_edu_post_downgrade.has_table("education_documents") is False

        command.downgrade(cfg, "0005_add_user_profiles")
        phase1_post_downgrade = inspect(migrator_inspect_engine)
        assert phase1_post_downgrade.has_table("user_profiles") is True
        assert phase1_post_downgrade.has_table("user_profile_activities") is True
        assert phase1_post_downgrade.has_table("educations") is False

        command.downgrade(cfg, "0004_add_oauth_tables")
        stage3c_post_downgrade = inspect(migrator_inspect_engine)
        assert stage3c_post_downgrade.has_table("oauth_accounts") is True
        assert stage3c_post_downgrade.has_table("user_profiles") is False
        assert stage3c_post_downgrade.has_table("user_profile_activities") is False

        command.downgrade(cfg, "0003_add_password_reset_tokens")
        stage3b_post_downgrade = inspect(migrator_inspect_engine)
        assert stage3b_post_downgrade.has_table("users") is True
        assert stage3b_post_downgrade.has_table("email_verification_tokens") is True
        assert stage3b_post_downgrade.has_table("password_reset_tokens") is True
        assert stage3b_post_downgrade.has_table("refresh_sessions") is True
        assert stage3b_post_downgrade.has_table("oauth_accounts") is False
        assert stage3b_post_downgrade.has_table("oauth_states") is False
        assert stage3b_post_downgrade.has_table("oauth_exchange_codes") is False

        command.downgrade(cfg, "0002_add_core_auth_tables")
        stage3a_inspector = inspect(migrator_inspect_engine)
        assert stage3a_inspector.has_table("users") is True
        assert stage3a_inspector.has_table("email_verification_tokens") is True
        assert stage3a_inspector.has_table("refresh_sessions") is True
        assert stage3a_inspector.has_table("password_reset_tokens") is False

        command.downgrade(cfg, "0001_create_users")
        mid_inspector = inspect(migrator_inspect_engine)
        assert mid_inspector.has_table("users") is True
        assert mid_inspector.has_table("email_verification_tokens") is False
        assert mid_inspector.has_table("password_reset_tokens") is False
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
        second_base_inspector = inspect(migrator_inspect_engine)
        for tbl in ALL_MIGRATED_TABLES:
            assert second_base_inspector.has_table(tbl) is False
        command.upgrade(cfg, "head")
        command.check(cfg)
    finally:
        try:
            command.upgrade(build_alembic_config(test_migration_database_url), "head")
            with migrator_inspect_engine.begin() as conn:
                conn.execute(text("DELETE FROM oauth_states"))
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
      - Application role can SELECT/INSERT/UPDATE/DELETE on all Stage 3A+3B+3C.3 tables.
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
                    "AND tablename IN ('users', 'email_verification_tokens', "
                    "'password_reset_tokens', 'refresh_sessions', "
                    "'oauth_accounts', 'oauth_states', 'oauth_exchange_codes', "
                    "'user_profiles', 'user_profile_activities', 'educations', "
                    "'documents', 'education_documents', 'document_analyses', "
                    "'projects', 'project_images', 'github_connections', 'github_oauth_states')"
                )
            ).all()
            assert dict(owners) == {
                "users": migrator_role,
                "email_verification_tokens": migrator_role,
                "password_reset_tokens": migrator_role,
                "refresh_sessions": migrator_role,
                "oauth_accounts": migrator_role,
                "oauth_states": migrator_role,
                "oauth_exchange_codes": migrator_role,
                "user_profiles": migrator_role,
                "user_profile_activities": migrator_role,
                "educations": migrator_role,
                "documents": migrator_role,
                "education_documents": migrator_role,
                "document_analyses": migrator_role,
                "projects": migrator_role,
                "project_images": migrator_role,
                "github_connections": migrator_role,
                "github_oauth_states": migrator_role,
            }
    finally:
        migrator_engine.dispose()

    # App role DML succeeds across all Stage 3A+3B+3C.3 tables
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
                "INSERT INTO password_reset_tokens "
                "(user_id, token_hash, requested_ip, expires_at) "
                "VALUES (:uid, repeat('c', 64), '2001:db8::1', now() + interval '30 minutes')"
            ),
            {"uid": user_id},
        )
        conn.execute(
            text(
                "INSERT INTO password_reset_tokens "
                "(user_id, token_hash, requested_ip, expires_at) "
                "VALUES (:uid, repeat('d', 64), NULL, now() + interval '30 minutes')"
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
        conn.execute(
            text(
                "INSERT INTO oauth_accounts "
                "(user_id, provider, provider_user_id, provider_email, provider_email_verified) "
                "VALUES (:uid, 'google', 'sub-12345', 'dml.check@example.com', true)"
            ),
            {"uid": user_id},
        )
        state_id = conn.execute(
            text(
                "INSERT INTO oauth_states "
                "(state_hash, provider, client_type, pkce_verifier_encrypted, "
                "nonce_hash, redirect_uri, client_binding_hash, exchange_code_challenge_hash, expires_at) "
                "VALUES (repeat('e', 64), 'google', 'web', 'v1:encrypted', "
                "repeat('f', 64), 'http://localhost:5173/auth/oauth/callback', "
                "repeat('0', 64), repeat('1', 64), now() + interval '10 minutes') "
                "RETURNING id"
            )
        ).scalar_one()
        conn.execute(
            text(
                "UPDATE oauth_states "
                "SET consumed_at = now(), pkce_verifier_encrypted = '[CONSUMED]' "
                "WHERE id = :sid"
            ),
            {"sid": state_id},
        )
        conn.execute(
            text(
                "INSERT INTO oauth_exchange_codes "
                "(user_id, code_hash, client_type, auth_version, "
                "exchange_code_challenge_hash, exchange_binding_hash, expires_at) "
                "VALUES (:uid, repeat('2', 64), 'mobile', 0, "
                "repeat('3', 64), NULL, now() + interval '60 seconds')"
            ),
            {"uid": user_id},
        )
        profile_id = conn.execute(
            text(
                "INSERT INTO user_profiles "
                "(user_id, slug, full_name, date_of_birth, interests, profile_completed, profile_completed_at) "
                "VALUES (:uid, 'dml_user', 'DML Check User', '2000-01-15', '[\"Python\"]'::jsonb, true, now()) "
                "RETURNING id"
            ),
            {"uid": user_id},
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO user_profile_activities "
                "(profile_id, activity_key, custom_label, description, display_order) "
                "VALUES (:pid, 'studying', NULL, 'B.E. CS', 0)"
            ),
            {"pid": profile_id},
        )
        edu_id = conn.execute(
            text(
                "INSERT INTO educations (user_id, institution, degree) "
                "VALUES (:uid, 'DML University', 'B.E.') RETURNING id"
            ),
            {"uid": user_id},
        ).scalar_one()
        doc_id = conn.execute(
            text(
                "INSERT INTO documents "
                "(user_id, title, original_filename, category, mime_type, size_bytes, "
                "sha256, storage_backend, storage_key) "
                "VALUES (:uid, 'DML Doc', 'doc.pdf', 'marksheet', 'application/pdf', 128, "
                "repeat('a', 64), 'local', :skey) RETURNING id"
            ),
            {"uid": user_id, "skey": f"{user_id}/{uuid.uuid4()}"},
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO education_documents (education_id, document_id, display_order) "
                "VALUES (:eid, :did, 0)"
            ),
            {"eid": edu_id, "did": doc_id},
        )
        conn.execute(
            text(
                "INSERT INTO document_analyses "
                "(document_id, user_id, status, provider_name, model_name) "
                "VALUES (:did, :uid, 'pending', 'mock', 'mock-academic-v1')"
            ),
            {"did": doc_id, "uid": user_id},
        )
        conn.execute(
            text("UPDATE educations SET branch = 'CS' WHERE id = :eid"),
            {"eid": edu_id},
        )
        conn.execute(
            text("DELETE FROM document_analyses WHERE document_id = :did"),
            {"did": doc_id},
        )
        conn.execute(
            text("DELETE FROM education_documents WHERE education_id = :eid"),
            {"eid": edu_id},
        )
        conn.execute(text("DELETE FROM documents WHERE id = :did"), {"did": doc_id})
        conn.execute(text("DELETE FROM educations WHERE id = :eid"), {"eid": edu_id})
        cnt = conn.execute(
            text("SELECT COUNT(*) FROM users WHERE id = :uid"),
            {"uid": user_id},
        ).scalar_one()
        assert cnt == 1
        conn.execute(
            text("UPDATE users SET is_active = false WHERE id = :uid"),
            {"uid": user_id},
        )
        conn.execute(text("DELETE FROM oauth_states WHERE id = :sid"), {"sid": state_id})
        conn.execute(text("DELETE FROM users WHERE id = :uid"), {"uid": user_id})

    # App role DDL and TRUNCATE must be denied with InsufficientPrivilege
    for ddl_stmt in (
        "CREATE TABLE public.unauthorized_ddl_probe (id integer)",
        "ALTER TABLE public.users ADD COLUMN unauthorized_col text",
        "DROP TABLE public.refresh_sessions",
        "DROP TABLE public.password_reset_tokens",
        "DROP TABLE public.oauth_accounts",
        "DROP TABLE public.oauth_states",
        "DROP TABLE public.oauth_exchange_codes",
        "DROP TABLE public.user_profile_activities",
        "DROP TABLE public.user_profiles",
        "DROP TABLE public.educations",
        "DROP TABLE public.education_documents",
        "DROP TABLE public.document_analyses",
        "DROP TABLE public.documents",
        "TRUNCATE TABLE public.users CASCADE",
        "TRUNCATE TABLE public.oauth_states",
        "TRUNCATE TABLE public.user_profiles CASCADE",
        "TRUNCATE TABLE public.educations CASCADE",
        "TRUNCATE TABLE public.document_analyses CASCADE",
        "TRUNCATE TABLE public.documents CASCADE",
    ):
        with pytest.raises(ProgrammingError):
            with db_engine.begin() as conn:
                conn.execute(text(ddl_stmt))
