"""Non-DB unit tests for Stage 3C Substage 3C.3 OAuth ORM models and migration 0004 (REV12)."""

from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import uuid

from alembic.config import Config
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
import sqlalchemy as sa
from sqlalchemy import CheckConstraint, Index, UniqueConstraint, create_mock_engine, inspect
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex, CreateTable

from app.core.security import (
    PKCE_VERIFIER_CONSUMED_MARKER,
    SUPPORTED_OAUTH_PROVIDERS,
    encrypt_pkce_verifier,
    generate_pkce_verifier,
)
from app.db.base import POSTGRES_NAMING_CONVENTION, Base
import app.models as models_pkg
from app.models import (
    EmailVerificationToken,
    OAuthAccount,
    OAuthExchangeCode,
    OAuthState,
    PasswordResetToken,
    RefreshSession,
    User,
)
from app.models.oauth import (
    OAuthAccount as OAuthAccountDirect,
    OAuthExchangeCode as OAuthExchangeCodeDirect,
    OAuthState as OAuthStateDirect,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _compile_pg(ddl_element: object) -> str:
    return str(ddl_element.compile(dialect=postgresql.dialect())).strip()  # type: ignore[attr-defined]


def _normalize_create_table(ddl: str) -> tuple[str, list[str], set[str]]:
    """Return header, ordered column lines, and set of normalized CONSTRAINT lines."""
    lines = [line.strip().rstrip(",") for line in ddl.splitlines() if line.strip()]
    header = lines[0]
    body = lines[1:-1]
    col_lines = [line for line in body if not line.startswith("CONSTRAINT ")]
    constraint_lines = {line for line in body if line.startswith("CONSTRAINT ")}
    return header, col_lines, constraint_lines


def test_oauth_model_exports_metadata_and_zero_relationships() -> None:
    assert OAuthAccount is OAuthAccountDirect
    assert OAuthState is OAuthStateDirect
    assert OAuthExchangeCode is OAuthExchangeCodeDirect

    assert {
        "Base",
        "User",
        "EmailVerificationToken",
        "PasswordResetToken",
        "RefreshSession",
        "OAuthAccount",
        "OAuthState",
        "OAuthExchangeCode",
    }.issubset(set(models_pkg.__all__))

    # Existing Stage 1-3B models and new Stage 3C.3 models all share Base.metadata
    assert {
        "users",
        "email_verification_tokens",
        "password_reset_tokens",
        "refresh_sessions",
        "oauth_accounts",
        "oauth_states",
        "oauth_exchange_codes",
    }.issubset(set(Base.metadata.tables.keys()))

    # No lazy-loading ORM relationships that could trigger unintended session autobegin
    for model_cls in (User, EmailVerificationToken, PasswordResetToken, RefreshSession, OAuthAccount, OAuthState, OAuthExchangeCode):
        assert dict(inspect(model_cls).relationships) == {}


def test_oauth_accounts_columns_constraints_and_indexes() -> None:
    table = OAuthAccount.__table__
    cols = {c.name: c for c in table.columns}
    assert list(cols.keys()) == [
        "id",
        "user_id",
        "provider",
        "provider_user_id",
        "provider_email",
        "provider_email_verified",
        "created_at",
        "updated_at",
    ]

    assert cols["id"].primary_key is True
    assert cols["id"].nullable is False
    assert isinstance(cols["id"].type, sa.Uuid)
    assert cols["id"].type.as_uuid is True
    assert cols["id"].default.is_callable is True
    assert isinstance(cols["id"].default.arg(None), uuid.UUID)
    assert "gen_random_uuid()" in str(cols["id"].server_default.arg)

    assert cols["user_id"].nullable is False
    assert cols["provider"].nullable is False
    assert cols["provider"].type.length == 32
    assert cols["provider_user_id"].nullable is False
    assert cols["provider_user_id"].type.length == 255
    assert cols["provider_email"].nullable is True
    assert cols["provider_email"].type.length == 320
    assert cols["provider_email_verified"].nullable is False
    assert cols["provider_email_verified"].default.arg is False
    assert str(cols["provider_email_verified"].server_default.arg) == "false"
    assert cols["created_at"].nullable is False
    assert cols["created_at"].type.timezone is True
    assert cols["updated_at"].nullable is False
    assert cols["updated_at"].type.timezone is True

    assert table.primary_key.name == "pk_oauth_accounts"

    fks = list(table.foreign_keys)
    assert len(fks) == 1
    assert fks[0].column.table.name == "users"
    assert fks[0].column.name == "id"
    assert fks[0].ondelete == "CASCADE"
    assert fks[0].constraint.name == "fk_oauth_accounts_user_id_users"

    uqs = {
        c.name: [col.name for col in c.columns]
        for c in table.constraints
        if isinstance(c, UniqueConstraint)
    }
    assert uqs == {
        "uq_oauth_accounts_provider_subject": ["provider", "provider_user_id"],
        "uq_oauth_accounts_user_provider": ["user_id", "provider"],
    }

    checks = {
        c.name: str(c.sqltext)
        for c in table.constraints
        if isinstance(c, CheckConstraint)
    }
    assert set(checks.keys()) == {
        "ck_oauth_accounts_provider",
        "ck_oauth_accounts_provider_user_id_valid",
        "ck_oauth_accounts_provider_email_canonical",
        "ck_oauth_accounts_email_verified_consistency",
    }
    compiled_ddl = _compile_pg(CreateTable(table))
    for full_name in checks:
        assert f"CONSTRAINT {full_name} CHECK" in compiled_ddl

    indexes = {idx.name: [col.name for col in idx.columns] for idx in table.indexes}
    assert indexes == {"ix_oauth_accounts_user_id": ["user_id"]}


def test_oauth_states_columns_constraints_indexes_and_3c2_alignment() -> None:
    table = OAuthState.__table__
    cols = {c.name: c for c in table.columns}
    assert list(cols.keys()) == [
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
    ]

    # Pre-auth state row has no FK to users
    assert list(table.foreign_keys) == []
    assert table.primary_key.name == "pk_oauth_states"

    assert cols["state_hash"].nullable is False
    assert isinstance(cols["state_hash"].type, sa.CHAR)
    assert cols["state_hash"].type.length == 64
    assert cols["provider"].nullable is False
    assert cols["provider"].type.length == 32
    assert cols["client_type"].nullable is False
    assert cols["client_type"].type.length == 16
    assert cols["pkce_verifier_encrypted"].nullable is False
    assert cols["pkce_verifier_encrypted"].type.length == 512
    assert cols["nonce_hash"].nullable is True
    assert isinstance(cols["nonce_hash"].type, sa.CHAR)
    assert cols["nonce_hash"].type.length == 64
    assert cols["redirect_uri"].nullable is False
    assert cols["redirect_uri"].type.length == 512
    assert cols["client_binding_hash"].nullable is True
    assert isinstance(cols["client_binding_hash"].type, sa.CHAR)
    assert cols["client_binding_hash"].type.length == 64
    assert cols["exchange_code_challenge_hash"].nullable is False
    assert isinstance(cols["exchange_code_challenge_hash"].type, sa.CHAR)
    assert cols["exchange_code_challenge_hash"].type.length == 64
    assert cols["expires_at"].nullable is False
    assert cols["expires_at"].type.timezone is True
    assert cols["consumed_at"].nullable is True
    assert cols["consumed_at"].type.timezone is True

    uqs = {
        c.name: [col.name for col in c.columns]
        for c in table.constraints
        if isinstance(c, UniqueConstraint)
    }
    assert uqs == {"uq_oauth_states_state_hash": ["state_hash"]}

    checks = {
        c.name: str(c.sqltext)
        for c in table.constraints
        if isinstance(c, CheckConstraint)
    }
    assert set(checks.keys()) == {
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
    assert f"'{PKCE_VERIFIER_CONSUMED_MARKER}'" in checks["ck_oauth_states_consumed_pkce_scrubbed"]
    for p in SUPPORTED_OAUTH_PROVIDERS:
        assert f"'{p}'" in checks["ck_oauth_states_provider"]

    compiled_ddl = _compile_pg(CreateTable(table))
    for full_name in checks:
        assert f"CONSTRAINT {full_name} CHECK" in compiled_ddl

    indexes = {idx.name: [col.name for col in idx.columns] for idx in table.indexes}
    assert indexes == {"ix_oauth_states_expires_at": ["expires_at"]}

    # Verify Substage 3C.2 AES-256-GCM ciphertext fits bounded storage column cleanly
    ciphertext = encrypt_pkce_verifier(
        generate_pkce_verifier(),
        key=os.urandom(32),
        provider="google",
        state_hash=hashlib.sha256(b"state").hexdigest(),
    )
    assert len(ciphertext) == 155 <= cols["pkce_verifier_encrypted"].type.length
    assert ciphertext != PKCE_VERIFIER_CONSUMED_MARKER


def test_oauth_exchange_codes_columns_constraints_and_indexes() -> None:
    table = OAuthExchangeCode.__table__
    cols = {c.name: c for c in table.columns}
    assert list(cols.keys()) == [
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
    ]

    assert table.primary_key.name == "pk_oauth_exchange_codes"
    assert cols["user_id"].nullable is False
    assert cols["code_hash"].nullable is False
    assert isinstance(cols["code_hash"].type, sa.CHAR)
    assert cols["code_hash"].type.length == 64
    assert cols["client_type"].nullable is False
    assert cols["client_type"].type.length == 16
    assert cols["auth_version"].nullable is False
    assert isinstance(cols["auth_version"].type, sa.Integer)
    assert cols["exchange_code_challenge_hash"].nullable is False
    assert isinstance(cols["exchange_code_challenge_hash"].type, sa.CHAR)
    assert cols["exchange_code_challenge_hash"].type.length == 64
    assert cols["exchange_binding_hash"].nullable is True
    assert isinstance(cols["exchange_binding_hash"].type, sa.CHAR)
    assert cols["exchange_binding_hash"].type.length == 64
    assert cols["expires_at"].nullable is False
    assert cols["expires_at"].type.timezone is True
    assert cols["consumed_at"].nullable is True
    assert cols["consumed_at"].type.timezone is True

    fks = list(table.foreign_keys)
    assert len(fks) == 1
    assert fks[0].column.table.name == "users"
    assert fks[0].column.name == "id"
    assert fks[0].ondelete == "CASCADE"
    assert fks[0].constraint.name == "fk_oauth_exchange_codes_user_id_users"

    uqs = {
        c.name: [col.name for col in c.columns]
        for c in table.constraints
        if isinstance(c, UniqueConstraint)
    }
    assert uqs == {"uq_oauth_exchange_codes_code_hash": ["code_hash"]}

    checks = {
        c.name: str(c.sqltext)
        for c in table.constraints
        if isinstance(c, CheckConstraint)
    }
    assert set(checks.keys()) == {
        "ck_oauth_exchange_codes_hash_hex",
        "ck_oauth_exchange_codes_client_type",
        "ck_oauth_exchange_codes_auth_version_non_negative",
        "ck_oauth_exchange_codes_exchange_code_challenge_hash_hex",
        "ck_oauth_exchange_codes_exchange_binding_consistency",
    }
    compiled_ddl = _compile_pg(CreateTable(table))
    for full_name in checks:
        assert f"CONSTRAINT {full_name} CHECK" in compiled_ddl

    indexes = {idx.name: [col.name for col in idx.columns] for idx in table.indexes}
    assert indexes == {
        "ix_oauth_exchange_codes_user_id": ["user_id"],
        "ix_oauth_exchange_codes_expires_at": ["expires_at"],
    }


def test_oauth_model_repr_never_exposes_hashes_ciphertexts_or_emails() -> None:
    uid = uuid.uuid4()
    acc = OAuthAccount(
        id=uuid.uuid4(),
        user_id=uid,
        provider="google",
        provider_user_id="secret-sub-999",
        provider_email="secret.user@example.com",
        provider_email_verified=True,
    )
    acc_repr = repr(acc)
    assert "secret-sub-999" not in acc_repr
    assert "secret.user@example.com" not in acc_repr
    assert "provider='google'" in acc_repr

    state_hash = "a" * 64
    nonce_hash = "b" * 64
    binding_hash = "c" * 64
    challenge_hash = "d" * 64
    st = OAuthState(
        id=uuid.uuid4(),
        state_hash=state_hash,
        provider="google",
        client_type="web",
        pkce_verifier_encrypted="v1:secretciphertext",
        nonce_hash=nonce_hash,
        redirect_uri="https://app.example.com/oauth/cb",
        client_binding_hash=binding_hash,
        exchange_code_challenge_hash=challenge_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    st_repr = repr(st)
    for sensitive in (
        state_hash,
        "v1:secretciphertext",
        nonce_hash,
        "https://app.example.com/oauth/cb",
        binding_hash,
        challenge_hash,
    ):
        assert sensitive not in st_repr
    assert "provider='google'" in st_repr

    code_hash = "e" * 64
    ex = OAuthExchangeCode(
        id=uuid.uuid4(),
        user_id=uid,
        code_hash=code_hash,
        client_type="web",
        auth_version=0,
        exchange_code_challenge_hash=challenge_hash,
        exchange_binding_hash=binding_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=60),
    )
    ex_repr = repr(ex)
    for sensitive in (code_hash, challenge_hash, binding_hash):
        assert sensitive not in ex_repr
    assert "client_type='web'" in ex_repr


def test_alembic_0004_revision_chain_and_mock_ddl_parity_with_metadata() -> None:
    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "alembic"))
    script = ScriptDirectory.from_config(cfg)

    heads = script.get_heads()
    assert heads == ["0005_add_user_profiles"]

    revs = list(script.walk_revisions("base", "head"))
    rev_ids = [r.revision for r in revs]
    assert rev_ids == [
        "0005_add_user_profiles",
        "0004_add_oauth_tables",
        "0003_add_password_reset_tokens",
        "0002_add_core_auth_tables",
        "0001_create_users",
    ]
    rev_0004 = script.get_revision("0004_add_oauth_tables")
    assert rev_0004 is not None
    assert rev_0004.down_revision == "0003_add_password_reset_tokens"
    assert rev_0004.module is not None

    # Execute upgrade() against a mock PostgreSQL engine and compare generated DDL
    # against Base.metadata.tables for 1-to-1 parity (types, defaults, constraints, indexes).
    assert POSTGRES_NAMING_CONVENTION["ck"] == "ck_%(table_name)s_%(constraint_name)s"

    upgrade_sql: list[str] = []
    upgrade_engine = create_mock_engine(
        "postgresql+psycopg://",
        lambda sql, *a, **kw: upgrade_sql.append(_compile_pg(sql)),
    )
    mc_up = MigrationContext.configure(
        connection=upgrade_engine.connect(),
        opts={"target_metadata": Base.metadata},
    )
    with Operations.context(mc_up):
        rev_0004.module.upgrade()

    expected_upgrade_sql = [
        _compile_pg(CreateTable(OAuthAccount.__table__)),
        _compile_pg(CreateIndex(next(iter(OAuthAccount.__table__.indexes)))),
        _compile_pg(CreateTable(OAuthState.__table__)),
        _compile_pg(CreateIndex(next(iter(OAuthState.__table__.indexes)))),
        _compile_pg(CreateTable(OAuthExchangeCode.__table__)),
        *[
            _compile_pg(CreateIndex(idx))
            for idx in sorted(OAuthExchangeCode.__table__.indexes, key=lambda i: i.name or "")
        ],
    ]
    # Compare exact ordered columns + all constraint definitions + indexes
    assert len(upgrade_sql) == len(expected_upgrade_sql)
    assert _normalize_create_table(upgrade_sql[0]) == _normalize_create_table(expected_upgrade_sql[0])
    assert upgrade_sql[1] == expected_upgrade_sql[1]
    assert _normalize_create_table(upgrade_sql[2]) == _normalize_create_table(expected_upgrade_sql[2])
    assert upgrade_sql[3] == expected_upgrade_sql[3]
    assert _normalize_create_table(upgrade_sql[4]) == _normalize_create_table(expected_upgrade_sql[4])
    assert set(upgrade_sql[5:]) == set(expected_upgrade_sql[5:])

    # Execute downgrade() and verify exact reverse-dependency drop order
    downgrade_sql: list[str] = []
    downgrade_engine = create_mock_engine(
        "postgresql+psycopg://",
        lambda sql, *a, **kw: downgrade_sql.append(_compile_pg(sql)),
    )
    mc_down = MigrationContext.configure(
        connection=downgrade_engine.connect(),
        opts={"target_metadata": Base.metadata},
    )
    with Operations.context(mc_down):
        rev_0004.module.downgrade()

    assert downgrade_sql == [
        "DROP INDEX ix_oauth_exchange_codes_expires_at",
        "DROP INDEX ix_oauth_exchange_codes_user_id",
        "DROP TABLE oauth_exchange_codes",
        "DROP INDEX ix_oauth_states_expires_at",
        "DROP TABLE oauth_states",
        "DROP INDEX ix_oauth_accounts_user_id",
        "DROP TABLE oauth_accounts",
    ]
