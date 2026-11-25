"""Add Stage 3C OAuth tables: oauth_accounts, oauth_states, oauth_exchange_codes.

Revision ID: 0004_add_oauth_tables
Revises: 0003_add_password_reset_tokens
Create Date: 2026-11-25 16:10:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0004_add_oauth_tables"
down_revision: Union[str, Sequence[str], None] = "0003_add_password_reset_tokens"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create oauth_accounts, oauth_states, and oauth_exchange_codes tables."""
    op.create_table(
        "oauth_accounts",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("provider_user_id", sa.String(length=255), nullable=False),
        sa.Column("provider_email", sa.String(length=320), nullable=True),
        sa.Column(
            "provider_email_verified",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_oauth_accounts"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_oauth_accounts_user_id_users",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "provider",
            "provider_user_id",
            name="uq_oauth_accounts_provider_subject",
        ),
        sa.UniqueConstraint(
            "user_id",
            "provider",
            name="uq_oauth_accounts_user_provider",
        ),
        sa.CheckConstraint(
            "provider IN ('google', 'github')",
            name="provider",
        ),
        sa.CheckConstraint(
            "provider_user_id = btrim(provider_user_id) "
            "AND provider_user_id <> '' "
            "AND provider_user_id !~ '[[:space:][:cntrl:]]'",
            name="provider_user_id_valid",
        ),
        sa.CheckConstraint(
            "provider_email IS NULL OR ("
            "provider_email = lower(btrim(provider_email)) "
            "AND provider_email <> '' "
            "AND provider_email !~ '[[:space:]]'"
            ")",
            name="provider_email_canonical",
        ),
        sa.CheckConstraint(
            "provider_email IS NOT NULL OR provider_email_verified = false",
            name="email_verified_consistency",
        ),
    )
    op.create_index(
        "ix_oauth_accounts_user_id",
        "oauth_accounts",
        ["user_id"],
    )

    op.create_table(
        "oauth_states",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("state_hash", sa.CHAR(length=64), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("client_type", sa.String(length=16), nullable=False),
        sa.Column("pkce_verifier_encrypted", sa.String(length=512), nullable=False),
        sa.Column("nonce_hash", sa.CHAR(length=64), nullable=True),
        sa.Column("redirect_uri", sa.String(length=512), nullable=False),
        sa.Column("client_binding_hash", sa.CHAR(length=64), nullable=True),
        sa.Column("exchange_code_challenge_hash", sa.CHAR(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_oauth_states"),
        sa.UniqueConstraint("state_hash", name="uq_oauth_states_state_hash"),
        sa.CheckConstraint(
            "provider IN ('google', 'github')",
            name="provider",
        ),
        sa.CheckConstraint(
            "client_type IN ('web', 'mobile')",
            name="client_type",
        ),
        sa.CheckConstraint(
            "state_hash ~ '^[0-9a-f]{64}$'",
            name="state_hash_hex",
        ),
        sa.CheckConstraint(
            "exchange_code_challenge_hash ~ '^[0-9a-f]{64}$'",
            name="exchange_code_challenge_hash_hex",
        ),
        sa.CheckConstraint(
            "length(btrim(pkce_verifier_encrypted)) > 0",
            name="pkce_not_empty",
        ),
        sa.CheckConstraint(
            "length(btrim(redirect_uri)) > 0 AND redirect_uri = btrim(redirect_uri)",
            name="redirect_uri_valid",
        ),
        sa.CheckConstraint(
            "(provider = 'google' AND nonce_hash IS NOT NULL AND nonce_hash ~ '^[0-9a-f]{64}$') "
            "OR (provider = 'github' AND nonce_hash IS NULL)",
            name="nonce_hash_consistency",
        ),
        sa.CheckConstraint(
            "(client_type = 'web' AND client_binding_hash IS NOT NULL AND client_binding_hash ~ '^[0-9a-f]{64}$') "
            "OR (client_type = 'mobile' AND client_binding_hash IS NULL)",
            name="client_binding_consistency",
        ),
        sa.CheckConstraint(
            "(consumed_at IS NULL AND pkce_verifier_encrypted <> '[CONSUMED]') "
            "OR (consumed_at IS NOT NULL AND pkce_verifier_encrypted = '[CONSUMED]')",
            name="consumed_pkce_scrubbed",
        ),
    )
    op.create_index(
        "ix_oauth_states_expires_at",
        "oauth_states",
        ["expires_at"],
    )

    op.create_table(
        "oauth_exchange_codes",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("code_hash", sa.CHAR(length=64), nullable=False),
        sa.Column("client_type", sa.String(length=16), nullable=False),
        sa.Column("auth_version", sa.Integer(), nullable=False),
        sa.Column("exchange_code_challenge_hash", sa.CHAR(length=64), nullable=False),
        sa.Column("exchange_binding_hash", sa.CHAR(length=64), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_oauth_exchange_codes"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_oauth_exchange_codes_user_id_users",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("code_hash", name="uq_oauth_exchange_codes_code_hash"),
        sa.CheckConstraint(
            "code_hash ~ '^[0-9a-f]{64}$'",
            name="hash_hex",
        ),
        sa.CheckConstraint(
            "client_type IN ('web', 'mobile')",
            name="client_type",
        ),
        sa.CheckConstraint(
            "auth_version >= 0",
            name="auth_version_non_negative",
        ),
        sa.CheckConstraint(
            "exchange_code_challenge_hash ~ '^[0-9a-f]{64}$'",
            name="exchange_code_challenge_hash_hex",
        ),
        sa.CheckConstraint(
            "(client_type = 'web' AND exchange_binding_hash IS NOT NULL AND exchange_binding_hash ~ '^[0-9a-f]{64}$') "
            "OR (client_type = 'mobile' AND exchange_binding_hash IS NULL)",
            name="exchange_binding_consistency",
        ),
    )
    op.create_index(
        "ix_oauth_exchange_codes_user_id",
        "oauth_exchange_codes",
        ["user_id"],
    )
    op.create_index(
        "ix_oauth_exchange_codes_expires_at",
        "oauth_exchange_codes",
        ["expires_at"],
    )


def downgrade() -> None:
    """Drop oauth_exchange_codes, oauth_states, and oauth_accounts tables."""
    op.drop_index(
        "ix_oauth_exchange_codes_expires_at",
        table_name="oauth_exchange_codes",
    )
    op.drop_index(
        "ix_oauth_exchange_codes_user_id",
        table_name="oauth_exchange_codes",
    )
    op.drop_table("oauth_exchange_codes")

    op.drop_index(
        "ix_oauth_states_expires_at",
        table_name="oauth_states",
    )
    op.drop_table("oauth_states")

    op.drop_index(
        "ix_oauth_accounts_user_id",
        table_name="oauth_accounts",
    )
    op.drop_table("oauth_accounts")
