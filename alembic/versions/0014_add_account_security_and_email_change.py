"""Add security_audit_events and email_change_tokens tables.

Revision ID: 0014_add_account_security
Revises: 0013_add_profile_settings
Create Date: 2026-11-28 08:55:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0014_add_account_security"
down_revision: Union[str, Sequence[str], None] = "0013_add_profile_settings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create security_audit_events and email_change_tokens tables."""
    op.create_table(
        "security_audit_events",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("device_label", sa.String(length=120), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "action = btrim(action) AND char_length(action) BETWEEN 1 AND 64",
            name="ck_security_audit_events_action_valid",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_security_audit_events_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_security_audit_events"),
    )
    op.create_index(
        "ix_security_audit_events_user_created",
        "security_audit_events",
        ["user_id", "created_at"],
    )

    op.create_table(
        "email_change_tokens",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("new_email", sa.String(length=320), nullable=False),
        sa.Column("token_hash", sa.CHAR(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "new_email = lower(btrim(new_email)) AND length(btrim(new_email)) > 0",
            name="ck_email_change_tokens_new_email_canonical",
        ),
        sa.CheckConstraint(
            "token_hash ~ '^[0-9a-f]{64}$'",
            name="ck_email_change_tokens_hash_hex",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_email_change_tokens_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_email_change_tokens"),
        sa.UniqueConstraint("token_hash", name="uq_email_change_tokens_token_hash"),
    )
    op.create_index(
        "ix_email_change_tokens_user_id",
        "email_change_tokens",
        ["user_id"],
    )


def downgrade() -> None:
    """Drop email_change_tokens and security_audit_events tables."""
    op.drop_index("ix_email_change_tokens_user_id", table_name="email_change_tokens")
    op.drop_table("email_change_tokens")
    op.drop_index("ix_security_audit_events_user_created", table_name="security_audit_events")
    op.drop_table("security_audit_events")
