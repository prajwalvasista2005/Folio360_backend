"""create users table

Revision ID: 0001_create_users
Revises:
Create Date: 2026-11-17 23:15:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0001_create_users"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the initial minimal users table with canonical email constraints."""
    op.create_table(
        "users",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column(
            "is_active",
            sa.Boolean(),
            server_default=sa.text("true"),
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
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("email", name="uq_users_email"),
        sa.CheckConstraint(
            "email = lower(btrim(email))",
            name="email_lowercase_trimmed",
        ),
        sa.CheckConstraint(
            "length(btrim(email)) > 0",
            name="email_not_empty",
        ),
        sa.CheckConstraint(
            "email !~ '[[:space:]]'",
            name="email_no_whitespace",
        ),
    )


def downgrade() -> None:
    """Drop the users table."""
    op.drop_table("users")
