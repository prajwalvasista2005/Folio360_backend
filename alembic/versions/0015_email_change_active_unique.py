"""Add partial unique index for active email change tokens.

Revision ID: 0015_email_change_active_unique
Revises: 0014_add_account_security
Create Date: 2026-11-28 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0015_email_change_active_unique"
down_revision: Union[str, Sequence[str], None] = "0014_add_account_security"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create partial unique index preventing concurrent active claims on the same email."""
    op.create_index(
        "uq_email_change_tokens_active_new_email",
        "email_change_tokens",
        ["new_email"],
        unique=True,
        postgresql_where=sa.text("consumed_at IS NULL AND revoked_at IS NULL"),
    )


def downgrade() -> None:
    """Drop partial unique index on active email change tokens."""
    op.drop_index(
        "uq_email_change_tokens_active_new_email",
        table_name="email_change_tokens",
        postgresql_where=sa.text("consumed_at IS NULL AND revoked_at IS NULL"),
    )
