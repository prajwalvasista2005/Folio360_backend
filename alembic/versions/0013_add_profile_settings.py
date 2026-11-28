"""Add visibility_settings and theme_preference columns to user_profiles.

Revision ID: 0013_add_profile_settings
Revises: 0012_add_experiences
Create Date: 2026-11-28 08:40:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0013_add_profile_settings"
down_revision: Union[str, Sequence[str], None] = "0012_add_experiences"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add public visibility settings and theme preference to user_profiles."""
    op.add_column(
        "user_profiles",
        sa.Column(
            "visibility_settings",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "user_profiles",
        sa.Column(
            "theme_preference",
            sa.String(length=16),
            server_default=sa.text("'light'"),
            nullable=False,
        ),
    )
    op.create_check_constraint(
        "ck_user_profiles_visibility_settings_object",
        "user_profiles",
        "jsonb_typeof(visibility_settings) = 'object'",
    )
    op.create_check_constraint(
        "ck_user_profiles_theme_preference_valid",
        "user_profiles",
        "theme_preference IN ('light', 'dark', 'system')",
    )


def downgrade() -> None:
    """Remove public visibility settings and theme preference from user_profiles."""
    op.drop_constraint(
        "ck_user_profiles_theme_preference_valid",
        "user_profiles",
        type_="check",
    )
    op.drop_constraint(
        "ck_user_profiles_visibility_settings_object",
        "user_profiles",
        type_="check",
    )
    op.drop_column("user_profiles", "theme_preference")
    op.drop_column("user_profiles", "visibility_settings")
