"""Extend user_profiles with personal profile fields, links, bio length 1000, and avatar storage.

Revision ID: 0016_profile_details_avatar
Revises: 0015_email_change_active_unique
Create Date: 2026-11-28 09:22:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0016_profile_details_avatar"
down_revision: Union[str, Sequence[str], None] = "0015_email_change_active_unique"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Widen bio to 1000 chars and add headline, contact, links, and avatar storage columns."""
    op.drop_constraint(
        "bio_valid",
        "user_profiles",
        type_="check",
    )
    op.alter_column(
        "user_profiles",
        "bio",
        existing_type=sa.String(length=500),
        type_=sa.String(length=1000),
        existing_nullable=True,
    )
    op.create_check_constraint(
        "bio_valid",
        "user_profiles",
        "bio IS NULL OR (bio = btrim(bio) AND char_length(bio) BETWEEN 1 AND 1000)",
    )

    op.add_column("user_profiles", sa.Column("headline", sa.String(length=120), nullable=True))
    op.add_column("user_profiles", sa.Column("location", sa.String(length=120), nullable=True))
    op.add_column("user_profiles", sa.Column("contact_email", sa.String(length=255), nullable=True))
    op.add_column("user_profiles", sa.Column("phone", sa.String(length=32), nullable=True))
    op.add_column("user_profiles", sa.Column("website", sa.String(length=512), nullable=True))
    op.add_column(
        "user_profiles",
        sa.Column(
            "links",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "user_profiles",
        sa.Column("avatar_storage_key", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "user_profiles",
        sa.Column("avatar_mime_type", sa.String(length=32), nullable=True),
    )

    op.create_check_constraint(
        "headline_valid",
        "user_profiles",
        "headline IS NULL OR (headline = btrim(headline) AND char_length(headline) BETWEEN 1 AND 120)",
    )
    op.create_check_constraint(
        "location_valid",
        "user_profiles",
        "location IS NULL OR (location = btrim(location) AND char_length(location) BETWEEN 1 AND 120)",
    )
    op.create_check_constraint(
        "links_object",
        "user_profiles",
        "jsonb_typeof(links) = 'object'",
    )


def downgrade() -> None:
    """Revert user_profiles additions and bio length change."""
    op.drop_constraint(
        "links_object",
        "user_profiles",
        type_="check",
    )
    op.drop_constraint(
        "location_valid",
        "user_profiles",
        type_="check",
    )
    op.drop_constraint(
        "headline_valid",
        "user_profiles",
        type_="check",
    )

    op.drop_column("user_profiles", "avatar_mime_type")
    op.drop_column("user_profiles", "avatar_storage_key")
    op.drop_column("user_profiles", "links")
    op.drop_column("user_profiles", "website")
    op.drop_column("user_profiles", "phone")
    op.drop_column("user_profiles", "contact_email")
    op.drop_column("user_profiles", "location")
    op.drop_column("user_profiles", "headline")

    op.drop_constraint(
        "bio_valid",
        "user_profiles",
        type_="check",
    )
    op.alter_column(
        "user_profiles",
        "bio",
        existing_type=sa.String(length=1000),
        type_=sa.String(length=500),
        existing_nullable=True,
    )
    op.create_check_constraint(
        "bio_valid",
        "user_profiles",
        "bio IS NULL OR (bio = btrim(bio) AND char_length(bio) BETWEEN 1 AND 500)",
    )
