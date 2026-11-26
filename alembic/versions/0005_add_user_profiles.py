"""Add Phase 1 user_profiles and user_profile_activities tables.

Revision ID: 0005_add_user_profiles
Revises: 0004_add_oauth_tables
Create Date: 2026-11-26 18:35:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0005_add_user_profiles"
down_revision: Union[str, Sequence[str], None] = "0004_add_oauth_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create user_profiles and user_profile_activities tables."""
    op.create_table(
        "user_profiles",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("slug", sa.String(length=30), nullable=True),
        sa.Column("full_name", sa.String(length=150), nullable=True),
        sa.Column("date_of_birth", sa.Date(), nullable=True),
        sa.Column("bio", sa.String(length=500), nullable=True),
        sa.Column("profile_picture_url", sa.String(length=512), nullable=True),
        sa.Column(
            "interests",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "profile_completed",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("profile_completed_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_user_profiles"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_user_profiles_user_id_users",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("user_id", name="uq_user_profiles_user_id"),
        sa.UniqueConstraint("slug", name="uq_user_profiles_slug"),
        sa.CheckConstraint(
            "slug IS NULL OR slug ~ '^[a-z0-9_]{3,30}$'",
            name="slug_canonical",
        ),
        sa.CheckConstraint(
            "full_name IS NULL OR ("
            "full_name = btrim(full_name) "
            "AND char_length(full_name) BETWEEN 2 AND 150"
            ")",
            name="full_name_valid",
        ),
        sa.CheckConstraint(
            "bio IS NULL OR ("
            "bio = btrim(bio) "
            "AND char_length(bio) BETWEEN 1 AND 500"
            ")",
            name="bio_valid",
        ),
        sa.CheckConstraint(
            "profile_picture_url IS NULL OR ("
            "profile_picture_url = btrim(profile_picture_url) "
            "AND char_length(profile_picture_url) > 0 "
            "AND profile_picture_url !~ '[[:space:][:cntrl:]]'"
            ")",
            name="picture_url_valid",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(interests) = 'array'",
            name="interests_array",
        ),
        sa.CheckConstraint(
            "(profile_completed = false AND profile_completed_at IS NULL) OR ("
            "profile_completed = true AND profile_completed_at IS NOT NULL "
            "AND slug IS NOT NULL "
            "AND full_name IS NOT NULL "
            "AND date_of_birth IS NOT NULL"
            ")",
            name="completion_consistency",
        ),
    )

    op.create_table(
        "user_profile_activities",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("profile_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("activity_key", sa.String(length=32), nullable=False),
        sa.Column("custom_label", sa.String(length=80), nullable=True),
        sa.Column("description", sa.String(length=200), nullable=True),
        sa.Column(
            "display_order",
            sa.SmallInteger(),
            server_default=sa.text("0"),
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
        sa.PrimaryKeyConstraint("id", name="pk_user_profile_activities"),
        sa.ForeignKeyConstraint(
            ["profile_id"],
            ["user_profiles.id"],
            name="fk_user_profile_activities_profile_id_user_profiles",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "profile_id",
            "activity_key",
            name="uq_user_profile_activities_profile_key",
        ),
        sa.CheckConstraint(
            "activity_key IN ('studying', 'working', 'interning', 'freelancing', "
            "'job_seeking', 'researching', 'building_project', 'learning_skills', 'other')",
            name="activity_key",
        ),
        sa.CheckConstraint(
            "(activity_key = 'other' AND custom_label IS NOT NULL "
            "AND custom_label = btrim(custom_label) "
            "AND char_length(custom_label) BETWEEN 2 AND 80) "
            "OR (activity_key <> 'other' AND custom_label IS NULL)",
            name="custom_label_consistency",
        ),
        sa.CheckConstraint(
            "description IS NULL OR ("
            "description = btrim(description) "
            "AND char_length(description) BETWEEN 1 AND 200"
            ")",
            name="description_valid",
        ),
        sa.CheckConstraint(
            "display_order >= 0",
            name="display_order_non_negative",
        ),
    )
    op.create_index(
        "ix_user_profile_activities_profile_id",
        "user_profile_activities",
        ["profile_id"],
    )


def downgrade() -> None:
    """Drop user_profile_activities and user_profiles tables."""
    op.drop_index(
        "ix_user_profile_activities_profile_id",
        table_name="user_profile_activities",
    )
    op.drop_table("user_profile_activities")
    op.drop_table("user_profiles")
