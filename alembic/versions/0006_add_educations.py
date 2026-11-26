"""Add Phase 2 educations table.

Revision ID: 0006_add_educations
Revises: 0005_add_user_profiles
Create Date: 2026-11-26 21:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0006_add_educations"
down_revision: Union[str, Sequence[str], None] = "0005_add_user_profiles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create educations table with check constraints, foreign key, and user_id index."""
    op.create_table(
        "educations",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("institution", sa.String(length=255), nullable=False),
        sa.Column("university_or_board", sa.String(length=255), nullable=True),
        sa.Column("education_level", sa.String(length=64), nullable=True),
        sa.Column("degree", sa.String(length=255), nullable=False),
        sa.Column("programme", sa.String(length=255), nullable=True),
        sa.Column("branch", sa.String(length=255), nullable=True),
        sa.Column("specialization", sa.String(length=255), nullable=True),
        sa.Column("country", sa.String(length=120), nullable=True),
        sa.Column("state", sa.String(length=120), nullable=True),
        sa.Column("start_month", sa.SmallInteger(), nullable=True),
        sa.Column("start_year", sa.SmallInteger(), nullable=True),
        sa.Column("end_month", sa.SmallInteger(), nullable=True),
        sa.Column("end_year", sa.SmallInteger(), nullable=True),
        sa.Column(
            "is_current",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("scheme_id", sa.String(length=64), nullable=True),
        sa.Column("result_type", sa.String(length=32), nullable=True),
        sa.Column("result_value", sa.String(length=64), nullable=True),
        sa.Column(
            "result_source",
            sa.String(length=16),
            server_default=sa.text("'manual'"),
            nullable=False,
        ),
        sa.Column(
            "computed_cgpa",
            sa.Numeric(precision=5, scale=2),
            nullable=True,
        ),
        sa.Column(
            "show_result_publicly",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column(
            "achievements",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "visibility",
            sa.String(length=32),
            server_default=sa.text("'public'"),
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
        sa.PrimaryKeyConstraint("id", name="pk_educations"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_educations_user_id_users",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "institution = btrim(institution) AND char_length(institution) BETWEEN 1 AND 255",
            name="institution_valid",
        ),
        sa.CheckConstraint(
            "degree = btrim(degree) AND char_length(degree) BETWEEN 1 AND 255",
            name="degree_valid",
        ),
        sa.CheckConstraint(
            "start_month IS NULL OR start_month BETWEEN 1 AND 12",
            name="start_month_range",
        ),
        sa.CheckConstraint(
            "end_month IS NULL OR end_month BETWEEN 1 AND 12",
            name="end_month_range",
        ),
        sa.CheckConstraint(
            "start_year IS NULL OR start_year BETWEEN 1900 AND 2100",
            name="start_year_range",
        ),
        sa.CheckConstraint(
            "end_year IS NULL OR end_year BETWEEN 1900 AND 2100",
            name="end_year_range",
        ),
        sa.CheckConstraint(
            "start_month IS NULL OR start_year IS NOT NULL",
            name="start_month_requires_year",
        ),
        sa.CheckConstraint(
            "end_month IS NULL OR end_year IS NOT NULL",
            name="end_month_requires_year",
        ),
        sa.CheckConstraint(
            "NOT (is_current = true AND (end_year IS NOT NULL OR end_month IS NOT NULL))",
            name="current_no_end_date",
        ),
        sa.CheckConstraint(
            "start_year IS NULL OR end_year IS NULL OR end_year > start_year OR "
            "(end_year = start_year AND (start_month IS NULL OR end_month IS NULL OR end_month >= start_month))",
            name="date_order_valid",
        ),
        sa.CheckConstraint(
            "result_source IN ('manual', 'computed')",
            name="result_source_valid",
        ),
        sa.CheckConstraint(
            "visibility IN ('public', 'private', 'unlisted', 'connections')",
            name="visibility_valid",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(achievements) = 'array'",
            name="achievements_array",
        ),
        sa.CheckConstraint(
            "computed_cgpa IS NULL OR (computed_cgpa >= 0 AND computed_cgpa <= 10)",
            name="computed_cgpa_range",
        ),
    )
    op.create_index("ix_educations_user_id", "educations", ["user_id"])


def downgrade() -> None:
    """Drop educations table."""
    op.drop_index("ix_educations_user_id", table_name="educations")
    op.drop_table("educations")
