"""Add experiences, experience_skills, and experience_documents tables.

Revision ID: 0012_add_experiences
Revises: 0011_add_certificates
Create Date: 2026-11-27 21:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0012_add_experiences"
down_revision: Union[str, Sequence[str], None] = "0011_add_certificates"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create experiences, experience_skills, and experience_documents tables."""
    op.create_table(
        "experiences",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column(
            "type",
            sa.String(length=32),
            server_default=sa.text("'internship'"),
            nullable=False,
        ),
        sa.Column("organization", sa.String(length=200), nullable=False),
        sa.Column("role", sa.String(length=200), nullable=False),
        sa.Column("location", sa.String(length=200), nullable=True),
        sa.Column(
            "is_remote",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("organization_url", sa.String(length=512), nullable=True),
        sa.Column("start_date", sa.Date(), nullable=False),
        sa.Column("end_date", sa.Date(), nullable=True),
        sa.Column(
            "is_current",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "highlights",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "featured",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "display_order",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "visibility",
            sa.String(length=16),
            server_default=sa.text("'private'"),
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
        sa.CheckConstraint(
            "organization = btrim(organization) AND char_length(organization) BETWEEN 1 AND 200",
            name="ck_experiences_organization_valid",
        ),
        sa.CheckConstraint(
            "role = btrim(role) AND char_length(role) BETWEEN 1 AND 200",
            name="ck_experiences_role_valid",
        ),
        sa.CheckConstraint(
            "type IN ('internship', 'employment', 'freelance', 'research', 'volunteering', 'mentorship', 'leadership', 'other')",
            name="ck_experiences_type_valid",
        ),
        sa.CheckConstraint(
            "NOT (is_current = true AND end_date IS NOT NULL)",
            name="ck_experiences_current_no_end_date",
        ),
        sa.CheckConstraint(
            "end_date IS NULL OR end_date >= start_date",
            name="ck_experiences_date_order_valid",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(highlights) = 'array'",
            name="ck_experiences_highlights_array",
        ),
        sa.CheckConstraint(
            "display_order >= 0",
            name="ck_experiences_display_order_non_negative",
        ),
        sa.CheckConstraint(
            "visibility IN ('private', 'public')",
            name="ck_experiences_visibility_valid",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_experiences_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_experiences"),
    )
    op.create_index("ix_experiences_user_id", "experiences", ["user_id"], unique=False)
    op.create_index(
        "ix_experiences_user_visibility",
        "experiences",
        ["user_id", "visibility"],
        unique=False,
    )

    op.create_table(
        "experience_skills",
        sa.Column("experience_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("skill_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["experience_id"],
            ["experiences.id"],
            name="fk_experience_skills_experience_id_experiences",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["skill_id"],
            ["skills.id"],
            name="fk_experience_skills_skill_id_skills",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("experience_id", "skill_id", name="pk_experience_skills"),
    )
    op.create_index(
        "ix_experience_skills_skill_id",
        "experience_skills",
        ["skill_id"],
        unique=False,
    )

    op.create_table(
        "experience_documents",
        sa.Column("experience_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("document_id", sa.Uuid(as_uuid=True), nullable=False),
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
        sa.CheckConstraint(
            "display_order >= 0",
            name="ck_experience_documents_display_order_non_negative",
        ),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["documents.id"],
            name="fk_experience_documents_document_id_documents",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["experience_id"],
            ["experiences.id"],
            name="fk_experience_documents_experience_id_experiences",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "experience_id",
            "document_id",
            name="pk_experience_documents",
        ),
    )
    op.create_index(
        "ix_experience_documents_document_id",
        "experience_documents",
        ["document_id"],
        unique=False,
    )


def downgrade() -> None:
    """Drop experience tables."""
    op.drop_index("ix_experience_documents_document_id", table_name="experience_documents")
    op.drop_table("experience_documents")
    op.drop_index("ix_experience_skills_skill_id", table_name="experience_skills")
    op.drop_table("experience_skills")
    op.drop_index("ix_experiences_user_visibility", table_name="experiences")
    op.drop_index("ix_experiences_user_id", table_name="experiences")
    op.drop_table("experiences")
