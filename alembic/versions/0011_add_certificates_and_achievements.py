"""Add certificates, certificate_skills, achievements, and achievement_documents tables.

Revision ID: 0011_add_certificates
Revises: 5727dc82b2a9
Create Date: 2026-11-27 20:02:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0011_add_certificates"
down_revision: Union[str, Sequence[str], None] = "5727dc82b2a9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create certificates and achievements tables with Document Vault links."""
    op.create_table(
        "certificates",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("issuer", sa.String(length=200), nullable=False),
        sa.Column(
            "category",
            sa.String(length=40),
            server_default=sa.text("'course'"),
            nullable=False,
        ),
        sa.Column("issue_date", sa.Date(), nullable=True),
        sa.Column("expiry_date", sa.Date(), nullable=True),
        sa.Column("credential_id", sa.String(length=120), nullable=True),
        sa.Column("verification_url", sa.String(length=512), nullable=True),
        sa.Column(
            "verification_status",
            sa.String(length=24),
            server_default=sa.text("'self_reported'"),
            nullable=False,
        ),
        sa.Column("document_id", sa.Uuid(as_uuid=True), nullable=True),
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
            "name = btrim(name) AND char_length(name) BETWEEN 1 AND 200",
            name="ck_certificates_name_valid",
        ),
        sa.CheckConstraint(
            "issuer = btrim(issuer) AND char_length(issuer) BETWEEN 1 AND 200",
            name="ck_certificates_issuer_valid",
        ),
        sa.CheckConstraint(
            "category IN ('course', 'professional', 'training', 'workshop', 'participation', 'academic', 'other')",
            name="ck_certificates_category_valid",
        ),
        sa.CheckConstraint(
            "issue_date IS NULL OR expiry_date IS NULL OR expiry_date >= issue_date",
            name="ck_certificates_date_order_valid",
        ),
        sa.CheckConstraint(
            "verification_status IN ('self_reported', 'link_provided', 'issuer_verified')",
            name="ck_certificates_verification_status_valid",
        ),
        sa.CheckConstraint(
            "display_order >= 0",
            name="ck_certificates_display_order_non_negative",
        ),
        sa.CheckConstraint(
            "visibility IN ('private', 'public')",
            name="ck_certificates_visibility_valid",
        ),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["documents.id"],
            name="fk_certificates_document_id_documents",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_certificates_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_certificates"),
    )
    op.create_index("ix_certificates_user_id", "certificates", ["user_id"], unique=False)
    op.create_index(
        "ix_certificates_user_visibility",
        "certificates",
        ["user_id", "visibility"],
        unique=False,
    )
    op.create_index(
        "ix_certificates_document_id",
        "certificates",
        ["document_id"],
        unique=False,
    )

    op.create_table(
        "certificate_skills",
        sa.Column("certificate_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("skill_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["certificate_id"],
            ["certificates.id"],
            name="fk_certificate_skills_certificate_id_certificates",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["skill_id"],
            ["skills.id"],
            name="fk_certificate_skills_skill_id_skills",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("certificate_id", "skill_id", name="pk_certificate_skills"),
    )
    op.create_index(
        "ix_certificate_skills_skill_id",
        "certificate_skills",
        ["skill_id"],
        unique=False,
    )

    op.create_table(
        "achievements",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column(
            "category",
            sa.String(length=40),
            server_default=sa.text("'award'"),
            nullable=False,
        ),
        sa.Column("organization", sa.String(length=200), nullable=True),
        sa.Column("date", sa.Date(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
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
            "title = btrim(title) AND char_length(title) BETWEEN 1 AND 200",
            name="ck_achievements_title_valid",
        ),
        sa.CheckConstraint(
            "category IN ('award', 'competition', 'publication', 'scholarship', 'academic_distinction', 'hackathon', 'leadership', 'extracurricular', 'other')",
            name="ck_achievements_category_valid",
        ),
        sa.CheckConstraint(
            "display_order >= 0",
            name="ck_achievements_display_order_non_negative",
        ),
        sa.CheckConstraint(
            "visibility IN ('private', 'public')",
            name="ck_achievements_visibility_valid",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_achievements_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_achievements"),
    )
    op.create_index("ix_achievements_user_id", "achievements", ["user_id"], unique=False)
    op.create_index(
        "ix_achievements_user_visibility",
        "achievements",
        ["user_id", "visibility"],
        unique=False,
    )

    op.create_table(
        "achievement_documents",
        sa.Column("achievement_id", sa.Uuid(as_uuid=True), nullable=False),
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
            name="ck_achievement_documents_display_order_non_negative",
        ),
        sa.ForeignKeyConstraint(
            ["achievement_id"],
            ["achievements.id"],
            name="fk_achievement_documents_achievement_id_achievements",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["documents.id"],
            name="fk_achievement_documents_document_id_documents",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "achievement_id",
            "document_id",
            name="pk_achievement_documents",
        ),
    )
    op.create_index(
        "ix_achievement_documents_document_id",
        "achievement_documents",
        ["document_id"],
        unique=False,
    )


def downgrade() -> None:
    """Drop certificates and achievements tables."""
    op.drop_index("ix_achievement_documents_document_id", table_name="achievement_documents")
    op.drop_table("achievement_documents")
    op.drop_index("ix_achievements_user_visibility", table_name="achievements")
    op.drop_index("ix_achievements_user_id", table_name="achievements")
    op.drop_table("achievements")
    op.drop_index("ix_certificate_skills_skill_id", table_name="certificate_skills")
    op.drop_table("certificate_skills")
    op.drop_index("ix_certificates_document_id", table_name="certificates")
    op.drop_index("ix_certificates_user_visibility", table_name="certificates")
    op.drop_index("ix_certificates_user_id", table_name="certificates")
    op.drop_table("certificates")
