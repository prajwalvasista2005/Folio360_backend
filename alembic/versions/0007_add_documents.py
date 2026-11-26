"""Add Phase 2 Stage 4 documents and education_documents tables.

Revision ID: 0007_add_documents
Revises: 0006_add_educations
Create Date: 2026-11-26 21:50:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0007_add_documents"
down_revision: Union[str, Sequence[str], None] = "0006_add_educations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create documents and education_documents tables."""
    op.create_table(
        "documents",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("original_filename", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("mime_type", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("page_count", sa.SmallInteger(), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("storage_backend", sa.String(length=16), nullable=False),
        sa.Column("storage_key", sa.String(length=512), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "processing_status",
            sa.String(length=24),
            server_default=sa.text("'none'"),
            nullable=False,
        ),
        sa.Column(
            "show_in_education",
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
        sa.PrimaryKeyConstraint("id", name="pk_documents"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_documents_user_id_users",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("storage_key", name="uq_documents_storage_key"),
        sa.CheckConstraint(
            "title = btrim(title) AND char_length(title) BETWEEN 1 AND 255",
            name="title_valid",
        ),
        sa.CheckConstraint(
            "original_filename = btrim(original_filename) AND char_length(original_filename) BETWEEN 1 AND 255",
            name="original_filename_valid",
        ),
        sa.CheckConstraint(
            "category IN ('marksheet', 'certificate', 'resume', 'identity', 'project_report', 'other')",
            name="category_valid",
        ),
        sa.CheckConstraint(
            "mime_type IN ('application/pdf', 'image/jpeg', 'image/png')",
            name="mime_type_valid",
        ),
        sa.CheckConstraint("size_bytes > 0", name="size_bytes_positive"),
        sa.CheckConstraint(
            "page_count IS NULL OR page_count > 0",
            name="page_count_positive",
        ),
        sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="sha256_hex"),
        sa.CheckConstraint(
            "storage_backend IN ('local', 's3')",
            name="storage_backend_valid",
        ),
        sa.CheckConstraint(
            "storage_key = btrim(storage_key) AND char_length(storage_key) BETWEEN 1 AND 512",
            name="storage_key_valid",
        ),
        sa.CheckConstraint(
            "processing_status IN ('none', 'queued', 'running', 'needs_review', 'confirmed', 'rejected', 'failed')",
            name="processing_status_valid",
        ),
    )
    op.create_index("ix_documents_user_id", "documents", ["user_id"])
    op.create_index("ix_documents_user_created", "documents", ["user_id", "created_at"])

    op.create_table(
        "education_documents",
        sa.Column("education_id", sa.Uuid(as_uuid=True), nullable=False),
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
        sa.PrimaryKeyConstraint(
            "education_id",
            "document_id",
            name="pk_education_documents",
        ),
        sa.ForeignKeyConstraint(
            ["education_id"],
            ["educations.id"],
            name="fk_education_documents_education_id_educations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["documents.id"],
            name="fk_education_documents_document_id_documents",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint("display_order >= 0", name="display_order_non_negative"),
    )
    op.create_index(
        "ix_education_documents_document_id",
        "education_documents",
        ["document_id"],
    )


def downgrade() -> None:
    """Drop education_documents and documents tables."""
    op.drop_index(
        "ix_education_documents_document_id",
        table_name="education_documents",
    )
    op.drop_table("education_documents")
    op.drop_index("ix_documents_user_created", table_name="documents")
    op.drop_index("ix_documents_user_id", table_name="documents")
    op.drop_table("documents")
