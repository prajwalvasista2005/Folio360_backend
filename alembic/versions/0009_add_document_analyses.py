"""Add Phase 2 Stage 6 document_analyses table.

Revision ID: 0009_add_document_analyses
Revises: 0008_document_quarantine_scan
Create Date: 2026-11-26 22:30:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0009_add_document_analyses"
down_revision: Union[str, Sequence[str], None] = "0008_document_quarantine_scan"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create document_analyses table for review-only AI extraction outputs."""
    op.create_table(
        "document_analyses",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("document_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column(
            "status",
            sa.String(length=24),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column("document_type", sa.String(length=32), nullable=True),
        sa.Column("provider_name", sa.String(length=32), nullable=False),
        sa.Column("model_name", sa.String(length=128), nullable=False),
        sa.Column(
            "analyzer_version",
            sa.String(length=32),
            server_default=sa.text("'stage6-v1'"),
            nullable=False,
        ),
        sa.Column(
            "attempts",
            sa.SmallInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("extracted_data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("confidence", sa.Numeric(precision=4, scale=3), nullable=True),
        sa.Column(
            "uncertain_fields",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("failure_reason", sa.String(length=64), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_document_analyses"),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["documents.id"],
            name="fk_document_analyses_document_id_documents",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_document_analyses_user_id_users",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("document_id", name="uq_document_analyses_document_id"),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'completed', 'failed')",
            name="status_valid",
        ),
        sa.CheckConstraint(
            "document_type IS NULL OR document_type IN ('marksheet', 'certificate', 'other')",
            name="document_type_valid",
        ),
        sa.CheckConstraint("attempts >= 0", name="attempts_non_negative"),
        sa.CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="confidence_range",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(uncertain_fields) = 'array'",
            name="uncertain_fields_array",
        ),
        sa.CheckConstraint(
            "failure_reason IS NULL OR failure_reason IN ('provider_not_configured', 'provider_unavailable', 'provider_timeout', 'provider_rate_limited', 'invalid_provider_output', 'unsupported_content', 'analysis_error')",
            name="failure_reason_valid",
        ),
        sa.CheckConstraint(
            "(status = 'completed' AND extracted_data IS NOT NULL AND failure_reason IS NULL) OR "
            "(status = 'failed' AND failure_reason IS NOT NULL) OR "
            "(status IN ('pending', 'processing') AND failure_reason IS NULL)",
            name="status_result_consistency",
        ),
    )
    op.create_index("ix_document_analyses_user_id", "document_analyses", ["user_id"])
    op.create_index(
        "ix_document_analyses_status_updated",
        "document_analyses",
        ["status", "updated_at"],
    )


def downgrade() -> None:
    """Drop document_analyses table and indexes."""
    op.drop_index("ix_document_analyses_status_updated", table_name="document_analyses")
    op.drop_index("ix_document_analyses_user_id", table_name="document_analyses")
    op.drop_table("document_analyses")
