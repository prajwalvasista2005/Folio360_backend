"""Add Phase 2 Stage 5 document quarantine, scan tracking, and status constraints.

Revision ID: 0008_document_quarantine_scan
Revises: 0007_add_documents
Create Date: 2026-11-26 22:15:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0008_document_quarantine_scan"
down_revision: Union[str, Sequence[str], None] = "0007_add_documents"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_STAGE5_STATUS_CHECK = (
    "processing_status IN ('pending_scan', 'scanning', 'ready', 'rejected', 'scan_failed')"
)
_STAGE4_STATUS_CHECK = (
    "processing_status IN ('none', 'queued', 'running', 'needs_review', 'confirmed', 'rejected', 'failed')"
)
_STORAGE_STATE_CHECK = "storage_state IN ('quarantine', 'trusted', 'deleted')"
_SCAN_ATTEMPTS_CHECK = "scan_attempts >= 0"
_FAILURE_REASON_CHECK = (
    "failure_reason IS NULL OR failure_reason IN "
    "('malware_detected', 'validation_failed', 'scanner_unavailable', "
    "'scanner_timeout', 'scanner_error', 'promotion_failed')"
)
_STATUS_STORAGE_CONSISTENCY_CHECK = (
    "(processing_status = 'ready' AND storage_state = 'trusted') OR "
    "(processing_status IN ('pending_scan', 'scanning') AND storage_state = 'quarantine') OR "
    "(processing_status IN ('rejected', 'scan_failed') AND storage_state IN ('quarantine', 'deleted'))"
)


def upgrade() -> None:
    """Extend documents table with quarantine state, scan attempt metadata, and state-machine checks."""
    op.add_column(
        "documents",
        sa.Column(
            "storage_state",
            sa.String(length=16),
            server_default=sa.text("'quarantine'"),
            nullable=False,
        ),
    )
    op.add_column(
        "documents",
        sa.Column(
            "scan_attempts",
            sa.SmallInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
    )
    op.add_column(
        "documents",
        sa.Column("scan_started_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "documents",
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "documents",
        sa.Column("failure_reason", sa.String(length=64), nullable=True),
    )

    op.drop_constraint("processing_status_valid", "documents", type_="check")
    op.execute(
        sa.text(
            "UPDATE documents "
            "SET processing_status = 'pending_scan' "
            "WHERE processing_status NOT IN "
            "('pending_scan', 'scanning', 'ready', 'rejected', 'scan_failed')"
        )
    )
    op.alter_column(
        "documents",
        "processing_status",
        existing_type=sa.String(length=24),
        server_default=sa.text("'pending_scan'"),
        existing_nullable=False,
    )

    op.create_check_constraint(
        "processing_status_valid",
        "documents",
        _STAGE5_STATUS_CHECK,
    )
    op.create_check_constraint(
        "storage_state_valid",
        "documents",
        _STORAGE_STATE_CHECK,
    )
    op.create_check_constraint(
        "scan_attempts_non_negative",
        "documents",
        _SCAN_ATTEMPTS_CHECK,
    )
    op.create_check_constraint(
        "failure_reason_valid",
        "documents",
        _FAILURE_REASON_CHECK,
    )
    op.create_check_constraint(
        "status_storage_consistency",
        "documents",
        _STATUS_STORAGE_CONSISTENCY_CHECK,
    )
    op.create_index(
        "ix_documents_processing_status",
        "documents",
        ["processing_status", "updated_at"],
    )


def downgrade() -> None:
    """Revert Stage 5 quarantine/scanning columns and restore Stage 4 processing_status check."""
    op.drop_index("ix_documents_processing_status", table_name="documents")
    op.drop_constraint("status_storage_consistency", "documents", type_="check")
    op.drop_constraint("failure_reason_valid", "documents", type_="check")
    op.drop_constraint("scan_attempts_non_negative", "documents", type_="check")
    op.drop_constraint("storage_state_valid", "documents", type_="check")
    op.drop_constraint("processing_status_valid", "documents", type_="check")

    op.execute(
        sa.text(
            "UPDATE documents "
            "SET processing_status = 'none' "
            "WHERE processing_status NOT IN "
            "('none', 'queued', 'running', 'needs_review', 'confirmed', 'rejected', 'failed')"
        )
    )
    op.alter_column(
        "documents",
        "processing_status",
        existing_type=sa.String(length=24),
        server_default=sa.text("'none'"),
        existing_nullable=False,
    )
    op.create_check_constraint(
        "processing_status_valid",
        "documents",
        _STAGE4_STATUS_CHECK,
    )

    op.drop_column("documents", "failure_reason")
    op.drop_column("documents", "scanned_at")
    op.drop_column("documents", "scan_started_at")
    op.drop_column("documents", "scan_attempts")
    op.drop_column("documents", "storage_state")
