"""SQLAlchemy ORM model for Phase 2 Stage 6 AI Document Analysis metadata and results."""

from datetime import datetime
from decimal import Decimal
from typing import Any, Optional
import uuid

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin

ANALYSIS_STATUSES: tuple[str, ...] = (
    "pending",
    "processing",
    "completed",
    "failed",
)
ANALYZED_DOCUMENT_TYPES: tuple[str, ...] = (
    "marksheet",
    "certificate",
    "other",
)
ANALYSIS_FAILURE_REASONS: tuple[str, ...] = (
    "provider_not_configured",
    "provider_unavailable",
    "provider_timeout",
    "provider_rate_limited",
    "invalid_provider_output",
    "unsupported_content",
    "analysis_error",
)

_ANALYSIS_STATUSES_SQL = ", ".join(f"'{s}'" for s in ANALYSIS_STATUSES)
_DOC_TYPES_SQL = ", ".join(f"'{t}'" for t in ANALYZED_DOCUMENT_TYPES)
_FAILURE_REASONS_SQL = ", ".join(f"'{r}'" for r in ANALYSIS_FAILURE_REASONS)


class DocumentAnalysis(Base, TimestampMixin):
    """Owner-scoped, review-only structured extraction record attached to a ready Document."""

    __tablename__ = "document_analyses"
    __table_args__ = (
        UniqueConstraint("document_id", name="uq_document_analyses_document_id"),
        CheckConstraint(
            f"status IN ({_ANALYSIS_STATUSES_SQL})",
            name="status_valid",
        ),
        CheckConstraint(
            f"document_type IS NULL OR document_type IN ({_DOC_TYPES_SQL})",
            name="document_type_valid",
        ),
        CheckConstraint(
            "attempts >= 0",
            name="attempts_non_negative",
        ),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="confidence_range",
        ),
        CheckConstraint(
            "jsonb_typeof(uncertain_fields) = 'array'",
            name="uncertain_fields_array",
        ),
        CheckConstraint(
            f"failure_reason IS NULL OR failure_reason IN ({_FAILURE_REASONS_SQL})",
            name="failure_reason_valid",
        ),
        CheckConstraint(
            "(status = 'completed' AND extracted_data IS NOT NULL AND failure_reason IS NULL) OR "
            "(status = 'failed' AND failure_reason IS NOT NULL) OR "
            "(status IN ('pending', 'processing') AND failure_reason IS NULL)",
            name="status_result_consistency",
        ),
        Index("ix_document_analyses_user_id", "user_id"),
        Index("ix_document_analyses_status_updated", "status", "updated_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        nullable=False,
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("documents.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(24),
        default="pending",
        server_default=text("'pending'"),
        nullable=False,
    )
    document_type: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
    )
    provider_name: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    model_name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    analyzer_version: Mapped[str] = mapped_column(
        String(32),
        default="stage6-v1",
        server_default=text("'stage6-v1'"),
        nullable=False,
    )
    attempts: Mapped[int] = mapped_column(
        SmallInteger(),
        default=0,
        server_default=text("0"),
        nullable=False,
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    summary: Mapped[Optional[str]] = mapped_column(
        Text(),
        nullable=True,
    )
    extracted_data: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True,
    )
    confidence: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(precision=4, scale=3),
        nullable=True,
    )
    uncertain_fields: Mapped[list[str]] = mapped_column(
        JSONB,
        default=list,
        server_default=text("'[]'::jsonb"),
        nullable=False,
    )
    failure_reason: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )

    def __repr__(self) -> str:
        return (
            f"<DocumentAnalysis id={self.id!r} document_id={self.document_id!r} "
            f"user_id={self.user_id!r} status={self.status!r}>"
        )
