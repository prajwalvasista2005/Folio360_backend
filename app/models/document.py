"""SQLAlchemy ORM models for Phase 2 Stage 4 Document Vault and Education linking."""

from datetime import datetime
from typing import TYPE_CHECKING, Optional
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.certificate import AchievementDocument, Certificate
    from app.models.education import Education
    from app.models.experience import ExperienceDocument

DOCUMENT_CATEGORIES: tuple[str, ...] = (
    "marksheet",
    "certificate",
    "resume",
    "identity",
    "project_report",
    "other",
)
DOCUMENT_MIME_TYPES: tuple[str, ...] = (
    "application/pdf",
    "image/jpeg",
    "image/png",
)
DOCUMENT_PROCESSING_STATUSES: tuple[str, ...] = (
    "pending_scan",
    "scanning",
    "ready",
    "rejected",
    "scan_failed",
)
DOCUMENT_STORAGE_STATES: tuple[str, ...] = (
    "quarantine",
    "trusted",
    "deleted",
)
DOCUMENT_FAILURE_REASONS: tuple[str, ...] = (
    "malware_detected",
    "validation_failed",
    "scanner_unavailable",
    "scanner_timeout",
    "scanner_error",
    "promotion_failed",
)
DOCUMENT_STORAGE_BACKENDS: tuple[str, ...] = ("local", "s3")

_CATEGORIES_SQL = ", ".join(f"'{cat}'" for cat in DOCUMENT_CATEGORIES)
_MIME_TYPES_SQL = ", ".join(f"'{mime}'" for mime in DOCUMENT_MIME_TYPES)
_STATUSES_SQL = ", ".join(f"'{st}'" for st in DOCUMENT_PROCESSING_STATUSES)
_STORAGE_STATES_SQL = ", ".join(f"'{state}'" for state in DOCUMENT_STORAGE_STATES)
_FAILURE_REASONS_SQL = ", ".join(f"'{reason}'" for reason in DOCUMENT_FAILURE_REASONS)
_BACKENDS_SQL = ", ".join(f"'{be}'" for be in DOCUMENT_STORAGE_BACKENDS)


class Document(Base, TimestampMixin):
    """Private-by-default user-owned document metadata record."""

    __tablename__ = "documents"
    __table_args__ = (
        UniqueConstraint("storage_key", name="uq_documents_storage_key"),
        CheckConstraint(
            "title = btrim(title) AND char_length(title) BETWEEN 1 AND 255",
            name="title_valid",
        ),
        CheckConstraint(
            "original_filename = btrim(original_filename) AND char_length(original_filename) BETWEEN 1 AND 255",
            name="original_filename_valid",
        ),
        CheckConstraint(
            f"category IN ({_CATEGORIES_SQL})",
            name="category_valid",
        ),
        CheckConstraint(
            f"mime_type IN ({_MIME_TYPES_SQL})",
            name="mime_type_valid",
        ),
        CheckConstraint(
            "size_bytes > 0",
            name="size_bytes_positive",
        ),
        CheckConstraint(
            "page_count IS NULL OR page_count > 0",
            name="page_count_positive",
        ),
        CheckConstraint(
            "sha256 ~ '^[0-9a-f]{64}$'",
            name="sha256_hex",
        ),
        CheckConstraint(
            f"storage_backend IN ({_BACKENDS_SQL})",
            name="storage_backend_valid",
        ),
        CheckConstraint(
            "storage_key = btrim(storage_key) AND char_length(storage_key) BETWEEN 1 AND 512",
            name="storage_key_valid",
        ),
        CheckConstraint(
            f"processing_status IN ({_STATUSES_SQL})",
            name="processing_status_valid",
        ),
        CheckConstraint(
            f"storage_state IN ({_STORAGE_STATES_SQL})",
            name="storage_state_valid",
        ),
        CheckConstraint(
            "scan_attempts >= 0",
            name="scan_attempts_non_negative",
        ),
        CheckConstraint(
            f"failure_reason IS NULL OR failure_reason IN ({_FAILURE_REASONS_SQL})",
            name="failure_reason_valid",
        ),
        CheckConstraint(
            "(processing_status = 'ready' AND storage_state = 'trusted') OR "
            "(processing_status IN ('pending_scan', 'scanning') AND storage_state = 'quarantine') OR "
            "(processing_status IN ('rejected', 'scan_failed') AND storage_state IN ('quarantine', 'deleted'))",
            name="status_storage_consistency",
        ),
        Index("ix_documents_user_id", "user_id"),
        Index("ix_documents_user_created", "user_id", "created_at"),
        Index("ix_documents_processing_status", "processing_status", "updated_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    original_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    category: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    mime_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    size_bytes: Mapped[int] = mapped_column(
        BigInteger(),
        nullable=False,
    )
    page_count: Mapped[Optional[int]] = mapped_column(
        SmallInteger(),
        nullable=True,
    )
    sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    storage_backend: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    storage_key: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )
    notes: Mapped[Optional[str]] = mapped_column(
        Text(),
        nullable=True,
    )
    processing_status: Mapped[str] = mapped_column(
        String(24),
        default="pending_scan",
        server_default=text("'pending_scan'"),
        nullable=False,
    )
    storage_state: Mapped[str] = mapped_column(
        String(16),
        default="quarantine",
        server_default=text("'quarantine'"),
        nullable=False,
    )
    scan_attempts: Mapped[int] = mapped_column(
        SmallInteger(),
        default=0,
        server_default=text("0"),
        nullable=False,
    )
    scan_started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    scanned_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    failure_reason: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    show_in_education: Mapped[bool] = mapped_column(
        Boolean(),
        default=True,
        server_default=text("true"),
        nullable=False,
    )

    education_links: Mapped[list["EducationDocument"]] = relationship(
        "EducationDocument",
        back_populates="document",
        cascade="all, delete-orphan",
    )
    certificates: Mapped[list["Certificate"]] = relationship(
        "Certificate",
        back_populates="document",
    )
    achievement_links: Mapped[list["AchievementDocument"]] = relationship(
        "AchievementDocument",
        back_populates="document",
        cascade="all, delete-orphan",
    )
    experience_links: Mapped[list["ExperienceDocument"]] = relationship(
        "ExperienceDocument",
        back_populates="document",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return (
            f"<Document id={self.id!r} user_id={self.user_id!r} "
            f"category={self.category!r}>"
        )


class EducationDocument(Base):
    """Association link between an Education record and an owned Document."""

    __tablename__ = "education_documents"
    __table_args__ = (
        CheckConstraint(
            "display_order >= 0",
            name="display_order_non_negative",
        ),
        Index("ix_education_documents_document_id", "document_id"),
    )

    education_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("educations.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("documents.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    display_order: Mapped[int] = mapped_column(
        SmallInteger(),
        default=0,
        server_default=text("0"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    education: Mapped["Education"] = relationship(
        "Education",
        back_populates="document_links",
    )
    document: Mapped["Document"] = relationship(
        "Document",
        back_populates="education_links",
    )

    def __repr__(self) -> str:
        return (
            f"<EducationDocument education_id={self.education_id!r} "
            f"document_id={self.document_id!r} display_order={self.display_order!r}>"
        )
