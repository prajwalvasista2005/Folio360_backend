"""SQLAlchemy ORM models for persistent security audit logs and email-change tokens."""

from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy import (
    CHAR,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class SecurityAuditEvent(Base):
    """Owner-scoped security audit trail record (never stores passwords or tokens)."""

    __tablename__ = "security_audit_events"
    __table_args__ = (
        CheckConstraint(
            "action = btrim(action) AND char_length(action) BETWEEN 1 AND 64",
            name="action_valid",
        ),
        Index(
            "ix_security_audit_events_user_created",
            "user_id",
            "created_at",
        ),
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
    action: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )
    device_label: Mapped[Optional[str]] = mapped_column(
        String(120),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class EmailChangeToken(Base):
    """Single-use hashed verification token for pending account email changes."""

    __tablename__ = "email_change_tokens"
    __table_args__ = (
        CheckConstraint(
            "new_email = lower(btrim(new_email)) AND length(btrim(new_email)) > 0",
            name="new_email_canonical",
        ),
        CheckConstraint(
            "token_hash ~ '^[0-9a-f]{64}$'",
            name="hash_hex",
        ),
        Index("ix_email_change_tokens_user_id", "user_id"),
        Index(
            "uq_email_change_tokens_active_new_email",
            "new_email",
            unique=True,
            postgresql_where=text("consumed_at IS NULL AND revoked_at IS NULL"),
        ),
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
    new_email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(
        CHAR(64),
        unique=True,
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    consumed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
