"""Email verification token ORM model for Stage 3A registration and Resend tracking."""

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
    desc,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class EmailVerificationToken(Base, TimestampMixin):
    """Single-use hashed email verification token with Resend delivery tracking."""

    __tablename__ = "email_verification_tokens"
    __table_args__ = (
        CheckConstraint(
            "delivery_status IN ('pending', 'sent', 'failed')",
            name="delivery_status",
        ),
        CheckConstraint(
            "token_hash ~ '^[0-9a-f]{64}$'",
            name="hash_hex",
        ),
        CheckConstraint(
            "NOT (consumed_at IS NOT NULL AND revoked_at IS NOT NULL)",
            name="not_both_consumed_revoked",
        ),
        Index(
            "ix_email_verification_tokens_user_created",
            "user_id",
            desc("created_at"),
        ),
        Index(
            "ix_email_verification_tokens_expires_at",
            "expires_at",
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
    token_hash: Mapped[str] = mapped_column(
        CHAR(64),
        unique=True,
        nullable=False,
    )
    delivery_status: Mapped[str] = mapped_column(
        String(16),
        default="pending",
        server_default=text("'pending'"),
        nullable=False,
    )
    delivery_attempted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
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

    def __repr__(self) -> str:
        return (
            f"<EmailVerificationToken id={self.id!r} user_id={self.user_id!r} "
            f"delivery_status={self.delivery_status!r}>"
        )
