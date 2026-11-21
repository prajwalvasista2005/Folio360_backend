"""Refresh session ORM model for rotating single-use opaque refresh tokens."""

from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy import CHAR, CheckConstraint, DateTime, ForeignKey, Index, String, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class RefreshSession(Base, TimestampMixin):
    """Rotating opaque refresh-token session grouped by family_id."""

    __tablename__ = "refresh_sessions"
    __table_args__ = (
        CheckConstraint(
            "client_type IN ('web', 'mobile')",
            name="client_type",
        ),
        CheckConstraint(
            "token_hash ~ '^[0-9a-f]{64}$'",
            name="hash_hex",
        ),
        CheckConstraint(
            "expires_at <= family_expires_at",
            name="expiry_bounds",
        ),
        CheckConstraint(
            "(revoked_at IS NULL AND revoke_reason IS NULL) OR "
            "(revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)",
            name="revoke_reason_consistency",
        ),
        Index(
            "ix_refresh_sessions_user_active",
            "user_id",
            "revoked_at",
        ),
        Index(
            "ix_refresh_sessions_family_id",
            "family_id",
        ),
        Index(
            "ix_refresh_sessions_expires_at",
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
    family_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(
        CHAR(64),
        unique=True,
        nullable=False,
    )
    parent_session_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("refresh_sessions.id", ondelete="SET NULL"),
        nullable=True,
    )
    replaced_by_session_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("refresh_sessions.id", ondelete="SET NULL"),
        nullable=True,
    )
    client_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    user_agent: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    family_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoke_reason: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )

    def __repr__(self) -> str:
        return (
            f"<RefreshSession id={self.id!r} user_id={self.user_id!r} "
            f"family_id={self.family_id!r} client_type={self.client_type!r}>"
        )
