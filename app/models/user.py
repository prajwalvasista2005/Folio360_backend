"""User ORM model for Folio360 persistence and Stage 3A authentication."""

from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy import Boolean, CheckConstraint, DateTime, Integer, String, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class User(Base, TimestampMixin):
    """Persistent user identity and authentication state record."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("email = lower(btrim(email))", name="email_lowercase_trimmed"),
        CheckConstraint("length(btrim(email)) > 0", name="email_not_empty"),
        CheckConstraint("email !~ '[[:space:]]'", name="email_no_whitespace"),
        CheckConstraint(
            "(is_email_verified = false AND email_verified_at IS NULL) OR "
            "(is_email_verified = true AND email_verified_at IS NOT NULL)",
            name="email_verified_at_consistency",
        ),
        CheckConstraint("auth_version >= 0", name="auth_version_non_negative"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        nullable=False,
    )
    email: Mapped[str] = mapped_column(
        String(320),
        unique=True,
        nullable=False,
    )
    password_hash: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean(),
        default=True,
        server_default=text("true"),
        nullable=False,
    )
    is_email_verified: Mapped[bool] = mapped_column(
        Boolean(),
        default=False,
        server_default=text("false"),
        nullable=False,
    )
    email_verified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    auth_version: Mapped[int] = mapped_column(
        Integer(),
        default=0,
        server_default=text("0"),
        nullable=False,
    )
    password_changed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def __repr__(self) -> str:
        return (
            f"<User id={self.id!r} is_active={self.is_active!r} "
            f"is_email_verified={self.is_email_verified!r}>"
        )
