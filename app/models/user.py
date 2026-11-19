"""Minimal User ORM model for Folio360 persistence."""

import uuid

from sqlalchemy import Boolean, CheckConstraint, String, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class User(Base, TimestampMixin):
    """Persistent user identity record."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("email = lower(btrim(email))", name="email_lowercase_trimmed"),
        CheckConstraint("length(btrim(email)) > 0", name="email_not_empty"),
        CheckConstraint("email !~ '[[:space:]]'", name="email_no_whitespace"),
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
    is_active: Mapped[bool] = mapped_column(
        Boolean(),
        default=True,
        server_default=text("true"),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<User id={self.id!r} is_active={self.is_active!r}>"
