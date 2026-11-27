"""SQLAlchemy ORM model for user skills."""

from typing import Optional
import uuid

from sqlalchemy import ForeignKey, Index, String, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class Skill(Base, TimestampMixin):
    """Persistent user-owned skill record."""

    __tablename__ = "skills"
    __table_args__ = (Index("ix_skills_user_id", "user_id"),)

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    category: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="technical",
        server_default=text("'technical'"),
    )
    proficiency: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
