"""SQLAlchemy ORM models for Experience, ExperienceSkill, and ExperienceDocument."""

from datetime import date as date_type, datetime
from typing import TYPE_CHECKING, Optional
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.document import Document
    from app.models.skill import Skill

EXPERIENCE_TYPES: tuple[str, ...] = (
    "internship",
    "employment",
    "freelance",
    "research",
    "volunteering",
    "mentorship",
    "leadership",
    "other",
)
EXPERIENCE_VISIBILITIES: tuple[str, ...] = ("private", "public")

_EXPERIENCE_TYPES_SQL = ", ".join(f"'{item}'" for item in EXPERIENCE_TYPES)
_VISIBILITIES_SQL = ", ".join(f"'{item}'" for item in EXPERIENCE_VISIBILITIES)


class Experience(Base, TimestampMixin):
    """Persistent user-owned professional, leadership, or volunteering experience."""

    __tablename__ = "experiences"
    __table_args__ = (
        CheckConstraint(
            "organization = btrim(organization) AND char_length(organization) BETWEEN 1 AND 200",
            name="organization_valid",
        ),
        CheckConstraint(
            "role = btrim(role) AND char_length(role) BETWEEN 1 AND 200",
            name="role_valid",
        ),
        CheckConstraint(
            f"type IN ({_EXPERIENCE_TYPES_SQL})",
            name="type_valid",
        ),
        CheckConstraint(
            "NOT (is_current = true AND end_date IS NOT NULL)",
            name="current_no_end_date",
        ),
        CheckConstraint(
            "end_date IS NULL OR end_date >= start_date",
            name="date_order_valid",
        ),
        CheckConstraint(
            "jsonb_typeof(highlights) = 'array'",
            name="highlights_array",
        ),
        CheckConstraint(
            "display_order >= 0",
            name="display_order_non_negative",
        ),
        CheckConstraint(
            f"visibility IN ({_VISIBILITIES_SQL})",
            name="visibility_valid",
        ),
        Index("ix_experiences_user_id", "user_id"),
        Index("ix_experiences_user_visibility", "user_id", "visibility"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    type: Mapped[str] = mapped_column(
        String(32),
        default="internship",
        server_default=text("'internship'"),
        nullable=False,
    )
    organization: Mapped[str] = mapped_column(String(200), nullable=False)
    role: Mapped[str] = mapped_column(String(200), nullable=False)
    location: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    is_remote: Mapped[bool] = mapped_column(
        Boolean(),
        default=False,
        server_default=text("false"),
        nullable=False,
    )
    organization_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    start_date: Mapped[date_type] = mapped_column(Date(), nullable=False)
    end_date: Mapped[Optional[date_type]] = mapped_column(Date(), nullable=True)
    is_current: Mapped[bool] = mapped_column(
        Boolean(),
        default=False,
        server_default=text("false"),
        nullable=False,
    )
    description: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)
    highlights: Mapped[list[str]] = mapped_column(
        JSONB(),
        default=list,
        server_default=text("'[]'::jsonb"),
        nullable=False,
    )
    featured: Mapped[bool] = mapped_column(
        Boolean(),
        default=False,
        server_default=text("false"),
        nullable=False,
    )
    display_order: Mapped[int] = mapped_column(
        Integer(),
        default=0,
        server_default=text("0"),
        nullable=False,
    )
    visibility: Mapped[str] = mapped_column(
        String(16),
        default="private",
        server_default=text("'private'"),
        nullable=False,
    )

    skill_links: Mapped[list["ExperienceSkill"]] = relationship(
        "ExperienceSkill",
        back_populates="experience",
        cascade="all, delete-orphan",
    )
    document_links: Mapped[list["ExperienceDocument"]] = relationship(
        "ExperienceDocument",
        back_populates="experience",
        cascade="all, delete-orphan",
        order_by="ExperienceDocument.display_order",
    )

    def __repr__(self) -> str:
        return (
            f"<Experience id={self.id!r} user_id={self.user_id!r} "
            f"visibility={self.visibility!r}>"
        )


class ExperienceSkill(Base):
    """Association link between an Experience record and an owned Skill."""

    __tablename__ = "experience_skills"
    __table_args__ = (
        Index("ix_experience_skills_skill_id", "skill_id"),
    )

    experience_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("experiences.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    skill_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("skills.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    experience: Mapped["Experience"] = relationship(
        "Experience",
        back_populates="skill_links",
    )
    skill: Mapped["Skill"] = relationship("Skill")


class ExperienceDocument(Base):
    """Association link between an Experience record and an owned Document."""

    __tablename__ = "experience_documents"
    __table_args__ = (
        CheckConstraint(
            "display_order >= 0",
            name="display_order_non_negative",
        ),
        Index("ix_experience_documents_document_id", "document_id"),
    )

    experience_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("experiences.id", ondelete="CASCADE"),
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

    experience: Mapped["Experience"] = relationship(
        "Experience",
        back_populates="document_links",
    )
    document: Mapped["Document"] = relationship(
        "Document",
        back_populates="experience_links",
    )


__all__ = [
    "EXPERIENCE_TYPES",
    "EXPERIENCE_VISIBILITIES",
    "Experience",
    "ExperienceDocument",
    "ExperienceSkill",
]
