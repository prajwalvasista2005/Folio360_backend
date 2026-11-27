"""SQLAlchemy ORM models for Certificates, CertificateSkills, Achievements, and AchievementDocuments."""

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
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.document import Document
    from app.models.skill import Skill

CERTIFICATE_CATEGORIES: tuple[str, ...] = (
    "course",
    "professional",
    "training",
    "workshop",
    "participation",
    "academic",
    "other",
)
CERTIFICATE_VERIFICATION_STATUSES: tuple[str, ...] = (
    "self_reported",
    "link_provided",
    "issuer_verified",
)
ACHIEVEMENT_CATEGORIES: tuple[str, ...] = (
    "award",
    "competition",
    "publication",
    "scholarship",
    "academic_distinction",
    "hackathon",
    "leadership",
    "extracurricular",
    "other",
)
CREDENTIAL_VISIBILITIES: tuple[str, ...] = ("private", "public")

_CERT_CATEGORIES_SQL = ", ".join(f"'{item}'" for item in CERTIFICATE_CATEGORIES)
_VERIF_STATUSES_SQL = ", ".join(f"'{item}'" for item in CERTIFICATE_VERIFICATION_STATUSES)
_ACH_CATEGORIES_SQL = ", ".join(f"'{item}'" for item in ACHIEVEMENT_CATEGORIES)
_VISIBILITIES_SQL = ", ".join(f"'{item}'" for item in CREDENTIAL_VISIBILITIES)


class Certificate(Base, TimestampMixin):
    """Persistent user-owned certificate record."""

    __tablename__ = "certificates"
    __table_args__ = (
        CheckConstraint(
            "name = btrim(name) AND char_length(name) BETWEEN 1 AND 200",
            name="name_valid",
        ),
        CheckConstraint(
            "issuer = btrim(issuer) AND char_length(issuer) BETWEEN 1 AND 200",
            name="issuer_valid",
        ),
        CheckConstraint(
            f"category IN ({_CERT_CATEGORIES_SQL})",
            name="category_valid",
        ),
        CheckConstraint(
            "issue_date IS NULL OR expiry_date IS NULL OR expiry_date >= issue_date",
            name="date_order_valid",
        ),
        CheckConstraint(
            f"verification_status IN ({_VERIF_STATUSES_SQL})",
            name="verification_status_valid",
        ),
        CheckConstraint(
            "display_order >= 0",
            name="display_order_non_negative",
        ),
        CheckConstraint(
            f"visibility IN ({_VISIBILITIES_SQL})",
            name="visibility_valid",
        ),
        Index("ix_certificates_user_id", "user_id"),
        Index("ix_certificates_user_visibility", "user_id", "visibility"),
        Index("ix_certificates_document_id", "document_id"),
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
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    issuer: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(
        String(40),
        default="course",
        server_default=text("'course'"),
        nullable=False,
    )
    issue_date: Mapped[Optional[date_type]] = mapped_column(Date(), nullable=True)
    expiry_date: Mapped[Optional[date_type]] = mapped_column(Date(), nullable=True)
    credential_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    verification_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    verification_status: Mapped[str] = mapped_column(
        String(24),
        default="self_reported",
        server_default=text("'self_reported'"),
        nullable=False,
    )
    document_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("documents.id", ondelete="SET NULL"),
        nullable=True,
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

    document: Mapped[Optional["Document"]] = relationship(
        "Document",
        back_populates="certificates",
    )
    skill_links: Mapped[list["CertificateSkill"]] = relationship(
        "CertificateSkill",
        back_populates="certificate",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return (
            f"<Certificate id={self.id!r} user_id={self.user_id!r} "
            f"visibility={self.visibility!r}>"
        )


class CertificateSkill(Base):
    """Association link between a Certificate and an owned Skill."""

    __tablename__ = "certificate_skills"
    __table_args__ = (
        Index("ix_certificate_skills_skill_id", "skill_id"),
    )

    certificate_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("certificates.id", ondelete="CASCADE"),
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

    certificate: Mapped["Certificate"] = relationship(
        "Certificate",
        back_populates="skill_links",
    )
    skill: Mapped["Skill"] = relationship("Skill")


class Achievement(Base, TimestampMixin):
    """Persistent user-owned achievement / recognition record."""

    __tablename__ = "achievements"
    __table_args__ = (
        CheckConstraint(
            "title = btrim(title) AND char_length(title) BETWEEN 1 AND 200",
            name="title_valid",
        ),
        CheckConstraint(
            f"category IN ({_ACH_CATEGORIES_SQL})",
            name="category_valid",
        ),
        CheckConstraint(
            "display_order >= 0",
            name="display_order_non_negative",
        ),
        CheckConstraint(
            f"visibility IN ({_VISIBILITIES_SQL})",
            name="visibility_valid",
        ),
        Index("ix_achievements_user_id", "user_id"),
        Index("ix_achievements_user_visibility", "user_id", "visibility"),
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
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(
        String(40),
        default="award",
        server_default=text("'award'"),
        nullable=False,
    )
    organization: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    date: Mapped[Optional[date_type]] = mapped_column(Date(), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)
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

    document_links: Mapped[list["AchievementDocument"]] = relationship(
        "AchievementDocument",
        back_populates="achievement",
        cascade="all, delete-orphan",
        order_by="AchievementDocument.display_order",
    )

    def __repr__(self) -> str:
        return (
            f"<Achievement id={self.id!r} user_id={self.user_id!r} "
            f"visibility={self.visibility!r}>"
        )


class AchievementDocument(Base):
    """Association link between an Achievement record and an owned Document."""

    __tablename__ = "achievement_documents"
    __table_args__ = (
        CheckConstraint(
            "display_order >= 0",
            name="display_order_non_negative",
        ),
        Index("ix_achievement_documents_document_id", "document_id"),
    )

    achievement_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("achievements.id", ondelete="CASCADE"),
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

    achievement: Mapped["Achievement"] = relationship(
        "Achievement",
        back_populates="document_links",
    )
    document: Mapped["Document"] = relationship(
        "Document",
        back_populates="achievement_links",
    )


__all__ = [
    "ACHIEVEMENT_CATEGORIES",
    "CERTIFICATE_CATEGORIES",
    "CERTIFICATE_VERIFICATION_STATUSES",
    "CREDENTIAL_VISIBILITIES",
    "Achievement",
    "AchievementDocument",
    "Certificate",
    "CertificateSkill",
]
