"""SQLAlchemy ORM models for Phase 3 Projects Portfolio."""

from datetime import date, datetime
from typing import Optional
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

PROJECT_VISIBILITIES: tuple[str, ...] = ("private", "public")
PROJECT_IMAGE_MIME_TYPES: tuple[str, ...] = ("image/jpeg", "image/png", "image/webp")
PROJECT_IMAGE_STORAGE_BACKENDS: tuple[str, ...] = ("local", "s3")

_VISIBILITIES_SQL = ", ".join(f"'{vis}'" for vis in PROJECT_VISIBILITIES)
_IMAGE_MIMES_SQL = ", ".join(f"'{mime}'" for mime in PROJECT_IMAGE_MIME_TYPES)
_BACKENDS_SQL = ", ".join(f"'{b}'" for b in PROJECT_IMAGE_STORAGE_BACKENDS)


class Project(Base, TimestampMixin):
    """Persistent user-owned portfolio project record."""

    __tablename__ = "projects"
    __table_args__ = (
        CheckConstraint(
            "title = btrim(title) AND char_length(title) BETWEEN 1 AND 200",
            name="title_valid",
        ),
        CheckConstraint(
            "summary = btrim(summary) AND char_length(summary) BETWEEN 1 AND 500",
            name="summary_valid",
        ),
        CheckConstraint(
            "category = btrim(category) AND char_length(category) BETWEEN 1 AND 80",
            name="category_valid",
        ),
        CheckConstraint(
            "jsonb_typeof(technologies) = 'array'",
            name="technologies_array",
        ),
        CheckConstraint(
            "NOT (is_ongoing = true AND end_date IS NOT NULL)",
            name="ongoing_no_end_date",
        ),
        CheckConstraint(
            "start_date IS NULL OR end_date IS NULL OR end_date >= start_date",
            name="date_order_valid",
        ),
        CheckConstraint(
            "display_order >= 0",
            name="display_order_non_negative",
        ),
        CheckConstraint(
            f"visibility IN ({_VISIBILITIES_SQL})",
            name="visibility_valid",
        ),
        Index("ix_projects_user_id", "user_id"),
        Index("ix_projects_user_visibility", "user_id", "visibility"),
        Index(
            "uq_projects_user_github_repo_id",
            "user_id",
            "github_repo_id",
            unique=True,
            postgresql_where=text("github_repo_id IS NOT NULL"),
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
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)
    category: Mapped[str] = mapped_column(
        String(80),
        default="General",
        server_default=text("'General'"),
        nullable=False,
    )
    technologies: Mapped[list[str]] = mapped_column(
        JSONB(),
        default=list,
        server_default=text("'[]'::jsonb"),
        nullable=False,
    )
    github_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    live_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    start_date: Mapped[Optional[date]] = mapped_column(Date(), nullable=True)
    end_date: Mapped[Optional[date]] = mapped_column(Date(), nullable=True)
    is_ongoing: Mapped[bool] = mapped_column(
        Boolean(),
        default=False,
        server_default=text("false"),
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
    github_repo_id: Mapped[Optional[int]] = mapped_column(BigInteger(), nullable=True)
    github_repo_full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    github_imported_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    images: Mapped[list["ProjectImage"]] = relationship(
        "ProjectImage",
        back_populates="project",
        cascade="all, delete-orphan",
        order_by="ProjectImage.display_order",
    )

    def __repr__(self) -> str:
        return (
            f"<Project id={self.id!r} user_id={self.user_id!r} "
            f"visibility={self.visibility!r}>"
        )


class ProjectImage(Base, TimestampMixin):
    """Cover / showcase image attached to a portfolio Project."""

    __tablename__ = "project_images"
    __table_args__ = (
        CheckConstraint(
            f"storage_backend IN ({_BACKENDS_SQL})",
            name="storage_backend_valid",
        ),
        CheckConstraint(
            f"mime_type IN ({_IMAGE_MIMES_SQL})",
            name="mime_type_valid",
        ),
        CheckConstraint(
            "size_bytes > 0",
            name="size_bytes_positive",
        ),
        CheckConstraint(
            "display_order >= 0",
            name="display_order_non_negative",
        ),
        Index("ix_project_images_project_id", "project_id"),
        Index("ix_project_images_user_id", "user_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        nullable=False,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    storage_backend: Mapped[str] = mapped_column(String(16), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer(), nullable=False)
    alt: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    display_order: Mapped[int] = mapped_column(
        Integer(),
        default=0,
        server_default=text("0"),
        nullable=False,
    )

    project: Mapped["Project"] = relationship("Project", back_populates="images")

    def __repr__(self) -> str:
        return f"<ProjectImage id={self.id!r} project_id={self.project_id!r}>"


__all__ = [
    "PROJECT_IMAGE_MIME_TYPES",
    "PROJECT_IMAGE_STORAGE_BACKENDS",
    "PROJECT_VISIBILITIES",
    "Project",
    "ProjectImage",
]
