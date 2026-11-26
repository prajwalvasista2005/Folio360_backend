"""SQLAlchemy ORM model for Phase 2 Education records."""

from decimal import Decimal
from typing import TYPE_CHECKING, Optional
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Numeric,
    SmallInteger,
    String,
    Text,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.document import EducationDocument

EDUCATION_RESULT_SOURCES: tuple[str, ...] = ("manual", "computed")
EDUCATION_VISIBILITIES: tuple[str, ...] = ("public", "private", "unlisted", "connections")

_RESULT_SOURCES_SQL = ", ".join(f"'{src}'" for src in EDUCATION_RESULT_SOURCES)
_VISIBILITIES_SQL = ", ".join(f"'{vis}'" for vis in EDUCATION_VISIBILITIES)


class Education(Base, TimestampMixin):
    """Persistent user-owned academic education record."""

    __tablename__ = "educations"
    __table_args__ = (
        CheckConstraint(
            "institution = btrim(institution) AND char_length(institution) BETWEEN 1 AND 255",
            name="institution_valid",
        ),
        CheckConstraint(
            "degree = btrim(degree) AND char_length(degree) BETWEEN 1 AND 255",
            name="degree_valid",
        ),
        CheckConstraint(
            "start_month IS NULL OR start_month BETWEEN 1 AND 12",
            name="start_month_range",
        ),
        CheckConstraint(
            "end_month IS NULL OR end_month BETWEEN 1 AND 12",
            name="end_month_range",
        ),
        CheckConstraint(
            "start_year IS NULL OR start_year BETWEEN 1900 AND 2100",
            name="start_year_range",
        ),
        CheckConstraint(
            "end_year IS NULL OR end_year BETWEEN 1900 AND 2100",
            name="end_year_range",
        ),
        CheckConstraint(
            "start_month IS NULL OR start_year IS NOT NULL",
            name="start_month_requires_year",
        ),
        CheckConstraint(
            "end_month IS NULL OR end_year IS NOT NULL",
            name="end_month_requires_year",
        ),
        CheckConstraint(
            "NOT (is_current = true AND (end_year IS NOT NULL OR end_month IS NOT NULL))",
            name="current_no_end_date",
        ),
        CheckConstraint(
            "start_year IS NULL OR end_year IS NULL OR end_year > start_year OR "
            "(end_year = start_year AND (start_month IS NULL OR end_month IS NULL OR end_month >= start_month))",
            name="date_order_valid",
        ),
        CheckConstraint(
            f"result_source IN ({_RESULT_SOURCES_SQL})",
            name="result_source_valid",
        ),
        CheckConstraint(
            f"visibility IN ({_VISIBILITIES_SQL})",
            name="visibility_valid",
        ),
        CheckConstraint(
            "jsonb_typeof(achievements) = 'array'",
            name="achievements_array",
        ),
        CheckConstraint(
            "computed_cgpa IS NULL OR (computed_cgpa >= 0 AND computed_cgpa <= 10)",
            name="computed_cgpa_range",
        ),
        Index("ix_educations_user_id", "user_id"),
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
    institution: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    university_or_board: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    education_level: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    degree: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    programme: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    branch: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    specialization: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    country: Mapped[Optional[str]] = mapped_column(
        String(120),
        nullable=True,
    )
    state: Mapped[Optional[str]] = mapped_column(
        String(120),
        nullable=True,
    )
    start_month: Mapped[Optional[int]] = mapped_column(
        SmallInteger(),
        nullable=True,
    )
    start_year: Mapped[Optional[int]] = mapped_column(
        SmallInteger(),
        nullable=True,
    )
    end_month: Mapped[Optional[int]] = mapped_column(
        SmallInteger(),
        nullable=True,
    )
    end_year: Mapped[Optional[int]] = mapped_column(
        SmallInteger(),
        nullable=True,
    )
    is_current: Mapped[bool] = mapped_column(
        Boolean(),
        default=False,
        server_default=text("false"),
        nullable=False,
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text(),
        nullable=True,
    )
    scheme_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    result_type: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
    )
    result_value: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    result_source: Mapped[str] = mapped_column(
        String(16),
        default="manual",
        server_default=text("'manual'"),
        nullable=False,
    )
    computed_cgpa: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(5, 2),
        nullable=True,
    )
    show_result_publicly: Mapped[bool] = mapped_column(
        Boolean(),
        default=True,
        server_default=text("true"),
        nullable=False,
    )
    achievements: Mapped[list[str]] = mapped_column(
        JSONB(),
        default=list,
        server_default=text("'[]'::jsonb"),
        nullable=False,
    )
    visibility: Mapped[str] = mapped_column(
        String(32),
        default="public",
        server_default=text("'public'"),
        nullable=False,
    )

    document_links: Mapped[list["EducationDocument"]] = relationship(
        "EducationDocument",
        back_populates="education",
        cascade="all, delete-orphan",
        order_by="EducationDocument.display_order",
    )

    def __repr__(self) -> str:
        return (
            f"<Education id={self.id!r} user_id={self.user_id!r} "
            f"is_current={self.is_current!r}>"
        )
