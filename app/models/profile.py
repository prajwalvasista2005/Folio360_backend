"""SQLAlchemy ORM models for Phase 1 UserProfile and UserProfileActivity."""

from datetime import date, datetime
from typing import Optional
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    SmallInteger,
    String,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.username import ACTIVITY_KEYS
from app.db.base import Base, TimestampMixin

_ACTIVITY_KEYS_SQL = ", ".join(f"'{key}'" for key in ACTIVITY_KEYS)


class UserProfile(Base, TimestampMixin):
    """Persistent 1:1 user onboarding and private profile record."""

    __tablename__ = "user_profiles"
    __table_args__ = (
        UniqueConstraint("user_id", name="uq_user_profiles_user_id"),
        UniqueConstraint("slug", name="uq_user_profiles_slug"),
        CheckConstraint(
            "slug IS NULL OR slug ~ '^[a-z0-9_]{3,30}$'",
            name="slug_canonical",
        ),
        CheckConstraint(
            "full_name IS NULL OR ("
            "full_name = btrim(full_name) "
            "AND char_length(full_name) BETWEEN 2 AND 150"
            ")",
            name="full_name_valid",
        ),
        CheckConstraint(
            "bio IS NULL OR ("
            "bio = btrim(bio) "
            "AND char_length(bio) BETWEEN 1 AND 500"
            ")",
            name="bio_valid",
        ),
        CheckConstraint(
            "profile_picture_url IS NULL OR ("
            "profile_picture_url = btrim(profile_picture_url) "
            "AND char_length(profile_picture_url) > 0 "
            "AND profile_picture_url !~ '[[:space:][:cntrl:]]'"
            ")",
            name="picture_url_valid",
        ),
        CheckConstraint(
            "jsonb_typeof(interests) = 'array'",
            name="interests_array",
        ),
        CheckConstraint(
            "(profile_completed = false AND profile_completed_at IS NULL) OR ("
            "profile_completed = true AND profile_completed_at IS NOT NULL "
            "AND slug IS NOT NULL "
            "AND full_name IS NOT NULL "
            "AND date_of_birth IS NOT NULL"
            ")",
            name="completion_consistency",
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
    slug: Mapped[Optional[str]] = mapped_column(
        String(30),
        nullable=True,
    )
    full_name: Mapped[Optional[str]] = mapped_column(
        String(150),
        nullable=True,
    )
    date_of_birth: Mapped[Optional[date]] = mapped_column(
        Date(),
        nullable=True,
    )
    bio: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )
    # Transitional Phase 1 URL field (mapped to API avatar_url); object storage is deferred.
    profile_picture_url: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
    )
    interests: Mapped[list[str]] = mapped_column(
        JSONB(),
        default=list,
        server_default=text("'[]'::jsonb"),
        nullable=False,
    )
    profile_completed: Mapped[bool] = mapped_column(
        Boolean(),
        default=False,
        server_default=text("false"),
        nullable=False,
    )
    profile_completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    activities: Mapped[list["UserProfileActivity"]] = relationship(
        "UserProfileActivity",
        back_populates="profile",
        cascade="all, delete-orphan",
        order_by="UserProfileActivity.display_order",
    )

    def __repr__(self) -> str:
        return (
            f"<UserProfile id={self.id!r} user_id={self.user_id!r} "
            f"profile_completed={self.profile_completed!r}>"
        )


class UserProfileActivity(Base, TimestampMixin):
    """Structured current activity selection belonging to a UserProfile."""

    __tablename__ = "user_profile_activities"
    __table_args__ = (
        UniqueConstraint(
            "profile_id",
            "activity_key",
            name="uq_user_profile_activities_profile_key",
        ),
        CheckConstraint(
            f"activity_key IN ({_ACTIVITY_KEYS_SQL})",
            name="activity_key",
        ),
        CheckConstraint(
            "(activity_key = 'other' AND custom_label IS NOT NULL "
            "AND custom_label = btrim(custom_label) "
            "AND char_length(custom_label) BETWEEN 2 AND 80) "
            "OR (activity_key <> 'other' AND custom_label IS NULL)",
            name="custom_label_consistency",
        ),
        CheckConstraint(
            "description IS NULL OR ("
            "description = btrim(description) "
            "AND char_length(description) BETWEEN 1 AND 200"
            ")",
            name="description_valid",
        ),
        CheckConstraint(
            "display_order >= 0",
            name="display_order_non_negative",
        ),
        Index(
            "ix_user_profile_activities_profile_id",
            "profile_id",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        nullable=False,
    )
    profile_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("user_profiles.id", ondelete="CASCADE"),
        nullable=False,
    )
    activity_key: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    custom_label: Mapped[Optional[str]] = mapped_column(
        String(80),
        nullable=True,
    )
    description: Mapped[Optional[str]] = mapped_column(
        String(200),
        nullable=True,
    )
    display_order: Mapped[int] = mapped_column(
        SmallInteger(),
        default=0,
        server_default=text("0"),
        nullable=False,
    )

    profile: Mapped["UserProfile"] = relationship(
        "UserProfile",
        back_populates="activities",
    )

    def __repr__(self) -> str:
        return (
            f"<UserProfileActivity id={self.id!r} profile_id={self.profile_id!r} "
            f"activity_key={self.activity_key!r}>"
        )
