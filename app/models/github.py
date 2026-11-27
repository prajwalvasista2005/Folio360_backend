"""SQLAlchemy ORM models for Phase 3 separate GitHub portfolio integration."""

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
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class GitHubConnection(Base, TimestampMixin):
    """Per-user GitHub portfolio connection storing an encrypted GitHub OAuth access token."""

    __tablename__ = "github_connections"
    __table_args__ = (
        UniqueConstraint("user_id", name="uq_github_connections_user_id"),
        CheckConstraint(
            "github_user_id = btrim(github_user_id) AND char_length(github_user_id) > 0",
            name="github_user_id_valid",
        ),
        CheckConstraint(
            "username = btrim(username) AND char_length(username) > 0",
            name="username_valid",
        ),
        CheckConstraint(
            "length(btrim(access_token_encrypted)) > 0",
            name="token_not_empty",
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
    github_user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    username: Mapped[str] = mapped_column(String(120), nullable=False)
    avatar_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    access_token_encrypted: Mapped[str] = mapped_column(Text(), nullable=False)
    token_scope: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    connected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<GitHubConnection id={self.id!r} user_id={self.user_id!r} username={self.username!r}>"


class GitHubOAuthState(Base, TimestampMixin):
    """Single-use state record for user-authenticated GitHub portfolio connect OAuth flow."""

    __tablename__ = "github_oauth_states"
    __table_args__ = (
        CheckConstraint(
            "state_hash ~ '^[0-9a-f]{64}$'",
            name="state_hash_hex",
        ),
        CheckConstraint(
            "length(btrim(redirect_uri)) > 0 AND redirect_uri = btrim(redirect_uri)",
            name="redirect_uri_valid",
        ),
        Index("ix_github_oauth_states_user_id", "user_id"),
        Index("ix_github_oauth_states_expires_at", "expires_at"),
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
    state_hash: Mapped[str] = mapped_column(CHAR(64), unique=True, nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<GitHubOAuthState id={self.id!r} user_id={self.user_id!r}>"


__all__ = [
    "GitHubConnection",
    "GitHubOAuthState",
]
