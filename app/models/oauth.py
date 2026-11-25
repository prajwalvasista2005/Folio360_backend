"""SQLAlchemy ORM models for Stage 3C OAuth accounts, state tracking, and exchange codes."""

from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy import (
    CHAR,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class OAuthAccount(Base, TimestampMixin):
    """Persistent immutable link between a Folio360 user and an OAuth provider identity."""

    __tablename__ = "oauth_accounts"
    __table_args__ = (
        UniqueConstraint(
            "provider",
            "provider_user_id",
            name="uq_oauth_accounts_provider_subject",
        ),
        UniqueConstraint(
            "user_id",
            "provider",
            name="uq_oauth_accounts_user_provider",
        ),
        CheckConstraint(
            "provider IN ('google', 'github')",
            name="provider",
        ),
        CheckConstraint(
            "provider_user_id = btrim(provider_user_id) "
            "AND provider_user_id <> '' "
            "AND provider_user_id !~ '[[:space:][:cntrl:]]'",
            name="provider_user_id_valid",
        ),
        CheckConstraint(
            "provider_email IS NULL OR ("
            "provider_email = lower(btrim(provider_email)) "
            "AND provider_email <> '' "
            "AND provider_email !~ '[[:space:]]'"
            ")",
            name="provider_email_canonical",
        ),
        CheckConstraint(
            "provider_email IS NOT NULL OR provider_email_verified = false",
            name="email_verified_consistency",
        ),
        Index("ix_oauth_accounts_user_id", "user_id"),
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
    provider: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    provider_user_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    provider_email: Mapped[Optional[str]] = mapped_column(
        String(320),
        nullable=True,
    )
    provider_email_verified: Mapped[bool] = mapped_column(
        Boolean(),
        default=False,
        server_default=text("false"),
        nullable=False,
    )

    def __repr__(self) -> str:
        return (
            f"<OAuthAccount id={self.id!r} user_id={self.user_id!r} "
            f"provider={self.provider!r}>"
        )


class OAuthState(Base, TimestampMixin):
    """Single-use pre-authentication OAuth state and encrypted PKCE verifier storage."""

    __tablename__ = "oauth_states"
    __table_args__ = (
        CheckConstraint(
            "provider IN ('google', 'github')",
            name="provider",
        ),
        CheckConstraint(
            "client_type IN ('web', 'mobile')",
            name="client_type",
        ),
        CheckConstraint(
            "state_hash ~ '^[0-9a-f]{64}$'",
            name="state_hash_hex",
        ),
        CheckConstraint(
            "exchange_code_challenge_hash ~ '^[0-9a-f]{64}$'",
            name="exchange_code_challenge_hash_hex",
        ),
        CheckConstraint(
            "length(btrim(pkce_verifier_encrypted)) > 0",
            name="pkce_not_empty",
        ),
        CheckConstraint(
            "length(btrim(redirect_uri)) > 0 AND redirect_uri = btrim(redirect_uri)",
            name="redirect_uri_valid",
        ),
        CheckConstraint(
            "(provider = 'google' AND nonce_hash IS NOT NULL AND nonce_hash ~ '^[0-9a-f]{64}$') "
            "OR (provider = 'github' AND nonce_hash IS NULL)",
            name="nonce_hash_consistency",
        ),
        CheckConstraint(
            "(client_type = 'web' AND client_binding_hash IS NOT NULL AND client_binding_hash ~ '^[0-9a-f]{64}$') "
            "OR (client_type = 'mobile' AND client_binding_hash IS NULL)",
            name="client_binding_consistency",
        ),
        CheckConstraint(
            "(consumed_at IS NULL AND pkce_verifier_encrypted <> '[CONSUMED]') "
            "OR (consumed_at IS NOT NULL AND pkce_verifier_encrypted = '[CONSUMED]')",
            name="consumed_pkce_scrubbed",
        ),
        Index("ix_oauth_states_expires_at", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        nullable=False,
    )
    state_hash: Mapped[str] = mapped_column(
        CHAR(64),
        unique=True,
        nullable=False,
    )
    provider: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    client_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    pkce_verifier_encrypted: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )
    nonce_hash: Mapped[Optional[str]] = mapped_column(
        CHAR(64),
        nullable=True,
    )
    redirect_uri: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )
    client_binding_hash: Mapped[Optional[str]] = mapped_column(
        CHAR(64),
        nullable=True,
    )
    exchange_code_challenge_hash: Mapped[str] = mapped_column(
        CHAR(64),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    consumed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def __repr__(self) -> str:
        return (
            f"<OAuthState id={self.id!r} provider={self.provider!r} "
            f"client_type={self.client_type!r}>"
        )


class OAuthExchangeCode(Base, TimestampMixin):
    """Single-use 60-second opaque exchange code bound to user, auth_version, and client proof."""

    __tablename__ = "oauth_exchange_codes"
    __table_args__ = (
        CheckConstraint(
            "code_hash ~ '^[0-9a-f]{64}$'",
            name="hash_hex",
        ),
        CheckConstraint(
            "client_type IN ('web', 'mobile')",
            name="client_type",
        ),
        CheckConstraint(
            "auth_version >= 0",
            name="auth_version_non_negative",
        ),
        CheckConstraint(
            "exchange_code_challenge_hash ~ '^[0-9a-f]{64}$'",
            name="exchange_code_challenge_hash_hex",
        ),
        CheckConstraint(
            "(client_type = 'web' AND exchange_binding_hash IS NOT NULL AND exchange_binding_hash ~ '^[0-9a-f]{64}$') "
            "OR (client_type = 'mobile' AND exchange_binding_hash IS NULL)",
            name="exchange_binding_consistency",
        ),
        Index("ix_oauth_exchange_codes_user_id", "user_id"),
        Index("ix_oauth_exchange_codes_expires_at", "expires_at"),
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
    code_hash: Mapped[str] = mapped_column(
        CHAR(64),
        unique=True,
        nullable=False,
    )
    client_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    auth_version: Mapped[int] = mapped_column(
        Integer(),
        nullable=False,
    )
    exchange_code_challenge_hash: Mapped[str] = mapped_column(
        CHAR(64),
        nullable=False,
    )
    exchange_binding_hash: Mapped[Optional[str]] = mapped_column(
        CHAR(64),
        nullable=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    consumed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def __repr__(self) -> str:
        return (
            f"<OAuthExchangeCode id={self.id!r} user_id={self.user_id!r} "
            f"client_type={self.client_type!r}>"
        )


__all__ = [
    "OAuthAccount",
    "OAuthState",
    "OAuthExchangeCode",
]
