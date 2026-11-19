"""Integration tests for the minimal User ORM model and PostgreSQL email constraints."""

from datetime import datetime, timezone
import uuid

import pytest
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from app.models.user import User


@pytest.mark.db
def test_user_create_read_update_defaults_and_utc_timestamps(db_session: Session) -> None:
    """Verify User insert, UUID generation, default is_active, UTC timestamps, and safe repr."""
    user = User(email="alice@example.com")
    db_session.add(user)
    db_session.flush()
    db_session.refresh(user)

    assert isinstance(user.id, uuid.UUID)
    assert user.email == "alice@example.com"
    assert user.is_active is True
    assert isinstance(user.created_at, datetime)
    assert isinstance(user.updated_at, datetime)
    assert user.created_at.tzinfo is not None
    assert user.updated_at.tzinfo is not None
    assert "alice@example.com" not in repr(user)

    fetched = db_session.execute(
        select(User).where(User.email == "alice@example.com")
    ).scalar_one()
    assert fetched.id == user.id

    # Update row and ensure ORM round-trip works
    fetched.is_active = False
    db_session.flush()
    db_session.refresh(fetched)
    assert fetched.is_active is False


@pytest.mark.db
def test_user_real_commit_persistence_and_cleanup(
    committed_db_session: Session,
    db_engine: Engine,
) -> None:
    """Verify actual PostgreSQL COMMIT visibility across independent sessions."""
    user = User(email="committed@example.com")
    committed_db_session.add(user)
    committed_db_session.commit()

    with db_engine.connect() as conn:
        found_email = conn.execute(
            text("SELECT email FROM users WHERE email = :email"),
            {"email": "committed@example.com"},
        ).scalar_one()
        assert found_email == "committed@example.com"


@pytest.mark.db
@pytest.mark.parametrize(
    "invalid_email",
    [
        "Alice@example.com",
        "USER@EXAMPLE.COM",
        " alice@example.com",
        "alice@example.com ",
        " alice@example.com ",
        "alice smith@example.com",
        "\talice@example.com",
        "alice@example.com\n",
        "alice@example.com\r",
        "",
        "   ",
        "\t\n",
    ],
)
def test_user_email_check_constraints_reject_non_canonical_values(
    db_session: Session,
    invalid_email: str,
) -> None:
    """PostgreSQL CHECK constraints must reject uppercase, spaces, control whitespace, and empty strings."""
    user = User(email=invalid_email)
    db_session.add(user)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


@pytest.mark.db
def test_user_duplicate_null_and_oversized_email_rejected_and_parameters_hidden(
    db_session: Session,
) -> None:
    """
    Enforce unique email, NOT NULL, VARCHAR(320), and verify SQLAlchemy hide_parameters=True
    suppresses bound parameter dictionaries in database error strings.
    """
    sentinel_email = "hidden_param_secret@example.com"
    db_session.add(User(email=sentinel_email))
    db_session.flush()

    explicit_id = uuid.uuid4()
    db_session.add(User(id=explicit_id, email=sentinel_email))
    with pytest.raises(IntegrityError) as dup_exc:
        db_session.flush()
    assert "[SQL parameters hidden due to hide_parameters=True]" in str(dup_exc.value)
    assert str(explicit_id) not in str(dup_exc.value)
    db_session.rollback()

    check_sentinel = "hiddencheckparam@example.com"
    db_session.add(User(email="UpperCase_" + check_sentinel))
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()

    secret_bound_param = "sql_bound_param_secret_999"
    with pytest.raises(DBAPIError) as div_exc:
        db_session.execute(
            text("SELECT 1 / :zero WHERE :tag != ''"),
            {"zero": 0, "tag": secret_bound_param},
        )
    assert "[SQL parameters hidden due to hide_parameters=True]" in str(div_exc.value)
    assert secret_bound_param not in str(div_exc.value)
    db_session.rollback()

    with pytest.raises(IntegrityError):
        db_session.execute(text("INSERT INTO users (email) VALUES (NULL)"))
    db_session.rollback()

    oversized_email = ("a" * 310) + "@example.com"  # 322 chars > VARCHAR(320)
    db_session.add(User(email=oversized_email))
    with pytest.raises(DBAPIError):
        db_session.flush()
    db_session.rollback()
