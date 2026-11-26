"""PostgreSQL ORM constraint, default, repr, and cascade tests for Education."""

from datetime import datetime, timezone
from decimal import Decimal
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.education import Education
from app.models.user import User


def _create_user(db_session: Session, email: str = "edu.model@example.com") -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        is_active=True,
        is_email_verified=True,
        email_verified_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.mark.db
def test_education_model_persistence_defaults_repr_and_cascade(db_session: Session) -> None:
    """Verify Education creation, server defaults, safe repr, and user CASCADE delete."""
    user = _create_user(db_session)
    edu = Education(
        id=uuid.uuid4(),
        user_id=user.id,
        institution="RV College of Engineering",
        university_or_board="Visvesvaraya Technological University",
        education_level="undergraduate",
        degree="B.E.",
        programme="Bachelor of Engineering",
        branch="Computer Science",
        start_month=8,
        start_year=2022,
        is_current=True,
        achievements=["Dean's Merit List"],
    )
    db_session.add(edu)
    db_session.flush()
    db_session.refresh(edu)

    assert edu.result_source == "manual"
    assert edu.computed_cgpa is None
    assert edu.show_result_publicly is True
    assert edu.visibility == "public"
    assert edu.achievements == ["Dean's Merit List"]
    assert edu.created_at is not None
    assert edu.updated_at is not None

    # Safe repr must not leak sensitive/free-form institution or user data
    assert "RV College" not in repr(edu)
    assert str(edu.id) in repr(edu)

    # Deleting owning user cascades to educations
    db_session.delete(user)
    db_session.flush()
    assert (
        db_session.execute(select(Education).where(Education.id == edu.id)).scalar_one_or_none()
        is None
    )


@pytest.mark.db
def test_education_db_check_constraints_and_hide_parameters(db_session: Session) -> None:
    """Verify PostgreSQL check constraints reject invalid rows and hide SQL parameters."""
    user = _create_user(db_session, "edu.constraints@example.com")

    invalid_cases = [
        Education(user_id=user.id, institution="   ", degree="B.E."),
        Education(user_id=user.id, institution="MIT", degree=""),
        Education(
            user_id=user.id,
            institution="MIT",
            degree="B.S.",
            start_month=13,
            start_year=2020,
        ),
        Education(
            user_id=user.id,
            institution="MIT",
            degree="B.S.",
            start_month=5,
            start_year=None,
        ),
        Education(
            user_id=user.id,
            institution="MIT",
            degree="B.S.",
            start_year=2022,
            end_year=2025,
            is_current=True,
        ),
        Education(
            user_id=user.id,
            institution="MIT",
            degree="B.S.",
            start_year=2024,
            end_year=2022,
        ),
        Education(
            user_id=user.id,
            institution="MIT",
            degree="B.S.",
            visibility="invalid_visibility",
        ),
        Education(
            user_id=user.id,
            institution="MIT",
            degree="B.S.",
            result_source="ai_magic",
        ),
        Education(
            user_id=user.id,
            institution="MIT",
            degree="B.S.",
            end_month=13,
            end_year=2024,
        ),
        Education(
            user_id=user.id,
            institution="MIT",
            degree="B.S.",
            start_year=1899,
        ),
        Education(
            user_id=user.id,
            institution="MIT",
            degree="B.S.",
            end_year=2101,
        ),
        Education(
            user_id=user.id,
            institution="MIT",
            degree="B.S.",
            end_month=6,
            end_year=None,
        ),
        Education(
            user_id=user.id,
            institution="MIT",
            degree="B.S.",
            achievements={"not": "an array"},  # type: ignore[arg-type]
        ),
        Education(
            user_id=user.id,
            institution="MIT",
            degree="B.S.",
            computed_cgpa=Decimal("10.01"),
        ),
        Education(
            user_id=user.id,
            institution="MIT",
            degree="B.S.",
            computed_cgpa=Decimal("-0.01"),
        ),
    ]

    for bad_row in invalid_cases:
        db_session.add(bad_row)
        with pytest.raises(IntegrityError) as exc_info:
            db_session.flush()
        assert "[SQL parameters hidden due to hide_parameters=True]" in str(exc_info.value)
        db_session.rollback()
        user = _create_user(db_session, f"edu.constraints.{uuid.uuid4().hex[:8]}@example.com")
