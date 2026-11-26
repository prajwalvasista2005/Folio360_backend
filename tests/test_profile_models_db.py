"""PostgreSQL ORM constraint and cascade tests for UserProfile and UserProfileActivity."""

from datetime import date, datetime, timezone
import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.profile import UserProfile, UserProfileActivity
from app.models.user import User


def _create_user(db_session: Session, email: str = "profile.model@example.com") -> User:
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
def test_profile_and_activity_creation_cascade_and_safe_repr(db_session: Session) -> None:
    """Verify 1:1 profile, 1:N activities, historical DOB persistence, repr safety, and CASCADE."""
    user = _create_user(db_session)
    now = datetime.now(timezone.utc)
    profile = UserProfile(
        id=uuid.uuid4(),
        user_id=user.id,
        slug="alice_2000",
        full_name="Alice Example",
        date_of_birth=date(1880, 3, 14),
        bio="Lifelong learner",
        profile_picture_url="https://cdn.example.com/alice.png",
        interests=["Python", "Distributed Systems"],
        profile_completed=True,
        profile_completed_at=now,
    )
    profile.activities.append(
        UserProfileActivity(
            id=uuid.uuid4(),
            activity_key="building_project",
            custom_label=None,
            description="Building Folio360",
            display_order=0,
        )
    )
    profile.activities.append(
        UserProfileActivity(
            id=uuid.uuid4(),
            activity_key="other",
            custom_label="OSS Maintainer",
            description=None,
            display_order=1,
        )
    )
    db_session.add(profile)
    db_session.flush()
    db_session.refresh(profile)

    assert profile.date_of_birth == date(1880, 3, 14)
    assert len(profile.activities) == 2
    assert "1880" not in repr(profile)
    assert "Alice" not in repr(profile)
    assert "Lifelong learner" not in repr(profile)

    # Deleting user cascades to user_profiles and user_profile_activities
    db_session.delete(user)
    db_session.flush()
    assert (
        db_session.execute(
            select(UserProfile).where(UserProfile.id == profile.id)
        ).scalar_one_or_none()
        is None
    )
    assert (
        db_session.execute(
            select(UserProfileActivity).where(
                UserProfileActivity.profile_id == profile.id
            )
        ).scalar_one_or_none()
        is None
    )


@pytest.mark.db
def test_profile_unique_constraints_and_hide_parameters(db_session: Session) -> None:
    """Verify unique user_id/slug, multiple NULL draft slugs allowed, and parameter redaction."""
    u1 = _create_user(db_session, "u1.prof@example.com")
    u2 = _create_user(db_session, "u2.prof@example.com")
    u3 = _create_user(db_session, "u3.prof@example.com")

    # Multiple incomplete drafts with slug=None are allowed
    db_session.add(UserProfile(user_id=u1.id, slug=None))
    db_session.add(UserProfile(user_id=u2.id, slug=None))
    db_session.flush()

    # Duplicate user_id rejected
    db_session.add(UserProfile(user_id=u1.id, slug="unique_slug"))
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()

    # Recreate u1/u3 with colliding slug -> rejected and parameters hidden
    u1 = _create_user(db_session, "u1b.prof@example.com")
    u3 = _create_user(db_session, "u3b.prof@example.com")
    db_session.add(UserProfile(user_id=u1.id, slug="taken_slug"))
    db_session.flush()

    explicit_profile_id = uuid.uuid4()
    db_session.add(UserProfile(id=explicit_profile_id, user_id=u3.id, slug="taken_slug"))
    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    assert "[SQL parameters hidden due to hide_parameters=True]" in str(exc_info.value)
    assert str(explicit_profile_id) not in str(exc_info.value)
    db_session.rollback()


@pytest.mark.db
def test_profile_and_activity_check_constraints(db_session: Session) -> None:
    """Verify PostgreSQL CHECK constraints on user_profiles and user_profile_activities."""
    # Cannot mark profile_completed=True without slug, full_name, date_of_birth, and completed_at
    u = _create_user(db_session, "check.prof@example.com")
    db_session.add(
        UserProfile(
            user_id=u.id,
            slug="valid_slug",
            full_name="Valid Name",
            date_of_birth=None,
            profile_completed=True,
            profile_completed_at=datetime.now(timezone.utc),
        )
    )
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()

    # Invalid slug format rejected at DB level
    u = _create_user(db_session, "check.slug@example.com")
    db_session.add(UserProfile(user_id=u.id, slug="Bad.Slug"))
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()

    # Valid draft profile for activity constraint tests
    u = _create_user(db_session, "check.act@example.com")
    profile = UserProfile(user_id=u.id, slug="act_owner")
    db_session.add(profile)
    db_session.flush()

    # 'other' without custom_label rejected
    db_session.add(
        UserProfileActivity(
            profile_id=profile.id,
            activity_key="other",
            custom_label=None,
        )
    )
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()

    # Non-'other' with custom_label rejected
    u = _create_user(db_session, "check.act2@example.com")
    profile = UserProfile(user_id=u.id, slug="act_owner_2")
    db_session.add(profile)
    db_session.flush()
    db_session.add(
        UserProfileActivity(
            profile_id=profile.id,
            activity_key="studying",
            custom_label="Should Be Null",
        )
    )
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()

    # Duplicate activity_key per profile rejected
    u = _create_user(db_session, "check.act3@example.com")
    profile = UserProfile(user_id=u.id, slug="act_owner_3")
    db_session.add(profile)
    db_session.flush()
    db_session.add(UserProfileActivity(profile_id=profile.id, activity_key="studying", display_order=0))
    db_session.add(UserProfileActivity(profile_id=profile.id, activity_key="studying", display_order=1))
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()
