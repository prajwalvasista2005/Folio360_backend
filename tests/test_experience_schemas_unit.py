"""Unit tests for Experience Pydantic v2 schemas."""

from datetime import date
import uuid

from pydantic import ValidationError
import pytest

from app.schemas.experience import (
    MAX_EXPERIENCE_HIGHLIGHTS,
    ExperienceCreate,
    ExperienceUpdate,
)


def test_experience_create_validates_and_normalizes() -> None:
    skill_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    doc_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
    payload = ExperienceCreate(
        type="INTERNSHIP",
        organization="  Acme Labs  ",
        role="  Software Engineering Intern  ",
        location="  Bengaluru, India  ",
        is_remote=True,
        organization_url="  https://acme.example.com  ",
        start_date=date(2025, 5, 1),
        end_date=date(2025, 8, 15),
        is_current=False,
        description="  Built APIs.\r\nWrote tests.  ",
        highlights=["  Built APIs  ", "   ", "Shipped CI pipeline"],
        skill_ids=[skill_id, skill_id],
        document_ids=[doc_id, doc_id],
        featured=True,
        order=1,
        visibility="PUBLIC",
    )
    assert payload.type == "internship"
    assert payload.organization == "Acme Labs"
    assert payload.role == "Software Engineering Intern"
    assert payload.location == "Bengaluru, India"
    assert payload.is_remote is True
    assert payload.organization_url == "https://acme.example.com"
    assert payload.description == "Built APIs.\nWrote tests."
    assert payload.highlights == ["Built APIs", "Shipped CI pipeline"]
    assert payload.skill_ids == [skill_id]
    assert payload.document_ids == [doc_id]
    assert payload.visibility == "public"


def test_experience_rejects_invalid_dates_urls_and_extra_fields() -> None:
    with pytest.raises(ValidationError):
        ExperienceCreate(
            organization="Acme",
            role="Intern",
            start_date=date(2025, 6, 1),
            end_date=date(2025, 5, 1),
        )

    with pytest.raises(ValidationError):
        ExperienceCreate(
            organization="Acme",
            role="Intern",
            start_date=date(2025, 6, 1),
            end_date=date(2025, 8, 1),
            is_current=True,
        )

    with pytest.raises(ValidationError):
        ExperienceCreate(
            organization="Acme",
            role="Intern",
            start_date=date(2025, 6, 1),
            organization_url="javascript:alert(1)",
        )

    with pytest.raises(ValidationError):
        ExperienceCreate(
            organization="   ",
            role="Intern",
            start_date=date(2025, 6, 1),
        )

    with pytest.raises(ValidationError):
        ExperienceCreate(
            organization="Acme",
            role="Intern",
            start_date=date(2025, 6, 1),
            highlights=[f"Item {i}" for i in range(MAX_EXPERIENCE_HIGHLIGHTS + 1)],
        )

    with pytest.raises(ValidationError):
        ExperienceCreate(
            organization="Acme",
            role="Intern",
            start_date=date(2025, 6, 1),
            unexpected="field",
        )


def test_experience_update_requires_fields_and_rejects_null_non_nullable() -> None:
    with pytest.raises(ValidationError):
        ExperienceUpdate()

    with pytest.raises(ValidationError):
        ExperienceUpdate(organization=None)

    with pytest.raises(ValidationError):
        ExperienceUpdate(role=None)

    with pytest.raises(ValidationError):
        ExperienceUpdate(start_date=None)

    with pytest.raises(ValidationError):
        ExperienceUpdate(order=-1)

    with pytest.raises(ValidationError):
        ExperienceUpdate(is_current=True, end_date=date(2025, 9, 1))
