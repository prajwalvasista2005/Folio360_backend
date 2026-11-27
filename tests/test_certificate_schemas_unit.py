"""Unit tests for Certificate and Achievement Pydantic v2 schemas."""

from datetime import date
import uuid

from pydantic import ValidationError
import pytest

from app.schemas.certificate import (
    AchievementCreate,
    AchievementUpdate,
    CertificateCreate,
    CertificateUpdate,
    compute_verification_status,
)


def test_certificate_create_validates_and_normalizes() -> None:
    payload = CertificateCreate(
        name="  AWS Solutions Architect  ",
        issuer="  Amazon Web Services  ",
        category="PROFESSIONAL",
        issue_date=date(2025, 1, 10),
        expiry_date=date(2028, 1, 10),
        credential_id="  AWS-123  ",
        verification_url="  https://aws.amazon.com/verify/123  ",
        skill_ids=[uuid.UUID("11111111-1111-1111-1111-111111111111")] * 2,
        featured=True,
        order=1,
        visibility="PUBLIC",
    )
    assert payload.name == "AWS Solutions Architect"
    assert payload.issuer == "Amazon Web Services"
    assert payload.category == "professional"
    assert payload.credential_id == "AWS-123"
    assert payload.verification_url == "https://aws.amazon.com/verify/123"
    assert len(payload.skill_ids) == 1
    assert payload.visibility == "public"
    assert compute_verification_status(payload.verification_url) == "link_provided"
    assert compute_verification_status(None) == "self_reported"


def test_certificate_rejects_expiry_before_issue_and_bad_url() -> None:
    with pytest.raises(ValidationError):
        CertificateCreate(
            name="Cert",
            issuer="Org",
            issue_date=date(2025, 6, 1),
            expiry_date=date(2025, 5, 1),
        )

    with pytest.raises(ValidationError):
        CertificateCreate(
            name="Cert",
            issuer="Org",
            verification_url="javascript:alert(1)",
        )

    with pytest.raises(ValidationError):
        CertificateCreate(
            name="Cert",
            issuer="Org",
            verification_status="issuer_verified",  # extra forbidden
        )


def test_certificate_update_requires_fields_and_rejects_null_required() -> None:
    with pytest.raises(ValidationError):
        CertificateUpdate()

    with pytest.raises(ValidationError):
        CertificateUpdate(name=None)

    with pytest.raises(ValidationError):
        CertificateUpdate(order=-1)


def test_achievement_create_and_update_validation() -> None:
    doc_id = uuid.uuid4()
    payload = AchievementCreate(
        title="  First Place Hackathon  ",
        category="HACKATHON",
        organization="  MIT  ",
        date=date(2025, 3, 15),
        description="  Line 1\r\nLine 2  ",
        document_ids=[doc_id, doc_id],
        featured=True,
        visibility="public",
    )
    assert payload.title == "First Place Hackathon"
    assert payload.category == "hackathon"
    assert payload.organization == "MIT"
    assert payload.description == "Line 1\nLine 2"
    assert payload.document_ids == [doc_id]
    assert payload.visibility == "public"

    with pytest.raises(ValidationError):
        AchievementCreate(title="   ")

    with pytest.raises(ValidationError):
        AchievementUpdate()

    with pytest.raises(ValidationError):
        AchievementUpdate(category="invalid_category")
