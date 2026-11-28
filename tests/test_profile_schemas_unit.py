"""Unit tests for Phase 1 username/slug validation, profile schemas, and error.code envelope."""

from datetime import date, datetime, timedelta, timezone
import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from app.core.exceptions import AppException, register_exception_handlers
from app.core.username import (
    ACTIVITY_KEYS,
    RESERVED_SLUGS,
    is_reserved_slug,
    normalize_slug,
    validate_assignable_slug,
    validate_safe_avatar_url,
    validate_slug_format,
)
from app.schemas.auth import MeResponse, UserPublicResponse
from app.schemas.profile import (
    PrivateProfileResponse,
    ProfileActivityInput,
    ProfileLinkItem,
    ProfileLinksInput,
    ProfileUpdateRequest,
    SlugUpdateRequest,
)


def test_slug_normalization_regex_and_reserved_slugs() -> None:
    """Username validation enforces ^[a-z0-9_]{3,30}$ and exact reserved slugs."""
    assert normalize_slug("  Prajwal_01 ") == "prajwal_01"
    assert validate_slug_format("  User_123 ") == "user_123"
    assert validate_assignable_slug("abc") == "abc"
    assert validate_assignable_slug("a" * 30) == "a" * 30

    assert RESERVED_SLUGS == frozenset(
        {
            "api",
            "login",
            "register",
            "auth",
            "explore",
            "settings",
            "admin",
            "workspace",
            "onboarding",
            "share",
        }
    )
    for reserved in RESERVED_SLUGS:
        assert is_reserved_slug(reserved) is True
        assert validate_slug_format(reserved.upper()) == reserved
        with pytest.raises(ValueError, match="reserved"):
            validate_assignable_slug(reserved)

    for bad_slug in (
        "",
        "  ",
        "ab",
        "a" * 31,
        "user.name",
        "user-name",
        "user name",
        "user@name",
        "prajwal!",
        "ünicode",
        123,
    ):
        with pytest.raises(ValueError):
            validate_slug_format(bad_slug)


def test_avatar_url_safety_validation() -> None:
    """Avatar URL validation rejects unsafe schemes, credentials, whitespace, and oversized URLs."""
    assert validate_safe_avatar_url(None) is None
    assert validate_safe_avatar_url("   ") is None
    assert (
        validate_safe_avatar_url("https://cdn.example.com/avatars/u1.png")
        == "https://cdn.example.com/avatars/u1.png"
    )
    assert (
        validate_safe_avatar_url(
            "http://localhost:5173/avatar.png",
            allow_localhost_http=True,
        )
        == "http://localhost:5173/avatar.png"
    )
    with pytest.raises(ValueError):
        validate_safe_avatar_url(
            "http://localhost:5173/avatar.png",
            allow_localhost_http=False,
        )

    for unsafe in (
        "http://example.com/avatar.png",
        "javascript:alert(1)",
        "data:image/png;base64,AAAA",
        "file:///etc/passwd",
        "https://user:pass@cdn.example.com/a.png",
        "https://cdn.example.com/a b.png",
        "https://cdn.example.com/a\\b.png",
        "https://cdn.example.com/\x00.png",
        "https://cdn.example.com/" + ("a" * 500),
        123,
    ):
        with pytest.raises(ValueError):
            validate_safe_avatar_url(unsafe, allow_localhost_http=True)


def test_profile_activity_input_validation() -> None:
    """Activity schemas enforce canonical keys and 'other' label consistency."""
    assert ACTIVITY_KEYS == (
        "studying",
        "working",
        "interning",
        "freelancing",
        "job_seeking",
        "researching",
        "building_project",
        "learning_skills",
        "other",
    )

    predefined = ProfileActivityInput(
        key="building_project",
        description="  Building Folio360  ",
    )
    assert predefined.key == "building_project"
    assert predefined.label is None
    assert predefined.description == "Building Folio360"

    learning = ProfileActivityInput(key="learning_skills", description="   ")
    assert learning.description is None

    other = ProfileActivityInput(
        key="other",
        label="  Open Source Maintainer  ",
        description="Maintaining Python libraries",
    )
    assert other.label == "Open Source Maintainer"

    # Legacy/display labels rejected
    with pytest.raises(ValidationError):
        ProfileActivityInput(key="Building a Project / Startup")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        ProfileActivityInput(key="building_project_startup")  # type: ignore[arg-type]

    # 'other' requires label (2..80 chars)
    with pytest.raises(ValidationError):
        ProfileActivityInput(key="other")
    with pytest.raises(ValidationError):
        ProfileActivityInput(key="other", label="A")
    with pytest.raises(ValidationError):
        ProfileActivityInput(key="other", label="x" * 81)

    # Non-'other' forbids label
    with pytest.raises(ValidationError):
        ProfileActivityInput(key="studying", label="CS Student")

    # Description max length 200
    with pytest.raises(ValidationError):
        ProfileActivityInput(key="working", description="d" * 201)

    # extra='forbid'
    with pytest.raises(ValidationError):
        ProfileActivityInput(key="studying", extra="nope")  # type: ignore[call-arg]


def test_profile_update_request_validation_boundaries() -> None:
    """Verify full_name (2..150), DOB policy, unlimited deduped interests, and extra='forbid'."""
    today_utc = datetime.now(timezone.utc).date()
    tomorrow_utc = today_utc + timedelta(days=1)

    # Valid boundary values: 2-char and 150-char names, 1850 DOB (no 1900 bound),
    # today UTC DOB (no min age), >50 interests (no arbitrary cap)
    many_interests = [f"Interest {i}" for i in range(65)]
    many_interests_with_dups = many_interests + ["  interest 0 ", "INTEREST 1"]
    req = ProfileUpdateRequest(
        full_name="  Al  ",
        date_of_birth=date(1850, 1, 1),
        bio="  Short bio  ",
        interests=many_interests_with_dups,
        current_activities=[
            ProfileActivityInput(key="studying"),
            ProfileActivityInput(key="learning_skills"),
            ProfileActivityInput(key="other", label="Mentor"),
        ],
        profile_completed=True,
    )
    assert req.full_name == "Al"
    assert req.date_of_birth == date(1850, 1, 1)
    assert req.bio == "Short bio"
    assert len(req.interests or []) == 65
    assert req.interests[0] == "Interest 0"

    req_max_name = ProfileUpdateRequest(
        full_name="N" * 150,
        date_of_birth=today_utc,
    )
    assert len(req_max_name.full_name or "") == 150
    assert req_max_name.date_of_birth == today_utc

    # Reject invalid full_name lengths
    with pytest.raises(ValidationError):
        ProfileUpdateRequest(full_name="A")
    with pytest.raises(ValidationError):
        ProfileUpdateRequest(full_name="N" * 151)

    # Reject future UTC DOB and numeric/datetime DOB
    with pytest.raises(ValidationError):
        ProfileUpdateRequest(date_of_birth=tomorrow_utc)
    with pytest.raises(ValidationError):
        ProfileUpdateRequest(date_of_birth=0)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        ProfileUpdateRequest(date_of_birth=datetime.now(timezone.utc))

    # Reject duplicate activity keys (including duplicate 'other')
    with pytest.raises(ValidationError):
        ProfileUpdateRequest(
            current_activities=[
                ProfileActivityInput(key="other", label="First"),
                ProfileActivityInput(key="other", label="Second"),
            ]
        )

    # Reject empty patch and null non-nullable fields
    with pytest.raises(ValidationError):
        ProfileUpdateRequest()
    with pytest.raises(ValidationError):
        ProfileUpdateRequest(interests=None)
    with pytest.raises(ValidationError):
        ProfileUpdateRequest(current_activities=None)
    with pytest.raises(ValidationError):
        ProfileUpdateRequest(profile_completed=None)

    # Reject out-of-scope / immutable fields via extra='forbid'
    for forbidden_field in ("social_links", "slug", "unknown_field"):
        with pytest.raises(ValidationError):
            ProfileUpdateRequest(**{forbidden_field: "value"})  # type: ignore[arg-type]

    # Personal profile fields & link validation
    full_req = ProfileUpdateRequest(
        headline="  Full-Stack Engineer  ",
        location="  Bengaluru, IN  ",
        contact_email="  Contact@Example.com  ",
        phone="  +91 98765 43210  ",
        website="https://example.dev",
        links=ProfileLinksInput(
            linkedin="https://linkedin.com/in/example",
            github="https://github.com/example",
            other=[ProfileLinkItem(label="  Portfolio  ", url="https://portfolio.example.com")],
        ),
    )
    assert full_req.headline == "Full-Stack Engineer"
    assert full_req.location == "Bengaluru, IN"
    assert full_req.contact_email == "contact@example.com"
    assert full_req.phone == "+91 98765 43210"
    assert full_req.website == "https://example.dev"
    assert full_req.links is not None
    assert full_req.links.other[0].label == "Portfolio"

    with pytest.raises(ValidationError):
        ProfileUpdateRequest(website="javascript:alert(1)")
    with pytest.raises(ValidationError):
        ProfileUpdateRequest(contact_email="not-an-email")
    with pytest.raises(ValidationError):
        ProfileLinksInput(linkedin="ftp://example.com/in/a")

    # SlugUpdateRequest extra='forbid'
    slug_req = SlugUpdateRequest(slug="  Valid_User_1 ")
    assert slug_req.slug == "valid_user_1"
    with pytest.raises(ValidationError):
        SlugUpdateRequest(slug="valid_user", extra="bad")  # type: ignore[call-arg]


def test_top_level_error_code_envelope_and_private_dob_exclusion() -> None:
    """Verify AppException error_code serializes as top-level error.code and DOB is excluded from auth schemas."""
    assert "profile_completed" in UserPublicResponse.model_fields
    assert "date_of_birth" not in UserPublicResponse.model_fields
    assert "date_of_birth" not in MeResponse.model_fields
    assert "avatar_url" in PrivateProfileResponse.model_fields
    assert "profile_picture_url" not in PrivateProfileResponse.model_fields

    test_app = FastAPI()
    register_exception_handlers(test_app)

    @test_app.get("/_slug-taken")
    def _raise_slug_taken() -> None:
        raise AppException(
            message="Internal: slug conflict",
            status_code=409,
            public_message="This username is already taken.",
            error_code="SLUG_TAKEN",
        )

    with TestClient(test_app, raise_server_exceptions=False) as client:
        resp = client.get("/_slug-taken")
        assert resp.status_code == 409
        body = resp.json()
        assert body["error"]["code"] == "SLUG_TAKEN"
        assert body["error"]["message"] == "This username is already taken."
        assert body["error"]["status_code"] == 409
        assert body["error"]["details"] is None


def test_multiline_bio_and_activity_description_normalization_and_control_char_policy() -> None:
    """Bio and activity description allow ordinary newlines with CRLF/CR normalization while rejecting other control chars."""
    # Valid multi-line bio and activity description (including CRLF & standalone CR normalization)
    req = ProfileUpdateRequest(
        bio="  Line 1\r\nLine 2\rLine 3\nLine 4  ",
        current_activities=[
            ProfileActivityInput(
                key="studying",
                description="  Semester 6\r\nFocus: Distributed Systems\rVTU  ",
            )
        ],
    )
    assert req.bio == "Line 1\nLine 2\nLine 3\nLine 4"
    assert req.current_activities is not None
    assert (
        req.current_activities[0].description
        == "Semester 6\nFocus: Distributed Systems\nVTU"
    )

    # Whitespace/newline-only strings normalize to None; max lengths still enforced after normalization
    req_blank = ProfileUpdateRequest(
        bio=" \r\n \t ",
        current_activities=[ProfileActivityInput(key="working", description=" \n\r ")],
    )
    assert req_blank.bio is None
    assert req_blank.current_activities is not None
    assert req_blank.current_activities[0].description is None

    assert len(ProfileUpdateRequest(bio="a" * 1000).bio or "") == 1000
    with pytest.raises(ValidationError):
        ProfileUpdateRequest(bio="a" * 1001)
    assert len(ProfileActivityInput(key="working", description="d" * 200).description or "") == 200
    with pytest.raises(ValidationError):
        ProfileActivityInput(key="working", description="d" * 201)

    # Prohibited C0 control characters and DEL (0x7F) are still rejected in bio and description
    for bad_ctrl in ("\x00", "\t", "\x07", "\x1f", "\x7f"):
        with pytest.raises(ValidationError):
            ProfileUpdateRequest(bio=f"Line 1\nLine{bad_ctrl}2")
        with pytest.raises(ValidationError):
            ProfileActivityInput(key="studying", description=f"Desc\nPart{bad_ctrl}2")

    # Single-line fields remain strict against newlines/CR
    with pytest.raises(ValidationError):
        ProfileUpdateRequest(full_name="Alice\nBob")
    with pytest.raises(ValidationError):
        ProfileActivityInput(key="other", label="Mentor\nLead")
    with pytest.raises(ValidationError):
        ProfileUpdateRequest(interests=["Python\n3"])
