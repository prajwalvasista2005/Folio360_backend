"""Unit tests for Phase 2 Education Pydantic schemas, validation helpers, and migration DDL parity."""

from datetime import datetime, timezone
from pathlib import Path
import uuid

from alembic.config import Config
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from pydantic import ValidationError
import pytest
from sqlalchemy import create_mock_engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex, CreateTable

from app.db.base import Base
from app.models.education import Education
from app.schemas.education import (
    EducationCreate,
    EducationListResponse,
    EducationResponse,
    EducationUpdate,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_education_create_valid_minimal_and_defaults() -> None:
    """Required institution and degree populate sensible defaults."""
    payload = EducationCreate(
        institution="  RV College of Engineering  ",
        degree="  B.E.  ",
    )
    assert payload.institution == "RV College of Engineering"
    assert payload.degree == "B.E."
    assert payload.is_current is False
    assert payload.show_result_publicly is True
    assert payload.achievements == []
    assert payload.document_ids == []
    assert payload.visibility == "public"


def test_education_create_full_payload_normalization_and_dedupe() -> None:
    """Optional strings, multiline description, result_value, achievements, and document_ids normalize."""
    doc_a = uuid.uuid4()
    doc_b = uuid.uuid4()
    payload = EducationCreate(
        institution="VTU",
        university_or_board="  Visvesvaraya Technological University  ",
        education_level="  undergraduate  ",
        degree="Bachelor of Engineering",
        programme="  B.E.  ",
        branch="  Computer Science and Engineering  ",
        specialization="   ",
        country="  India ",
        state=" Karnataka ",
        start_month=8,
        start_year=2021,
        end_month=6,
        end_year=2025,
        is_current=False,
        description="  Line 1\r\nLine 2  ",
        scheme_id="  vtu-2021  ",
        result_type="CGPA",
        result_value=8.75,  # type: ignore[arg-type]
        show_result_publicly=False,
        achievements=["  Dean's List  ", "Hackathon Winner"],
        document_ids=[doc_a, doc_b, doc_a],
        visibility="CONNECTIONS",  # type: ignore[arg-type]
    )
    assert payload.university_or_board == "Visvesvaraya Technological University"
    assert payload.specialization is None
    assert payload.description == "Line 1\nLine 2"
    assert payload.result_type == "cgpa"
    assert payload.result_value == "8.75"
    assert payload.achievements == ["Dean's List", "Hackathon Winner"]
    assert payload.document_ids == [doc_a, doc_b]
    assert payload.visibility == "connections"


def test_education_create_rejects_missing_or_blank_required_fields() -> None:
    """Missing, blank, control-char, or extra fields are rejected."""
    with pytest.raises(ValidationError):
        EducationCreate(institution="MIT")  # type: ignore[call-arg]

    with pytest.raises(ValidationError):
        EducationCreate(degree="B.S.")  # type: ignore[call-arg]

    for bad in ("", "   ", "MIT\x00", "A" * 256):
        with pytest.raises(ValidationError):
            EducationCreate(institution=bad, degree="B.S.")
        with pytest.raises(ValidationError):
            EducationCreate(institution="MIT", degree=bad)

    with pytest.raises(ValidationError):
        EducationCreate(
            institution="MIT",
            degree="B.S.",
            user_id=uuid.uuid4(),  # type: ignore[call-arg]
        )


def test_education_create_date_validation() -> None:
    """Validate months, years, month-requires-year, ongoing no-end-date, and date ordering."""
    # Invalid months / years / booleans
    for bad_month in (0, 13, -1, True):
        with pytest.raises(ValidationError):
            EducationCreate(
                institution="MIT",
                degree="B.S.",
                start_month=bad_month,  # type: ignore[arg-type]
                start_year=2022,
            )

    for bad_year in (1899, 2101, False):
        with pytest.raises(ValidationError):
            EducationCreate(
                institution="MIT",
                degree="B.S.",
                start_year=bad_year,  # type: ignore[arg-type]
            )

    # Month without year
    with pytest.raises(ValidationError, match="start_year is required"):
        EducationCreate(institution="MIT", degree="B.S.", start_month=5)

    with pytest.raises(ValidationError, match="end_year is required"):
        EducationCreate(institution="MIT", degree="B.S.", end_month=5)

    # Ongoing with end_year or end_month
    with pytest.raises(ValidationError, match="Ongoing education cannot specify an end date"):
        EducationCreate(
            institution="MIT",
            degree="B.S.",
            start_year=2023,
            end_year=2027,
            is_current=True,
        )

    # End year before start year
    with pytest.raises(ValidationError, match="end_year cannot be earlier than start_year"):
        EducationCreate(
            institution="MIT",
            degree="B.S.",
            start_year=2024,
            end_year=2023,
        )

    # Same year, end month before start month
    with pytest.raises(ValidationError, match="End date cannot be earlier than start date"):
        EducationCreate(
            institution="MIT",
            degree="B.S.",
            start_month=8,
            start_year=2024,
            end_month=5,
            end_year=2024,
        )

    # Same month & year is valid (e.g., short certificate/bootcamp)
    valid_same_month = EducationCreate(
        institution="MIT",
        degree="Certificate",
        start_month=5,
        start_year=2024,
        end_month=5,
        end_year=2024,
    )
    assert valid_same_month.end_month == 5


def test_education_create_result_visibility_and_achievements_validation() -> None:
    """Validate result type/value consistency, visibility enum, and achievements array."""
    # result_value without result_type
    with pytest.raises(ValidationError, match="result_type is required"):
        EducationCreate(institution="MIT", degree="B.S.", result_value="9.1")

    # CGPA/GPA out of bounds or non-numeric
    for bad_cgpa in ("-0.1", "10.1", "nan", "abc"):
        with pytest.raises(ValidationError):
            EducationCreate(
                institution="MIT",
                degree="B.S.",
                result_type="cgpa",
                result_value=bad_cgpa,
            )

    # Percentage bounds
    ok_pct = EducationCreate(
        institution="MIT",
        degree="B.S.",
        result_type="percentage",
        result_value="92.5%",
    )
    assert ok_pct.result_value == "92.5%"

    for bad_pct in ("-1", "100.5%", "unknown"):
        with pytest.raises(ValidationError):
            EducationCreate(
                institution="MIT",
                degree="B.S.",
                result_type="percentage",
                result_value=bad_pct,
            )

    # Invalid visibility
    with pytest.raises(ValidationError):
        EducationCreate(
            institution="MIT",
            degree="B.S.",
            visibility="friends_only",  # type: ignore[arg-type]
        )

    # Achievements validation
    with pytest.raises(ValidationError):
        EducationCreate(
            institution="MIT",
            degree="B.S.",
            achievements=["Valid", "   "],
        )

    with pytest.raises(ValidationError):
        EducationCreate(
            institution="MIT",
            degree="B.S.",
            achievements="Not a list",  # type: ignore[arg-type]
        )


def test_education_update_partial_semantics() -> None:
    """EducationUpdate requires at least one field, tracks model_fields_set, and blocks invalid nulls."""
    with pytest.raises(ValidationError, match="At least one education field"):
        EducationUpdate()

    patch = EducationUpdate(branch="AIML", description=None)
    assert patch.model_fields_set == {"branch", "description"}
    assert patch.branch == "AIML"
    assert patch.description is None

    for non_nullable in (
        "institution",
        "degree",
        "is_current",
        "show_result_publicly",
        "achievements",
        "document_ids",
        "visibility",
    ):
        with pytest.raises(ValidationError):
            EducationUpdate(**{non_nullable: None})

    with pytest.raises(ValidationError):
        EducationUpdate(is_current=True, end_year=2025)


def test_education_response_and_list_response_serialization() -> None:
    """EducationResponse and EducationListResponse match expected frontend contract."""
    now = datetime.now(timezone.utc)
    item = EducationResponse(
        id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        institution="MIT",
        university_or_board=None,
        education_level="undergraduate",
        degree="B.S.",
        programme=None,
        branch="Computer Science",
        specialization=None,
        country="USA",
        state="MA",
        start_month=9,
        start_year=2021,
        end_month=5,
        end_year=2025,
        is_current=False,
        description=None,
        scheme_id=None,
        result_type="gpa",
        result_value="3.9",
        result_source="manual",
        computed_cgpa=None,
        show_result_publicly=True,
        achievements=["Gold Medal"],
        document_ids=[],
        documents=[],
        visibility="public",
        created_at=now,
        updated_at=now,
    )
    listing = EducationListResponse(
        items=[item],
        page=1,
        page_size=100,
        total=1,
        total_pages=1,
    )
    dumped = listing.model_dump()
    assert dumped["total"] == 1
    assert dumped["total_pages"] == 1
    assert dumped["items"][0]["result_source"] == "manual"
    assert dumped["items"][0]["computed_cgpa"] is None
    assert dumped["items"][0]["documents"] == []
    assert dumped["items"][0]["document_ids"] == []


def _compile_pg(ddl_element: object) -> str:
    return str(ddl_element.compile(dialect=postgresql.dialect())).strip()  # type: ignore[attr-defined]


def _normalize_create_table(ddl: str) -> tuple[str, list[str], set[str]]:
    lines = [line.strip().rstrip(",") for line in ddl.splitlines() if line.strip()]
    header = lines[0]
    body = lines[1:-1]
    col_lines = [line for line in body if not line.startswith("CONSTRAINT ")]
    constraint_lines = {line for line in body if line.startswith("CONSTRAINT ")}
    return header, col_lines, constraint_lines


def test_alembic_0006_education_ddl_parity_with_metadata() -> None:
    """Verify migration 0006_add_educations matches Education ORM metadata 1-to-1."""
    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "alembic"))
    script = ScriptDirectory.from_config(cfg)

    rev_0006 = script.get_revision("0006_add_educations")
    assert rev_0006 is not None
    assert rev_0006.down_revision == "0005_add_user_profiles"
    assert rev_0006.module is not None

    upgrade_sql: list[str] = []
    upgrade_engine = create_mock_engine(
        "postgresql+psycopg://",
        lambda sql, *a, **kw: upgrade_sql.append(_compile_pg(sql)),
    )
    mc_up = MigrationContext.configure(
        connection=upgrade_engine.connect(),
        opts={"target_metadata": Base.metadata},
    )
    with Operations.context(mc_up):
        rev_0006.module.upgrade()

    expected_upgrade_sql = [
        _compile_pg(CreateTable(Education.__table__)),
        _compile_pg(CreateIndex(next(iter(Education.__table__.indexes)))),
    ]
    assert len(upgrade_sql) == len(expected_upgrade_sql)
    assert _normalize_create_table(upgrade_sql[0]) == _normalize_create_table(
        expected_upgrade_sql[0]
    )
    assert upgrade_sql[1] == expected_upgrade_sql[1]

    downgrade_sql: list[str] = []
    downgrade_engine = create_mock_engine(
        "postgresql+psycopg://",
        lambda sql, *a, **kw: downgrade_sql.append(_compile_pg(sql)),
    )
    mc_down = MigrationContext.configure(
        connection=downgrade_engine.connect(),
        opts={"target_metadata": Base.metadata},
    )
    with Operations.context(mc_down):
        rev_0006.module.downgrade()

    assert downgrade_sql == [
        "DROP INDEX ix_educations_user_id",
        "DROP TABLE educations",
    ]


def test_education_document_ids_dedupe_and_ref_serialization() -> None:
    """EducationCreate and EducationUpdate deduplicate UUIDs while preserving order."""
    doc_1 = uuid.uuid4()
    doc_2 = uuid.uuid4()
    create_payload = EducationCreate(
        institution="MIT",
        degree="B.S.",
        document_ids=[doc_1, doc_2, doc_1],
    )
    assert create_payload.document_ids == [doc_1, doc_2]

    update_payload = EducationUpdate(document_ids=[doc_2, doc_1, doc_2])
    assert update_payload.document_ids == [doc_2, doc_1]
