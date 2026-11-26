"""End-to-end Phase 2 Education CRUD, sorting, pagination, and security tests against PostgreSQL 17."""

from datetime import datetime, timedelta, timezone
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import Engine, select, text

from app.core.config import Settings
from app.core.security import create_access_token, hash_password
from app.db.session import build_sessionmaker
from app.main import create_app
from app.models.education import Education
from app.models.user import User


def _build_test_app(
    test_database_url: str,
    *,
    rate_limit_enabled: bool = False,
    storage_dir: str = "/tmp/folio360_edu_test_docs",
) -> tuple[Settings, object]:
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL=test_database_url,
        JWT_SECRET_KEY="education-integration-jwt-secret-key-at-least-32-chars",
        JWT_ISSUER="folio360",
        JWT_AUDIENCE="folio360-api",
        JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15,
        REFRESH_TOKEN_EXPIRE_DAYS=14,
        REFRESH_TOKEN_ABSOLUTE_EXPIRE_DAYS=30,
        FRONTEND_BASE_URL="http://localhost:5173",
        CORS_ORIGINS=["http://localhost:5173"],
        RESEND_API_KEY="re_education_integration_mock_key",
        EMAIL_FROM_ADDRESS="no-reply@folio360.com",
        RATE_LIMIT_ENABLED=rate_limit_enabled,
        STORAGE_BACKEND="local",
        DOCUMENT_LOCAL_STORAGE_DIR=storage_dir,
        MALWARE_SCANNER_BACKEND="mock",
    )
    return settings, create_app(settings=settings)


@pytest.fixture
def clean_education_db(db_engine: Engine):
    """Clean users (and cascaded educations) before and after each test."""
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))
    yield
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))


def _create_db_user(
    db_engine: Engine,
    *,
    email: str,
    is_active: bool = True,
    is_email_verified: bool = True,
) -> User:
    session_factory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password("StrongPassword!2026"),
        is_active=is_active,
        is_email_verified=is_email_verified,
        email_verified_at=now if is_email_verified else None,
        auth_version=0,
    )
    with session_factory() as session:
        session.add(user)
        session.commit()
        session.refresh(user)
    return user


def _auth_headers(user: User, settings: Settings) -> dict[str, str]:
    token, _ = create_access_token(
        user_id=user.id,
        auth_version=user.auth_version,
        settings=settings,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.db
def test_education_crud_partial_patch_and_stage2_contract(
    test_database_url: str,
    db_engine: Engine,
    clean_education_db: None,
    tmp_path: object,
) -> None:
    """Verify POST, GET list, GET one, partial PATCH, DELETE, and Document linking lifecycle."""
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    user = _create_db_user(db_engine, email="edu.crud@example.com")
    headers = _auth_headers(user, settings)

    with TestClient(app) as client:  # type: ignore[arg-type]
        # Empty list initially
        empty_resp = client.get("/api/v1/education", headers=headers)
        assert empty_resp.status_code == 200
        assert empty_resp.json() == {
            "items": [],
            "page": 1,
            "page_size": 100,
            "total": 0,
            "total_pages": 0,
        }

        # Non-existent document_ids on POST is rejected with 422 INVALID_REFERENCE
        missing_doc_uuid = str(uuid.uuid4())
        rejected_create = client.post(
            "/api/v1/education",
            headers=headers,
            json={
                "institution": "Should Not Persist",
                "degree": "B.E.",
                "document_ids": [missing_doc_uuid],
            },
        )
        assert rejected_create.status_code == 422
        assert rejected_create.json()["error"]["code"] == "INVALID_REFERENCE"
        assert client.get("/api/v1/education", headers=headers).json()["total"] == 0

        # Upload an owned document to link
        up_doc = client.post(
            "/api/v1/documents",
            headers=headers,
            files={"file": ("marksheet.pdf", b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n", "application/pdf")},
            data={"category": "marksheet", "title": "Final Transcript"},
        )
        assert up_doc.status_code == 201
        owned_doc_id = up_doc.json()["document"]["id"]

        # Create full record with empty document_ids: []
        create_resp = client.post(
            "/api/v1/education",
            headers=headers,
            json={
                "institution": "BMS College of Engineering",
                "university_or_board": "VTU",
                "education_level": "undergraduate",
                "degree": "B.E.",
                "programme": "Bachelor of Engineering",
                "branch": "Computer Science",
                "specialization": "AI & ML",
                "country": "India",
                "state": "Karnataka",
                "start_month": 8,
                "start_year": 2021,
                "end_month": 6,
                "end_year": 2025,
                "is_current": False,
                "description": "Core CS coursework",
                "scheme_id": "vtu-2021",
                "result_type": "cgpa",
                "result_value": "9.12",
                "show_result_publicly": True,
                "achievements": ["Best Outgoing Student", "Smart India Hackathon Finalist"],
                "document_ids": [],
                "visibility": "public",
            },
        )
        assert create_resp.status_code == 201
        created = create_resp.json()
        edu_id = created["id"]
        assert created["user_id"] == str(user.id)
        assert created["institution"] == "BMS College of Engineering"
        assert created["result_source"] == "manual"
        assert created["computed_cgpa"] is None
        assert created["document_ids"] == []
        assert created["documents"] == []
        assert created["achievements"] == [
            "Best Outgoing Student",
            "Smart India Hackathon Finalist",
        ]

        # GET by ID
        get_resp = client.get(f"/api/v1/education/{edu_id}", headers=headers)
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == edu_id

        # Non-existent document_ids on PATCH returns 422 INVALID_REFERENCE and never mutates
        before_updated_at = created["updated_at"]
        bad_doc_patch = client.patch(
            f"/api/v1/education/{edu_id}",
            headers=headers,
            json={"degree": "Should Not Change", "document_ids": [missing_doc_uuid]},
        )
        assert bad_doc_patch.status_code == 422
        assert bad_doc_patch.json()["error"]["code"] == "INVALID_REFERENCE"

        unchanged = client.get(f"/api/v1/education/{edu_id}", headers=headers).json()
        assert unchanged["degree"] == "B.E."
        assert unchanged["updated_at"] == before_updated_at

        # Link owned document via PATCH
        link_doc_patch = client.patch(
            f"/api/v1/education/{edu_id}",
            headers=headers,
            json={"document_ids": [owned_doc_id]},
        )
        assert link_doc_patch.status_code == 200
        assert link_doc_patch.json()["document_ids"] == [owned_doc_id]
        assert link_doc_patch.json()["documents"] == [
            {
                "id": owned_doc_id,
                "title": "Final Transcript",
                "category": "marksheet",
                "mime_type": "application/pdf",
            }
        ]

        # Partial PATCH omitting document_ids preserves linked documents
        patch_resp = client.patch(
            f"/api/v1/education/{edu_id}",
            headers=headers,
            json={"specialization": "Distributed Systems", "description": None},
        )
        assert patch_resp.status_code == 200
        patched = patch_resp.json()
        assert patched["specialization"] == "Distributed Systems"
        assert patched["description"] is None
        assert patched["document_ids"] == [owned_doc_id]

        # Unlink via PATCH {"document_ids": []}
        unlink_doc_patch = client.patch(
            f"/api/v1/education/{edu_id}",
            headers=headers,
            json={"document_ids": []},
        )
        assert unlink_doc_patch.status_code == 200
        assert unlink_doc_patch.json()["document_ids"] == []
        assert unlink_doc_patch.json()["documents"] == []

        # Partial PATCH updates only specified field and preserves all omitted fields
        patch_resp = client.patch(
            f"/api/v1/education/{edu_id}",
            headers=headers,
            json={"specialization": "Distributed Systems", "description": None},
        )
        assert patch_resp.status_code == 200
        patched = patch_resp.json()
        assert patched["specialization"] == "Distributed Systems"
        assert patched["description"] is None
        assert patched["institution"] == "BMS College of Engineering"
        assert patched["degree"] == "B.E."
        assert patched["branch"] == "Computer Science"
        assert patched["result_value"] == "9.12"
        assert patched["achievements"] == [
            "Best Outgoing Student",
            "Smart India Hackathon Finalist",
        ]

        # Invalid merged PATCH (setting is_current=True while existing record still has end_year=2025)
        bad_merge_resp = client.patch(
            f"/api/v1/education/{edu_id}",
            headers=headers,
            json={"is_current": True},
        )
        assert bad_merge_resp.status_code == 422
        assert bad_merge_resp.json()["error"]["code"] == "VALIDATION_ERROR"

        # Valid transition to ongoing when end_year & end_month are cleared together
        valid_merge_resp = client.patch(
            f"/api/v1/education/{edu_id}",
            headers=headers,
            json={"is_current": True, "end_year": None, "end_month": None},
        )
        assert valid_merge_resp.status_code == 200
        assert valid_merge_resp.json()["is_current"] is True
        assert valid_merge_resp.json()["end_year"] is None

        # DELETE record
        del_resp = client.delete(f"/api/v1/education/{edu_id}", headers=headers)
        assert del_resp.status_code == 204

        # Subsequent GET/PATCH/DELETE return 404 EDUCATION_NOT_FOUND
        after_del = client.get(f"/api/v1/education/{edu_id}", headers=headers)
        assert after_del.status_code == 404
        assert after_del.json()["error"]["code"] == "EDUCATION_NOT_FOUND"


@pytest.mark.db
def test_education_auth_and_cross_user_isolation(
    test_database_url: str,
    db_engine: Engine,
    clean_education_db: None,
) -> None:
    """Verify unauthenticated/unverified/inactive users are blocked and users cannot access others' records."""
    settings, app = _build_test_app(test_database_url)
    owner = _create_db_user(db_engine, email="owner.edu@example.com")
    other = _create_db_user(db_engine, email="other.edu@example.com")
    unverified = _create_db_user(
        db_engine, email="unverified.edu@example.com", is_email_verified=False
    )
    inactive = _create_db_user(
        db_engine, email="inactive.edu@example.com", is_active=False
    )

    owner_headers = _auth_headers(owner, settings)
    other_headers = _auth_headers(other, settings)
    unverified_headers = _auth_headers(unverified, settings)
    inactive_headers = _auth_headers(inactive, settings)

    with TestClient(app) as client:  # type: ignore[arg-type]
        assert client.get("/api/v1/education").status_code == 401
        assert client.get("/api/v1/education", headers=unverified_headers).status_code == 403
        assert client.get("/api/v1/education", headers=inactive_headers).status_code == 403

        create_resp = client.post(
            "/api/v1/education",
            headers=owner_headers,
            json={"institution": "Owner University", "degree": "M.Tech"},
        )
        assert create_resp.status_code == 201
        edu_id = create_resp.json()["id"]

        # Other user cannot see it in list, GET, PATCH, or DELETE
        other_list = client.get("/api/v1/education", headers=other_headers)
        assert other_list.status_code == 200
        assert other_list.json()["total"] == 0

        for resp in (
            client.get(f"/api/v1/education/{edu_id}", headers=other_headers),
            client.patch(
                f"/api/v1/education/{edu_id}",
                headers=other_headers,
                json={"degree": "Hijacked"},
            ),
            client.delete(f"/api/v1/education/{edu_id}", headers=other_headers),
        ):
            assert resp.status_code == 404
            assert resp.json()["error"]["code"] == "EDUCATION_NOT_FOUND"

        # Owner still sees unmodified record
        owner_get = client.get(f"/api/v1/education/{edu_id}", headers=owner_headers)
        assert owner_get.status_code == 200
        assert owner_get.json()["degree"] == "M.Tech"


@pytest.mark.db
def test_education_canonical_sorting_and_pagination(
    test_database_url: str,
    db_engine: Engine,
    clean_education_db: None,
) -> None:
    """
    Verify canonical sorting:
      1. Ongoing first, sorted by latest start date first.
      2. Completed next, sorted by latest end date first (fallback to start date if end missing).
      3. Deterministic tie-breaking and accurate pagination metadata.
    """
    settings, app = _build_test_app(test_database_url)
    user = _create_db_user(db_engine, email="edu.sort@example.com")
    headers = _auth_headers(user, settings)

    records_to_create = [
        # Completed older (2018-2020)
        {
            "institution": "PU College",
            "degree": "12th",
            "start_month": 6,
            "start_year": 2018,
            "end_month": 4,
            "end_year": 2020,
            "is_current": False,
        },
        # Ongoing older start (2023-01)
        {
            "institution": "Ongoing Older",
            "degree": "Fellowship",
            "start_month": 1,
            "start_year": 2023,
            "is_current": True,
        },
        # Completed missing end date, fallback to start_year=2024
        {
            "institution": "Completed Fallback 2024",
            "degree": "Diploma",
            "start_month": 3,
            "start_year": 2024,
            "is_current": False,
        },
        # Ongoing latest start (2025-09)
        {
            "institution": "Ongoing Latest",
            "degree": "M.S.",
            "start_month": 9,
            "start_year": 2025,
            "is_current": True,
        },
        # Completed latest end (2025-05)
        {
            "institution": "Completed 2025",
            "degree": "B.E.",
            "start_month": 8,
            "start_year": 2021,
            "end_month": 5,
            "end_year": 2025,
            "is_current": False,
        },
        # Ongoing with no start date (nulls last among ongoing)
        {
            "institution": "Ongoing No Start",
            "degree": "Self-Paced",
            "is_current": True,
        },
    ]

    with TestClient(app) as client:  # type: ignore[arg-type]
        for payload in records_to_create:
            resp = client.post("/api/v1/education", headers=headers, json=payload)
            assert resp.status_code == 201

        full_list = client.get("/api/v1/education", headers=headers)
        assert full_list.status_code == 200
        body = full_list.json()
        assert body["total"] == 6
        assert body["total_pages"] == 1
        assert [item["institution"] for item in body["items"]] == [
            "Ongoing Latest",
            "Ongoing Older",
            "Ongoing No Start",
            "Completed 2025",
            "Completed Fallback 2024",
            "PU College",
        ]

        # Pagination slices
        page_1 = client.get("/api/v1/education?page=1&page_size=2", headers=headers).json()
        page_2 = client.get("/api/v1/education?page=2&page_size=2", headers=headers).json()
        page_3 = client.get("/api/v1/education?page=3&page_size=2", headers=headers).json()
        page_4 = client.get("/api/v1/education?page=4&page_size=2", headers=headers).json()

        assert page_1["total"] == 6
        assert page_1["total_pages"] == 3
        assert [i["institution"] for i in page_1["items"]] == [
            "Ongoing Latest",
            "Ongoing Older",
        ]
        assert [i["institution"] for i in page_2["items"]] == [
            "Ongoing No Start",
            "Completed 2025",
        ]
        assert [i["institution"] for i in page_3["items"]] == [
            "Completed Fallback 2024",
            "PU College",
        ]
        assert page_4["items"] == []
        assert page_4["total"] == 6
        assert page_4["total_pages"] == 3


@pytest.mark.db
def test_education_merged_patch_validation_errors(
    test_database_url: str,
    db_engine: Engine,
    clean_education_db: None,
) -> None:
    """Verify PATCH validates merged date and result state against persisted DB values."""
    settings, app = _build_test_app(test_database_url)
    user = _create_db_user(db_engine, email="edu.merged.patch@example.com")
    headers = _auth_headers(user, settings)

    with TestClient(app) as client:  # type: ignore[arg-type]
        create_resp = client.post(
            "/api/v1/education",
            headers=headers,
            json={
                "institution": "VTU College",
                "degree": "B.E.",
                "start_month": 8,
                "start_year": 2021,
                "end_month": 6,
                "end_year": 2025,
                "is_current": False,
                "result_type": "percentage",
                "result_value": "92.5%",
            },
        )
        assert create_resp.status_code == 201
        edu_id = create_resp.json()["id"]

        for invalid_patch in (
            {"result_type": None},
            {"result_type": "cgpa"},
            {"start_year": 2026},
            {"start_year": None},
        ):
            resp = client.patch(
                f"/api/v1/education/{edu_id}",
                headers=headers,
                json=invalid_patch,
            )
            assert resp.status_code == 422
            assert resp.json()["error"]["code"] == "VALIDATION_ERROR"

        # Original values remain intact after rejected PATCHes
        persisted = client.get(f"/api/v1/education/{edu_id}", headers=headers).json()
        assert persisted["result_type"] == "percentage"
        assert persisted["result_value"] == "92.5%"
        assert persisted["start_year"] == 2021
        assert persisted["start_month"] == 8
        assert persisted["end_year"] == 2025


@pytest.mark.db
def test_education_canonical_sorting_edge_cases_and_tie_breakers(
    test_database_url: str,
    db_engine: Engine,
    clean_education_db: None,
) -> None:
    """
    Verify edge cases and deterministic tie-breakers in canonical sorting:
      - Completed end_year with end_month present vs end_month=None
      - Tied end_year/end_month broken by start_year DESC, then start_month DESC
      - Tied all date fields broken by created_at DESC, then id DESC
      - Missing both start and end dates sorted last
    """
    settings, app = _build_test_app(test_database_url)
    user = _create_db_user(db_engine, email="edu.tiebreak@example.com")
    headers = _auth_headers(user, settings)

    t0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=5)
    id_low = uuid.UUID("00000000-0000-4000-8000-000000000001")
    id_high = uuid.UUID("ffffffff-ffff-4fff-8fff-ffffffffffff")

    session_factory = build_sessionmaker(db_engine)
    with session_factory() as session:
        session.add_all(
            [
                # 6. No start or end dates -> last
                Education(
                    id=uuid.uuid4(),
                    user_id=user.id,
                    institution="Completed Undated",
                    degree="Cert",
                    is_current=False,
                    created_at=t1,
                    updated_at=t1,
                ),
                # 5. Completed 2025 with end_month=None (must sort after 2025-05 despite later start_month)
                Education(
                    id=uuid.uuid4(),
                    user_id=user.id,
                    institution="Completed 2025 No End Month",
                    degree="B.E.",
                    start_month=11,
                    start_year=2021,
                    end_month=None,
                    end_year=2025,
                    is_current=False,
                    created_at=t1,
                    updated_at=t1,
                ),
                # 4. Tied end 2025-05, earlier start_year 2020
                Education(
                    id=uuid.uuid4(),
                    user_id=user.id,
                    institution="Tied End Start 2020",
                    degree="B.E.",
                    start_month=9,
                    start_year=2020,
                    end_month=5,
                    end_year=2025,
                    is_current=False,
                    created_at=t1,
                    updated_at=t1,
                ),
                # 3. Tied end 2025-05 + start 2021-08, earlier created_at t0
                Education(
                    id=uuid.uuid4(),
                    user_id=user.id,
                    institution="Tied Dates Older Created",
                    degree="B.E.",
                    start_month=8,
                    start_year=2021,
                    end_month=5,
                    end_year=2025,
                    is_current=False,
                    created_at=t0,
                    updated_at=t0,
                ),
                # 2. Tied end 2025-05 + start 2021-08 + created_at t1, lower UUID
                Education(
                    id=id_low,
                    user_id=user.id,
                    institution="Tied All Lower ID",
                    degree="B.E.",
                    start_month=8,
                    start_year=2021,
                    end_month=5,
                    end_year=2025,
                    is_current=False,
                    created_at=t1,
                    updated_at=t1,
                ),
                # 1. Tied end 2025-05 + start 2021-08 + created_at t1, higher UUID
                Education(
                    id=id_high,
                    user_id=user.id,
                    institution="Tied All Higher ID",
                    degree="B.E.",
                    start_month=8,
                    start_year=2021,
                    end_month=5,
                    end_year=2025,
                    is_current=False,
                    created_at=t1,
                    updated_at=t1,
                ),
                # 0. Tied end 2025-05, later start_month 2021-09 -> wins over 2021-08
                Education(
                    id=uuid.uuid4(),
                    user_id=user.id,
                    institution="Tied End Start 2021-09",
                    degree="B.E.",
                    start_month=9,
                    start_year=2021,
                    end_month=5,
                    end_year=2025,
                    is_current=False,
                    created_at=t0,
                    updated_at=t0,
                ),
            ]
        )
        session.commit()

    with TestClient(app) as client:  # type: ignore[arg-type]
        resp = client.get("/api/v1/education", headers=headers)
        assert resp.status_code == 200
        assert [item["institution"] for item in resp.json()["items"]] == [
            "Tied End Start 2021-09",
            "Tied All Higher ID",
            "Tied All Lower ID",
            "Tied Dates Older Created",
            "Tied End Start 2020",
            "Completed 2025 No End Month",
            "Completed Undated",
        ]


@pytest.mark.db
def test_education_pagination_and_path_uuid_validation(
    test_database_url: str,
    db_engine: Engine,
    clean_education_db: None,
) -> None:
    """Verify pagination query bounds and invalid UUID path parameters return HTTP 422."""
    settings, app = _build_test_app(test_database_url)
    user = _create_db_user(db_engine, email="edu.queryval@example.com")
    headers = _auth_headers(user, settings)

    with TestClient(app) as client:  # type: ignore[arg-type]
        for query in ("page=0", "page_size=0", "page_size=201"):
            resp = client.get(f"/api/v1/education?{query}", headers=headers)
            assert resp.status_code == 422

        assert client.get("/api/v1/education/not-a-uuid", headers=headers).status_code == 422
        assert (
            client.patch(
                "/api/v1/education/not-a-uuid",
                headers=headers,
                json={"degree": "Updated"},
            ).status_code
            == 422
        )
        assert client.delete("/api/v1/education/not-a-uuid", headers=headers).status_code == 422
