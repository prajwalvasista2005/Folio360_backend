"""Integration tests for GET /api/v1/analytics/dashboard."""

from datetime import date, datetime, timedelta, timezone
import struct
import uuid
import zlib

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import Engine, text

from app.core.config import Settings
from app.core.security import create_access_token, hash_password
from app.db.session import build_sessionmaker
from app.main import create_app
from app.models.certificate import Achievement, Certificate
from app.models.document import Document
from app.models.document_analysis import DocumentAnalysis
from app.models.education import Education
from app.models.experience import Experience
from app.models.profile import UserProfile
from app.models.project import Project
from app.models.skill import Skill
from app.models.user import User

pytestmark = pytest.mark.db


def _build_test_app(test_database_url: str, *, storage_dir: str) -> tuple[Settings, object]:
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL=test_database_url,
        JWT_SECRET_KEY="analytics-dashboard-jwt-secret-key-32chars",
        JWT_ISSUER="folio360",
        JWT_AUDIENCE="folio360-api",
        JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15,
        FRONTEND_BASE_URL="http://localhost:5173",
        BACKEND_BASE_URL="http://localhost:8000",
        CORS_ORIGINS=["http://localhost:5173"],
        OAUTH_PKCE_ENCRYPTION_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        EMAIL_FROM_ADDRESS="no-reply@folio360.com",
        RATE_LIMIT_ENABLED=False,
        STORAGE_BACKEND="local",
        DOCUMENT_LOCAL_STORAGE_DIR=storage_dir,
        MALWARE_SCANNER_BACKEND="mock",
    )
    return settings, create_app(settings=settings)


@pytest.fixture
def clean_analytics_db(db_engine: Engine):
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))
    yield
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))


def _create_user(
    db_engine: Engine,
    *,
    email: str,
    verified: bool = True,
) -> User:
    session_factory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password("StrongPassword!2026"),
        is_active=True,
        is_email_verified=verified,
        email_verified_at=now if verified else None,
        auth_version=0,
    )
    with session_factory() as session:
        session.add(user)
        session.commit()
        session.refresh(user)
    return user


def _create_profile(
    db_engine: Engine,
    *,
    user_id: uuid.UUID,
    slug: str | None = None,
    full_name: str | None = None,
    bio: str | None = None,
    avatar_url: str | None = None,
    interests: list[str] | None = None,
    profile_completed: bool = False,
    created_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> UserProfile:
    session_factory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)
    profile = UserProfile(
        id=uuid.uuid4(),
        user_id=user_id,
        slug=slug,
        full_name=full_name,
        date_of_birth=date(2002, 5, 10) if profile_completed else None,
        bio=bio,
        profile_picture_url=avatar_url,
        interests=interests or [],
        profile_completed=profile_completed,
        profile_completed_at=now if profile_completed else None,
        created_at=created_at or now,
        updated_at=updated_at or created_at or now,
    )
    with session_factory() as session:
        session.add(profile)
        session.commit()
        session.refresh(profile)
    return profile


def _create_document(
    db_engine: Engine,
    *,
    user_id: uuid.UUID,
    title: str,
    processing_status: str = "ready",
    storage_state: str = "trusted",
    created_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> Document:
    session_factory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)
    doc_id = uuid.uuid4()
    doc = Document(
        id=doc_id,
        user_id=user_id,
        title=title,
        original_filename=f"{doc_id}.pdf",
        category="marksheet",
        mime_type="application/pdf",
        size_bytes=1024,
        sha256="a" * 64,
        storage_backend="local",
        storage_key=f"local/{user_id}/{doc_id}.pdf",
        processing_status=processing_status,
        storage_state=storage_state,
        created_at=created_at or now,
        updated_at=updated_at or created_at or now,
    )
    with session_factory() as session:
        session.add(doc)
        session.commit()
        session.refresh(doc)
    return doc


def _auth_headers(user: User, settings: Settings) -> dict[str, str]:
    token, _ = create_access_token(
        user_id=user.id,
        auth_version=user.auth_version,
        settings=settings,
    )
    return {"Authorization": f"Bearer {token}"}


def test_dashboard_requires_authenticated_verified_user(
    db_engine: Engine,
    test_database_url: str,
    tmp_path,
    clean_analytics_db,
) -> None:
    del clean_analytics_db
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    unverified_user = _create_user(
        db_engine,
        email="unverified@example.com",
        verified=False,
    )

    with TestClient(app) as client:
        unauth_res = client.get("/api/v1/analytics/dashboard")
        assert unauth_res.status_code == 401

        unverified_res = client.get(
            "/api/v1/analytics/dashboard",
            headers=_auth_headers(unverified_user, settings),
        )
        assert unverified_res.status_code == 403
        assert unverified_res.json()["error"]["details"]["code"] == "EMAIL_NOT_VERIFIED"


def test_dashboard_empty_new_user_and_missing_profile_fields(
    db_engine: Engine,
    test_database_url: str,
    tmp_path,
    clean_analytics_db,
) -> None:
    del clean_analytics_db
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    new_user = _create_user(db_engine, email="alex.new@example.com")
    sparse_user = _create_user(db_engine, email="sparse.user@example.com")
    _create_profile(
        db_engine,
        user_id=sparse_user.id,
        slug=None,
        full_name=None,
        bio=None,
        avatar_url=None,
        profile_completed=False,
    )

    with TestClient(app) as client:
        res_new = client.get(
            "/api/v1/analytics/dashboard",
            headers=_auth_headers(new_user, settings),
        )
        assert res_new.status_code == 200
        body_new = res_new.json()
        assert body_new["first_name"] == "alex.new"
        assert body_new["slug"] is None
        assert body_new["avatar_url"] is None
        assert body_new["completeness"] == {"percent": 0}
        assert body_new["counts"] == {
            "projects": 0,
            "skills": 0,
            "certificates": 0,
            "experience": 0,
            "documents": 0,
            "pending_reviews": 0,
        }
        assert body_new["recent_activity"] == []
        assert len(body_new["continue_items"]) > 0
        assert all(item["action_route"] != "/workspace/resumes" for item in body_new["continue_items"])
        assert body_new["continue_items"][0]["action_route"] == "/onboarding/profile"

        res_sparse = client.get(
            "/api/v1/analytics/dashboard",
            headers=_auth_headers(sparse_user, settings),
        )
        assert res_sparse.status_code == 200
        body_sparse = res_sparse.json()
        assert body_sparse["first_name"] == "sparse.user"
        assert body_sparse["slug"] is None
        assert body_sparse["avatar_url"] is None
        assert body_sparse["completeness"] == {"percent": 0}


def test_dashboard_user_scoping_counts_completeness_and_activity_order(
    db_engine: Engine,
    test_database_url: str,
    tmp_path,
    clean_analytics_db,
) -> None:
    del clean_analytics_db
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    user_a = _create_user(db_engine, email="owner.a@example.com")
    user_b = _create_user(db_engine, email="owner.b@example.com")

    base_time = datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)
    _create_profile(
        db_engine,
        user_id=user_a.id,
        slug="alex_mercer",
        full_name="Alex Mercer",
        bio="Systems engineer and student.",
        avatar_url="https://example.com/avatar-a.png",
        interests=["Distributed Systems"],
        profile_completed=True,
        created_at=base_time,
        updated_at=base_time,
    )
    _create_profile(
        db_engine,
        user_id=user_b.id,
        slug="other_user",
        full_name="Other User",
        bio="Should stay isolated.",
        profile_completed=True,
        created_at=base_time + timedelta(days=5),
        updated_at=base_time + timedelta(days=5),
    )

    session_factory = build_sessionmaker(db_engine)
    with session_factory() as session:
        # User A records across all sections
        session.add(
            Education(
                id=uuid.uuid4(),
                user_id=user_a.id,
                institution="RVCE",
                degree="B.E.",
                result_source="manual",
                visibility="public",
                created_at=base_time + timedelta(hours=1),
                updated_at=base_time + timedelta(hours=1),
            )
        )
        session.add(
            Project(
                id=uuid.uuid4(),
                user_id=user_a.id,
                title="Folio360 Core",
                summary="Portfolio platform",
                category="Web",
                technologies=["FastAPI"],
                created_at=base_time + timedelta(hours=2),
                updated_at=base_time + timedelta(hours=6),  # updated later -> verb "updated"
            )
        )
        session.add(
            Skill(
                id=uuid.uuid4(),
                user_id=user_a.id,
                name="Python",
                category="language",
                created_at=base_time + timedelta(hours=3),
                updated_at=base_time + timedelta(hours=3),
            )
        )
        session.add(
            Certificate(
                id=uuid.uuid4(),
                user_id=user_a.id,
                name="AWS Foundations",
                issuer="AWS",
                created_at=base_time + timedelta(hours=4),
                updated_at=base_time + timedelta(hours=4),
            )
        )
        session.add(
            Experience(
                id=uuid.uuid4(),
                user_id=user_a.id,
                type="internship",
                organization="Systems Lab",
                role="Backend Intern",
                start_date=date(2026, 6, 1),
                is_current=False,
                highlights=[],
                created_at=base_time + timedelta(hours=5),
                updated_at=base_time + timedelta(hours=5),
            )
        )

        # User B records that must NOT leak into User A's dashboard
        session.add(
            Project(
                id=uuid.uuid4(),
                user_id=user_b.id,
                title="Secret User B Project",
                summary="Private",
                category="Private",
                created_at=base_time + timedelta(days=10),
                updated_at=base_time + timedelta(days=10),
            )
        )
        session.add(
            Skill(
                id=uuid.uuid4(),
                user_id=user_b.id,
                name="Rust",
                category="language",
                created_at=base_time + timedelta(days=10),
                updated_at=base_time + timedelta(days=10),
            )
        )
        session.commit()

    _create_document(
        db_engine,
        user_id=user_a.id,
        title="Sem 5 Marksheet",
        created_at=base_time + timedelta(hours=7),
        updated_at=base_time + timedelta(hours=7),
    )
    _create_document(
        db_engine,
        user_id=user_b.id,
        title="User B Private Doc",
        processing_status="pending_scan",
        storage_state="quarantine",
        created_at=base_time + timedelta(days=10),
        updated_at=base_time + timedelta(days=10),
    )

    with TestClient(app) as client:
        res = client.get(
            "/api/v1/analytics/dashboard",
            headers=_auth_headers(user_a, settings),
        )
        assert res.status_code == 200
        data = res.json()

        assert data["first_name"] == "Alex"
        assert data["slug"] == "alex_mercer"
        assert data["avatar_url"] == "https://example.com/avatar-a.png"
        assert data["completeness"]["percent"] == 100
        assert data["continue_items"] == []
        assert data["counts"] == {
            "projects": 1,
            "skills": 1,
            "certificates": 1,
            "experience": 1,
            "documents": 1,
            "pending_reviews": 0,
        }

        activity = data["recent_activity"]
        assert len(activity) == 7
        assert all("User B" not in ev["label"] for ev in activity)
        timestamps = [datetime.fromisoformat(ev["created_at"]) for ev in activity]
        assert timestamps == sorted(timestamps, reverse=True)
        assert activity[0]["entity_type"] == "document"
        assert activity[0]["verb"] == "uploaded"
        assert activity[0]["label"] == "Sem 5 Marksheet"
        assert activity[1]["entity_type"] == "project"
        assert activity[1]["verb"] == "updated"
        assert activity[1]["label"] == "Folio360 Core"


def test_dashboard_pending_reviews_reflects_document_and_analysis_states(
    db_engine: Engine,
    test_database_url: str,
    tmp_path,
    clean_analytics_db,
) -> None:
    del clean_analytics_db
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    user = _create_user(db_engine, email="reviewer@example.com")
    _create_profile(
        db_engine,
        user_id=user.id,
        slug="reviewer_user",
        full_name="Reviewer User",
        profile_completed=True,
    )

    doc_ready_no_analysis = _create_document(db_engine, user_id=user.id, title="Ready Doc")
    doc_pending_scan = _create_document(
        db_engine,
        user_id=user.id,
        title="Pending Scan Doc",
        processing_status="pending_scan",
        storage_state="quarantine",
    )
    doc_scanning = _create_document(
        db_engine,
        user_id=user.id,
        title="Scanning Doc",
        processing_status="scanning",
        storage_state="quarantine",
    )
    doc_rejected = _create_document(
        db_engine,
        user_id=user.id,
        title="Rejected Doc",
        processing_status="rejected",
        storage_state="quarantine",
    )
    doc_analysis_processing = _create_document(
        db_engine,
        user_id=user.id,
        title="Analyzing Doc",
    )
    doc_analysis_completed = _create_document(
        db_engine,
        user_id=user.id,
        title="Analyzed Doc",
    )
    doc_analysis_failed = _create_document(
        db_engine,
        user_id=user.id,
        title="Failed Analysis Doc",
    )
    del doc_ready_no_analysis, doc_rejected

    session_factory = build_sessionmaker(db_engine)
    with session_factory() as session:
        # Pending analysis on a scanning doc should count only once for that doc.
        session.add(
            DocumentAnalysis(
                id=uuid.uuid4(),
                document_id=doc_scanning.id,
                user_id=user.id,
                status="pending",
                provider_name="mock",
                model_name="mock-v1",
            )
        )
        session.add(
            DocumentAnalysis(
                id=uuid.uuid4(),
                document_id=doc_analysis_processing.id,
                user_id=user.id,
                status="processing",
                provider_name="mock",
                model_name="mock-v1",
            )
        )
        session.add(
            DocumentAnalysis(
                id=uuid.uuid4(),
                document_id=doc_analysis_completed.id,
                user_id=user.id,
                status="completed",
                document_type="other",
                provider_name="mock",
                model_name="mock-v1",
                summary="Done",
                extracted_data={"document_type": "other", "is_verified": False},
            )
        )
        session.add(
            DocumentAnalysis(
                id=uuid.uuid4(),
                document_id=doc_analysis_failed.id,
                user_id=user.id,
                status="failed",
                provider_name="mock",
                model_name="mock-v1",
                failure_reason="analysis_error",
            )
        )
        session.commit()

    with TestClient(app) as client:
        res = client.get(
            "/api/v1/analytics/dashboard",
            headers=_auth_headers(user, settings),
        )
        assert res.status_code == 200
        counts = res.json()["counts"]
        assert counts["documents"] == 7
        # Pending: doc_pending_scan + doc_scanning (deduped) + doc_analysis_processing = 3
        assert counts["pending_reviews"] == 3
        assert res.json()["completeness"]["percent"] == 20  # completed profile + 10 for docs
        assert len(res.json()["continue_items"]) == 4
        # Verify Achievement count doesn't break completeness when Certificate is 0
    with session_factory() as session:
        session.add(
            Achievement(
                id=uuid.uuid4(),
                user_id=user.id,
                title="Hackathon Winner",
                category="hackathon",
            )
        )
        session.commit()

    with TestClient(app) as client:
        res_ach = client.get(
            "/api/v1/analytics/dashboard",
            headers=_auth_headers(user, settings),
        )
        assert res_ach.status_code == 200
        assert res_ach.json()["completeness"]["percent"] == 30


def _build_minimal_png() -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def test_dashboard_refreshes_after_document_upload(
    db_engine: Engine,
    test_database_url: str,
    tmp_path,
    clean_analytics_db,
) -> None:
    del clean_analytics_db
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    user = _create_user(db_engine, email="uploader@example.com")
    _create_profile(
        db_engine,
        user_id=user.id,
        slug="uploader_user",
        full_name="Uploader User",
        profile_completed=True,
    )
    headers = _auth_headers(user, settings)

    with TestClient(app) as client:
        before_res = client.get("/api/v1/analytics/dashboard", headers=headers)
        assert before_res.status_code == 200
        before_data = before_res.json()
        assert before_data["counts"]["documents"] == 0
        assert before_data["completeness"]["percent"] == 10

        upload_res = client.post(
            "/api/v1/documents",
            headers=headers,
            files={"file": ("transcript.png", _build_minimal_png(), "image/png")},
            data={"category": "marksheet", "title": "Semester Transcript"},
        )
        assert upload_res.status_code == 201

        after_res = client.get("/api/v1/analytics/dashboard", headers=headers)
        assert after_res.status_code == 200
        after_data = after_res.json()
        assert after_data["counts"]["documents"] == 1
        assert after_data["completeness"]["percent"] == 20
        assert after_data["recent_activity"][0]["entity_type"] == "document"
        assert after_data["recent_activity"][0]["verb"] == "uploaded"
        assert after_data["recent_activity"][0]["label"] == "Semester Transcript"
