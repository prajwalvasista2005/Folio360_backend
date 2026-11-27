"""End-to-end integration tests for Experience CRUD, Vault protection, Skills, and Public Profile."""

from datetime import date, datetime, timezone
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
from app.models.profile import UserProfile
from app.models.skill import Skill
from app.models.user import User


def _build_minimal_png() -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _build_test_app(
    test_database_url: str,
    *,
    storage_dir: str,
) -> tuple[Settings, object]:
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL=test_database_url,
        JWT_SECRET_KEY="experience-integration-jwt-secret-key-32chars",
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
def clean_experience_db(db_engine: Engine):
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))
    yield
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))


def _create_db_user_with_profile(
    db_engine: Engine,
    *,
    email: str,
    slug: str,
) -> User:
    session_factory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password("StrongPassword!2026"),
        is_active=True,
        is_email_verified=True,
        email_verified_at=now,
        auth_version=0,
    )
    profile = UserProfile(
        id=uuid.uuid4(),
        user_id=user.id,
        slug=slug,
        full_name=f"User {slug}",
        date_of_birth=date(2002, 5, 10),
        interests=["Distributed Systems"],
        profile_completed=True,
        profile_completed_at=now,
    )
    with session_factory() as session:
        session.add(user)
        session.flush()
        session.add(profile)
        session.commit()
        session.refresh(user)
    return user


def _create_skill(db_engine: Engine, *, user_id: uuid.UUID, name: str) -> Skill:
    session_factory = build_sessionmaker(db_engine)
    skill = Skill(user_id=user_id, name=name, category="technical", proficiency="Advanced")
    with session_factory() as session:
        session.add(skill)
        session.commit()
        session.refresh(skill)
    return skill


def _auth_headers(user: User, settings: Settings) -> dict[str, str]:
    token, _ = create_access_token(
        user_id=user.id,
        auth_version=user.auth_version,
        settings=settings,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.db
def test_experience_crud_idor_vault_protection_and_public_profile(
    db_engine: Engine,
    test_database_url: str,
    clean_experience_db: None,
    tmp_path,
) -> None:
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    owner = _create_db_user_with_profile(db_engine, email="exp.owner@example.com", slug="exp_owner")
    other = _create_db_user_with_profile(db_engine, email="exp.other@example.com", slug="exp_other")
    owner_skill = _create_skill(db_engine, user_id=owner.id, name="FastAPI")
    other_skill = _create_skill(db_engine, user_id=other.id, name="Forbidden Skill")

    with TestClient(app) as client:  # type: ignore[arg-type]
        # 1. Authentication required
        assert client.get("/api/v1/experience").status_code == 401
        assert client.post("/api/v1/experience", json={}).status_code == 401

        # 2. Upload Vault documents for owner and other user
        up_owner_1 = client.post(
            "/api/v1/documents",
            headers=_auth_headers(owner, settings),
            files={"file": ("offer-letter.png", _build_minimal_png(), "image/png")},
            data={"category": "other", "title": "Acme Offer Letter"},
        )
        assert up_owner_1.status_code == 201, up_owner_1.text
        owner_doc_1 = up_owner_1.json()["document"]["id"]

        up_owner_2 = client.post(
            "/api/v1/documents",
            headers=_auth_headers(owner, settings),
            files={"file": ("completion-letter.png", _build_minimal_png(), "image/png")},
            data={"category": "certificate", "title": "Completion Letter"},
        )
        assert up_owner_2.status_code == 201, up_owner_2.text
        owner_doc_2 = up_owner_2.json()["document"]["id"]

        up_other = client.post(
            "/api/v1/documents",
            headers=_auth_headers(other, settings),
            files={"file": ("other.png", _build_minimal_png(), "image/png")},
            data={"category": "other", "title": "Other Scan"},
        )
        assert up_other.status_code == 201
        other_doc_id = up_other.json()["document"]["id"]

        # 3. Cross-user document / skill ownership checks
        bad_doc = client.post(
            "/api/v1/experience",
            headers=_auth_headers(owner, settings),
            json={
                "type": "internship",
                "organization": "Acme",
                "role": "Intern",
                "start_date": "2025-05-01",
                "document_ids": [other_doc_id],
            },
        )
        assert bad_doc.status_code == 422

        bad_skill = client.post(
            "/api/v1/experience",
            headers=_auth_headers(owner, settings),
            json={
                "type": "internship",
                "organization": "Acme",
                "role": "Intern",
                "start_date": "2025-05-01",
                "skill_ids": [str(other_skill.id)],
            },
        )
        assert bad_skill.status_code == 422

        # 4. Create public current internship + private past leadership record
        pub_resp = client.post(
            "/api/v1/experience",
            headers=_auth_headers(owner, settings),
            json={
                "type": "internship",
                "organization": "Acme Cloud",
                "role": "Backend Engineering Intern",
                "location": "Bengaluru, India",
                "is_remote": True,
                "organization_url": "https://acme.example.com",
                "start_date": "2025-06-01",
                "is_current": True,
                "description": "Designed telemetry APIs.",
                "highlights": ["Cut p95 latency by 35%", "Added OpenAPI tests"],
                "skill_ids": [str(owner_skill.id)],
                "document_ids": [owner_doc_1],
                "featured": True,
                "visibility": "public",
            },
        )
        assert pub_resp.status_code == 201, pub_resp.text
        pub_exp = pub_resp.json()
        pub_exp_id = pub_exp["id"]
        assert pub_exp["is_remote"] is True
        assert pub_exp["skills"] == [{"id": str(owner_skill.id), "name": "FastAPI"}]
        assert len(pub_exp["documents"]) == 1
        assert pub_exp["documents"][0]["id"] == owner_doc_1

        priv_resp = client.post(
            "/api/v1/experience",
            headers=_auth_headers(owner, settings),
            json={
                "type": "leadership",
                "organization": "Campus ACM Chapter",
                "role": "Technical Lead",
                "start_date": "2024-01-10",
                "end_date": "2024-12-20",
                "is_current": False,
                "highlights": ["Organized 4 hackathons"],
                "visibility": "private",
            },
        )
        assert priv_resp.status_code == 201, priv_resp.text
        priv_exp_id = priv_resp.json()["id"]

        # 5. Filters & search
        list_all = client.get("/api/v1/experience", headers=_auth_headers(owner, settings))
        assert list_all.status_code == 200
        assert list_all.json()["total"] == 2
        assert list_all.json()["items"][0]["id"] == pub_exp_id

        list_leadership = client.get(
            "/api/v1/experience?type=leadership&visibility=private",
            headers=_auth_headers(owner, settings),
        )
        assert list_leadership.status_code == 200
        assert [row["id"] for row in list_leadership.json()["items"]] == [priv_exp_id]

        list_search = client.get(
            "/api/v1/experience?q=Telemetry",
            headers=_auth_headers(owner, settings),
        )
        assert list_search.status_code == 200
        assert [row["id"] for row in list_search.json()["items"]] == [pub_exp_id]

        # 6. IDOR protection against other user
        assert (
            client.get(
                f"/api/v1/experience/{pub_exp_id}",
                headers=_auth_headers(other, settings),
            ).status_code
            == 404
        )
        assert (
            client.patch(
                f"/api/v1/experience/{pub_exp_id}",
                headers=_auth_headers(other, settings),
                json={"role": "Hacked"},
            ).status_code
            == 404
        )
        assert (
            client.delete(
                f"/api/v1/experience/{pub_exp_id}",
                headers=_auth_headers(other, settings),
            ).status_code
            == 404
        )

        # 7. Partial update validation & marking past role as current clears end_date
        bad_patch = client.patch(
            f"/api/v1/experience/{priv_exp_id}",
            headers=_auth_headers(owner, settings),
            json={"end_date": "2023-01-01"},
        )
        assert bad_patch.status_code == 422

        mark_current = client.patch(
            f"/api/v1/experience/{priv_exp_id}",
            headers=_auth_headers(owner, settings),
            json={"is_current": True},
        )
        assert mark_current.status_code == 200, mark_current.text
        assert mark_current.json()["is_current"] is True
        assert mark_current.json()["end_date"] is None

        # 8. Document Vault attached_to & 409 DOCUMENT_IN_USE protection
        doc_detail = client.get(
            f"/api/v1/documents/{owner_doc_1}",
            headers=_auth_headers(owner, settings),
        )
        assert doc_detail.status_code == 200
        assert any(
            item["entity_type"] == "experience"
            and item["entity_id"] == pub_exp_id
            and "Backend Engineering Intern" in item["label"]
            for item in doc_detail.json()["attached_to"]
        )

        blocked_delete = client.delete(
            f"/api/v1/documents/{owner_doc_1}",
            headers=_auth_headers(owner, settings),
        )
        assert blocked_delete.status_code == 409
        assert blocked_delete.json()["error"]["code"] == "DOCUMENT_IN_USE"

        forced_delete = client.delete(
            f"/api/v1/documents/{owner_doc_1}?force=true",
            headers=_auth_headers(owner, settings),
        )
        assert forced_delete.status_code == 204

        # Attach second document and ensure deleting the experience preserves the document
        relink = client.patch(
            f"/api/v1/experience/{priv_exp_id}",
            headers=_auth_headers(owner, settings),
            json={"document_ids": [owner_doc_2]},
        )
        assert relink.status_code == 200
        assert [d["id"] for d in relink.json()["documents"]] == [owner_doc_2]

        # 9. Public profile exposes only public experience without Vault keys/docs
        public_resp = client.get("/api/v1/public/profiles/exp_owner")
        assert public_resp.status_code == 200, public_resp.text
        public_exps = public_resp.json()["sections"]["experience"]
        assert len(public_exps) == 1
        assert public_exps[0]["role"] == "Backend Engineering Intern"
        assert public_exps[0]["organization"] == "Acme Cloud"
        assert public_exps[0]["skills"] == ["FastAPI"]
        assert "document_ids" not in public_exps[0]
        assert "documents" not in public_exps[0]

        # 10. Delete experience keeps owner_doc_2 intact in Vault
        del_exp = client.delete(
            f"/api/v1/experience/{priv_exp_id}",
            headers=_auth_headers(owner, settings),
        )
        assert del_exp.status_code == 204
        assert (
            client.get(
                f"/api/v1/experience/{priv_exp_id}",
                headers=_auth_headers(owner, settings),
            ).status_code
            == 404
        )
        doc_still_there = client.get(
            f"/api/v1/documents/{owner_doc_2}",
            headers=_auth_headers(owner, settings),
        )
        assert doc_still_there.status_code == 200
        assert doc_still_there.json()["attached_to"] == []
