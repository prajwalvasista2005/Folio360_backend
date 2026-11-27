"""End-to-end integration tests for Certificates, Achievements, Document Vault protection, and Public Profile."""

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
        JWT_SECRET_KEY="certificate-integration-jwt-secret-key-32chars",
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
def clean_certificates_db(db_engine: Engine):
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
        interests=["Python"],
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
def test_certificates_achievements_idor_vault_protection_and_public_profile(
    db_engine: Engine,
    test_database_url: str,
    clean_certificates_db: None,
    tmp_path,
) -> None:
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    owner = _create_db_user_with_profile(db_engine, email="cert.owner@example.com", slug="cert_owner")
    other = _create_db_user_with_profile(db_engine, email="cert.other@example.com", slug="cert_other")
    owner_skill = _create_skill(db_engine, user_id=owner.id, name="Cloud Architecture")
    other_skill = _create_skill(db_engine, user_id=other.id, name="Other Skill")

    with TestClient(app) as client:  # type: ignore[arg-type]
        # Unauthenticated requests rejected
        assert client.get("/api/v1/certificates").status_code == 401
        assert client.get("/api/v1/achievements").status_code == 401

        # Upload trusted document for owner and another document for other user
        up_owner = client.post(
            "/api/v1/documents",
            headers=_auth_headers(owner, settings),
            files={"file": ("aws-cert.png", _build_minimal_png(), "image/png")},
            data={"category": "certificate", "title": "AWS Certificate Scan"},
        )
        assert up_owner.status_code == 201, up_owner.text
        owner_doc_id = up_owner.json()["document"]["id"]

        up_other = client.post(
            "/api/v1/documents",
            headers=_auth_headers(other, settings),
            files={"file": ("other.png", _build_minimal_png(), "image/png")},
            data={"category": "certificate", "title": "Other Scan"},
        )
        assert up_other.status_code == 201
        other_doc_id = up_other.json()["document"]["id"]

        # Reject linking another user's document or skill
        bad_doc_cert = client.post(
            "/api/v1/certificates",
            headers=_auth_headers(owner, settings),
            json={"name": "Bad Doc", "issuer": "Org", "document_id": other_doc_id},
        )
        assert bad_doc_cert.status_code == 422

        bad_skill_cert = client.post(
            "/api/v1/certificates",
            headers=_auth_headers(owner, settings),
            json={"name": "Bad Skill", "issuer": "Org", "skill_ids": [str(other_skill.id)]},
        )
        assert bad_skill_cert.status_code == 422

        # Create public featured certificate with evidence & verification URL
        c_pub = client.post(
            "/api/v1/certificates",
            headers=_auth_headers(owner, settings),
            json={
                "name": "AWS Solutions Architect",
                "issuer": "AWS",
                "category": "professional",
                "issue_date": "2025-01-15",
                "credential_id": "AWS-99",
                "verification_url": "https://aws.amazon.com/verify/99",
                "document_id": owner_doc_id,
                "skill_ids": [str(owner_skill.id)],
                "featured": True,
                "order": 1,
                "visibility": "public",
            },
        )
        assert c_pub.status_code == 201, c_pub.text
        pub_cert = c_pub.json()
        assert pub_cert["verification_status"] == "link_provided"
        assert pub_cert["document"]["id"] == owner_doc_id
        assert [s["name"] for s in pub_cert["skills"]] == ["Cloud Architecture"]

        # Create private self-reported certificate
        c_priv = client.post(
            "/api/v1/certificates",
            headers=_auth_headers(owner, settings),
            json={
                "name": "Internal Security Training",
                "issuer": "CorpSec",
                "category": "training",
                "visibility": "private",
            },
        )
        assert c_priv.status_code == 201
        priv_cert = c_priv.json()
        assert priv_cert["verification_status"] == "self_reported"

        # Create public featured achievement and private achievement referencing owner_doc_id
        a_pub = client.post(
            "/api/v1/achievements",
            headers=_auth_headers(owner, settings),
            json={
                "title": "National Hackathon Winner",
                "category": "hackathon",
                "organization": "TechFest",
                "date": "2025-02-20",
                "description": "Won 1st prize out of 120 teams.",
                "document_ids": [owner_doc_id],
                "featured": True,
                "order": 0,
                "visibility": "public",
            },
        )
        assert a_pub.status_code == 201, a_pub.text
        pub_ach = a_pub.json()
        assert len(pub_ach["documents"]) == 1

        a_priv = client.post(
            "/api/v1/achievements",
            headers=_auth_headers(owner, settings),
            json={
                "title": "Private Scholarship",
                "category": "scholarship",
                "visibility": "private",
            },
        )
        assert a_priv.status_code == 201
        priv_ach = a_priv.json()

        # Cross-user IDOR returns 404
        assert (
            client.get(
                f"/api/v1/certificates/{pub_cert['id']}",
                headers=_auth_headers(other, settings),
            ).status_code
            == 404
        )
        assert (
            client.patch(
                f"/api/v1/certificates/{pub_cert['id']}",
                headers=_auth_headers(other, settings),
                json={"name": "Hijacked"},
            ).status_code
            == 404
        )
        assert (
            client.delete(
                f"/api/v1/certificates/{pub_cert['id']}",
                headers=_auth_headers(other, settings),
            ).status_code
            == 404
        )
        assert (
            client.get(
                f"/api/v1/achievements/{pub_ach['id']}",
                headers=_auth_headers(other, settings),
            ).status_code
            == 404
        )
        assert (
            client.delete(
                f"/api/v1/achievements/{pub_ach['id']}",
                headers=_auth_headers(other, settings),
            ).status_code
            == 404
        )

        # Document deletion protection: 409 DOCUMENT_IN_USE and attached_to tracking
        doc_meta = client.get(
            f"/api/v1/documents/{owner_doc_id}",
            headers=_auth_headers(owner, settings),
        )
        assert doc_meta.status_code == 200
        attached_types = {item["entity_type"] for item in doc_meta.json()["attached_to"]}
        assert attached_types == {"certificate", "achievement"}

        del_doc_blocked = client.delete(
            f"/api/v1/documents/{owner_doc_id}",
            headers=_auth_headers(owner, settings),
        )
        assert del_doc_blocked.status_code == 409
        assert del_doc_blocked.json()["error"]["code"] == "DOCUMENT_IN_USE"

        # Public profile returns ONLY public records and omits private Vault docs
        pub_profile = client.get("/api/v1/public/profiles/cert_owner")
        assert pub_profile.status_code == 200, pub_profile.text
        sections = pub_profile.json()["sections"]
        assert [c["name"] for c in sections["certificates"]] == ["AWS Solutions Architect"]
        assert "document" not in sections["certificates"][0]
        assert [a["title"] for a in sections["achievements"]] == ["National Hackathon Winner"]
        assert "documents" not in sections["achievements"][0]

        # Force delete document preserves certificate and achievement records
        del_doc_force = client.delete(
            f"/api/v1/documents/{owner_doc_id}?force=true",
            headers=_auth_headers(owner, settings),
        )
        assert del_doc_force.status_code == 204
        assert (
            client.get(
                f"/api/v1/certificates/{pub_cert['id']}",
                headers=_auth_headers(owner, settings),
            ).json()["document"]
            is None
        )
        assert (
            client.get(
                f"/api/v1/achievements/{pub_ach['id']}",
                headers=_auth_headers(owner, settings),
            ).json()["documents"]
            == []
        )

        # Cleanup delete certificate and achievement
        assert (
            client.delete(
                f"/api/v1/certificates/{priv_cert['id']}",
                headers=_auth_headers(owner, settings),
            ).status_code
            == 204
        )
        assert (
            client.delete(
                f"/api/v1/achievements/{priv_ach['id']}",
                headers=_auth_headers(owner, settings),
            ).status_code
            == 204
        )
