"""Integration tests for complete Settings flows (account deletion, export, audit log, email change, OAuth connections, public skills/CGPA)."""

from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
import threading
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import Engine, select, text

from app.core.config import Settings
from app.core.security import create_access_token, hash_opaque_token, hash_password
from app.db.session import build_sessionmaker
from app.main import create_app
from app.models.account import EmailChangeToken
from app.models.document import Document
from app.models.education import Education
from app.models.oauth import OAuthAccount
from app.models.profile import UserProfile
from app.models.refresh_session import RefreshSession
from app.models.skill import Skill
from app.models.user import User

pytestmark = pytest.mark.db


def _build_test_app(test_database_url: str, *, storage_dir: str) -> tuple[Settings, object]:
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL=test_database_url,
        JWT_SECRET_KEY="account-complete-jwt-secret-key-32chars",
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
def clean_account_db(db_engine: Engine):
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))
    yield
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))


def _create_user(
    db_engine: Engine,
    *,
    email: str,
    password: str | None = "StrongPassword!2026",
    verified: bool = True,
) -> User:
    session_factory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password(password) if password is not None else None,
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
    slug: str,
) -> UserProfile:
    session_factory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)
    profile = UserProfile(
        id=uuid.uuid4(),
        user_id=user_id,
        slug=slug,
        full_name=f"User {slug}",
        date_of_birth=date(2002, 5, 10),
        interests=["Systems"],
        profile_completed=True,
        profile_completed_at=now,
    )
    with session_factory() as session:
        session.add(profile)
        session.commit()
        session.refresh(profile)
    return profile


def _auth_headers(user: User, settings: Settings) -> dict[str, str]:
    token, _ = create_access_token(
        user_id=user.id,
        auth_version=user.auth_version,
        settings=settings,
    )
    return {"Authorization": f"Bearer {token}"}


def test_account_deletion_requires_verification_cleans_storage_and_cascades(
    db_engine: Engine,
    test_database_url: str,
    tmp_path: Path,
    clean_account_db,
) -> None:
    del clean_account_db
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    user_a = _create_user(db_engine, email="del.a@example.com")
    user_b = _create_user(db_engine, email="del.b@example.com")
    _create_profile(db_engine, user_id=user_a.id, slug="del_user_a")
    _create_profile(db_engine, user_id=user_b.id, slug="del_user_b")

    doc_id = uuid.uuid4()
    storage_key = f"trusted/{user_a.id}/{doc_id}"
    stored_file = tmp_path / storage_key
    stored_file.parent.mkdir(parents=True, exist_ok=True)
    stored_file.write_bytes(b"%PDF-1.4\ntest\n")

    session_factory = build_sessionmaker(db_engine)
    with session_factory() as session:
        session.add(
            Document(
                id=doc_id,
                user_id=user_a.id,
                title="Private Marksheet",
                original_filename="marksheet.pdf",
                category="marksheet",
                mime_type="application/pdf",
                size_bytes=14,
                sha256="b" * 64,
                storage_backend="local",
                storage_key=storage_key,
                processing_status="ready",
                storage_state="trusted",
            )
        )
        session.commit()

    headers_a = _auth_headers(user_a, settings)
    headers_b = _auth_headers(user_b, settings)

    with TestClient(app) as client:
        assert client.request("DELETE", "/api/v1/account", json={"confirm": "DELETE"}).status_code == 401

        # Wrong confirmation rejected
        bad_conf = client.request(
            "DELETE",
            "/api/v1/account",
            headers=headers_a,
            json={"confirm": "NOPE", "current_password": "StrongPassword!2026"},
        )
        assert bad_conf.status_code == 422

        # Wrong password rejected
        bad_pw = client.request(
            "DELETE",
            "/api/v1/account",
            headers=headers_a,
            json={"confirm": "DELETE", "current_password": "WrongPassword!2026"},
        )
        assert bad_pw.status_code == 401

        # Valid deletion succeeds
        res_del = client.request(
            "DELETE",
            "/api/v1/account",
            headers=headers_a,
            json={"confirm": "DELETE", "current_password": "StrongPassword!2026"},
        )
        assert res_del.status_code == 204
        assert not stored_file.exists()

        # Token is immediately invalid & User B untouched
        assert client.get("/api/v1/account", headers=headers_a).status_code == 401
        res_b = client.get("/api/v1/account", headers=headers_b)
        assert res_b.status_code == 200
        assert res_b.json()["email"] == "del.b@example.com"


def test_data_export_and_security_audit_log_isolation(
    db_engine: Engine,
    test_database_url: str,
    tmp_path: Path,
    clean_account_db,
) -> None:
    del clean_account_db
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    user_a = _create_user(db_engine, email="export.a@example.com")
    user_b = _create_user(db_engine, email="export.b@example.com")
    _create_profile(db_engine, user_id=user_a.id, slug="export_a")
    _create_profile(db_engine, user_id=user_b.id, slug="export_b")

    session_factory = build_sessionmaker(db_engine)
    with session_factory() as session:
        session.add(Skill(user_id=user_a.id, name="FastAPI", category="framework"))
        session.add(Skill(user_id=user_b.id, name="SecretUserBSkill", category="technical"))
        session.add(
            Document(
                id=uuid.uuid4(),
                user_id=user_a.id,
                title="A Transcript",
                original_filename="a.pdf",
                category="marksheet",
                mime_type="application/pdf",
                size_bytes=123,
                sha256="c" * 64,
                storage_backend="local",
                storage_key=f"trusted/{user_a.id}/{uuid.uuid4()}",
                processing_status="ready",
                storage_state="trusted",
            )
        )
        session.commit()

    headers_a = _auth_headers(user_a, settings)
    headers_b = _auth_headers(user_b, settings)

    with TestClient(app) as client:
        # Trigger real login event + failed login event
        assert (
            client.post(
                "/api/v1/auth/login",
                headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
                json={"email": "export.a@example.com", "password": "WrongPassword!2026"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/v1/auth/login",
                headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
                json={"email": "export.a@example.com", "password": "StrongPassword!2026"},
            ).status_code
            == 200
        )

        res_export = client.post("/api/v1/account/export", headers=headers_a)
        assert res_export.status_code == 200
        exported = res_export.json()
        assert exported["account"]["email"] == "export.a@example.com"
        assert "password_hash" not in str(exported)
        assert "storage_key" not in str(exported)
        assert [s["name"] for s in exported["skills"]] == ["FastAPI"]
        assert "SecretUserBSkill" not in str(exported)
        assert [d["title"] for d in exported["documents"]] == ["A Transcript"]

        res_log_a = client.get("/api/v1/account/security-log", headers=headers_a)
        assert res_log_a.status_code == 200
        actions_a = [ev["action"] for ev in res_log_a.json()["items"]]
        assert "data_exported" in actions_a
        assert "login_success" in actions_a
        assert "login_failed" in actions_a
        assert "password" not in str(res_log_a.json()).lower()

        res_log_b = client.get("/api/v1/account/security-log", headers=headers_b)
        assert res_log_b.status_code == 200
        assert res_log_b.json()["items"] == []


def test_email_change_flow_validation_verification_and_expiry(
    db_engine: Engine,
    test_database_url: str,
    tmp_path: Path,
    monkeypatch,
    clean_account_db,
) -> None:
    del clean_account_db
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    user_a = _create_user(db_engine, email="orig.a@example.com")
    _create_user(db_engine, email="taken@example.com")
    user_oauth = _create_user(db_engine, email="primary.oauth@example.com", password=None)
    session_factory = build_sessionmaker(db_engine)
    with session_factory() as session:
        session.add(
            OAuthAccount(
                id=uuid.uuid4(),
                user_id=user_oauth.id,
                provider="google",
                provider_user_id="google-oauth-taken-1",
                provider_email="oauth.linked@example.com",
                provider_email_verified=True,
            )
        )
        session.commit()

    captured_tokens: list[str] = []
    monkeypatch.setattr(
        "app.services.account_service.send_email_change_verification_email",
        lambda *, to_email, raw_token, settings: captured_tokens.append(raw_token),
    )

    headers_a = _auth_headers(user_a, settings)
    headers_oauth = _auth_headers(user_oauth, settings)
    with TestClient(app) as client:
        # Invalid email format
        assert (
            client.post(
                "/api/v1/account/email",
                headers=headers_a,
                json={"new_email": "not-an-email", "current_password": "StrongPassword!2026"},
            ).status_code
            == 422
        )

        # Unchanged email rejected without sending verification email
        res_same = client.post(
            "/api/v1/account/email",
            headers=headers_a,
            json={"new_email": "  ORIG.A@Example.com  ", "current_password": "StrongPassword!2026"},
        )
        assert res_same.status_code == 422
        assert res_same.json()["error"]["code"] == "SAME_EMAIL"
        assert captured_tokens == []

        # Duplicate account email rejected without sending verification email
        res_dup = client.post(
            "/api/v1/account/email",
            headers=headers_a,
            json={"new_email": "  TAKEN@Example.com  ", "current_password": "StrongPassword!2026"},
        )
        assert res_dup.status_code == 409
        assert res_dup.json()["error"]["code"] == "EMAIL_TAKEN"
        assert captured_tokens == []

        # Email linked to another user's OAuth account rejected without sending verification email
        res_oauth_dup = client.post(
            "/api/v1/account/email",
            headers=headers_a,
            json={"new_email": "oauth.linked@example.com", "current_password": "StrongPassword!2026"},
        )
        assert res_oauth_dup.status_code == 409
        assert res_oauth_dup.json()["error"]["code"] == "EMAIL_TAKEN"
        assert captured_tokens == []

        # Valid unused request creates pending token without changing email yet
        res_req = client.post(
            "/api/v1/account/email",
            headers=headers_a,
            json={"new_email": "  Updated.A@example.com  ", "current_password": "StrongPassword!2026"},
        )
        assert res_req.status_code == 200
        assert res_req.json()["pending_email"] == "updated.a@example.com"
        assert len(captured_tokens) == 1

        # Re-requesting the same pending email by same user does not generate a duplicate email
        res_pending_same = client.post(
            "/api/v1/account/email",
            headers=headers_a,
            json={"new_email": "updated.a@example.com", "current_password": "StrongPassword!2026"},
        )
        assert res_pending_same.status_code == 409
        assert res_pending_same.json()["error"]["code"] == "EMAIL_CHANGE_ALREADY_PENDING"
        assert len(captured_tokens) == 1

        # Another account attempting to claim the pending email is also rejected
        res_pending_other = client.post(
            "/api/v1/account/email",
            headers=headers_oauth,
            json={"new_email": "updated.a@example.com"},
        )
        assert res_pending_other.status_code == 409
        assert res_pending_other.json()["error"]["code"] == "EMAIL_TAKEN"
        assert len(captured_tokens) == 1

        res_acct_pending = client.get("/api/v1/account", headers=headers_a)
        assert res_acct_pending.status_code == 200
        assert res_acct_pending.json()["email"] == "orig.a@example.com"
        assert res_acct_pending.json()["pending_email"] == "updated.a@example.com"

        # Invalid token rejected and account email unchanged
        assert (
            client.post(
                "/api/v1/account/email/confirm",
                json={"token": "invalid-token"},
            ).status_code
            == 400
        )
        assert client.get("/api/v1/account", headers=headers_a).json()["email"] == "orig.a@example.com"

        # Confirm with valid token
        res_confirm = client.post(
            "/api/v1/account/email/confirm",
            json={"token": captured_tokens[0]},
        )
        assert res_confirm.status_code == 200
        assert res_confirm.json()["email"] == "updated.a@example.com"
        assert res_confirm.json()["pending_email"] is None

        # Reusing same token fails
        assert (
            client.post(
                "/api/v1/account/email/confirm",
                json={"token": captured_tokens[0]},
            ).status_code
            == 400
        )

    # Expired token fails and leaves email unchanged
    expired_raw = "expired-email-change-token-value"
    with session_factory() as session:
        session.add(
            EmailChangeToken(
                id=uuid.uuid4(),
                user_id=user_a.id,
                new_email="never@example.com",
                token_hash=hash_opaque_token(expired_raw),
                expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
            )
        )
        session.commit()

    with TestClient(app) as client:
        assert (
            client.post(
                "/api/v1/account/email/confirm",
                json={"token": expired_raw},
            ).status_code
            == 400
        )
        assert client.get("/api/v1/account", headers=headers_a).json()["email"] == "updated.a@example.com"


def test_email_change_concurrent_claims_race_safety(
    db_engine: Engine,
    test_database_url: str,
    tmp_path: Path,
    monkeypatch,
    clean_account_db,
) -> None:
    del clean_account_db
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    user_1 = _create_user(db_engine, email="racer1@example.com")
    user_2 = _create_user(db_engine, email="racer2@example.com")

    sent_recipients: list[str] = []
    send_lock = threading.Lock()

    def _capture_email(*, to_email: str, raw_token: str, settings: Settings) -> None:
        del raw_token, settings
        with send_lock:
            sent_recipients.append(to_email)

    monkeypatch.setattr(
        "app.services.account_service.send_email_change_verification_email",
        _capture_email,
    )

    barrier = threading.Barrier(2)

    def _submit(user: User) -> int:
        headers = _auth_headers(user, settings)
        with TestClient(app) as client:
            barrier.wait(timeout=5)
            res = client.post(
                "/api/v1/account/email",
                headers=headers,
                json={"new_email": "contested@example.com", "current_password": "StrongPassword!2026"},
            )
            return res.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(_submit, user_1)
        f2 = pool.submit(_submit, user_2)
        statuses = sorted([f1.result(timeout=15), f2.result(timeout=15)])

    assert statuses == [200, 409]
    assert sent_recipients == ["contested@example.com"]

    session_factory = build_sessionmaker(db_engine)
    with session_factory() as session:
        active_claims = session.execute(
            select(EmailChangeToken).where(
                EmailChangeToken.new_email == "contested@example.com",
                EmailChangeToken.consumed_at.is_(None),
                EmailChangeToken.revoked_at.is_(None),
            )
        ).scalars().all()
        assert len(active_claims) == 1


def test_oauth_connections_listing_disconnect_and_lockout_guard(
    db_engine: Engine,
    test_database_url: str,
    tmp_path: Path,
    clean_account_db,
) -> None:
    del clean_account_db
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    oauth_only_user = _create_user(db_engine, email="oauth.only@example.com", password=None)
    pw_user = _create_user(db_engine, email="pw.linked@example.com", password="StrongPassword!2026")

    session_factory = build_sessionmaker(db_engine)
    with session_factory() as session:
        session.add_all(
            [
                OAuthAccount(
                    id=uuid.uuid4(),
                    user_id=oauth_only_user.id,
                    provider="google",
                    provider_user_id="google-sub-1",
                    provider_email="oauth.only@example.com",
                    provider_email_verified=True,
                ),
                OAuthAccount(
                    id=uuid.uuid4(),
                    user_id=pw_user.id,
                    provider="github",
                    provider_user_id="gh-id-2",
                    provider_email="pw.linked@example.com",
                    provider_email_verified=True,
                ),
            ]
        )
        session.commit()

    with TestClient(app) as client:
        # OAuth-only user with 1 provider cannot disconnect last auth method
        headers_oauth = _auth_headers(oauth_only_user, settings)
        res_list = client.get("/api/v1/account/connections", headers=headers_oauth)
        assert res_list.status_code == 200
        assert [c["provider"] for c in res_list.json()["items"]] == ["google"]

        res_lockout = client.delete("/api/v1/account/connections/google", headers=headers_oauth)
        assert res_lockout.status_code == 400

        # Password-enabled user CAN safely disconnect linked OAuth provider
        headers_pw = _auth_headers(pw_user, settings)
        res_ok = client.delete("/api/v1/account/connections/github", headers=headers_pw)
        assert res_ok.status_code == 204
        assert client.get("/api/v1/account/connections", headers=headers_pw).json()["items"] == []


def test_public_profile_skills_and_academics_cgpa_visibility(
    db_engine: Engine,
    test_database_url: str,
    tmp_path: Path,
    clean_account_db,
) -> None:
    del clean_account_db
    settings, app = _build_test_app(test_database_url, storage_dir=str(tmp_path))
    user = _create_user(db_engine, email="public.vis@example.com")
    _create_profile(db_engine, user_id=user.id, slug="pub_vis_user")

    session_factory = build_sessionmaker(db_engine)
    with session_factory() as session:
        session.add(Skill(user_id=user.id, name="TypeScript", category="language", proficiency="Advanced"))
        session.add(
            Education(
                id=uuid.uuid4(),
                user_id=user.id,
                institution="RVCE",
                degree="B.E.",
                result_type="cgpa",
                result_value="8.91",
                result_source="manual",
                show_result_publicly=True,
                visibility="public",
            )
        )
        session.add(
            Education(
                id=uuid.uuid4(),
                user_id=user.id,
                institution="Private School",
                degree="Private Degree",
                result_type="cgpa",
                result_value="9.99",
                result_source="manual",
                show_result_publicly=True,
                visibility="private",
            )
        )
        session.commit()

    headers = _auth_headers(user, settings)
    with TestClient(app) as client:
        # Default: skills=True, academics_cgpa=False
        pub1 = client.get("/api/v1/public/profiles/pub_vis_user")
        assert pub1.status_code == 200
        sec1 = pub1.json()["sections"]
        assert [s["name"] for s in sec1["skills"]] == ["TypeScript"]
        assert sec1["academics"] is None
        assert sec1["education"][0]["result"] is None
        assert all(e["institution"] != "Private School" for e in sec1["education"])

        # Enable academics_cgpa and disable skills
        patch_res = client.patch(
            "/api/v1/profile/me/visibility",
            headers=headers,
            json={"public_sections": {"skills": False, "academics_cgpa": True}},
        )
        assert patch_res.status_code == 200

        pub2 = client.get("/api/v1/public/profiles/pub_vis_user")
        assert pub2.status_code == 200
        sec2 = pub2.json()["sections"]
        assert sec2["skills"] == []
        assert sec2["academics"] == {"cgpa": 8.91}
        assert sec2["education"][0]["result"] == "8.91"
