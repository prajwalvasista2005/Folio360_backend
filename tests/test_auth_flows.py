"""End-to-end Stage 3A PostgreSQL 17 integration tests (DML-only app role, mocked Resend)."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit
import uuid

from fastapi.testclient import TestClient
import jwt
import pytest
from sqlalchemy import Engine, select, text

from app.core.config import Settings
from app.core.security import hash_opaque_token
from app.main import create_app
from app.models.email_verification_token import EmailVerificationToken
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.services import email_service as email_service_module


def _build_test_app(
    test_database_url: str,
    *,
    rate_limit_enabled: bool = True,
    cors_origins: list[str] | None = None,
) -> tuple[Settings, object]:
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        DATABASE_URL=test_database_url,
        JWT_SECRET_KEY="integration-test-jwt-secret-key-at-least-32-chars",
        JWT_ISSUER="folio360",
        JWT_AUDIENCE="folio360-api",
        JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15,
        REFRESH_TOKEN_EXPIRE_DAYS=14,
        REFRESH_TOKEN_ABSOLUTE_EXPIRE_DAYS=30,
        FRONTEND_BASE_URL="http://localhost:5173",
        CORS_ORIGINS=cors_origins or ["http://localhost:5173"],
        RESEND_API_KEY="re_integration_mock_key_123456",
        EMAIL_FROM_ADDRESS="no-reply@folio360.local",
        RATE_LIMIT_ENABLED=rate_limit_enabled,
    )
    app = create_app(settings=settings)
    return settings, app


def _extract_token_from_sent_params(params: dict) -> str:
    text_body: str = params["text"]
    for line in text_body.splitlines():
        if "/verify-email?token=" in line:
            parsed = urlsplit(line.strip())
            return parse_qs(parsed.query)["token"][0]
    raise AssertionError("Verification token URL not found in Resend payload")


@pytest.fixture
def clean_auth_db(db_engine: Engine):
    """Ensure clean Stage 3A tables before and after each real-DB integration test."""
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))
    yield
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))


@pytest.mark.db
def test_register_verify_email_no_auto_login_and_me_flow(
    test_database_url: str,
    db_engine: Engine,
    clean_auth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_payloads: list[dict] = []

    def fake_send(params, options=None):
        sent_payloads.append(dict(params))
        return {"id": f"msg_{len(sent_payloads)}"}

    monkeypatch.setattr(email_service_module.resend.Emails, "send", fake_send)

    _settings, app = _build_test_app(test_database_url, rate_limit_enabled=False)

    with TestClient(app) as client:  # type: ignore[arg-type]
        # 1. Register normalizes email and creates unverified user
        reg_resp = client.post(
            "/api/v1/auth/register",
            json={
                "email": "  Alice.Student@Example.COM ",
                "password": "StrongPassword!2026",
            },
        )
        assert reg_resp.status_code == 201
        reg_data = reg_resp.json()
        assert reg_data["verification_email_sent"] is True
        assert reg_data["user"]["email"] == "alice.student@example.com"
        assert reg_data["user"]["is_email_verified"] is False
        assert reg_data["user"]["has_password"] is True
        assert "set-cookie" not in {k.lower() for k in reg_resp.headers}
        assert len(sent_payloads) == 1

        # 2. Duplicate registration returns 409 EMAIL_ALREADY_REGISTERED
        dup_resp = client.post(
            "/api/v1/auth/register",
            json={
                "email": "alice.student@example.com",
                "password": "AnotherStrongPassword!2026",
            },
        )
        assert dup_resp.status_code == 409
        assert dup_resp.json()["error"]["details"]["code"] == "EMAIL_ALREADY_REGISTERED"

        # 3. Unverified user cannot log in (after valid password check)
        unverified_login = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={
                "email": "alice.student@example.com",
                "password": "StrongPassword!2026",
            },
        )
        assert unverified_login.status_code == 403
        assert unverified_login.json()["error"]["details"]["code"] == "EMAIL_NOT_VERIFIED"

        # 4. Wrong password before verification still returns generic 401 INVALID_CREDENTIALS
        wrong_pw_login = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={
                "email": "alice.student@example.com",
                "password": "WrongPassword!2026",
            },
        )
        assert wrong_pw_login.status_code == 401
        assert wrong_pw_login.json()["error"]["details"]["code"] == "INVALID_CREDENTIALS"

        # 5. Extra redirect parameter on /verify-email rejected (422)
        raw_token = _extract_token_from_sent_params(sent_payloads[0])
        bad_verify = client.post(
            "/api/v1/auth/verify-email",
            json={"token": raw_token, "redirect_uri": "https://evil.test/login"},
        )
        assert bad_verify.status_code == 422

        # 6. Valid verification marks user verified WITHOUT auto-authenticating
        verify_resp = client.post("/api/v1/auth/verify-email", json={"token": raw_token})
        assert verify_resp.status_code == 200
        verify_data = verify_resp.json()
        assert verify_data == {
            "message": "Email verified successfully.",
            "email_verified": True,
        }
        assert "set-cookie" not in {k.lower() for k in verify_resp.headers}
        assert "access_token" not in verify_data
        assert "refresh_token" not in verify_data

        with db_engine.connect() as conn:
            session_count = conn.execute(text("SELECT COUNT(*) FROM refresh_sessions")).scalar_one()
            assert session_count == 0

        # 7. Token is strictly single-use
        reuse_verify = client.post("/api/v1/auth/verify-email", json={"token": raw_token})
        assert reuse_verify.status_code == 400
        assert reuse_verify.json()["error"]["details"]["code"] == "INVALID_VERIFICATION_TOKEN"

        # 8. Mobile login issues JSON tokens and zero cookies
        login_resp = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={
                "email": "alice.student@example.com",
                "password": "StrongPassword!2026",
            },
        )
        assert login_resp.status_code == 200
        assert "set-cookie" not in {k.lower() for k in login_resp.headers}
        login_data = login_resp.json()
        assert login_data["token_type"] == "bearer"
        assert login_data["expires_in"] == 900
        assert login_data["refresh_expires_in"] == 14 * 86400
        assert login_data["access_token"]
        assert login_data["refresh_token"]

        # 9. GET /api/v1/auth/me returns Stage 3A profile (no oauth_providers)
        me_resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {login_data['access_token']}"},
        )
        assert me_resp.status_code == 200
        me_data = me_resp.json()
        assert me_data["email"] == "alice.student@example.com"
        assert me_data["is_email_verified"] is True
        assert me_data["has_password"] is True
        assert "oauth_providers" not in me_data


@pytest.mark.db
def test_web_login_origin_enforcement_and_cookie_transport(
    test_database_url: str,
    db_engine: Engine,
    clean_auth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All 5 Rev10 §20.4 web login Origin tests + mobile header parity."""
    sent_payloads: list[dict] = []
    monkeypatch.setattr(
        email_service_module.resend.Emails,
        "send",
        lambda params, options=None: sent_payloads.append(dict(params)) or {"id": "m1"},
    )

    settings, app = _build_test_app(
        test_database_url,
        rate_limit_enabled=False,
        cors_origins=["http://localhost:5173"],
    )

    with TestClient(app) as client:  # type: ignore[arg-type]
        client.post(
            "/api/v1/auth/register",
            json={"email": "web.user@example.com", "password": "WebPassword!2026"},
        )
        tok = _extract_token_from_sent_params(sent_payloads[0])
        assert client.post("/api/v1/auth/verify-email", json={"token": tok}).status_code == 200

        # Test 2: Missing Origin on X-Client-Type: web -> 403 CSRF_ORIGIN_MISMATCH
        r_missing = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "web"},
            json={"email": "web.user@example.com", "password": "WebPassword!2026"},
        )
        assert r_missing.status_code == 403
        assert r_missing.json()["error"]["details"]["code"] == "CSRF_ORIGIN_MISMATCH"
        assert "set-cookie" not in {k.lower() for k in r_missing.headers}

        # Test 3: Untrusted / "null" / trailing-slash Origin -> 403 CSRF_ORIGIN_MISMATCH
        for bad_origin in ("https://evil.example", "null", "http://localhost:5173/", ""):
            r_bad = client.post(
                "/api/v1/auth/login",
                headers={"X-Client-Type": "web", "Origin": bad_origin},
                json={"email": "web.user@example.com", "password": "WebPassword!2026"},
            )
            assert r_bad.status_code == 403
            assert r_bad.json()["error"]["details"]["code"] == "CSRF_ORIGIN_MISMATCH"
            assert "set-cookie" not in {k.lower() for k in r_bad.headers}

        with db_engine.connect() as conn:
            assert conn.execute(text("SELECT COUNT(*) FROM refresh_sessions")).scalar_one() == 0

        # Test 5: Valid Origin + wrong password -> 401 INVALID_CREDENTIALS
        r_wrong = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
            json={"email": "web.user@example.com", "password": "WrongWebPassword!2026"},
        )
        assert r_wrong.status_code == 401
        assert r_wrong.json()["error"]["details"]["code"] == "INVALID_CREDENTIALS"

        # Test 1: Valid Origin + credentials -> 200 + HttpOnly refresh cookie + no refresh_token in JSON
        r_ok = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
            json={"email": "web.user@example.com", "password": "WebPassword!2026"},
        )
        assert r_ok.status_code == 200
        body_ok = r_ok.json()
        assert "refresh_token" not in body_ok
        assert body_ok["access_token"]
        set_cookie = r_ok.headers.get("set-cookie", "")
        assert f"{settings.REFRESH_COOKIE_NAME}=" in set_cookie
        assert "HttpOnly" in set_cookie
        assert "Path=/api/v1/auth" in set_cookie

        # Test 4: Mobile login requires no Origin and sets zero cookies
        r_mob = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "web.user@example.com", "password": "WebPassword!2026"},
        )
        assert r_mob.status_code == 200
        assert "set-cookie" not in {k.lower() for k in r_mob.headers}
        assert r_mob.json()["refresh_token"]


@pytest.mark.db
def test_resend_delivery_state_machine_and_concurrency(
    test_database_url: str,
    db_engine: Engine,
    clean_auth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All 8 Rev10 §20.4 Resend delivery failure, first-retry, cooldown, and concurrency tests."""
    send_behavior = {"fail": True, "calls": 0, "tokens": []}

    def fake_send(params, options=None):
        send_behavior["calls"] += 1
        send_behavior["tokens"].append(_extract_token_from_sent_params(params))
        if send_behavior["fail"]:
            raise RuntimeError("Simulated Resend network failure")
        return {"id": f"msg_{send_behavior['calls']}"}

    monkeypatch.setattr(email_service_module.resend.Emails, "send", fake_send)
    _settings, app = _build_test_app(test_database_url, rate_limit_enabled=False)

    with TestClient(app) as client:  # type: ignore[arg-type]
        # (1 & 8) Initial failure keeps user committed & allows immediate 0s first retry
        r_reg = client.post(
            "/api/v1/auth/register",
            json={"email": "retry.user@example.com", "password": "RetryPassword!2026"},
        )
        assert r_reg.status_code == 201
        assert r_reg.json()["verification_email_sent"] is False
        assert send_behavior["calls"] == 1

        # Duplicate register does NOT duplicate account
        assert (
            client.post(
                "/api/v1/auth/register",
                json={"email": "retry.user@example.com", "password": "RetryPassword!2026"},
            ).status_code
            == 409
        )

        # (2) First retry after initial failure runs immediately (0s wait) and here also fails -> 2 consecutive failures
        r_retry1 = client.post(
            "/api/v1/auth/resend-verification",
            json={"email": "retry.user@example.com"},
        )
        assert r_retry1.status_code == 202
        assert send_behavior["calls"] == 2

        # Retry immediately after 2nd failure is suppressed within 10s backoff
        r_suppressed = client.post(
            "/api/v1/auth/resend-verification",
            json={"email": "retry.user@example.com"},
        )
        assert r_suppressed.status_code == 202
        assert send_behavior["calls"] == 2

        # (3) Simulate >= 10s elapsed since latest failed attempt -> retry allowed and succeeds
        with db_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE email_verification_tokens "
                    "SET delivery_attempted_at = now() - interval '15 seconds' "
                    "WHERE delivery_status = 'failed'"
                )
            )
        send_behavior["fail"] = False
        r_retry2 = client.post(
            "/api/v1/auth/resend-verification",
            json={"email": "retry.user@example.com"},
        )
        assert r_retry2.status_code == 202
        assert send_behavior["calls"] == 3

        # (4) Successful 'sent' activates 60s cooldown
        r_cooldown = client.post(
            "/api/v1/auth/resend-verification",
            json={"email": "retry.user@example.com"},
        )
        assert r_cooldown.status_code == 202
        assert send_behavior["calls"] == 3

        # (5) Advance timestamps beyond 60s for 2 more sends (total 3 within hour), then 4th is suppressed
        for expected_calls in (4, 5):
            with db_engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE email_verification_tokens "
                        "SET delivery_attempted_at = delivery_attempted_at - interval '2 minutes', "
                        "created_at = created_at - interval '2 minutes'"
                    )
                )
            r_more = client.post(
                "/api/v1/auth/resend-verification",
                json={"email": "retry.user@example.com"},
            )
            assert r_more.status_code == 202
            assert send_behavior["calls"] == expected_calls

        with db_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE email_verification_tokens "
                    "SET delivery_attempted_at = delivery_attempted_at - interval '2 minutes', "
                    "created_at = created_at - interval '2 minutes' "
                    "WHERE delivery_status = 'sent' "
                    "AND id = (SELECT id FROM email_verification_tokens ORDER BY created_at DESC LIMIT 1)"
                )
            )
        r_cap = client.post(
            "/api/v1/auth/resend-verification",
            json={"email": "retry.user@example.com"},
        )
        assert r_cap.status_code == 202
        assert send_behavior["calls"] == 5

        # (6) Stale pending recovery (> 30s) on a second user
        send_behavior["fail"] = False
        client.post(
            "/api/v1/auth/register",
            json={"email": "stale.pending@example.com", "password": "RetryPassword!2026"},
        )
        assert send_behavior["calls"] == 6
        with db_engine.begin() as conn:
            stale_uid = conn.execute(
                text("SELECT id FROM users WHERE email = 'stale.pending@example.com'")
            ).scalar_one()
            conn.execute(
                text("DELETE FROM email_verification_tokens WHERE user_id = :uid"),
                {"uid": stale_uid},
            )
            # Fresh pending (< 30s) must be suppressed
            conn.execute(
                text(
                    "INSERT INTO email_verification_tokens "
                    "(user_id, token_hash, delivery_status, expires_at, created_at) "
                    "VALUES (:uid, repeat('c', 64), 'pending', now() + interval '1 hour', now())"
                ),
                {"uid": stale_uid},
            )
        client.post(
            "/api/v1/auth/resend-verification",
            json={"email": "stale.pending@example.com"},
        )
        assert send_behavior["calls"] == 6

        # Age pending token beyond 30s -> recovery succeeds
        with db_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE email_verification_tokens "
                    "SET created_at = now() - interval '45 seconds' "
                    "WHERE user_id = :uid AND delivery_status = 'pending'"
                ),
                {"uid": stale_uid},
            )
        client.post(
            "/api/v1/auth/resend-verification",
            json={"email": "stale.pending@example.com"},
        )
        assert send_behavior["calls"] == 7

        # (7) Two-thread concurrent resend serialized under users FOR UPDATE -> only 1 send executes
        client.post(
            "/api/v1/auth/register",
            json={"email": "race.resend@example.com", "password": "RetryPassword!2026"},
        )
        assert send_behavior["calls"] == 8
        with db_engine.begin() as conn:
            race_uid = conn.execute(
                text("SELECT id FROM users WHERE email = 'race.resend@example.com'")
            ).scalar_one()
            conn.execute(
                text(
                    "UPDATE email_verification_tokens "
                    "SET delivery_attempted_at = now() - interval '2 minutes', "
                    "created_at = now() - interval '2 minutes' "
                    "WHERE user_id = :uid"
                ),
                {"uid": race_uid},
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            futs = [
                pool.submit(
                    lambda: client.post(
                        "/api/v1/auth/resend-verification",
                        json={"email": "race.resend@example.com"},
                    ).status_code
                )
                for _ in range(2)
            ]
            assert [f.result(timeout=10) for f in futs] == [202, 202]
        assert send_behavior["calls"] == 9


@pytest.mark.db
def test_refresh_rotation_replay_family_isolation_concurrency_and_logout_all(
    test_database_url: str,
    db_engine: Engine,
    clean_auth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_payloads: list[dict] = []
    monkeypatch.setattr(
        email_service_module.resend.Emails,
        "send",
        lambda params, options=None: sent_payloads.append(dict(params)) or {"id": "m_rot"},
    )

    settings, app = _build_test_app(test_database_url, rate_limit_enabled=False)

    with TestClient(app) as client:  # type: ignore[arg-type]
        client.post(
            "/api/v1/auth/register",
            json={"email": "session.user@example.com", "password": "SessionPassword!2026"},
        )
        tok = _extract_token_from_sent_params(sent_payloads[0])
        client.post("/api/v1/auth/verify-email", json={"token": tok})

        # Create two independent families (Family A and Family B)
        fam_a_login = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "session.user@example.com", "password": "SessionPassword!2026"},
        ).json()
        fam_b_login = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "session.user@example.com", "password": "SessionPassword!2026"},
        ).json()

        # Rotate Family A once -> rt_a1 becomes rotated, rt_a2 is active
        rot_a2 = client.post(
            "/api/v1/auth/refresh",
            headers={"X-Client-Type": "mobile"},
            json={"refresh_token": fam_a_login["refresh_token"]},
        )
        assert rot_a2.status_code == 200
        rt_a2 = rot_a2.json()["refresh_token"]
        assert rt_a2 != fam_a_login["refresh_token"]

        # Replay already-rotated rt_a1 -> 401 REFRESH_TOKEN_REUSE_DETECTED + revokes Family A (rt_a2 fails too)
        replay = client.post(
            "/api/v1/auth/refresh",
            headers={"X-Client-Type": "mobile"},
            json={"refresh_token": fam_a_login["refresh_token"]},
        )
        assert replay.status_code == 401
        assert replay.json()["error"]["details"]["code"] == "REFRESH_TOKEN_REUSE_DETECTED"

        rt_a2_after_replay = client.post(
            "/api/v1/auth/refresh",
            headers={"X-Client-Type": "mobile"},
            json={"refresh_token": rt_a2},
        )
        assert rt_a2_after_replay.status_code == 401

        # Family B remains completely unaffected
        rot_b2 = client.post(
            "/api/v1/auth/refresh",
            headers={"X-Client-Type": "mobile"},
            json={"refresh_token": fam_b_login["refresh_token"]},
        )
        assert rot_b2.status_code == 200
        rt_b2 = rot_b2.json()["refresh_token"]

        # 30-day absolute family cap: expires_at clamped to family_expires_at
        with db_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE refresh_sessions "
                    "SET family_expires_at = now() + interval '2 days', "
                    "expires_at = now() + interval '2 days' "
                    "WHERE token_hash = :h"
                ),
                {"h": hash_opaque_token(rt_b2)},
            )
        rot_b3 = client.post(
            "/api/v1/auth/refresh",
            headers={"X-Client-Type": "mobile"},
            json={"refresh_token": rt_b2},
        )
        assert rot_b3.status_code == 200
        assert rot_b3.json()["refresh_expires_in"] <= 2 * 86400 + 5
        rt_b3 = rot_b3.json()["refresh_token"]

        # Client type mismatch rejected (401 INVALID_REFRESH_TOKEN)
        mismatch_resp = client.post(
            "/api/v1/auth/refresh",
            headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
            cookies={settings.REFRESH_COOKIE_NAME: rt_b3},
        )
        assert mismatch_resp.status_code == 401
        assert mismatch_resp.json()["error"]["details"]["code"] == "INVALID_REFRESH_TOKEN"

        # Two-thread concurrent refresh serialization via FOR UPDATE on rt_b3:
        # exactly one succeeds (200) and the second triggers replay detection (401)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futs = [
                pool.submit(
                    lambda: client.post(
                        "/api/v1/auth/refresh",
                        headers={"X-Client-Type": "mobile"},
                        json={"refresh_token": rt_b3},
                    )
                )
                for _ in range(2)
            ]
            responses = [f.result(timeout=10) for f in futs]
        statuses = sorted(r.status_code for r in responses)
        assert statuses == [200, 401]
        failed = next(r for r in responses if r.status_code == 401)
        assert failed.json()["error"]["details"]["code"] == "REFRESH_TOKEN_REUSE_DETECTED"

        # Web login -> logout current session -> cookie cleared & session revoked
        web_login = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
            json={"email": "session.user@example.com", "password": "SessionPassword!2026"},
        )
        assert web_login.status_code == 200
        web_access = web_login.json()["access_token"]
        web_cookie = web_login.cookies[settings.REFRESH_COOKIE_NAME]

        # Logout current web session
        logout_resp = client.post(
            "/api/v1/auth/logout",
            headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
            cookies={settings.REFRESH_COOKIE_NAME: web_cookie},
        )
        assert logout_resp.status_code == 200
        assert (
            client.post(
                "/api/v1/auth/refresh",
                headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
                cookies={settings.REFRESH_COOKIE_NAME: web_cookie},
            ).status_code
            == 401
        )

        # New session + logout-all immediately invalidates existing access JWT via auth_version
        mob_login = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "session.user@example.com", "password": "SessionPassword!2026"},
        ).json()
        assert (
            client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {mob_login['access_token']}"},
            ).status_code
            == 200
        )

        logout_all_resp = client.post(
            "/api/v1/auth/logout-all",
            headers={
                "Authorization": f"Bearer {mob_login['access_token']}",
                "X-Client-Type": "web",
                "Origin": "http://localhost:5173",
            },
        )
        assert logout_all_resp.status_code == 200
        assert f"{settings.REFRESH_COOKIE_NAME}=" in logout_all_resp.headers.get("set-cookie", "")

        # Existing access JWTs (same second!) are immediately invalid via auth_version increment
        for old_jwt in (web_access, mob_login["access_token"]):
            me_after = client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {old_jwt}"},
            )
            assert me_after.status_code == 401
            assert me_after.headers.get("www-authenticate") == "Bearer"
            assert me_after.json()["error"]["details"]["code"] == "INVALID_ACCESS_TOKEN"

        # Refresh session also revoked
        assert (
            client.post(
                "/api/v1/auth/refresh",
                headers={"X-Client-Type": "mobile"},
                json={"refresh_token": mob_login["refresh_token"]},
            ).status_code
            == 401
        )


@pytest.mark.db
def test_route_ip_rate_limiting_returns_429_with_retry_after(
    test_database_url: str,
    clean_auth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        email_service_module.resend.Emails,
        "send",
        lambda params, options=None: {"id": "rl_msg"},
    )
    _settings, app = _build_test_app(test_database_url, rate_limit_enabled=True)

    with TestClient(app) as client:  # type: ignore[arg-type]
        for idx in range(5):
            r = client.post(
                "/api/v1/auth/resend-verification",
                json={"email": f"nobody{idx}@example.com"},
            )
            assert r.status_code == 202

        limited = client.post(
            "/api/v1/auth/resend-verification",
            json={"email": "nobody99@example.com"},
        )
        assert limited.status_code == 429
        assert limited.json()["error"]["details"]["code"] == "RATE_LIMIT_EXCEEDED"
        assert int(limited.headers["Retry-After"]) >= 1


@pytest.mark.db
def test_cross_channel_refresh_token_replay_revokes_only_compromised_family(
    test_database_url: str,
    db_engine: Engine,
    clean_auth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_payloads: list[dict] = []
    monkeypatch.setattr(
        email_service_module.resend.Emails,
        "send",
        lambda params, options=None: sent_payloads.append(dict(params)) or {"id": "m_xchan"},
    )

    settings, app = _build_test_app(test_database_url, rate_limit_enabled=False)

    with TestClient(app) as client:  # type: ignore[arg-type]
        client.post(
            "/api/v1/auth/register",
            json={"email": "cross.channel@example.com", "password": "StrongPassword!2026"},
        )
        tok = _extract_token_from_sent_params(sent_payloads[0])
        assert client.post("/api/v1/auth/verify-email", json={"token": tok}).status_code == 200

        # Family A (mobile) and unrelated Family B (mobile)
        fam_a = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "cross.channel@example.com", "password": "StrongPassword!2026"},
        ).json()
        fam_b = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "cross.channel@example.com", "password": "StrongPassword!2026"},
        ).json()

        # Active mobile token sent via web channel is rejected as INVALID_REFRESH_TOKEN without revoking family
        active_mismatch = client.post(
            "/api/v1/auth/refresh",
            headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
            cookies={settings.REFRESH_COOKIE_NAME: fam_a["refresh_token"]},
        )
        assert active_mismatch.status_code == 401
        assert active_mismatch.json()["error"]["details"]["code"] == "INVALID_REFRESH_TOKEN"

        # Rotate Family A legitimately on mobile -> rt_a1 becomes rotated, rt_a2 is active
        rot_a2 = client.post(
            "/api/v1/auth/refresh",
            headers={"X-Client-Type": "mobile"},
            json={"refresh_token": fam_a["refresh_token"]},
        )
        assert rot_a2.status_code == 200
        rt_a2 = rot_a2.json()["refresh_token"]

        # Replay already-rotated mobile rt_a1 via web channel -> must trigger family-wide replay revocation!
        cross_replay = client.post(
            "/api/v1/auth/refresh",
            headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
            cookies={settings.REFRESH_COOKIE_NAME: fam_a["refresh_token"]},
        )
        assert cross_replay.status_code == 401
        assert cross_replay.json()["error"]["details"]["code"] == "REFRESH_TOKEN_REUSE_DETECTED"

        # Child token rt_a2 in Family A must now be revoked too
        child_after = client.post(
            "/api/v1/auth/refresh",
            headers={"X-Client-Type": "mobile"},
            json={"refresh_token": rt_a2},
        )
        assert child_after.status_code == 401
        assert child_after.json()["error"]["details"]["code"] == "INVALID_REFRESH_TOKEN"

        # Unrelated Family B must still rotate normally
        rot_b2 = client.post(
            "/api/v1/auth/refresh",
            headers={"X-Client-Type": "mobile"},
            json={"refresh_token": fam_b["refresh_token"]},
        )
        assert rot_b2.status_code == 200

    with db_engine.connect() as conn:
        child_reason = conn.execute(
            text("SELECT revoke_reason FROM refresh_sessions WHERE token_hash = :h"),
            {"h": hash_opaque_token(rt_a2)},
        ).scalar_one()
        assert child_reason == "reuse_detected"
