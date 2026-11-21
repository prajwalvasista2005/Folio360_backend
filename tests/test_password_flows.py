"""End-to-end Stage 3B PostgreSQL 17 integration and deterministic concurrency tests."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import threading
import time
from urllib.parse import parse_qs, urlsplit
import uuid

from fastapi.testclient import TestClient
import jwt
import pytest
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import AppException
from app.core.security import create_access_token, hash_opaque_token, verify_password
from app.db.session import build_sessionmaker
from app.main import create_app
from app.models.user import User
from app.services import auth_service
from app.services import email_service as email_service_module


def _build_test_app(
    test_database_url: str,
    *,
    rate_limit_enabled: bool = True,
    cors_origins: list[str] | None = None,
    password_reset_expire_minutes: int = 30,
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
        PASSWORD_RESET_EXPIRE_MINUTES=password_reset_expire_minutes,
        RATE_LIMIT_ENABLED=rate_limit_enabled,
    )
    app = create_app(settings=settings)
    return settings, app


def _extract_token_from_email_params(params: dict, route_path: str) -> str:
    text_body: str = params["text"]
    needle = f"{route_path}?token="
    for line in text_body.splitlines():
        if needle in line:
            parsed = urlsplit(line.split()[-1].strip())
            return parse_qs(parsed.query)["token"][0]
    raise AssertionError(f"Token URL for {route_path} not found in email payload")


def _register_and_verify_user(
    client: TestClient,
    sent_payloads: list[dict],
    *,
    email: str,
    password: str = "StrongPassword!2026",
) -> uuid.UUID:
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password},
    )
    assert reg_resp.status_code == 201
    tok = _extract_token_from_email_params(sent_payloads[-1], "/verify-email")
    verify_resp = client.post("/api/v1/auth/verify-email", json={"token": tok})
    assert verify_resp.status_code == 200
    return uuid.UUID(reg_resp.json()["user"]["id"])


def _wait_for_pg_lock_wait(
    db_engine: Engine,
    *,
    exclude_pid: int | None = None,
    timeout: float = 5.0,
) -> None:
    """Wait until another PostgreSQL backend (excluding winner PID) blocks on a row Lock."""
    deadline = time.monotonic() + timeout
    sql = (
        "SELECT COUNT(*) FROM pg_stat_activity "
        "WHERE datname = current_database() "
        "AND usename = current_user "
        "AND wait_event_type = 'Lock'"
    )
    params: dict[str, object] = {}
    if exclude_pid is not None:
        sql += " AND pid <> :exclude_pid"
        params["exclude_pid"] = exclude_pid

    while time.monotonic() < deadline:
        with db_engine.connect() as obs_conn:
            wait_count = obs_conn.execute(text(sql), params).scalar_one()
        if wait_count >= 1:
            return
        time.sleep(0.02)
    raise AssertionError("Timed out waiting for worker session to block on PostgreSQL row lock")


@pytest.fixture
def clean_auth_db(db_engine: Engine):
    """Ensure clean auth tables before and after each real-DB test."""
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))
    yield
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM users"))


@pytest.mark.db
def test_forgot_password_eligibility_tx_isolation_requested_ip_and_no_leakage(
    test_database_url: str,
    db_engine: Engine,
    clean_auth_db: None,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    Verify /forgot-password enumeration safety, eligibility gates, SHA-256-only storage,
    30m expiry, IPv4/IPv6/NULL requested_ip persistence, proxy-header isolation,
    FOR UPDATE NOWAIT lock release before Resend HTTP, and zero secret/IP log leakage.
    """
    caplog.set_level("INFO")
    sent_payloads: list[dict] = []
    db_states_during_send: list[dict] = []
    orig_send = auth_service.send_password_reset_email

    def inspected_send_password_reset_email(*, to_email: str, raw_token: str, settings: Settings):
        # Independent connection proves BOTH:
        #   1. pending row was committed before Resend HTTP started
        #   2. FOR UPDATE NOWAIT succeeds on users row (lock already released!)
        with db_engine.connect() as obs_conn:
            with obs_conn.begin():
                row = obs_conn.execute(
                    text(
                        "SELECT user_id, delivery_status, delivery_attempted_at, token_hash, requested_ip "
                        "FROM password_reset_tokens WHERE token_hash = :th"
                    ),
                    {"th": hash_opaque_token(raw_token)},
                ).mappings().one()
                locked_uid = obs_conn.execute(
                    text("SELECT id FROM users WHERE id = :uid FOR UPDATE NOWAIT"),
                    {"uid": row["user_id"]},
                ).scalar_one()
                assert locked_uid == row["user_id"]
                db_states_during_send.append(dict(row))
        return orig_send(to_email=to_email, raw_token=raw_token, settings=settings)

    monkeypatch.setattr(
        auth_service, "send_password_reset_email", inspected_send_password_reset_email
    )
    monkeypatch.setattr(
        email_service_module.resend.Emails,
        "send",
        lambda params, options=None: sent_payloads.append(dict(params)) or {"id": "re_fp_01"},
    )

    settings, app = _build_test_app(
        test_database_url, rate_limit_enabled=False, password_reset_expire_minutes=30
    )

    with TestClient(app) as client:  # type: ignore[arg-type]
        # Eligible users for IPv4, IPv6, and NULL requested_ip cases
        uid_ipv4 = _register_and_verify_user(
            client, sent_payloads, email="fp.ipv4@example.com"
        )
        uid_ipv6 = _register_and_verify_user(
            client, sent_payloads, email="fp.ipv6@example.com"
        )
        uid_null = _register_and_verify_user(
            client, sent_payloads, email="fp.null@example.com"
        )

        # Unverified, inactive, and OAuth-only accounts
        r_unverified = client.post(
            "/api/v1/auth/register",
            json={"email": "fp.unverified@example.com", "password": "StrongPassword!2026"},
        )
        assert r_unverified.status_code == 201
        uid_unverified = uuid.UUID(r_unverified.json()["user"]["id"])

        uid_inactive = _register_and_verify_user(
            client, sent_payloads, email="fp.inactive@example.com"
        )
        uid_oauth = _register_and_verify_user(
            client, sent_payloads, email="fp.oauth@example.com"
        )
        with db_engine.begin() as conn:
            conn.execute(
                text("UPDATE users SET is_active = false WHERE id = :uid"),
                {"uid": uid_inactive},
            )
            conn.execute(
                text("UPDATE users SET password_hash = NULL WHERE id = :uid"),
                {"uid": uid_oauth},
            )

        sent_payloads.clear()

        # Ineligible / nonexistent accounts return identical generic 202 Accepted
        expected_bodies = set()
        for email in (
            "nobody@example.com",
            "fp.unverified@example.com",
            "fp.inactive@example.com",
            "fp.oauth@example.com",
        ):
            resp = client.post("/api/v1/auth/forgot-password", json={"email": email})
            assert resp.status_code == 202
            expected_bodies.add(resp.json()["message"])
            assert len(sent_payloads) == 0
        assert len(expected_bodies) == 1

        # 1. Default non-IP TestClient host ("testclient") persists NULL requested_ip
        r_null_fallback = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "fp.null@example.com"},
        )
        assert r_null_fallback.status_code == 202
        with db_engine.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT requested_ip FROM password_reset_tokens WHERE user_id = :u"),
                    {"u": uid_null},
                ).scalar_one()
                is None
            )

        # Direct service call with requested_ip=None persists NULL requested_ip
        with db_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE password_reset_tokens "
                    "SET delivery_attempted_at = now() - interval '5 minutes', "
                    "created_at = created_at - interval '5 minutes' "
                    "WHERE user_id = :u"
                ),
                {"u": uid_null},
            )
        session_maker = build_sessionmaker(db_engine)
        with session_maker() as direct_db:
            assert (
                auth_service.request_password_reset(
                    direct_db,
                    email="fp.null@example.com",
                    requested_ip=None,
                    settings=settings,
                )
                is True
            )
        with db_engine.connect() as conn:
            null_ips = conn.execute(
                text("SELECT requested_ip FROM password_reset_tokens WHERE user_id = :u"),
                {"u": uid_null},
            ).scalars().all()
            assert null_ips == [None, None]

    # 2. IPv4 client ignores spoofed X-Forwarded-For and persists exact ASGI client IP
    before_call = datetime.now(timezone.utc)
    with TestClient(app, client=("203.0.113.42", 50000)) as ipv4_client:  # type: ignore[arg-type]
        ok_ipv4 = ipv4_client.post(
            "/api/v1/auth/forgot-password",
            headers={"X-Forwarded-For": "198.51.100.99, 10.0.0.1"},
            json={"email": "  FP.IPV4@Example.COM "},
        )
    after_call = datetime.now(timezone.utc)
    assert ok_ipv4.status_code == 202
    assert ok_ipv4.json()["message"] in expected_bodies

    raw_ipv4_tok = _extract_token_from_email_params(sent_payloads[-1], "/reset-password")
    assert (
        f"http://localhost:5173/reset-password?token={raw_ipv4_tok}"
        in sent_payloads[-1]["text"]
    )
    assert db_states_during_send[-1]["delivery_status"] == "pending"
    assert db_states_during_send[-1]["delivery_attempted_at"] is None
    assert db_states_during_send[-1]["requested_ip"] == "203.0.113.42"

    # 3. IPv6 client canonicalizes and persists exact canonical IPv6
    with TestClient(app, client=("2001:0db8:0000:0000::1", 50000)) as ipv6_client:  # type: ignore[arg-type]
        ok_ipv6 = ipv6_client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "fp.ipv6@example.com"},
        )
    assert ok_ipv6.status_code == 202
    raw_ipv6_tok = _extract_token_from_email_params(sent_payloads[-1], "/reset-password")

    with db_engine.connect() as conn:
        ipv4_row = conn.execute(
            text("SELECT * FROM password_reset_tokens WHERE user_id = :u"),
            {"u": uid_ipv4},
        ).mappings().one()
        assert ipv4_row["token_hash"] == hash_opaque_token(raw_ipv4_tok)
        assert ipv4_row["token_hash"] != raw_ipv4_tok
        assert ipv4_row["requested_ip"] == "203.0.113.42"
        assert ipv4_row["delivery_status"] == "sent"
        assert ipv4_row["delivery_attempted_at"] is not None
        assert ipv4_row["consumed_at"] is None
        assert ipv4_row["revoked_at"] is None
        assert (before_call + timedelta(minutes=29, seconds=50)) <= ipv4_row["expires_at"]
        assert ipv4_row["expires_at"] <= (after_call + timedelta(minutes=30, seconds=10))

        ipv6_row = conn.execute(
            text("SELECT * FROM password_reset_tokens WHERE user_id = :u"),
            {"u": uid_ipv6},
        ).mappings().one()
        assert ipv6_row["token_hash"] == hash_opaque_token(raw_ipv6_tok)
        assert ipv6_row["requested_ip"] == "2001:db8::1"
        assert ipv6_row["delivery_status"] == "sent"

        for excluded_uid in (uid_unverified, uid_inactive, uid_oauth):
            cnt = conn.execute(
                text("SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = :u"),
                {"u": excluded_uid},
            ).scalar_one()
            assert cnt == 0

    # 4. Verify rate limiting continues bucketing strictly on resolved ASGI IP (ignores spoofed XFF)
    _, app_rl = _build_test_app(test_database_url, rate_limit_enabled=True)
    with TestClient(app_rl, client=("203.0.113.50", 50000)) as rl_client_a:  # type: ignore[arg-type]
        for idx in range(5):
            r = rl_client_a.post(
                "/api/v1/auth/forgot-password",
                headers={"X-Forwarded-For": f"198.51.100.{idx + 1}"},
                json={"email": f"miss{idx}@example.com"},
            )
            assert r.status_code == 202
        r_blocked = rl_client_a.post(
            "/api/v1/auth/forgot-password",
            headers={"X-Forwarded-For": "198.51.100.250"},
            json={"email": "miss5@example.com"},
        )
        assert r_blocked.status_code == 429
    with TestClient(app_rl, client=("203.0.113.51", 50000)) as rl_client_b:  # type: ignore[arg-type]
        assert (
            rl_client_b.post(
                "/api/v1/auth/forgot-password", json={"email": "miss6@example.com"}
            ).status_code
            == 202
        )

    joined_logs = "\n".join(rec.getMessage() for rec in caplog.records)
    assert raw_ipv4_tok not in joined_logs
    assert raw_ipv6_tok not in joined_logs
    assert "203.0.113.42" not in joined_logs
    assert "2001:db8::1" not in joined_logs
    assert "re_integration_mock_key_123456" not in joined_logs


@pytest.mark.db
def test_forgot_password_resend_4state_delivery_stale_pending_and_tx1_contention(
    test_database_url: str,
    db_engine: Engine,
    clean_auth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Verify Rev10 §11.2 4-state Resend delivery machine on /forgot-password:
      1. Consecutive failures allow immediate 1st retry, backoff after 2 failures, reset on success.
      2. Cooldown blocks repeat sends within EMAIL_COOLDOWN_SECONDS.
      3. Rolling hour cap (EMAIL_MAX_PER_HOUR) caps total sends and revokes prior active tokens.
      4. In-flight pending blocks post-Tx1 overlapping request.
      5. Stale pending (>30s) recovers cleanly and revokes stale token.
      6. Concurrent Tx 1 users FOR UPDATE contention deterministically serializes & respects state machine.
    """
    sent_payloads: list[dict] = []
    send_results: list[bool] = []
    in_send = threading.Event()
    release_send = threading.Event()
    gate_first_send = False

    def fake_resend_send(params, options=None):
        if gate_first_send:
            in_send.set()
            assert release_send.wait(timeout=5)
        should_succeed = send_results.pop(0) if send_results else True
        if not should_succeed:
            raise RuntimeError("transient provider outage")
        sent_payloads.append(dict(params))
        return {"id": f"re_fp_{len(sent_payloads)}"}

    monkeypatch.setattr(email_service_module.resend.Emails, "send", fake_resend_send)
    _, app = _build_test_app(test_database_url, rate_limit_enabled=False)

    with TestClient(app) as client:  # type: ignore[arg-type]
        uid = _register_and_verify_user(client, sent_payloads, email="fp.sm@example.com")
        sent_payloads.clear()

        # 1. Two consecutive failures: 1st fail -> 2nd immediate fail -> 3rd blocked by backoff
        send_results.extend([False, False, True])
        for _ in range(3):
            assert (
                client.post(
                    "/api/v1/auth/forgot-password", json={"email": "fp.sm@example.com"}
                ).status_code
                == 202
            )
        assert send_results == [True]

        with db_engine.connect() as conn:
            statuses = conn.execute(
                text(
                    "SELECT delivery_status, revoked_at FROM password_reset_tokens "
                    "WHERE user_id = :u ORDER BY created_at ASC"
                ),
                {"u": uid},
            ).all()
            assert len(statuses) == 2
            assert statuses[0][0] == "failed" and statuses[0][1] is not None
            assert statuses[1][0] == "failed" and statuses[1][1] is None

        # Backdate failure past backoff -> next send succeeds & resets failure sequence
        with db_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE password_reset_tokens SET delivery_attempted_at = now() - interval '60 seconds' "
                    "WHERE user_id = :u"
                ),
                {"u": uid},
            )
        assert (
            client.post("/api/v1/auth/forgot-password", json={"email": "fp.sm@example.com"}).status_code
            == 202
        )
        assert len(sent_payloads) == 1

        # 2. Cooldown blocks immediate retry
        assert (
            client.post("/api/v1/auth/forgot-password", json={"email": "fp.sm@example.com"}).status_code
            == 202
        )
        assert len(sent_payloads) == 1

        # 3. Clear cooldown twice more to hit rolling hour cap (EMAIL_MAX_PER_HOUR = 3)
        for _ in range(2):
            with db_engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE password_reset_tokens "
                        "SET delivery_attempted_at = delivery_attempted_at - interval '2 minutes', "
                        "created_at = created_at - interval '2 minutes' "
                        "WHERE user_id = :u"
                    ),
                    {"u": uid},
                )
            assert (
                client.post(
                    "/api/v1/auth/forgot-password", json={"email": "fp.sm@example.com"}
                ).status_code
                == 202
            )
        assert len(sent_payloads) == 3

        # Even past 60s cooldown, 4th send in same hour is blocked
        with db_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE password_reset_tokens "
                    "SET delivery_attempted_at = delivery_attempted_at - interval '2 minutes' "
                    "WHERE user_id = :u"
                ),
                {"u": uid},
            )
        assert (
            client.post("/api/v1/auth/forgot-password", json={"email": "fp.sm@example.com"}).status_code
            == 202
        )
        assert len(sent_payloads) == 3

        # 4. In-flight pending guard blocks overlapping call after Tx 1 commit
        with db_engine.begin() as conn:
            conn.execute(
                text("DELETE FROM password_reset_tokens WHERE user_id = :u"),
                {"u": uid},
            )
        gate_first_send = True
        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(
                lambda: client.post(
                    "/api/v1/auth/forgot-password", json={"email": "fp.sm@example.com"}
                )
            )
            assert in_send.wait(timeout=5)
            f2 = pool.submit(
                lambda: client.post(
                    "/api/v1/auth/forgot-password", json={"email": "fp.sm@example.com"}
                )
            )
            r2 = f2.result(timeout=5)
            assert r2.status_code == 202
            gate_first_send = False
            release_send.set()
            r1 = f1.result(timeout=5)
            assert r1.status_code == 202
        assert len(sent_payloads) == 4  # only 1 additional email sent

        # 5. Stale pending (>30s) recovers, revokes stale token, and replacement succeeds on reset
        with db_engine.begin() as conn:
            conn.execute(
                text("DELETE FROM password_reset_tokens WHERE user_id = :u"),
                {"u": uid},
            )
            stale_raw_tok = "stale-pending-reset-token-31s"
            conn.execute(
                text(
                    "INSERT INTO password_reset_tokens "
                    "(user_id, token_hash, delivery_status, delivery_attempted_at, "
                    "expires_at, created_at, updated_at) "
                    "VALUES (:u, :th, 'pending', NULL, now() + interval '30 minutes', "
                    "now() - interval '31 seconds', now() - interval '31 seconds')"
                ),
                {"u": uid, "th": hash_opaque_token(stale_raw_tok)},
            )

        r_recover = client.post(
            "/api/v1/auth/forgot-password", json={"email": "fp.sm@example.com"}
        )
        assert r_recover.status_code == 202
        assert len(sent_payloads) == 5
        replacement_tok = _extract_token_from_email_params(sent_payloads[-1], "/reset-password")

        with db_engine.connect() as conn:
            stale_db = conn.execute(
                text(
                    "SELECT delivery_status, consumed_at, revoked_at "
                    "FROM password_reset_tokens WHERE token_hash = :th"
                ),
                {"th": hash_opaque_token(stale_raw_tok)},
            ).mappings().one()
            assert stale_db["delivery_status"] == "pending"
            assert stale_db["consumed_at"] is None
            assert stale_db["revoked_at"] is not None

            fresh_db = conn.execute(
                text(
                    "SELECT delivery_status, delivery_attempted_at, revoked_at "
                    "FROM password_reset_tokens WHERE token_hash = :th"
                ),
                {"th": hash_opaque_token(replacement_tok)},
            ).mappings().one()
            assert fresh_db["delivery_status"] == "sent"
            assert fresh_db["delivery_attempted_at"] is not None
            assert fresh_db["revoked_at"] is None

        # Old stale token cannot reset password; replacement token succeeds
        r_use_stale = client.post(
            "/api/v1/auth/reset-password",
            json={"token": stale_raw_tok, "new_password": "ShouldNotWork!2026"},
        )
        assert r_use_stale.status_code == 400
        assert r_use_stale.json()["error"]["details"]["code"] == "INVALID_RESET_TOKEN"

        r_use_fresh = client.post(
            "/api/v1/auth/reset-password",
            json={"token": replacement_tok, "new_password": "RecoveredReset!2026"},
        )
        assert r_use_fresh.status_code == 200

        # 6. Concurrent /forgot-password Tx 1 contention (two requests race on users FOR UPDATE lock)
        with db_engine.begin() as conn:
            conn.execute(
                text("DELETE FROM password_reset_tokens WHERE user_id = :u"),
                {"u": uid},
            )
        sent_before_tx1_race = len(sent_payloads)
        orig_fpr = auth_service.request_password_reset
        claim_lock = threading.Lock()
        first_claimed = False
        tx1_at_commit = threading.Event()
        release_tx1 = threading.Event()
        winner_pid_box: list[int] = []

        def wrapped_fpr(db: Session, *args, **kwargs):
            nonlocal first_claimed
            pause_this_call = False
            with claim_lock:
                if not first_claimed:
                    first_claimed = True
                    pause_this_call = True
            if not pause_this_call:
                return orig_fpr(db, *args, **kwargs)

            orig_commit = db.commit
            commit_count = 0

            def pause_tx1_commit():
                nonlocal commit_count
                commit_count += 1
                if commit_count == 1:
                    winner_pid_box.append(
                        db.execute(text("SELECT pg_backend_pid()")).scalar_one()
                    )
                    tx1_at_commit.set()
                    assert release_tx1.wait(timeout=8), "Coordinator never released Tx 1 commit"
                return orig_commit()

            db.commit = pause_tx1_commit  # type: ignore[method-assign]
            try:
                return orig_fpr(db, *args, **kwargs)
            finally:
                db.commit = orig_commit  # type: ignore[method-assign]

        with monkeypatch.context() as mp:
            mp.setattr(auth_service, "request_password_reset", wrapped_fpr)
            try:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    f_req1 = pool.submit(
                        lambda: client.post(
                            "/api/v1/auth/forgot-password", json={"email": "fp.sm@example.com"}
                        )
                    )
                    assert tx1_at_commit.wait(timeout=8), "Req 1 never reached Tx 1 commit"

                    # Launch Req 2 while Req 1 STILL holds users FOR UPDATE inside Tx 1!
                    f_req2 = pool.submit(
                        lambda: client.post(
                            "/api/v1/auth/forgot-password", json={"email": "fp.sm@example.com"}
                        )
                    )
                    _wait_for_pg_lock_wait(
                        db_engine, exclude_pid=winner_pid_box[0], timeout=8.0
                    )

                    release_tx1.set()
                    res1 = f_req1.result(timeout=10)
                    res2 = f_req2.result(timeout=10)
            finally:
                release_tx1.set()

        assert res1.status_code == 202
        assert res2.status_code == 202
        assert len(sent_payloads) == sent_before_tx1_race + 1
        with db_engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT delivery_status, revoked_at FROM password_reset_tokens "
                    "WHERE user_id = :u"
                ),
                {"u": uid},
            ).mappings().all()
            assert len(rows) == 1
            assert rows[0]["delivery_status"] == "sent"
            assert rows[0]["revoked_at"] is None


@pytest.mark.db
def test_reset_password_validation_revocation_and_security_edges(
    test_database_url: str,
    db_engine: Engine,
    clean_auth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Verify /reset-password updates password, bumps auth_version, consumes reset token,
    revokes sibling reset tokens and all active sessions, returns zero auth credentials,
    and rejects invalid/revoked/expired/weak/inactive/unverified/oauth-only inputs safely.
    """
    sent_payloads: list[dict] = []
    monkeypatch.setattr(
        email_service_module.resend.Emails,
        "send",
        lambda params, options=None: sent_payloads.append(dict(params)) or {"id": "re_rp"},
    )
    settings, app = _build_test_app(test_database_url, rate_limit_enabled=False)

    with TestClient(app) as client:  # type: ignore[arg-type]
        uid = _register_and_verify_user(client, sent_payloads, email="rp.user@example.com")

        # Establish active web and mobile sessions
        web_login = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
            json={"email": "rp.user@example.com", "password": "StrongPassword!2026"},
        )
        assert web_login.status_code == 200
        web_cookie = web_login.cookies[settings.REFRESH_COOKIE_NAME]

        mob_login = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "rp.user@example.com", "password": "StrongPassword!2026"},
        ).json()

        sent_payloads.clear()
        assert (
            client.post("/api/v1/auth/forgot-password", json={"email": "rp.user@example.com"}).status_code
            == 202
        )
        tok1 = _extract_token_from_email_params(sent_payloads[-1], "/reset-password")

        # Backdate cooldown & issue tok2 (revoking tok1)
        with db_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE password_reset_tokens "
                    "SET delivery_attempted_at = now() - interval '5 minutes', "
                    "created_at = created_at - interval '5 minutes' "
                    "WHERE user_id = :u"
                ),
                {"u": uid},
            )
        assert (
            client.post("/api/v1/auth/forgot-password", json={"email": "rp.user@example.com"}).status_code
            == 202
        )
        tok2 = _extract_token_from_email_params(sent_payloads[-1], "/reset-password")
        assert tok1 != tok2

        # Unknown & revoked tokens fail 400 INVALID_RESET_TOKEN
        for bad_tok in ("does-not-exist-token", tok1):
            r_bad = client.post(
                "/api/v1/auth/reset-password",
                json={"token": bad_tok, "new_password": "BetterPassword!2026"},
            )
            assert r_bad.status_code == 400
            assert r_bad.json()["error"]["details"]["code"] == "INVALID_RESET_TOKEN"

        # Weak password & password==email fail 422 VALIDATION_ERROR without consuming tok2
        for bad_pw in ("weak", "RP.USER@EXAMPLE.COM"):
            r_weak = client.post(
                "/api/v1/auth/reset-password",
                json={"token": tok2, "new_password": bad_pw},
            )
            assert r_weak.status_code == 422
            assert r_weak.json()["error"]["details"]["code"] == "VALIDATION_ERROR"
            assert bad_pw not in r_weak.text
            for err in r_weak.json()["error"]["details"]["errors"]:
                assert "input" not in err

        # Inactive user returns 403 ACCOUNT_INACTIVE and preserves tok2 unconsumed
        with db_engine.begin() as conn:
            conn.execute(text("UPDATE users SET is_active = false WHERE id = :u"), {"u": uid})
        r_inactive = client.post(
            "/api/v1/auth/reset-password",
            json={"token": tok2, "new_password": "BetterPassword!2026"},
        )
        assert r_inactive.status_code == 403
        assert r_inactive.json()["error"]["details"]["code"] == "ACCOUNT_INACTIVE"
        with db_engine.begin() as conn:
            conn.execute(text("UPDATE users SET is_active = true WHERE id = :u"), {"u": uid})

        # Expired token test (temporary synthetic expired token)
        exp_raw = "expired-synthetic-reset-token-123"
        with db_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO password_reset_tokens "
                    "(user_id, token_hash, delivery_status, expires_at) "
                    "VALUES (:u, :th, 'sent', now() - interval '1 minute')"
                ),
                {"u": uid, "th": hash_opaque_token(exp_raw)},
            )
        r_exp = client.post(
            "/api/v1/auth/reset-password",
            json={"token": exp_raw, "new_password": "BetterPassword!2026"},
        )
        assert r_exp.status_code == 400
        assert r_exp.json()["error"]["details"]["code"] == "INVALID_RESET_TOKEN"

        # Successful reset using tok2 with whitespace padding
        r_ok = client.post(
            "/api/v1/auth/reset-password",
            json={"token": f"  {tok2}  ", "new_password": "BetterPassword!2026"},
        )
        assert r_ok.status_code == 200
        body_ok = r_ok.json()
        assert set(body_ok.keys()) == {"message"}
        assert "set-cookie" not in {k.lower() for k in r_ok.headers.keys()}

        # Verify DB effects
        with db_engine.connect() as conn:
            u_row = conn.execute(
                text("SELECT password_hash, auth_version, password_changed_at FROM users WHERE id = :u"),
                {"u": uid},
            ).mappings().one()
            assert u_row["auth_version"] == 1
            assert u_row["password_changed_at"] is not None
            assert verify_password("BetterPassword!2026", u_row["password_hash"])
            assert not verify_password("StrongPassword!2026", u_row["password_hash"])

            t2_row = conn.execute(
                text("SELECT consumed_at, revoked_at FROM password_reset_tokens WHERE token_hash = :th"),
                {"th": hash_opaque_token(tok2)},
            ).mappings().one()
            assert t2_row["consumed_at"] is not None
            assert t2_row["revoked_at"] is None

            sess_rows = conn.execute(
                text("SELECT revoked_at, revoke_reason FROM refresh_sessions WHERE user_id = :u"),
                {"u": uid},
            ).mappings().all()
            assert len(sess_rows) == 2
            assert all(r["revoked_at"] is not None and r["revoke_reason"] == "password_reset" for r in sess_rows)

        # Replay of tok2 fails 400 INVALID_RESET_TOKEN
        r_replay = client.post(
            "/api/v1/auth/reset-password",
            json={"token": tok2, "new_password": "ThirdPassword!2026"},
        )
        assert r_replay.status_code == 400
        assert r_replay.json()["error"]["details"]["code"] == "INVALID_RESET_TOKEN"

        # Old JWT and old refresh sessions are dead; old password rejected; new password works
        assert (
            client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {mob_login['access_token']}"}).status_code
            == 401
        )
        assert (
            client.post(
                "/api/v1/auth/refresh",
                headers={"X-Client-Type": "mobile"},
                json={"refresh_token": mob_login["refresh_token"]},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/v1/auth/refresh",
                headers={
                    "X-Client-Type": "web",
                    "Origin": "http://localhost:5173",
                    "Cookie": f"{settings.REFRESH_COOKIE_NAME}={web_cookie}",
                },
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/v1/auth/login",
                headers={"X-Client-Type": "mobile"},
                json={"email": "rp.user@example.com", "password": "StrongPassword!2026"},
            ).status_code
            == 401
        )
        new_login = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "rp.user@example.com", "password": "BetterPassword!2026"},
        )
        assert new_login.status_code == 200

        # Defensive rejection for unverified account (is_email_verified=False) with active session + token
        r_unv_reg = client.post(
            "/api/v1/auth/register",
            json={"email": "rp.unverified@example.com", "password": "UnverifiedPass!2026"},
        )
        assert r_unv_reg.status_code == 201
        uid_unverified = uuid.UUID(r_unv_reg.json()["user"]["id"])
        unv_tok = "synthetic-unverified-reset-token-888"
        with db_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO password_reset_tokens "
                    "(user_id, token_hash, delivery_status, expires_at) "
                    "VALUES (:u, :th, 'sent', now() + interval '30 minutes')"
                ),
                {"u": uid_unverified, "th": hash_opaque_token(unv_tok)},
            )
            conn.execute(
                text(
                    "INSERT INTO refresh_sessions "
                    "(user_id, family_id, token_hash, client_type, expires_at, family_expires_at) "
                    "VALUES (:u, gen_random_uuid(), repeat('e', 64), 'mobile', "
                    "now() + interval '1 day', now() + interval '7 days')"
                ),
                {"u": uid_unverified},
            )
            unv_before = conn.execute(
                text("SELECT password_hash, auth_version, password_changed_at FROM users WHERE id = :u"),
                {"u": uid_unverified},
            ).mappings().one()

        r_unv_reset = client.post(
            "/api/v1/auth/reset-password",
            json={"token": unv_tok, "new_password": "ThirdPassword!2026"},
        )
        assert r_unv_reset.status_code == 400
        assert r_unv_reset.json()["error"]["details"]["code"] == "INVALID_RESET_TOKEN"
        with db_engine.connect() as conn:
            unv_after = conn.execute(
                text("SELECT password_hash, auth_version, password_changed_at FROM users WHERE id = :u"),
                {"u": uid_unverified},
            ).mappings().one()
            assert dict(unv_after) == dict(unv_before)
            tok_after = conn.execute(
                text("SELECT consumed_at, revoked_at FROM password_reset_tokens WHERE token_hash = :th"),
                {"th": hash_opaque_token(unv_tok)},
            ).mappings().one()
            assert tok_after["consumed_at"] is None and tok_after["revoked_at"] is None
            sess_after = conn.execute(
                text("SELECT revoked_at FROM refresh_sessions WHERE user_id = :u"),
                {"u": uid_unverified},
            ).scalar_one()
            assert sess_after is None

        # Defensive rejection if token row points to OAuth-only (password_hash=None) account
        oauth_tok = "synthetic-oauth-reset-token-999"
        with db_engine.begin() as conn:
            conn.execute(text("UPDATE users SET password_hash = NULL WHERE id = :u"), {"u": uid})
            conn.execute(
                text(
                    "INSERT INTO password_reset_tokens "
                    "(user_id, token_hash, delivery_status, expires_at) "
                    "VALUES (:u, :th, 'sent', now() + interval '30 minutes')"
                ),
                {"u": uid, "th": hash_opaque_token(oauth_tok)},
            )
        r_oauth = client.post(
            "/api/v1/auth/reset-password",
            json={"token": oauth_tok, "new_password": "ThirdPassword!2026"},
        )
        assert r_oauth.status_code == 400
        assert r_oauth.json()["error"]["details"]["code"] == "INVALID_RESET_TOKEN"


@pytest.mark.db
def test_change_password_web_mobile_and_mandatory_validation_order(
    test_database_url: str,
    db_engine: Engine,
    clean_auth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Verify /change-password on web & mobile channels, session/reset-token revocation,
    fresh family_id issuance, updated auth_version JWT ver claim, Origin enforcement,
    and strict validation check order 1..7.
    """
    sent_payloads: list[dict] = []
    monkeypatch.setattr(
        email_service_module.resend.Emails,
        "send",
        lambda params, options=None: sent_payloads.append(dict(params)) or {"id": "re_cp"},
    )
    settings, app = _build_test_app(test_database_url, rate_limit_enabled=False)

    with TestClient(app) as client:  # type: ignore[arg-type]
        uid = _register_and_verify_user(client, sent_payloads, email="cp.user@example.com")
        sent_payloads.clear()

        # Issue an active reset token that must be revoked on password change
        assert (
            client.post("/api/v1/auth/forgot-password", json={"email": "cp.user@example.com"}).status_code
            == 202
        )
        pending_reset_tok = _extract_token_from_email_params(sent_payloads[-1], "/reset-password")

        # Log in on mobile and web
        mob1 = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "cp.user@example.com", "password": "StrongPassword!2026"},
        ).json()
        web1 = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "web", "Origin": "http://localhost:5173"},
            json={"email": "cp.user@example.com", "password": "StrongPassword!2026"},
        )
        assert web1.status_code == 200
        web1_cookie = web1.cookies[settings.REFRESH_COOKIE_NAME]

        # Mandatory check order (wrong checks combined to prove priority!):
        # Order 5 before 6/7: wrong current_password + email-equal/weak new_password -> 401 INVALID_CREDENTIALS
        r_wrong_cur = client.post(
            "/api/v1/auth/change-password",
            headers={
                "Authorization": f"Bearer {mob1['access_token']}",
                "X-Client-Type": "mobile",
            },
            json={"current_password": "WrongPassword!999", "new_password": "cp.user@example.com"},
        )
        assert r_wrong_cur.status_code == 401
        assert r_wrong_cur.json()["error"]["details"]["code"] == "INVALID_CREDENTIALS"

        # Order 6 before 7: same current == new -> 400 SAME_PASSWORD_NOT_ALLOWED
        r_same = client.post(
            "/api/v1/auth/change-password",
            headers={
                "Authorization": f"Bearer {mob1['access_token']}",
                "X-Client-Type": "mobile",
            },
            json={
                "current_password": "StrongPassword!2026",
                "new_password": "StrongPassword!2026",
            },
        )
        assert r_same.status_code == 400
        assert r_same.json()["error"]["details"]["code"] == "SAME_PASSWORD_NOT_ALLOWED"

        # Order 7: valid current + weak or email-equal new -> 422 VALIDATION_ERROR (input stripped)
        for bad_new in ("weak", "CP.USER@EXAMPLE.COM"):
            r_policy = client.post(
                "/api/v1/auth/change-password",
                headers={
                    "Authorization": f"Bearer {mob1['access_token']}",
                    "X-Client-Type": "mobile",
                },
                json={"current_password": "StrongPassword!2026", "new_password": bad_new},
            )
            assert r_policy.status_code == 422
            assert r_policy.json()["error"]["details"]["code"] == "VALIDATION_ERROR"
            assert bad_new not in r_policy.text
            for err in r_policy.json()["error"]["details"]["errors"]:
                assert "input" not in err

        # Web channel requires Origin -> 403 CSRF_ORIGIN_MISMATCH
        r_no_origin = client.post(
            "/api/v1/auth/change-password",
            headers={
                "Authorization": f"Bearer {mob1['access_token']}",
                "X-Client-Type": "web",
            },
            json={"current_password": "StrongPassword!2026", "new_password": "MobileNewPass!2026"},
        )
        assert r_no_origin.status_code == 403
        assert r_no_origin.json()["error"]["details"]["code"] == "CSRF_ORIGIN_MISMATCH"

        # Missing X-Client-Type rejected
        assert (
            client.post(
                "/api/v1/auth/change-password",
                headers={"Authorization": f"Bearer {mob1['access_token']}"},
                json={"current_password": "StrongPassword!2026", "new_password": "MobileNewPass!2026"},
            ).status_code
            == 400
        )

        with db_engine.connect() as conn:
            old_family_ids_1 = set(
                conn.execute(
                    text("SELECT family_id FROM refresh_sessions WHERE user_id = :u"),
                    {"u": uid},
                ).scalars().all()
            )
        assert len(old_family_ids_1) == 2

        # 1. Mobile /change-password succeeds
        r_mob_cp = client.post(
            "/api/v1/auth/change-password",
            headers={
                "Authorization": f"Bearer {mob1['access_token']}",
                "X-Client-Type": "mobile",
            },
            json={"current_password": "StrongPassword!2026", "new_password": "MobileNewPass!2026"},
        )
        assert r_mob_cp.status_code == 200
        assert "set-cookie" not in {k.lower() for k in r_mob_cp.headers.keys()}
        mob_cp = r_mob_cp.json()
        assert mob_cp["refresh_token"]
        assert mob_cp["refresh_expires_in"] > 0
        assert mob_cp["user"]["has_password"] is True
        mob_claims = jwt.decode(
            mob_cp["access_token"],
            settings.JWT_SECRET_KEY.get_secret_value(),
            algorithms=["HS256"],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
        )
        assert mob_claims["ver"] == 1
        assert mob_claims["sub"] == str(uid)

        # Old JWT -> 401 (Order 1: stale auth_version beats wrong current_password!)
        r_stale_jwt = client.post(
            "/api/v1/auth/change-password",
            headers={
                "Authorization": f"Bearer {mob1['access_token']}",
                "X-Client-Type": "mobile",
            },
            json={"current_password": "WrongPassword", "new_password": "weak"},
        )
        assert r_stale_jwt.status_code == 401
        assert r_stale_jwt.headers.get("www-authenticate") == "Bearer"
        assert r_stale_jwt.json()["error"]["details"]["code"] == "INVALID_ACCESS_TOKEN"

        # Old refresh sessions & pending reset token were revoked
        assert (
            client.post(
                "/api/v1/auth/refresh",
                headers={"X-Client-Type": "mobile"},
                json={"refresh_token": mob1["refresh_token"]},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/v1/auth/refresh",
                headers={
                    "X-Client-Type": "web",
                    "Origin": "http://localhost:5173",
                    "Cookie": f"{settings.REFRESH_COOKIE_NAME}={web1_cookie}",
                },
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/v1/auth/reset-password",
                json={"token": pending_reset_tok, "new_password": "AnotherNewPass!2026"},
            ).status_code
            == 400
        )

        # DB checks: auth_version==1, password_changed_at set, reset token revoked,
        # prior sessions revoked, 1 fresh mobile session with new family_id & matching token_hash
        with db_engine.connect() as conn:
            u1 = conn.execute(
                text("SELECT auth_version, password_changed_at, password_hash FROM users WHERE id = :u"),
                {"u": uid},
            ).mappings().one()
            assert u1["auth_version"] == 1
            assert u1["password_changed_at"] is not None
            assert verify_password("MobileNewPass!2026", u1["password_hash"])

            prt_revoked = conn.execute(
                text("SELECT revoked_at FROM password_reset_tokens WHERE token_hash = :th"),
                {"th": hash_opaque_token(pending_reset_tok)},
            ).scalar_one()
            assert prt_revoked is not None

            active_rows = conn.execute(
                text(
                    "SELECT id, family_id, token_hash, client_type, parent_session_id "
                    "FROM refresh_sessions WHERE user_id = :u AND revoked_at IS NULL"
                ),
                {"u": uid},
            ).mappings().all()
            assert len(active_rows) == 1
            assert active_rows[0]["client_type"] == "mobile"
            assert active_rows[0]["parent_session_id"] is None
            assert active_rows[0]["family_id"] not in old_family_ids_1
            assert active_rows[0]["token_hash"] == hash_opaque_token(mob_cp["refresh_token"])
            family_after_mob = active_rows[0]["family_id"]

            revoked_reasons = conn.execute(
                text(
                    "SELECT revoke_reason FROM refresh_sessions "
                    "WHERE user_id = :u AND revoked_at IS NOT NULL"
                ),
                {"u": uid},
            ).scalars().all()
            assert len(revoked_reasons) == 2
            assert set(revoked_reasons) == {"password_changed"}

        # Fresh JWT works on /me
        assert (
            client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {mob_cp['access_token']}"}).status_code
            == 200
        )

        # 2. Web /change-password sets HttpOnly cookie and omits refresh_token from JSON
        r_web_cp = client.post(
            "/api/v1/auth/change-password",
            headers={
                "Authorization": f"Bearer {mob_cp['access_token']}",
                "X-Client-Type": "web",
                "Origin": "http://localhost:5173",
            },
            json={"current_password": "MobileNewPass!2026", "new_password": "WebFinalPass!2026"},
        )
        assert r_web_cp.status_code == 200
        web_cp_body = r_web_cp.json()
        assert "refresh_token" not in web_cp_body
        assert settings.REFRESH_COOKIE_NAME in r_web_cp.cookies
        web_cp_cookie = r_web_cp.cookies[settings.REFRESH_COOKIE_NAME]
        set_cookie_hdr = r_web_cp.headers.get("set-cookie", "").lower()
        assert "httponly" in set_cookie_hdr
        assert "path=/api/v1/auth" in set_cookie_hdr

        web_claims = jwt.decode(
            web_cp_body["access_token"],
            settings.JWT_SECRET_KEY.get_secret_value(),
            algorithms=["HS256"],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
        )
        assert web_claims["ver"] == 2
        with db_engine.connect() as conn:
            u2 = conn.execute(
                text("SELECT auth_version, password_changed_at, password_hash FROM users WHERE id = :u"),
                {"u": uid},
            ).mappings().one()
            assert u2["auth_version"] == 2
            assert u2["password_changed_at"] >= u1["password_changed_at"]
            assert verify_password("WebFinalPass!2026", u2["password_hash"])

            web_active = conn.execute(
                text(
                    "SELECT family_id, token_hash, client_type, parent_session_id "
                    "FROM refresh_sessions WHERE user_id = :u AND revoked_at IS NULL"
                ),
                {"u": uid},
            ).mappings().one()
            assert web_active["client_type"] == "web"
            assert web_active["parent_session_id"] is None
            assert web_active["family_id"] not in (old_family_ids_1 | {family_after_mob})
            assert web_active["token_hash"] == hash_opaque_token(web_cp_cookie)

            all_revoked_cnt = conn.execute(
                text(
                    "SELECT COUNT(*) FROM refresh_sessions "
                    "WHERE user_id = :u AND revoked_at IS NOT NULL AND revoke_reason = 'password_changed'"
                ),
                {"u": uid},
            ).scalar_one()
            assert all_revoked_cnt == 3

        # Fresh web cookie rotates cleanly on /refresh
        r_web_ref = client.post(
            "/api/v1/auth/refresh",
            headers={
                "X-Client-Type": "web",
                "Origin": "http://localhost:5173",
                "Cookie": f"{settings.REFRESH_COOKIE_NAME}={web_cp_cookie}",
            },
        )
        assert r_web_ref.status_code == 200

        # Order 3: inactive user via HTTP guard -> 403 ACCOUNT_INACTIVE
        fresh_jwt = web_cp_body["access_token"]
        with db_engine.begin() as conn:
            conn.execute(text("UPDATE users SET is_active = false WHERE id = :u"), {"u": uid})
        r_inact_cp = client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {fresh_jwt}", "X-Client-Type": "mobile"},
            json={"current_password": "wrong", "new_password": "weak"},
        )
        assert r_inact_cp.status_code == 403
        assert r_inact_cp.json()["error"]["details"]["code"] == "ACCOUNT_INACTIVE"

        # Order 4: OAuth-only user (password_hash=None) -> 400 PASSWORD_NOT_SET
        with db_engine.begin() as conn:
            conn.execute(
                text("UPDATE users SET is_active = true, password_hash = NULL WHERE id = :u"),
                {"u": uid},
            )
        r_no_pw = client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {fresh_jwt}", "X-Client-Type": "mobile"},
            json={"current_password": "wrong", "new_password": "cp.user@example.com"},
        )
        assert r_no_pw.status_code == 400
        assert r_no_pw.json()["error"]["details"]["code"] == "PASSWORD_NOT_SET"


@pytest.mark.db
def test_change_password_post_lock_inactive_user_direct_service(
    test_database_url: str,
    db_engine: Engine,
    clean_auth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    MAJOR-2A: Directly invoke auth_service.change_password when User was previously loaded
    as active into Session identity map, then deactivated by another transaction before lock.
    Must raise 403 ACCOUNT_INACTIVE via populate_existing=True with zero DB mutations.
    """
    sent_payloads: list[dict] = []
    monkeypatch.setattr(
        email_service_module.resend.Emails,
        "send",
        lambda params, options=None: sent_payloads.append(dict(params)) or {"id": "re_inact_svc"},
    )
    settings, app = _build_test_app(test_database_url, rate_limit_enabled=False)

    with TestClient(app) as client:  # type: ignore[arg-type]
        uid = _register_and_verify_user(client, sent_payloads, email="cp.postlock@example.com")
        login_res = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "cp.postlock@example.com", "password": "StrongPassword!2026"},
        )
        assert login_res.status_code == 200

    session_maker = build_sessionmaker(db_engine)
    with session_maker() as db:
        # Load active User into identity map first (simulates post-get_current_auth_context state)
        loaded_user = db.execute(select(User).where(User.id == uid)).scalar_one()
        assert loaded_user.is_active is True

        # Separate committed transaction marks account inactive before service locks row
        with db_engine.begin() as conn:
            conn.execute(text("UPDATE users SET is_active = false WHERE id = :u"), {"u": uid})

        with pytest.raises(AppException) as exc_info:
            auth_service.change_password(
                db,
                user_id=uid,
                expected_auth_version=0,
                current_password="StrongPassword!2026",
                new_password="ShouldNotChange!2026",
                client_type="mobile",
                user_agent="unit-agent",
                ip_address="203.0.113.10",
                settings=settings,
            )

    assert exc_info.value.status_code == 403
    assert exc_info.value.details == {"code": "ACCOUNT_INACTIVE"}

    with db_engine.connect() as conn:
        u_after = conn.execute(
            text("SELECT password_hash, auth_version, password_changed_at FROM users WHERE id = :u"),
            {"u": uid},
        ).mappings().one()
        assert u_after["auth_version"] == 0
        assert u_after["password_changed_at"] is None
        assert verify_password("StrongPassword!2026", u_after["password_hash"])
        active_cnt = conn.execute(
            text("SELECT COUNT(*) FROM refresh_sessions WHERE user_id = :u AND revoked_at IS NULL"),
            {"u": uid},
        ).scalar_one()
        assert active_cnt == 1


@pytest.mark.db
def test_reset_and_change_password_mid_transaction_rollback_atomicity(
    test_database_url: str,
    db_engine: Engine,
    clean_auth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    MAJOR-1B: Induce a controlled failure AFTER SQL mutations flush inside PostgreSQL
    but before commit for both /reset-password and /change-password, proving complete
    atomic rollback of all touched tables.
    """
    sent_payloads: list[dict] = []
    monkeypatch.setattr(
        email_service_module.resend.Emails,
        "send",
        lambda params, options=None: sent_payloads.append(dict(params)) or {"id": "re_rb"},
    )
    _, app = _build_test_app(test_database_url, rate_limit_enabled=False)

    # Use raise_server_exceptions=False to assert clean HTTP 500 + DB rollback
    with TestClient(app, raise_server_exceptions=False) as client:  # type: ignore[arg-type]
        # Part A: reset_password mid-transaction rollback
        uid_a = _register_and_verify_user(client, sent_payloads, email="rb.reset@example.com")
        for _ in range(2):
            assert (
                client.post(
                    "/api/v1/auth/login",
                    headers={"X-Client-Type": "mobile"},
                    json={"email": "rb.reset@example.com", "password": "StrongPassword!2026"},
                ).status_code
                == 200
            )
        tok_main = "rollback-reset-main-token"
        tok_sib = "rollback-reset-sibling-token"
        with db_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO password_reset_tokens "
                    "(user_id, token_hash, delivery_status, expires_at) VALUES "
                    "(:u, :th1, 'sent', now() + interval '30 minutes'), "
                    "(:u, :th2, 'sent', now() + interval '30 minutes')"
                ),
                {
                    "u": uid_a,
                    "th1": hash_opaque_token(tok_main),
                    "th2": hash_opaque_token(tok_sib),
                },
            )
            snap_u_a = conn.execute(
                text("SELECT password_hash, password_changed_at, auth_version FROM users WHERE id = :u"),
                {"u": uid_a},
            ).mappings().one()
            snap_sess_a = conn.execute(
                text(
                    "SELECT id, family_id, revoked_at, revoke_reason "
                    "FROM refresh_sessions WHERE user_id = :u ORDER BY id"
                ),
                {"u": uid_a},
            ).mappings().all()

        orig_reset = auth_service.reset_password

        def reset_flush_then_boom(db: Session, *args, **kwargs):
            def fail_after_flush():
                db.flush()  # Execute user update, token consume/revoke, session revocations in PG
                raise RuntimeError("simulated reset commit failure")

            db.commit = fail_after_flush  # type: ignore[method-assign]
            return orig_reset(db, *args, **kwargs)

        with monkeypatch.context() as mp:
            mp.setattr(auth_service, "reset_password", reset_flush_then_boom)
            r_fail_a = client.post(
                "/api/v1/auth/reset-password",
                json={"token": tok_main, "new_password": "RolledBackReset!2026"},
            )
        assert r_fail_a.status_code == 500

        with db_engine.connect() as conn:
            after_u_a = conn.execute(
                text("SELECT password_hash, password_changed_at, auth_version FROM users WHERE id = :u"),
                {"u": uid_a},
            ).mappings().one()
            assert dict(after_u_a) == dict(snap_u_a)

            after_toks_a = conn.execute(
                text(
                    "SELECT token_hash, consumed_at, revoked_at "
                    "FROM password_reset_tokens WHERE user_id = :u"
                ),
                {"u": uid_a},
            ).mappings().all()
            assert all(t["consumed_at"] is None and t["revoked_at"] is None for t in after_toks_a)

            after_sess_a = conn.execute(
                text(
                    "SELECT id, family_id, revoked_at, revoke_reason "
                    "FROM refresh_sessions WHERE user_id = :u ORDER BY id"
                ),
                {"u": uid_a},
            ).mappings().all()
            assert [dict(r) for r in after_sess_a] == [dict(r) for r in snap_sess_a]

        # Confirm tok_main remained completely usable after rollback
        assert (
            client.post(
                "/api/v1/auth/reset-password",
                json={"token": tok_main, "new_password": "PostRollbackReset!2026"},
            ).status_code
            == 200
        )

        # Part B: change_password mid-transaction rollback
        uid_b = _register_and_verify_user(client, sent_payloads, email="rb.change@example.com")
        mob_b = None
        for _ in range(2):
            lr = client.post(
                "/api/v1/auth/login",
                headers={"X-Client-Type": "mobile"},
                json={"email": "rb.change@example.com", "password": "StrongPassword!2026"},
            )
            assert lr.status_code == 200
            mob_b = lr.json()
        assert mob_b is not None

        tok_pending_b = "rollback-change-pending-reset"
        with db_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO password_reset_tokens "
                    "(user_id, token_hash, delivery_status, expires_at) "
                    "VALUES (:u, :th, 'sent', now() + interval '30 minutes')"
                ),
                {"u": uid_b, "th": hash_opaque_token(tok_pending_b)},
            )
            snap_u_b = conn.execute(
                text("SELECT password_hash, password_changed_at, auth_version FROM users WHERE id = :u"),
                {"u": uid_b},
            ).mappings().one()
            snap_sess_b = conn.execute(
                text(
                    "SELECT id, family_id, revoked_at, revoke_reason "
                    "FROM refresh_sessions WHERE user_id = :u ORDER BY id"
                ),
                {"u": uid_b},
            ).mappings().all()

        orig_change = auth_service.change_password

        def change_flush_then_boom(db: Session, *args, **kwargs):
            def fail_after_flush():
                db.flush()  # Execute user update, token/session revocations AND new session INSERT
                raise RuntimeError("simulated change commit failure")

            db.commit = fail_after_flush  # type: ignore[method-assign]
            return orig_change(db, *args, **kwargs)

        with monkeypatch.context() as mp:
            mp.setattr(auth_service, "change_password", change_flush_then_boom)
            r_fail_b = client.post(
                "/api/v1/auth/change-password",
                headers={
                    "Authorization": f"Bearer {mob_b['access_token']}",
                    "X-Client-Type": "mobile",
                },
                json={
                    "current_password": "StrongPassword!2026",
                    "new_password": "RolledBackChange!2026",
                },
            )
        assert r_fail_b.status_code == 500

        with db_engine.connect() as conn:
            after_u_b = conn.execute(
                text("SELECT password_hash, password_changed_at, auth_version FROM users WHERE id = :u"),
                {"u": uid_b},
            ).mappings().one()
            assert dict(after_u_b) == dict(snap_u_b)

            after_tok_b = conn.execute(
                text("SELECT consumed_at, revoked_at FROM password_reset_tokens WHERE token_hash = :th"),
                {"th": hash_opaque_token(tok_pending_b)},
            ).mappings().one()
            assert after_tok_b["consumed_at"] is None and after_tok_b["revoked_at"] is None

            after_sess_b = conn.execute(
                text(
                    "SELECT id, family_id, revoked_at, revoke_reason "
                    "FROM refresh_sessions WHERE user_id = :u ORDER BY id"
                ),
                {"u": uid_b},
            ).mappings().all()
            # Exactly the original 2 unrevoked sessions remain (no newly inserted session persisted!)
            assert [dict(r) for r in after_sess_b] == [dict(r) for r in snap_sess_b]


@pytest.mark.db
def test_stage3b_route_rate_limits(
    test_database_url: str,
    clean_auth_db: None,
) -> None:
    """Verify IP rate limits: forgot-password (5/15m), reset-password (10/15m), change-password (30/15m)."""
    _, app = _build_test_app(test_database_url, rate_limit_enabled=True)
    with TestClient(app) as client:  # type: ignore[arg-type]
        for i in range(5):
            r = client.post("/api/v1/auth/forgot-password", json={"email": f"u{i}@example.com"})
            assert r.status_code == 202
        r_fp_limited = client.post("/api/v1/auth/forgot-password", json={"email": "u5@example.com"})
        assert r_fp_limited.status_code == 429
        assert "retry-after" in {k.lower() for k in r_fp_limited.headers.keys()}

        for _ in range(10):
            r = client.post(
                "/api/v1/auth/reset-password",
                json={"token": "nonexistent", "new_password": "ValidPassword!2026"},
            )
            assert r.status_code == 400
        r_rp_limited = client.post(
            "/api/v1/auth/reset-password",
            json={"token": "nonexistent", "new_password": "ValidPassword!2026"},
        )
        assert r_rp_limited.status_code == 429
        assert "retry-after" in {k.lower() for k in r_rp_limited.headers.keys()}

        settings = app.state.settings  # type: ignore[attr-defined]
        fake_jwt, _ = create_access_token(
            user_id=uuid.uuid4(), auth_version=0, settings=settings
        )
        for _ in range(30):
            r = client.post(
                "/api/v1/auth/change-password",
                headers={"Authorization": f"Bearer {fake_jwt}", "X-Client-Type": "mobile"},
                json={"current_password": "x", "new_password": "y"},
            )
            assert r.status_code == 401
        r_cp_limited = client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {fake_jwt}", "X-Client-Type": "mobile"},
            json={"current_password": "x", "new_password": "y"},
        )
        assert r_cp_limited.status_code == 429
        assert "retry-after" in {k.lower() for k in r_cp_limited.headers.keys()}


@pytest.mark.db
def test_stage3b_deterministic_cross_operation_concurrency(
    test_database_url: str,
    db_engine: Engine,
    clean_auth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Deterministic dual-order PostgreSQL lock-coordination proofs (independent sessions +
    PID-filtered pg_stat_activity wait_event_type='Lock') across all Stage 3B races:
      1. reset-password vs refresh (both win orders -> zero escaped child sessions).
      2. change-password vs refresh (both win orders -> zero escaped child sessions).
      3. change-password vs logout-all (both win orders -> exact auth_version serialization).
      4. Concurrent same-token reset-password.
      5. Concurrent same-JWT change-password (with persisted DB & credential assertions).
      6. Concurrent reset-password vs change-password (both orders, with DB & login checks).
      7. Concurrent two-distinct-token reset-password (both win orders, sibling revocation & DB checks).
    """
    sent_payloads: list[dict] = []
    monkeypatch.setattr(
        email_service_module.resend.Emails,
        "send",
        lambda params, options=None: sent_payloads.append(dict(params)) or {"id": "re_conc"},
    )
    _, app = _build_test_app(test_database_url, rate_limit_enabled=False)

    def _run_ordered_pair(winner_service_name: str, winner_fn, loser_fn):
        orig_fn = getattr(auth_service, winner_service_name)
        claim_lock = threading.Lock()
        winner_claimed = False
        winner_pid_box: list[int] = []
        winner_at_commit = threading.Event()
        release_winner = threading.Event()

        def wrapped_service(db: Session, *args, **kwargs):
            nonlocal winner_claimed
            should_pause = False
            with claim_lock:
                if not winner_claimed:
                    winner_claimed = True
                    should_pause = True

            if not should_pause:
                return orig_fn(db, *args, **kwargs)

            orig_commit = db.commit

            def paused_commit():
                winner_pid_box.append(
                    db.execute(text("SELECT pg_backend_pid()")).scalar_one()
                )
                winner_at_commit.set()
                assert release_winner.wait(timeout=8), "Coordinator never released winner commit"
                return orig_commit()

            db.commit = paused_commit  # type: ignore[method-assign]
            try:
                return orig_fn(db, *args, **kwargs)
            finally:
                db.commit = orig_commit  # type: ignore[method-assign]

        with monkeypatch.context() as mp:
            mp.setattr(auth_service, winner_service_name, wrapped_service)
            try:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    f_win = pool.submit(winner_fn)
                    assert winner_at_commit.wait(timeout=8), "Winner never reached commit barrier"

                    f_lose = pool.submit(loser_fn)
                    _wait_for_pg_lock_wait(
                        db_engine, exclude_pid=winner_pid_box[0], timeout=8.0
                    )

                    release_winner.set()
                    return f_win.result(timeout=10), f_lose.result(timeout=10)
            finally:
                release_winner.set()

    with TestClient(app) as client:  # type: ignore[arg-type]
        # 1A. Reset vs Refresh — Reset wins lock first, Refresh waits then rejects 401
        uid1 = _register_and_verify_user(client, sent_payloads, email="conc1a@example.com")
        mob1a = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "conc1a@example.com", "password": "StrongPassword!2026"},
        ).json()
        sent_payloads.clear()
        client.post("/api/v1/auth/forgot-password", json={"email": "conc1a@example.com"})
        rtok1a = _extract_token_from_email_params(sent_payloads[-1], "/reset-password")

        r_reset_win, r_ref_lose = _run_ordered_pair(
            "reset_password",
            lambda: client.post(
                "/api/v1/auth/reset-password",
                json={"token": rtok1a, "new_password": "ResetWin!2026"},
            ),
            lambda: client.post(
                "/api/v1/auth/refresh",
                headers={"X-Client-Type": "mobile"},
                json={"refresh_token": mob1a["refresh_token"]},
            ),
        )
        assert r_reset_win.status_code == 200
        assert r_ref_lose.status_code == 401
        with db_engine.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT COUNT(*) FROM refresh_sessions WHERE user_id = :u AND revoked_at IS NULL"),
                    {"u": uid1},
                ).scalar_one()
                == 0
            )

        # 1B. Reset vs Refresh — Refresh wins lock first & commits child session; Reset waits then revokes child!
        uid1b = _register_and_verify_user(client, sent_payloads, email="conc1b@example.com")
        mob1b = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "conc1b@example.com", "password": "StrongPassword!2026"},
        ).json()
        sent_payloads.clear()
        client.post("/api/v1/auth/forgot-password", json={"email": "conc1b@example.com"})
        rtok1b = _extract_token_from_email_params(sent_payloads[-1], "/reset-password")

        r_ref_win, r_reset_second = _run_ordered_pair(
            "refresh_session_token",
            lambda: client.post(
                "/api/v1/auth/refresh",
                headers={"X-Client-Type": "mobile"},
                json={"refresh_token": mob1b["refresh_token"]},
            ),
            lambda: client.post(
                "/api/v1/auth/reset-password",
                json={"token": rtok1b, "new_password": "ResetSecond!2026"},
            ),
        )
        assert r_ref_win.status_code == 200
        assert r_reset_second.status_code == 200
        child_body = r_ref_win.json()
        assert (
            client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {child_body['access_token']}"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/v1/auth/refresh",
                headers={"X-Client-Type": "mobile"},
                json={"refresh_token": child_body["refresh_token"]},
            ).status_code
            == 401
        )
        with db_engine.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT COUNT(*) FROM refresh_sessions WHERE user_id = :u AND revoked_at IS NULL"),
                    {"u": uid1b},
                ).scalar_one()
                == 0
            )

        # 2A. Change-Password vs Refresh — Change wins first -> Refresh rejects 401
        uid2a = _register_and_verify_user(client, sent_payloads, email="conc2a@example.com")
        mob2a = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "conc2a@example.com", "password": "StrongPassword!2026"},
        ).json()
        r_chg_win, r_ref2a_lose = _run_ordered_pair(
            "change_password",
            lambda: client.post(
                "/api/v1/auth/change-password",
                headers={"Authorization": f"Bearer {mob2a['access_token']}", "X-Client-Type": "mobile"},
                json={"current_password": "StrongPassword!2026", "new_password": "ChangeWin!2026"},
            ),
            lambda: client.post(
                "/api/v1/auth/refresh",
                headers={"X-Client-Type": "mobile"},
                json={"refresh_token": mob2a["refresh_token"]},
            ),
        )
        assert r_chg_win.status_code == 200
        assert r_ref2a_lose.status_code == 401
        with db_engine.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT COUNT(*) FROM refresh_sessions WHERE user_id = :u AND revoked_at IS NULL"),
                    {"u": uid2a},
                ).scalar_one()
                == 1
            )

        # 2B. Change-Password vs Refresh — Refresh wins first -> Change revokes child & leaves ONLY its 1 new session!
        uid2b = _register_and_verify_user(client, sent_payloads, email="conc2b@example.com")
        mob2b = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "conc2b@example.com", "password": "StrongPassword!2026"},
        ).json()
        r_ref2b_win, r_chg2b_second = _run_ordered_pair(
            "refresh_session_token",
            lambda: client.post(
                "/api/v1/auth/refresh",
                headers={"X-Client-Type": "mobile"},
                json={"refresh_token": mob2b["refresh_token"]},
            ),
            lambda: client.post(
                "/api/v1/auth/change-password",
                headers={"Authorization": f"Bearer {mob2b['access_token']}", "X-Client-Type": "mobile"},
                json={"current_password": "StrongPassword!2026", "new_password": "ChangeSecond!2026"},
            ),
        )
        assert r_ref2b_win.status_code == 200
        assert r_chg2b_second.status_code == 200
        escaped_child = r_ref2b_win.json()
        assert (
            client.post(
                "/api/v1/auth/refresh",
                headers={"X-Client-Type": "mobile"},
                json={"refresh_token": escaped_child["refresh_token"]},
            ).status_code
            == 401
        )
        with db_engine.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT COUNT(*) FROM refresh_sessions WHERE user_id = :u AND revoked_at IS NULL"),
                    {"u": uid2b},
                ).scalar_one()
                == 1
            )

        # 3A. Change-Password vs Logout-All — Change wins first -> Logout-All fails 401, new session survives
        _register_and_verify_user(client, sent_payloads, email="conc3a@example.com")
        mob3a = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "conc3a@example.com", "password": "StrongPassword!2026"},
        ).json()
        r_chg3a, r_lall3a = _run_ordered_pair(
            "change_password",
            lambda: client.post(
                "/api/v1/auth/change-password",
                headers={"Authorization": f"Bearer {mob3a['access_token']}", "X-Client-Type": "mobile"},
                json={"current_password": "StrongPassword!2026", "new_password": "ChangeOverLall!2026"},
            ),
            lambda: client.post(
                "/api/v1/auth/logout-all",
                headers={"Authorization": f"Bearer {mob3a['access_token']}"},
            ),
        )
        assert r_chg3a.status_code == 200
        assert r_lall3a.status_code == 401
        assert (
            client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {r_chg3a.json()['access_token']}"},
            ).status_code
            == 200
        )

        # 3B. Change-Password vs Logout-All — Logout-All wins first -> Change rejects 401 (password unchanged)
        uid3b = _register_and_verify_user(client, sent_payloads, email="conc3b@example.com")
        mob3b = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "conc3b@example.com", "password": "StrongPassword!2026"},
        ).json()
        r_lall3b, r_chg3b = _run_ordered_pair(
            "logout_all_sessions",
            lambda: client.post(
                "/api/v1/auth/logout-all",
                headers={"Authorization": f"Bearer {mob3b['access_token']}"},
            ),
            lambda: client.post(
                "/api/v1/auth/change-password",
                headers={"Authorization": f"Bearer {mob3b['access_token']}", "X-Client-Type": "mobile"},
                json={"current_password": "StrongPassword!2026", "new_password": "LallBlockedChange!2026"},
            ),
        )
        assert r_lall3b.status_code == 200
        assert r_chg3b.status_code == 401
        assert r_chg3b.json()["error"]["details"]["code"] == "INVALID_ACCESS_TOKEN"
        with db_engine.connect() as conn:
            pw_hash = conn.execute(
                text("SELECT password_hash FROM users WHERE id = :u"),
                {"u": uid3b},
            ).scalar_one()
            assert verify_password("StrongPassword!2026", pw_hash)

        # 4. Same-token concurrent /reset-password -> exactly one 200 and one 400
        uid4 = _register_and_verify_user(client, sent_payloads, email="conc4@example.com")
        sent_payloads.clear()
        client.post("/api/v1/auth/forgot-password", json={"email": "conc4@example.com"})
        rtok4 = _extract_token_from_email_params(sent_payloads[-1], "/reset-password")
        r4a, r4b = _run_ordered_pair(
            "reset_password",
            lambda: client.post(
                "/api/v1/auth/reset-password",
                json={"token": rtok4, "new_password": "RaceResetA!2026"},
            ),
            lambda: client.post(
                "/api/v1/auth/reset-password",
                json={"token": rtok4, "new_password": "RaceResetB!2026"},
            ),
        )
        assert r4a.status_code == 200
        assert r4b.status_code == 400
        assert r4b.json()["error"]["details"]["code"] == "INVALID_RESET_TOKEN"
        with db_engine.connect() as conn:
            assert (
                conn.execute(text("SELECT auth_version FROM users WHERE id = :u"), {"u": uid4}).scalar_one()
                == 1
            )

        # 5. Concurrent same-JWT /change-password -> 200 and 401 + full DB & credential verification
        uid5 = _register_and_verify_user(client, sent_payloads, email="conc5@example.com")
        mob5 = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "conc5@example.com", "password": "StrongPassword!2026"},
        ).json()
        with db_engine.connect() as conn:
            old_fam5 = conn.execute(
                text("SELECT family_id FROM refresh_sessions WHERE user_id = :u"),
                {"u": uid5},
            ).scalar_one()

        r5a, r5b = _run_ordered_pair(
            "change_password",
            lambda: client.post(
                "/api/v1/auth/change-password",
                headers={"Authorization": f"Bearer {mob5['access_token']}", "X-Client-Type": "mobile"},
                json={"current_password": "StrongPassword!2026", "new_password": "RaceChangeA!2026"},
            ),
            lambda: client.post(
                "/api/v1/auth/change-password",
                headers={"Authorization": f"Bearer {mob5['access_token']}", "X-Client-Type": "mobile"},
                json={"current_password": "StrongPassword!2026", "new_password": "RaceChangeB!2026"},
            ),
        )
        assert r5a.status_code == 200
        assert r5b.status_code == 401
        assert r5b.json()["error"]["details"]["code"] == "INVALID_ACCESS_TOKEN"
        r5a_body = r5a.json()
        with db_engine.connect() as conn:
            u5 = conn.execute(
                text("SELECT auth_version, password_changed_at, password_hash FROM users WHERE id = :u"),
                {"u": uid5},
            ).mappings().one()
            assert u5["auth_version"] == 1
            assert u5["password_changed_at"] is not None
            assert verify_password("RaceChangeA!2026", u5["password_hash"])
            assert not verify_password("RaceChangeB!2026", u5["password_hash"])

            s5_active = conn.execute(
                text(
                    "SELECT family_id, token_hash FROM refresh_sessions "
                    "WHERE user_id = :u AND revoked_at IS NULL"
                ),
                {"u": uid5},
            ).mappings().one()
            assert s5_active["family_id"] != old_fam5
            assert s5_active["token_hash"] == hash_opaque_token(r5a_body["refresh_token"])
            s5_revoked = conn.execute(
                text(
                    "SELECT revoke_reason FROM refresh_sessions "
                    "WHERE user_id = :u AND revoked_at IS NOT NULL"
                ),
                {"u": uid5},
            ).scalars().all()
            assert s5_revoked == ["password_changed"]

        assert (
            client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {r5a_body['access_token']}"},
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/api/v1/auth/refresh",
                headers={"X-Client-Type": "mobile"},
                json={"refresh_token": r5a_body["refresh_token"]},
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/api/v1/auth/login",
                headers={"X-Client-Type": "mobile"},
                json={"email": "conc5@example.com", "password": "RaceChangeA!2026"},
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/api/v1/auth/login",
                headers={"X-Client-Type": "mobile"},
                json={"email": "conc5@example.com", "password": "RaceChangeB!2026"},
            ).status_code
            == 401
        )

        # 6A. Concurrent /reset-password wins vs /change-password loses
        uid6 = _register_and_verify_user(client, sent_payloads, email="conc6@example.com")
        mob6 = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "conc6@example.com", "password": "StrongPassword!2026"},
        ).json()
        sent_payloads.clear()
        client.post("/api/v1/auth/forgot-password", json={"email": "conc6@example.com"})
        rtok6 = _extract_token_from_email_params(sent_payloads[-1], "/reset-password")
        r6_reset, r6_chg = _run_ordered_pair(
            "reset_password",
            lambda: client.post(
                "/api/v1/auth/reset-password",
                json={"token": rtok6, "new_password": "ResetBeatChg!2026"},
            ),
            lambda: client.post(
                "/api/v1/auth/change-password",
                headers={"Authorization": f"Bearer {mob6['access_token']}", "X-Client-Type": "mobile"},
                json={"current_password": "StrongPassword!2026", "new_password": "ChgLost!2026"},
            ),
        )
        assert r6_reset.status_code == 200
        assert r6_chg.status_code == 401
        assert r6_chg.json()["error"]["details"]["code"] == "INVALID_ACCESS_TOKEN"
        with db_engine.connect() as conn:
            u6 = conn.execute(
                text("SELECT auth_version, password_changed_at, password_hash FROM users WHERE id = :u"),
                {"u": uid6},
            ).mappings().one()
            assert u6["auth_version"] == 1
            assert u6["password_changed_at"] is not None
            assert verify_password("ResetBeatChg!2026", u6["password_hash"])
            t6 = conn.execute(
                text("SELECT consumed_at, revoked_at FROM password_reset_tokens WHERE token_hash = :th"),
                {"th": hash_opaque_token(rtok6)},
            ).mappings().one()
            assert t6["consumed_at"] is not None and t6["revoked_at"] is None
            s6 = conn.execute(
                text("SELECT revoked_at, revoke_reason FROM refresh_sessions WHERE user_id = :u"),
                {"u": uid6},
            ).mappings().all()
            assert len(s6) == 1 and s6[0]["revoked_at"] is not None and s6[0]["revoke_reason"] == "password_reset"
        assert (
            client.post(
                "/api/v1/auth/login",
                headers={"X-Client-Type": "mobile"},
                json={"email": "conc6@example.com", "password": "ResetBeatChg!2026"},
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/api/v1/auth/login",
                headers={"X-Client-Type": "mobile"},
                json={"email": "conc6@example.com", "password": "ChgLost!2026"},
            ).status_code
            == 401
        )

        # 6B. Concurrent /change-password wins vs /reset-password loses
        uid7 = _register_and_verify_user(client, sent_payloads, email="conc7@example.com")
        mob7 = client.post(
            "/api/v1/auth/login",
            headers={"X-Client-Type": "mobile"},
            json={"email": "conc7@example.com", "password": "StrongPassword!2026"},
        ).json()
        with db_engine.connect() as conn:
            old_fam7 = conn.execute(
                text("SELECT family_id FROM refresh_sessions WHERE user_id = :u"),
                {"u": uid7},
            ).scalar_one()
        sent_payloads.clear()
        client.post("/api/v1/auth/forgot-password", json={"email": "conc7@example.com"})
        rtok7 = _extract_token_from_email_params(sent_payloads[-1], "/reset-password")
        r7_chg, r7_reset = _run_ordered_pair(
            "change_password",
            lambda: client.post(
                "/api/v1/auth/change-password",
                headers={"Authorization": f"Bearer {mob7['access_token']}", "X-Client-Type": "mobile"},
                json={"current_password": "StrongPassword!2026", "new_password": "ChgBeatReset!2026"},
            ),
            lambda: client.post(
                "/api/v1/auth/reset-password",
                json={"token": rtok7, "new_password": "ResetLost!2026"},
            ),
        )
        assert r7_chg.status_code == 200
        assert r7_reset.status_code == 400
        assert r7_reset.json()["error"]["details"]["code"] == "INVALID_RESET_TOKEN"
        r7_body = r7_chg.json()
        with db_engine.connect() as conn:
            u7 = conn.execute(
                text("SELECT auth_version, password_changed_at, password_hash FROM users WHERE id = :u"),
                {"u": uid7},
            ).mappings().one()
            assert u7["auth_version"] == 1
            assert u7["password_changed_at"] is not None
            assert verify_password("ChgBeatReset!2026", u7["password_hash"])
            t7 = conn.execute(
                text("SELECT consumed_at, revoked_at FROM password_reset_tokens WHERE token_hash = :th"),
                {"th": hash_opaque_token(rtok7)},
            ).mappings().one()
            assert t7["consumed_at"] is None and t7["revoked_at"] is not None
            s7_active = conn.execute(
                text(
                    "SELECT family_id, token_hash FROM refresh_sessions "
                    "WHERE user_id = :u AND revoked_at IS NULL"
                ),
                {"u": uid7},
            ).mappings().one()
            assert s7_active["family_id"] != old_fam7
            assert s7_active["token_hash"] == hash_opaque_token(r7_body["refresh_token"])
            s7_rev = conn.execute(
                text(
                    "SELECT revoke_reason FROM refresh_sessions "
                    "WHERE user_id = :u AND revoked_at IS NOT NULL"
                ),
                {"u": uid7},
            ).scalars().all()
            assert s7_rev == ["password_changed"]
        assert (
            client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {r7_body['access_token']}"},
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/api/v1/auth/login",
                headers={"X-Client-Type": "mobile"},
                json={"email": "conc7@example.com", "password": "ChgBeatReset!2026"},
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/api/v1/auth/login",
                headers={"X-Client-Type": "mobile"},
                json={"email": "conc7@example.com", "password": "ResetLost!2026"},
            ).status_code
            == 401
        )

        # 7A & 7B. Two-distinct-token concurrent /reset-password (both win orders)
        for idx, (win_tok_first, email_addr, pw_win, pw_lose) in enumerate(
            [
                (True, "conc8a@example.com", "DistinctResetA!2026", "DistinctResetB!2026"),
                (False, "conc8b@example.com", "DistinctResetB2!2026", "DistinctResetA2!2026"),
            ]
        ):
            uid_d = _register_and_verify_user(client, sent_payloads, email=email_addr)
            assert (
                client.post(
                    "/api/v1/auth/login",
                    headers={"X-Client-Type": "mobile"},
                    json={"email": email_addr, "password": "StrongPassword!2026"},
                ).status_code
                == 200
            )
            tok_1 = f"distinct-token-one-{idx}"
            tok_2 = f"distinct-token-two-{idx}"
            with db_engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO password_reset_tokens "
                        "(user_id, token_hash, delivery_status, expires_at) VALUES "
                        "(:u, :th1, 'sent', now() + interval '30 minutes'), "
                        "(:u, :th2, 'sent', now() + interval '30 minutes')"
                    ),
                    {
                        "u": uid_d,
                        "th1": hash_opaque_token(tok_1),
                        "th2": hash_opaque_token(tok_2),
                    },
                )

            win_tok, lose_tok = (tok_1, tok_2) if win_tok_first else (tok_2, tok_1)
            r_win, r_lose = _run_ordered_pair(
                "reset_password",
                lambda wt=win_tok, wp=pw_win: client.post(
                    "/api/v1/auth/reset-password",
                    json={"token": wt, "new_password": wp},
                ),
                lambda lt=lose_tok, lp=pw_lose: client.post(
                    "/api/v1/auth/reset-password",
                    json={"token": lt, "new_password": lp},
                ),
            )
            assert r_win.status_code == 200
            assert r_lose.status_code == 400
            assert r_lose.json()["error"]["details"]["code"] == "INVALID_RESET_TOKEN"

            with db_engine.connect() as conn:
                u_d = conn.execute(
                    text("SELECT auth_version, password_changed_at, password_hash FROM users WHERE id = :u"),
                    {"u": uid_d},
                ).mappings().one()
                assert u_d["auth_version"] == 1
                assert u_d["password_changed_at"] is not None
                assert verify_password(pw_win, u_d["password_hash"])
                assert not verify_password(pw_lose, u_d["password_hash"])

                win_row = conn.execute(
                    text("SELECT consumed_at, revoked_at FROM password_reset_tokens WHERE token_hash = :th"),
                    {"th": hash_opaque_token(win_tok)},
                ).mappings().one()
                assert win_row["consumed_at"] is not None and win_row["revoked_at"] is None

                lose_row = conn.execute(
                    text("SELECT consumed_at, revoked_at FROM password_reset_tokens WHERE token_hash = :th"),
                    {"th": hash_opaque_token(lose_tok)},
                ).mappings().one()
                assert lose_row["consumed_at"] is None and lose_row["revoked_at"] is not None

                sess_d = conn.execute(
                    text("SELECT revoked_at, revoke_reason FROM refresh_sessions WHERE user_id = :u"),
                    {"u": uid_d},
                ).mappings().all()
                assert len(sess_d) == 1
                assert sess_d[0]["revoked_at"] is not None
                assert sess_d[0]["revoke_reason"] == "password_reset"

            assert (
                client.post(
                    "/api/v1/auth/login",
                    headers={"X-Client-Type": "mobile"},
                    json={"email": email_addr, "password": pw_win},
                ).status_code
                == 200
            )
            assert (
                client.post(
                    "/api/v1/auth/login",
                    headers={"X-Client-Type": "mobile"},
                    json={"email": email_addr, "password": pw_lose},
                ).status_code
                == 401
            )
