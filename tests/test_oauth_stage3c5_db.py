"""PostgreSQL integration tests for Stage 3C Substage 3C.5 OAuth Service Orchestration (REV12)."""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import threading
import time
from typing import Any
from urllib.parse import parse_qsl, urlsplit
import uuid

import pytest
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.crypto_keys import decode_aes256_base64url_key
from app.core.exceptions import AppException
from app.core.security import (
    PKCE_VERIFIER_CONSUMED_MARKER,
    decode_access_token,
    encrypt_pkce_verifier,
    generate_pkce_verifier,
    hash_opaque_token,
)
from app.db.session import build_sessionmaker
from app.models.oauth import OAuthAccount, OAuthExchangeCode, OAuthState
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.services.auth_service import logout_all_sessions
from app.services.oauth_providers import (
    GitHubUser,
    GitHubVerifiedEmailRequiredError,
    GoogleIdentity,
    ensure_no_open_db_transaction,
)
import app.services.oauth_providers as oauth_providers
import app.services.oauth_service as oauth_service
from app.services.oauth_service import (
    OAuthCallbackJsonError,
    cleanup_expired_oauth_records,
    exchange_oauth_code,
    handle_oauth_callback,
    list_user_oauth_providers,
    start_oauth_flow,
)
from tests.conftest import verify_test_database_identity
from tests.test_password_flows import _wait_for_pg_lock_wait

pytestmark = pytest.mark.db

PRIMARY_KEY = secrets.token_urlsafe(32)
PREVIOUS_KEY = secrets.token_urlsafe(32)


def _settings(**overrides: Any) -> Settings:
    params: dict[str, Any] = {
        "_env_file": None,
        "ENVIRONMENT": "testing",
        "JWT_SECRET_KEY": "test-jwt-secret-key-at-least-32-chars-long",
        "OAUTH_PKCE_ENCRYPTION_KEY": PRIMARY_KEY,
        "OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS": PREVIOUS_KEY,
        "GOOGLE_CLIENT_ID": "google-client-3c5-db",
        "GOOGLE_CLIENT_SECRET": "google-secret-3c5-db",
        "GITHUB_CLIENT_ID": "github-client-3c5-db",
        "GITHUB_CLIENT_SECRET": "github-secret-3c5-db",
        "CORS_ORIGINS": ["http://localhost:5173", "https://app.folio360.com"],
        "OAUTH_ALLOWED_WEB_REDIRECT_URIS": [
            "http://localhost:5173/auth/oauth/callback",
            "https://app.folio360.com/auth/oauth/callback",
        ],
        "OAUTH_ALLOWED_MOBILE_REDIRECT_URIS": [
            "folio360://auth/callback",
        ],
    }
    params.update(overrides)
    return Settings(**params)


def _exchange_pair(verifier: str | None = None) -> tuple[str, str]:
    raw_verifier = verifier or secrets.token_urlsafe(40)
    digest = hashlib.sha256(raw_verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return raw_verifier, challenge


@pytest.fixture
def clean_oauth_db(db_engine: Engine):
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM oauth_exchange_codes"))
        conn.execute(text("DELETE FROM oauth_accounts"))
        conn.execute(text("DELETE FROM oauth_states"))
        conn.execute(text("DELETE FROM refresh_sessions"))
        conn.execute(text("DELETE FROM users"))
    yield
    with db_engine.begin() as conn:
        conn.execute(text("DELETE FROM oauth_exchange_codes"))
        conn.execute(text("DELETE FROM oauth_accounts"))
        conn.execute(text("DELETE FROM oauth_states"))
        conn.execute(text("DELETE FROM refresh_sessions"))
        conn.execute(text("DELETE FROM users"))


def _state_from_start_url(url: str) -> str:
    return dict(parse_qsl(urlsplit(url).query))["state"]


# ---------------------------------------------------------------------------
# 1. Start Flow Persistence & Cleanup
# ---------------------------------------------------------------------------


def test_start_oauth_flow_persists_state_and_runs_cleanup(
    test_database_url: str,
    db_engine: Engine,
    clean_oauth_db: None,
) -> None:
    verify_test_database_identity(test_database_url, engine=db_engine, allow_migrator=False)
    settings = _settings()
    SessionFactory = build_sessionmaker(db_engine)
    verifier, challenge = _exchange_pair()
    now = datetime.now(timezone.utc)

    # Seed an old expired state that cleanup should remove on /start
    with SessionFactory() as seed_db:
        seed_db.add(
            OAuthState(
                id=uuid.uuid4(),
                state_hash=hash_opaque_token("old-state-1"),
                provider="github",
                client_type="mobile",
                pkce_verifier_encrypted="v1:placeholder",
                nonce_hash=None,
                redirect_uri="folio360://auth/callback",
                client_binding_hash=None,
                exchange_code_challenge_hash="a" * 64,
                expires_at=now - timedelta(minutes=5),
                consumed_at=None,
            )
        )
        seed_db.commit()

    with SessionFactory() as db:
        res = start_oauth_flow(
            db,
            provider="google",
            client_type="web",
            redirect_uri="http://localhost:5173/auth/oauth/callback",
            exchange_code_challenge=challenge,
            settings=settings,
            now=now,
        )
        raw_state = _state_from_start_url(res.authorization_url)
        assert res.binding_cookie_value is not None

    with SessionFactory() as verify_db:
        rows = verify_db.execute(select(OAuthState)).scalars().all()
        assert len(rows) == 1
        assert rows[0].state_hash == hash_opaque_token(raw_state)
        assert rows[0].consumed_at is None


# ---------------------------------------------------------------------------
# 2. Callback State Machine (Orders 1-12, Checkpoints, S3C2-F1, Concurrency)
# ---------------------------------------------------------------------------


def test_callback_orders_1_to_12_consume_scrub_and_replay_on_postgres(
    db_engine: Engine,
    clean_oauth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    SessionFactory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)

    # Orders 1-3: invalid provider, missing/duplicate/oversized/unknown state -> JSON 400
    with SessionFactory() as db:
        for kwargs, code in [
            ({"provider": "facebook", "state_values": ["x"]}, "INVALID_OAUTH_PROVIDER"),
            ({"provider": "google", "state_values": []}, "INVALID_OAUTH_STATE"),
            ({"provider": "google", "state_values": ["   "]}, "INVALID_OAUTH_STATE"),
            ({"provider": "google", "state_values": ["a", "b"]}, "INVALID_OAUTH_STATE"),
            ({"provider": "google", "state_values": ["x" * 257]}, "INVALID_OAUTH_STATE"),
            ({"provider": "google", "state_values": ["unknown-state"]}, "INVALID_OAUTH_STATE"),
        ]:
            with pytest.raises(OAuthCallbackJsonError) as exc_json:
                handle_oauth_callback(db, settings=settings, **kwargs)
            assert exc_json.value.status_code == 400
            assert exc_json.value.details == {"code": code}
            assert exc_json.value.clear_binding_cookie_mode == "if_present"

    # Orders 4, 5, 6, 7, 8, 9a, 9b, 10, 11
    def _seed_state(
        *,
        provider: str = "google",
        client_type: str = "web",
        expires_delta: timedelta = timedelta(minutes=10),
        consumed_at: datetime | None = None,
        created_at: datetime | None = None,
        use_previous_key: bool = False,
        redirect_uri: str = "http://localhost:5173/auth/oauth/callback",
    ) -> tuple[str, str | None]:
        raw_state = secrets.token_urlsafe(32)
        state_hash = hash_opaque_token(raw_state)
        binding_cookie = secrets.token_urlsafe(32) if client_type == "web" else None
        verifier = generate_pkce_verifier()
        if consumed_at is not None:
            enc = PKCE_VERIFIER_CONSUMED_MARKER
        else:
            key_str = PREVIOUS_KEY if use_previous_key else PRIMARY_KEY
            raw_key = decode_aes256_base64url_key(key_str, field_name="key")
            enc = encrypt_pkce_verifier(
                verifier, key=raw_key, provider=provider, state_hash=state_hash
            )
        row = OAuthState(
            id=uuid.uuid4(),
            state_hash=state_hash,
            provider=provider,
            client_type=client_type,
            pkce_verifier_encrypted=enc,
            nonce_hash=hash_opaque_token("n" * 43) if provider == "google" else None,
            redirect_uri=redirect_uri,
            client_binding_hash=(
                hash_opaque_token(binding_cookie) if binding_cookie is not None else None
            ),
            exchange_code_challenge_hash="b" * 64,
            expires_at=now + expires_delta,
            consumed_at=consumed_at,
        )
        if created_at is not None:
            row.created_at = created_at
        with SessionFactory() as s:
            s.add(row)
            s.commit()
        return raw_state, binding_cookie

    def _assert_state_row(raw_state: str, *, consumed: bool) -> None:
        with SessionFactory() as s:
            row = s.execute(
                select(OAuthState).where(OAuthState.state_hash == hash_opaque_token(raw_state))
            ).scalar_one()
            if consumed:
                assert row.consumed_at is not None
                assert row.pkce_verifier_encrypted == PKCE_VERIFIER_CONSUMED_MARKER
            else:
                assert row.consumed_at is None

    # Order 4 (consumed) & Order 5 (expired) -> roll back untouched
    s4, b4 = _seed_state(consumed_at=now - timedelta(minutes=1))
    s5, b5 = _seed_state(expires_delta=timedelta(minutes=-1))
    with SessionFactory() as db:
        r4 = handle_oauth_callback(db, provider="google", state_values=[s4], code_values=["c"], binding_cookie=b4, settings=settings, now=now)
        assert "error=invalid_oauth_state" in r4.redirect_url and r4.clear_binding_cookie is True
        r5 = handle_oauth_callback(db, provider="google", state_values=[s5], code_values=["c"], binding_cookie=b5, settings=settings, now=now)
        assert "error=invalid_oauth_state" in r5.redirect_url and r5.clear_binding_cookie is True
    with SessionFactory() as s:
        row5 = s.execute(select(OAuthState).where(OAuthState.state_hash == hash_opaque_token(s5))).scalar_one()
        assert row5.consumed_at is None and row5.pkce_verifier_encrypted != PKCE_VERIFIER_CONSUMED_MARKER

    # Order 6 (provider mismatch) -> consumed/scrubbed
    s6, b6 = _seed_state(provider="google")
    with SessionFactory() as db:
        r6 = handle_oauth_callback(db, provider="github", state_values=[s6], code_values=["c"], binding_cookie=b6, settings=settings, now=now)
        assert "error=invalid_oauth_state" in r6.redirect_url
    _assert_state_row(s6, consumed=True)

    # Order 7 (matching active provider unconfigured) -> JSON 503 untouched
    s7, b7 = _seed_state(provider="github")
    gh_unconf = _settings(GITHUB_CLIENT_ID=None, GITHUB_CLIENT_SECRET=None)
    with SessionFactory() as db:
        with pytest.raises(OAuthCallbackJsonError) as e7:
            handle_oauth_callback(db, provider="github", state_values=[s7], code_values=["c"], binding_cookie=b7, settings=gh_unconf, now=now)
        assert e7.value.status_code == 503
        assert e7.value.clear_binding_cookie_mode == "always"
    _assert_state_row(s7, consumed=False)

    # Order 8 (binding cookie mismatch) -> consumed/scrubbed
    s8, _ = _seed_state(provider="google", client_type="web")
    with SessionFactory() as db:
        r8 = handle_oauth_callback(db, provider="google", state_values=[s8], code_values=["c"], binding_cookie="wrong-cookie", settings=settings, now=now)
        assert "error=invalid_oauth_state" in r8.redirect_url
    _assert_state_row(s8, consumed=True)

    # Order 9a (malformed/duplicate/whitespace code), 9b (access_denied), 10 (other error/missing)
    s9a, b9a = _seed_state(provider="github")
    s9b, b9b = _seed_state(provider="github")
    s10, b10 = _seed_state(provider="github")
    with SessionFactory() as db:
        r9a = handle_oauth_callback(db, provider="github", state_values=[s9a], code_values=["bad code"], binding_cookie=b9a, settings=settings, now=now)
        assert "error=oauth_provider_error" in r9a.redirect_url
        r9b = handle_oauth_callback(db, provider="github", state_values=[s9b], error_values=["access_denied"], binding_cookie=b9b, settings=settings, now=now)
        assert "error=oauth_cancelled" in r9b.redirect_url
        r10 = handle_oauth_callback(db, provider="github", state_values=[s10], binding_cookie=b10, settings=settings, now=now)
        assert "error=oauth_provider_error" in r10.redirect_url
    for st in (s9a, s9b, s10):
        _assert_state_row(st, consumed=True)

    # Order 11 (S3C2-F1 expired previous-key window rejected & scrubbed on real PostgreSQL row)
    s11, _ = _seed_state(
        provider="github",
        client_type="mobile",
        created_at=now - timedelta(minutes=20),
        expires_delta=timedelta(minutes=20),
        use_previous_key=True,
        redirect_uri="folio360://auth/callback",
    )
    with SessionFactory() as db:
        r11 = handle_oauth_callback(db, provider="github", state_values=[s11], code_values=["valid-code"], settings=settings, now=now)
        assert "error=oauth_provider_error" in r11.redirect_url
    _assert_state_row(s11, consumed=True)

    # Order 12 Checkpoint 1 (redirect_uri no longer in allowlist) -> scrub + JSON 400, zero Phase 2 HTTP
    s12, _ = _seed_state(
        provider="github",
        client_type="mobile",
        redirect_uri="folio360://auth/callback",
    )
    narrowed = _settings(OAUTH_ALLOWED_MOBILE_REDIRECT_URIS=["folio360://other/cb"])
    with SessionFactory() as db:
        with pytest.raises(OAuthCallbackJsonError) as e12:
            handle_oauth_callback(db, provider="github", state_values=[s12], code_values=["valid-code"], settings=narrowed, now=now)
        assert e12.value.status_code == 400 and e12.value.details == {"code": "INVALID_REDIRECT_URI"}
    _assert_state_row(s12, consumed=True)


def test_concurrent_callback_replay_blocks_on_for_update_and_runs_phase2_once(
    db_engine: Engine,
    clean_oauth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    SessionFactory = build_sessionmaker(db_engine)
    _, challenge = _exchange_pair()

    with SessionFactory() as db:
        start_res = start_oauth_flow(
            db,
            provider="github",
            client_type="mobile",
            redirect_uri="folio360://auth/callback",
            exchange_code_challenge=challenge,
            settings=settings,
        )
    raw_state = _state_from_start_url(start_res.authorization_url)

    phase2_calls = 0
    monkeypatch.setattr(
        oauth_service,
        "exchange_github_authorization_code",
        lambda db, **kw: (ensure_no_open_db_transaction(db), "gh-tok")[1],
    )

    def _fake_gh_user(db: Session, **kw: Any) -> GitHubUser:
        nonlocal phase2_calls
        ensure_no_open_db_transaction(db)
        phase2_calls += 1
        return GitHubUser(provider_user_id="999001")

    monkeypatch.setattr(oauth_service, "fetch_github_user", _fake_gh_user)
    monkeypatch.setattr(
        oauth_service,
        "fetch_github_verified_email",
        lambda db, **kw: "concurrent.gh@example.com",
    )

    # Force Worker 1 to hold the PostgreSQL FOR UPDATE row lock inside Phase 1 until Worker 2 blocks
    locked_in_phase1 = threading.Event()
    release_phase1 = threading.Event()
    orig_consume = oauth_service._consume_and_scrub_state
    once_lock = threading.Lock()
    paused_once = False

    def _pausing_consume(state_row: OAuthState, ts: datetime) -> None:
        nonlocal paused_once
        with once_lock:
            should_pause = not paused_once
            if should_pause:
                paused_once = True
        if should_pause:
            locked_in_phase1.set()
            release_phase1.wait(timeout=5.0)
        orig_consume(state_row, ts)

    monkeypatch.setattr(oauth_service, "_consume_and_scrub_state", _pausing_consume)

    worker_results: list[Any] = []
    worker_errors: list[BaseException] = []

    def _callback_worker(code_val: str) -> None:
        try:
            with SessionFactory() as wdb:
                res = handle_oauth_callback(
                    wdb,
                    provider="github",
                    state_values=[raw_state],
                    code_values=[code_val],
                    settings=settings,
                )
                worker_results.append(res)
        except BaseException as exc:  # pragma: no cover
            worker_errors.append(exc)

    t1 = threading.Thread(target=_callback_worker, args=("code-1",))
    t2 = threading.Thread(target=_callback_worker, args=("code-2",))
    t1.start()
    assert locked_in_phase1.wait(timeout=5.0)
    t2.start()
    _wait_for_pg_lock_wait(db_engine)
    release_phase1.set()
    t1.join(timeout=5.0)
    t2.join(timeout=5.0)

    assert not worker_errors
    assert len(worker_results) == 2
    redirects = sorted(r.redirect_url for r in worker_results)
    assert any("code=" in url for url in redirects)
    assert any("error=invalid_oauth_state" in url for url in redirects)
    assert phase2_calls == 1


# ---------------------------------------------------------------------------
# 3. REV12-1 GitHub Fast-Path Hit/Miss + SAVEPOINT + D20 + Google Returning
# ---------------------------------------------------------------------------


def test_rev12_1_github_fast_path_hit_and_miss_close_transaction(
    db_engine: Engine,
    clean_oauth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    SessionFactory = build_sessionmaker(db_engine)

    # 1. Miss path (new GitHub user)
    _, ch_miss = _exchange_pair()
    with SessionFactory() as db:
        st_miss = _state_from_start_url(
            start_oauth_flow(
                db,
                provider="github",
                client_type="mobile",
                redirect_uri="folio360://auth/callback",
                exchange_code_challenge=ch_miss,
                settings=settings,
            ).authorization_url
        )

    email_fetch_calls: list[bool] = []
    monkeypatch.setattr(oauth_service, "exchange_github_authorization_code", lambda db, **kw: "gh-tok")
    monkeypatch.setattr(oauth_service, "fetch_github_user", lambda db, **kw: GitHubUser("gh-fast-42"))

    def _spy_emails(db: Session, **kw: Any) -> str:
        # REV12-1: transaction MUST be closed before paginated /user/emails
        assert db.in_transaction() is False
        ensure_no_open_db_transaction(db)
        email_fetch_calls.append(True)
        return "gh.fast@example.com"

    monkeypatch.setattr(oauth_service, "fetch_github_verified_email", _spy_emails)

    with SessionFactory() as db:
        res_miss = handle_oauth_callback(
            db,
            provider="github",
            state_values=[st_miss],
            code_values=["c-miss"],
            settings=settings,
        )
        assert "code=" in res_miss.redirect_url
        assert len(email_fetch_calls) == 1

    # 2. Hit path (returning GitHub user): /user/emails skipped AND db.rollback() closes autobegin before Phase 3!
    rollback_spy_count = 0

    _, ch_hit = _exchange_pair()
    with SessionFactory() as db:
        st_hit = _state_from_start_url(
            start_oauth_flow(
                db,
                provider="github",
                client_type="mobile",
                redirect_uri="folio360://auth/callback",
                exchange_code_challenge=ch_hit,
                settings=settings,
            ).authorization_url
        )

    real_guard = oauth_service.ensure_no_open_db_transaction
    guard_observations: list[bool] = []

    def _spy_guard(db_arg: Session) -> None:
        real_guard(db_arg)
        guard_observations.append(db_arg.in_transaction())

    monkeypatch.setattr(oauth_service, "ensure_no_open_db_transaction", _spy_guard)
    with SessionFactory() as db:
        orig_rollback = db.rollback

        def _counting_rollback() -> None:
            nonlocal rollback_spy_count
            rollback_spy_count += 1
            orig_rollback()

        monkeypatch.setattr(db, "rollback", _counting_rollback)
        res_hit = handle_oauth_callback(
            db,
            provider="github",
            state_values=[st_hit],
            code_values=["c-hit"],
            settings=settings,
        )
        assert "code=" in res_hit.redirect_url
        assert len(email_fetch_calls) == 1  # skipped /user/emails!
        assert rollback_spy_count >= 1
        assert guard_observations and all(tx is False for tx in guard_observations)


def test_phase3_savepoint_3way_recovery_d20_and_google_returning_refinements(
    db_engine: Engine,
    clean_oauth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    SessionFactory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)

    # Seed existing password user with existing@example.com
    with SessionFactory() as s:
        existing_user = User(
            id=uuid.uuid4(),
            email="existing@example.com",
            password_hash="argon2-hash",
            is_active=True,
            is_email_verified=True,
            email_verified_at=now,
            auth_version=0,
        )
        s.add(existing_user)
        s.commit()

    def _new_google_state() -> str:
        _, ch = _exchange_pair()
        with SessionFactory() as s:
            return _state_from_start_url(
                start_oauth_flow(
                    s,
                    provider="google",
                    client_type="mobile",
                    redirect_uri="folio360://auth/callback",
                    exchange_code_challenge=ch,
                    settings=settings,
                ).authorization_url
            )

    monkeypatch.setattr(oauth_service, "exchange_google_authorization_code", lambda db, **kw: "id-tok")
    monkeypatch.setattr(oauth_service, "ensure_no_open_db_transaction", ensure_no_open_db_transaction)
    fake_jwk = object()

    # Way 1: uq_users_email -> 302 email_already_registered (D05 zero auto-merge)
    monkeypatch.setattr(
        oauth_service,
        "verify_google_id_token",
        lambda db, **kw: GoogleIdentity("sub-new-collision", "existing@example.com", True),
    )
    with SessionFactory() as db:
        r_dup_email = handle_oauth_callback(
            db,
            provider="google",
            state_values=[_new_google_state()],
            code_values=["c1"],
            settings=settings,
            jwk_client=fake_jwk,  # type: ignore[arg-type]
        )
        assert "error=email_already_registered" in r_dup_email.redirect_url

    # Way 2: uq_oauth_accounts_provider_subject concurrent creation race inside SAVEPOINT
    # Simulate sibling committing the new OAuthAccount right when db.begin_nested() exits
    st_race = _new_google_state()
    monkeypatch.setattr(
        oauth_service,
        "verify_google_id_token",
        lambda db, **kw: GoogleIdentity("sub-race-win", "race.winner@example.com", True),
    )
    with SessionFactory() as db:
        orig_begin_nested = db.begin_nested

        def _race_commit_during_savepoint() -> Any:
            # Sibling commits the same (provider, provider_user_id) with a distinct email before SAVEPOINT inserts
            with SessionFactory() as sibling:
                sib_user = User(
                    id=uuid.uuid4(),
                    email="race.sibling.old@example.com",
                    password_hash=None,
                    is_active=True,
                    is_email_verified=True,
                    email_verified_at=now,
                    auth_version=0,
                )
                sibling.add(sib_user)
                sibling.flush()
                sibling.add(
                    OAuthAccount(
                        id=uuid.uuid4(),
                        user_id=sib_user.id,
                        provider="google",
                        provider_user_id="sub-race-win",
                        provider_email="old.email@example.com",
                        provider_email_verified=True,
                    )
                )
                sibling.commit()
            return orig_begin_nested()

        monkeypatch.setattr(db, "begin_nested", _race_commit_during_savepoint)
        r_race = handle_oauth_callback(
            db,
            provider="google",
            state_values=[st_race],
            code_values=["c2"],
            settings=settings,
            jwk_client=fake_jwk,  # type: ignore[arg-type]
        )
        assert "code=" in r_race.redirect_url

    # Verify D20: User.email remained sibling's original email, OAuthAccount.provider_email refreshed cleanly
    with SessionFactory() as s:
        oa = s.execute(
            select(OAuthAccount).where(OAuthAccount.provider_user_id == "sub-race-win")
        ).scalar_one()
        u = s.execute(select(User).where(User.id == oa.user_id)).scalar_one()
        assert u.email == "race.sibling.old@example.com"
        assert oa.provider_email == "race.winner@example.com"
        assert oa.provider_email_verified is True

    # Returning Google permits email_verified=False & absent email without overwriting prior verified provider_email
    monkeypatch.setattr(
        oauth_service,
        "verify_google_id_token",
        lambda db, **kw: GoogleIdentity("sub-race-win", None, False),
    )
    with SessionFactory() as db:
        r_ret_no_email = handle_oauth_callback(
            db,
            provider="google",
            state_values=[_new_google_state()],
            code_values=["c3"],
            settings=settings,
            jwk_client=fake_jwk,  # type: ignore[arg-type]
        )
        assert "code=" in r_ret_no_email.redirect_url
    with SessionFactory() as s:
        oa_after = s.execute(
            select(OAuthAccount).where(OAuthAccount.provider_user_id == "sub-race-win")
        ).scalar_one()
        assert oa_after.provider_email == "race.winner@example.com"

    # Way 3: uq_oauth_accounts_user_provider -> raise inside SAVEPOINT triggers oauth_provider_error redirect
    st_up = _new_google_state()
    monkeypatch.setattr(
        oauth_service,
        "verify_google_id_token",
        lambda db, **kw: GoogleIdentity("sub-other-err", "brand.new@example.com", True),
    )
    with SessionFactory() as db:
        orig_flush = db.flush

        def _fail_up() -> None:
            if any(isinstance(obj, OAuthAccount) for obj in db.new):
                class _D:
                    constraint_name = "uq_oauth_accounts_user_provider"

                class _O:
                    diag = _D()

                e = IntegrityError("INSERT ...", {}, Exception("up"))
                e.orig = _O()  # type: ignore[assignment]
                raise e
            orig_flush()

        monkeypatch.setattr(db, "flush", _fail_up)
        r_up = handle_oauth_callback(
            db,
            provider="google",
            state_values=[st_up],
            code_values=["c4"],
            settings=settings,
            jwk_client=fake_jwk,  # type: ignore[arg-type]
        )
        assert "error=oauth_provider_error" in r_up.redirect_url

    # New Google account with unverified email -> 302 verified_email_required
    monkeypatch.setattr(
        oauth_service,
        "verify_google_id_token",
        lambda db, **kw: GoogleIdentity("sub-brand-unverified", "unver@example.com", False),
    )
    with SessionFactory() as db:
        r_unv = handle_oauth_callback(
            db,
            provider="google",
            state_values=[_new_google_state()],
            code_values=["c5"],
            settings=settings,
            jwk_client=fake_jwk,  # type: ignore[arg-type]
        )
        assert "error=verified_email_required" in r_unv.redirect_url


# ---------------------------------------------------------------------------
# 4. Exchange Service, Lock Ordering, Auth Version Races & Atomic Rollback
# ---------------------------------------------------------------------------


def test_exchange_oauth_code_web_mobile_burn_403_atomic_rollback_and_sorted_providers(
    db_engine: Engine,
    clean_oauth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    SessionFactory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)

    with SessionFactory() as s:
        u = User(
            id=uuid.uuid4(),
            email="exchange.user@example.com",
            password_hash=None,
            is_active=True,
            is_email_verified=True,
            email_verified_at=now,
            auth_version=1,
        )
        s.add(u)
        s.flush()
        s.add(OAuthAccount(id=uuid.uuid4(), user_id=u.id, provider="google", provider_user_id="g1"))
        s.add(OAuthAccount(id=uuid.uuid4(), user_id=u.id, provider="github", provider_user_id="gh1"))
        s.commit()
        user_id = u.id
        assert list_user_oauth_providers(s, user_id=user_id) == ["github", "google"]

    def _seed_code(
        *,
        client_type: str = "web",
        auth_version: int = 1,
        expires_delta: timedelta = timedelta(seconds=60),
    ) -> tuple[str, str, str | None]:
        raw_code = secrets.token_urlsafe(32)
        ver, chal = _exchange_pair()
        cookie = secrets.token_urlsafe(32) if client_type == "web" else None
        with SessionFactory() as s:
            s.add(
                OAuthExchangeCode(
                    id=uuid.uuid4(),
                    user_id=user_id,
                    code_hash=hash_opaque_token(raw_code),
                    client_type=client_type,
                    auth_version=auth_version,
                    exchange_code_challenge_hash=hash_opaque_token(chal),
                    exchange_binding_hash=(
                        hash_opaque_token(cookie) if cookie is not None else None
                    ),
                    expires_at=now + expires_delta,
                    consumed_at=None,
                )
            )
            s.commit()
        return raw_code, ver, cookie

    # 1. Wrong valid-format verifier burns code cleanly and fails second attempt
    c_burn, _, cook_burn = _seed_code(client_type="web")
    with SessionFactory() as db:
        with pytest.raises(AppException) as e_wrong:
            exchange_oauth_code(
                db,
                code=c_burn,
                exchange_code_verifier="w" * 48,
                client_type="web",
                exchange_cookie=cook_burn,
                settings=settings,
                now=now,
            )
        assert e_wrong.value.details == {"code": "INVALID_OAUTH_EXCHANGE_CODE"}
    with SessionFactory() as s:
        row_burned = s.execute(
            select(OAuthExchangeCode).where(OAuthExchangeCode.code_hash == hash_opaque_token(c_burn))
        ).scalar_one()
        assert row_burned.consumed_at is not None

    # 2. Web cookie mismatch burns code cleanly
    c_cook, v_cook, _ = _seed_code(client_type="web")
    with SessionFactory() as db:
        with pytest.raises(AppException):
            exchange_oauth_code(
                db,
                code=c_cook,
                exchange_code_verifier=v_cook,
                client_type="web",
                exchange_cookie="wrong-cookie",
                settings=settings,
                now=now,
            )
    with SessionFactory() as s:
        assert (
            s.execute(
                select(OAuthExchangeCode.consumed_at).where(
                    OAuthExchangeCode.code_hash == hash_opaque_token(c_cook)
                )
            ).scalar_one()
            is not None
        )

    # 3. Inactive user -> 403 ACCOUNT_INACTIVE WITHOUT consuming code
    c_inact, v_inact, cook_inact = _seed_code(client_type="web")
    with SessionFactory() as s:
        u_obj = s.execute(select(User).where(User.id == user_id)).scalar_one()
        u_obj.is_active = False
        s.commit()
    with SessionFactory() as db:
        with pytest.raises(AppException) as e_inact:
            exchange_oauth_code(
                db,
                code=c_inact,
                exchange_code_verifier=v_inact,
                client_type="web",
                exchange_cookie=cook_inact,
                settings=settings,
                now=now,
            )
        assert e_inact.value.status_code == 403 and e_inact.value.details == {"code": "ACCOUNT_INACTIVE"}
    with SessionFactory() as s:
        assert (
            s.execute(
                select(OAuthExchangeCode.consumed_at).where(
                    OAuthExchangeCode.code_hash == hash_opaque_token(c_inact)
                )
            ).scalar_one()
            is None
        )
        u_obj = s.execute(select(User).where(User.id == user_id)).scalar_one()
        u_obj.is_active = True
        s.commit()

    # 4. Atomic commit failure rolls back BOTH consumed_at and RefreshSession
    c_fail, v_fail, _ = _seed_code(client_type="mobile")
    with SessionFactory() as db:
        def _boom_commit() -> None:
            raise RuntimeError("simulated commit failure")

        monkeypatch.setattr(db, "commit", _boom_commit)
        with pytest.raises(RuntimeError, match="simulated commit failure"):
            exchange_oauth_code(
                db,
                code=c_fail,
                exchange_code_verifier=v_fail,
                client_type="mobile",
                settings=settings,
                now=now,
            )
    with SessionFactory() as s:
        assert (
            s.execute(
                select(OAuthExchangeCode.consumed_at).where(
                    OAuthExchangeCode.code_hash == hash_opaque_token(c_fail)
                )
            ).scalar_one()
            is None
        )
        assert s.execute(select(RefreshSession).where(RefreshSession.user_id == user_id)).all() == []

    # 5. Valid exchange consumes code and creates RefreshSession atomically
    with SessionFactory() as db:
        out_u, access_jwt, expires_in, rt, rt_exp = exchange_oauth_code(
            db,
            code=c_fail,
            exchange_code_verifier=v_fail,
            client_type="mobile",
            settings=settings,
            now=now,
        )
        assert out_u.id == user_id and expires_in > 0 and rt and rt_exp > 0
        sub_uid, av, _ = decode_access_token(access_jwt, settings)
        assert sub_uid == user_id and av == 1


def test_exchange_vs_logout_all_dual_order_lock_race(
    db_engine: Engine,
    clean_oauth_db: None,
) -> None:
    settings = _settings()
    SessionFactory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)

    with SessionFactory() as s:
        u = User(
            id=uuid.uuid4(),
            email="race.av@example.com",
            password_hash=None,
            is_active=True,
            is_email_verified=True,
            email_verified_at=now,
            auth_version=0,
        )
        s.add(u)
        s.flush()
        raw_code = secrets.token_urlsafe(32)
        ver, chal = _exchange_pair()
        s.add(
            OAuthExchangeCode(
                id=uuid.uuid4(),
                user_id=u.id,
                code_hash=hash_opaque_token(raw_code),
                client_type="mobile",
                auth_version=0,
                exchange_code_challenge_hash=hash_opaque_token(chal),
                exchange_binding_hash=None,
                expires_at=now + timedelta(seconds=60),
                consumed_at=None,
            )
        )
        s.commit()
        user_id = u.id

    # Hold users FOR UPDATE in connection A -> logout_all increments auth_version -> blocked exchange sees new auth_version via populate_existing=True!
    results: list[Any] = []
    with db_engine.connect() as conn_a:
        tx_a = conn_a.begin()
        pid_a = conn_a.execute(text("SELECT pg_backend_pid()")).scalar_one()
        conn_a.execute(text("SELECT id FROM users WHERE id = :uid FOR UPDATE"), {"uid": user_id})

        def _exchange_worker() -> None:
            with SessionFactory() as wdb:
                try:
                    results.append(
                        exchange_oauth_code(
                            wdb,
                            code=raw_code,
                            exchange_code_verifier=ver,
                            client_type="mobile",
                            settings=settings,
                            now=now,
                        )
                    )
                except AppException as exc:
                    results.append(exc)

        t = threading.Thread(target=_exchange_worker)
        t.start()
        _wait_for_pg_lock_wait(db_engine, exclude_pid=pid_a)
        conn_a.execute(text("UPDATE users SET auth_version = auth_version + 1 WHERE id = :uid"), {"uid": user_id})
        tx_a.commit()

    t.join(timeout=5.0)
    assert len(results) == 1
    assert isinstance(results[0], AppException)
    assert results[0].details == {"code": "INVALID_OAUTH_EXCHANGE_CODE"}


# ---------------------------------------------------------------------------
# 5. Bounded SKIP LOCKED Cleanup
# ---------------------------------------------------------------------------


def test_cleanup_expired_oauth_records_bounded_skip_locked_and_grace(
    db_engine: Engine,
    clean_oauth_db: None,
) -> None:
    SessionFactory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)

    with SessionFactory() as s:
        u = User(
            id=uuid.uuid4(),
            email="cleanup@example.com",
            password_hash=None,
            is_active=True,
            is_email_verified=True,
            email_verified_at=now,
            auth_version=0,
        )
        s.add(u)
        s.flush()

        # 105 old expired states + 1 inside 60s grace window
        for idx in range(105):
            s.add(
                OAuthState(
                    id=uuid.uuid4(),
                    state_hash=hash_opaque_token(f"old-{idx}"),
                    provider="github",
                    client_type="mobile",
                    pkce_verifier_encrypted="v1:old",
                    nonce_hash=None,
                    redirect_uri="folio360://auth/callback",
                    client_binding_hash=None,
                    exchange_code_challenge_hash="a" * 64,
                    expires_at=now - timedelta(seconds=120 + idx),
                    consumed_at=None,
                )
            )
        grace_state_id = uuid.uuid4()
        s.add(
            OAuthState(
                id=grace_state_id,
                state_hash=hash_opaque_token("grace-state"),
                provider="github",
                client_type="mobile",
                pkce_verifier_encrypted="v1:grace",
                nonce_hash=None,
                redirect_uri="folio360://auth/callback",
                client_binding_hash=None,
                exchange_code_challenge_hash="b" * 64,
                expires_at=now - timedelta(seconds=30),  # inside 60s grace period
                consumed_at=None,
            )
        )
        # 2 old expired exchange codes + 1 locked row by another connection
        locked_code_id = uuid.uuid4()
        for cid, ch in ((locked_code_id, "locked-c"), (uuid.uuid4(), "free-c-1")):
            s.add(
                OAuthExchangeCode(
                    id=cid,
                    user_id=u.id,
                    code_hash=hash_opaque_token(ch),
                    client_type="mobile",
                    auth_version=0,
                    exchange_code_challenge_hash="c" * 64,
                    exchange_binding_hash=None,
                    expires_at=now - timedelta(seconds=120),
                    consumed_at=None,
                )
            )
        s.commit()

    # Hold FOR UPDATE lock on locked_code_id while running bounded cleanup (batch=100, grace=60)
    with db_engine.connect() as lock_conn:
        tx = lock_conn.begin()
        lock_conn.execute(
            text("SELECT id FROM oauth_exchange_codes WHERE id = :cid FOR UPDATE"),
            {"cid": locked_code_id},
        )
        with SessionFactory() as cleanup_db:
            del_states, del_codes = cleanup_expired_oauth_records(cleanup_db, now=now)
        tx.rollback()

    assert del_states == 100
    assert del_codes == 1  # skipped locked_code_id!

    with SessionFactory() as s:
        remaining_states = s.execute(select(OAuthState.id)).scalars().all()
        assert len(remaining_states) == 6  # 5 overflow old + 1 grace state
        assert grace_state_id in remaining_states
        remaining_codes = s.execute(select(OAuthExchangeCode.id)).scalars().all()
        assert remaining_codes == [locked_code_id]


# ---------------------------------------------------------------------------
# 6. Audit Remediation Tests (S3C5-F1 & S3C5-F3)
# ---------------------------------------------------------------------------


def _seed_mobile_google_state(
    SessionFactory: Any,
    settings: Settings,
) -> str:
    _, challenge = _exchange_pair()
    with SessionFactory() as db:
        return _state_from_start_url(
            start_oauth_flow(
                db,
                provider="google",
                client_type="mobile",
                redirect_uri="folio360://auth/callback",
                exchange_code_challenge=challenge,
                settings=settings,
            ).authorization_url
        )


def test_s3c5_f1_concurrent_first_time_same_email_recovers_winner(
    db_engine: Engine,
    clean_oauth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S3C5-F1: Concurrent first-time callbacks for identical subject & email hit uq_users_email and recover winner."""
    settings = _settings()
    SessionFactory = build_sessionmaker(db_engine)
    st1 = _seed_mobile_google_state(SessionFactory, settings)
    st2 = _seed_mobile_google_state(SessionFactory, settings)

    monkeypatch.setattr(oauth_service, "exchange_google_authorization_code", lambda db, **kw: "id-tok")
    monkeypatch.setattr(
        oauth_service,
        "verify_google_id_token",
        lambda db, **kw: GoogleIdentity("sub-same-email-race", "same.email.race@example.com", True),
    )

    winner_user_flushed = threading.Event()
    release_winner = threading.Event()
    worker_results: list[Any] = []
    worker_errors: list[BaseException] = []
    fake_jwk = object()

    def _run_callback(raw_state: str, code_val: str, *, hold_user_lock: bool) -> None:
        try:
            with SessionFactory() as wdb:
                if hold_user_lock:
                    orig_flush = wdb.flush

                    def _pausing_flush(*args: Any, **kwargs: Any) -> None:
                        inserting_user = any(isinstance(obj, User) for obj in wdb.new)
                        orig_flush(*args, **kwargs)
                        if inserting_user:
                            winner_user_flushed.set()
                            release_winner.wait(timeout=5.0)

                    wdb.flush = _pausing_flush  # type: ignore[method-assign]

                res = handle_oauth_callback(
                    wdb,
                    provider="google",
                    state_values=[raw_state],
                    code_values=[code_val],
                    settings=settings,
                    jwk_client=fake_jwk,  # type: ignore[arg-type]
                )
                worker_results.append(res)
        except BaseException as exc:  # pragma: no cover
            worker_errors.append(exc)

    t_winner = threading.Thread(target=_run_callback, args=(st1, "c-win"), kwargs={"hold_user_lock": True})
    t_loser = threading.Thread(target=_run_callback, args=(st2, "c-lose"), kwargs={"hold_user_lock": False})

    t_winner.start()
    assert winner_user_flushed.wait(timeout=5.0)
    t_loser.start()
    _wait_for_pg_lock_wait(db_engine)
    release_winner.set()
    t_winner.join(timeout=5.0)
    t_loser.join(timeout=5.0)

    assert not worker_errors
    assert len(worker_results) == 2
    assert all("code=" in r.redirect_url for r in worker_results)
    assert all("email_already_registered" not in r.redirect_url for r in worker_results)

    with SessionFactory() as s:
        users = s.execute(select(User).where(User.email == "same.email.race@example.com")).scalars().all()
        accounts = s.execute(
            select(OAuthAccount).where(OAuthAccount.provider_user_id == "sub-same-email-race")
        ).scalars().all()
        codes = s.execute(select(OAuthExchangeCode)).scalars().all()
        assert len(users) == 1
        assert len(accounts) == 1
        assert accounts[0].user_id == users[0].id
        assert len(codes) == 2
        assert all(c.user_id == users[0].id for c in codes)


def test_exchange_vs_logout_all_reverse_order_lock_race(
    db_engine: Engine,
    clean_oauth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S3C5-F3: Reverse lock order (exchange holds users FOR UPDATE while logout_all waits) serializes cleanly."""
    settings = _settings()
    SessionFactory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)

    with SessionFactory() as s:
        u = User(
            id=uuid.uuid4(),
            email="reverse.race@example.com",
            password_hash=None,
            is_active=True,
            is_email_verified=True,
            email_verified_at=now,
            auth_version=0,
        )
        s.add(u)
        s.flush()
        raw_code = secrets.token_urlsafe(32)
        ver, chal = _exchange_pair()
        s.add(
            OAuthExchangeCode(
                id=uuid.uuid4(),
                user_id=u.id,
                code_hash=hash_opaque_token(raw_code),
                client_type="mobile",
                auth_version=0,
                exchange_code_challenge_hash=hash_opaque_token(chal),
                exchange_binding_hash=None,
                expires_at=now + timedelta(seconds=60),
                consumed_at=None,
            )
        )
        s.commit()
        user_id = u.id

    holding_lock = threading.Event()
    release_exchange = threading.Event()
    orig_create_session = oauth_service.create_session_and_mint_tokens

    def _pausing_create_session(db: Session, **kw: Any) -> Any:
        res = orig_create_session(db, **kw)
        holding_lock.set()
        release_exchange.wait(timeout=5.0)
        return res

    monkeypatch.setattr(oauth_service, "create_session_and_mint_tokens", _pausing_create_session)

    exchange_res: list[Any] = []
    logout_errors: list[BaseException] = []

    def _exchange_worker() -> None:
        with SessionFactory() as wdb:
            exchange_res.append(
                exchange_oauth_code(
                    wdb,
                    code=raw_code,
                    exchange_code_verifier=ver,
                    client_type="mobile",
                    settings=settings,
                    now=now,
                )
            )

    def _logout_worker() -> None:
        try:
            with SessionFactory() as wdb:
                logout_all_sessions(wdb, user_id=user_id, expected_auth_version=0)
        except BaseException as exc:  # pragma: no cover
            logout_errors.append(exc)

    t_ex = threading.Thread(target=_exchange_worker)
    t_lo = threading.Thread(target=_logout_worker)
    t_ex.start()
    assert holding_lock.wait(timeout=5.0)
    t_lo.start()
    _wait_for_pg_lock_wait(db_engine)
    release_exchange.set()
    t_ex.join(timeout=5.0)
    t_lo.join(timeout=5.0)

    assert not logout_errors
    assert len(exchange_res) == 1
    with SessionFactory() as s:
        u_after = s.execute(select(User).where(User.id == user_id)).scalar_one()
        code_after = s.execute(
            select(OAuthExchangeCode).where(OAuthExchangeCode.user_id == user_id)
        ).scalar_one()
        sessions = s.execute(
            select(RefreshSession).where(RefreshSession.user_id == user_id)
        ).scalars().all()
        assert u_after.auth_version == 1
        assert code_after.consumed_at is not None
        assert len(sessions) == 1
        assert sessions[0].revoked_at is not None


def test_exchange_oauth_code_email_not_verified_deletion_race_and_step5_rejections(
    db_engine: Engine,
    clean_oauth_db: None,
) -> None:
    """S3C5-F3: EMAIL_NOT_VERIFIED 403 unconsumed, prelim lookup deletion race, and Step 5 rejections."""
    settings = _settings()
    SessionFactory = build_sessionmaker(db_engine)
    now = datetime.now(timezone.utc)

    with SessionFactory() as s:
        u = User(
            id=uuid.uuid4(),
            email="step5.edge@example.com",
            password_hash=None,
            is_active=True,
            is_email_verified=False,
            email_verified_at=None,
            auth_version=0,
        )
        s.add(u)
        s.commit()
        user_id = u.id

    def _insert_code(
        *,
        client_type: str = "mobile",
        expires_delta: timedelta = timedelta(seconds=60),
        consumed_at: datetime | None = None,
    ) -> tuple[str, str]:
        raw_code = secrets.token_urlsafe(32)
        ver, chal = _exchange_pair()
        with SessionFactory() as s:
            s.add(
                OAuthExchangeCode(
                    id=uuid.uuid4(),
                    user_id=user_id,
                    code_hash=hash_opaque_token(raw_code),
                    client_type=client_type,
                    auth_version=0,
                    exchange_code_challenge_hash=hash_opaque_token(chal),
                    exchange_binding_hash=(
                        hash_opaque_token("web-cookie") if client_type == "web" else None
                    ),
                    expires_at=now + expires_delta,
                    consumed_at=consumed_at,
                )
            )
            s.commit()
        return raw_code, ver

    # 1. EMAIL_NOT_VERIFIED -> 403 and leaves code unconsumed
    c_unv, v_unv = _insert_code()
    with SessionFactory() as db:
        with pytest.raises(AppException) as e_unv:
            exchange_oauth_code(
                db,
                code=c_unv,
                exchange_code_verifier=v_unv,
                client_type="mobile",
                settings=settings,
                now=now,
            )
        assert e_unv.value.status_code == 403
        assert e_unv.value.details == {"code": "EMAIL_NOT_VERIFIED"}
    with SessionFactory() as s:
        row_unv = s.execute(
            select(OAuthExchangeCode).where(OAuthExchangeCode.code_hash == hash_opaque_token(c_unv))
        ).scalar_one()
        assert row_unv.consumed_at is None
        u_verify = s.execute(select(User).where(User.id == user_id)).scalar_one()
        u_verify.is_email_verified = True
        u_verify.email_verified_at = now
        s.commit()

    # 2. Preliminary non-locking lookup followed by concurrent deletion before locked re-fetch
    c_del, v_del = _insert_code()
    del_hash = hash_opaque_token(c_del)
    with SessionFactory() as db:
        orig_execute = db.execute
        exec_count = 0

        def _delete_after_prelim(stmt: Any, *args: Any, **kwargs: Any) -> Any:
            nonlocal exec_count
            exec_count += 1
            res = orig_execute(stmt, *args, **kwargs)
            if exec_count == 1:
                with SessionFactory() as killer:
                    killer.execute(
                        text("DELETE FROM oauth_exchange_codes WHERE code_hash = :h"),
                        {"h": del_hash},
                    )
                    killer.commit()
            return res

        db.execute = _delete_after_prelim  # type: ignore[method-assign]
        with pytest.raises(AppException) as e_del:
            exchange_oauth_code(
                db,
                code=c_del,
                exchange_code_verifier=v_del,
                client_type="mobile",
                settings=settings,
                now=now,
            )
        assert e_del.value.status_code == 400
        assert e_del.value.details == {"code": "INVALID_OAUTH_EXCHANGE_CODE"}

    # 3. Step 5 rejections: expired, already consumed, client_type mismatch
    c_exp, v_exp = _insert_code(expires_delta=timedelta(seconds=-5))
    c_cons, v_cons = _insert_code(consumed_at=now - timedelta(seconds=1))
    c_type, v_type = _insert_code(client_type="web")

    for bad_code, bad_ver in ((c_exp, v_exp), (c_cons, v_cons), (c_type, v_type)):
        with SessionFactory() as db:
            with pytest.raises(AppException) as e_step5:
                exchange_oauth_code(
                    db,
                    code=bad_code,
                    exchange_code_verifier=bad_ver,
                    client_type="mobile",
                    settings=settings,
                    now=now,
                )
            assert e_step5.value.status_code == 400
            assert e_step5.value.details == {"code": "INVALID_OAUTH_EXCHANGE_CODE"}

    with SessionFactory() as s:
        assert s.execute(select(RefreshSession).where(RefreshSession.user_id == user_id)).all() == []


def test_callback_order_9a_subcases_and_checkpoints_2_3(
    db_engine: Engine,
    clean_oauth_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S3C5-F3: Order 9a sub-cases (both/duplicate/error>128) and Checkpoints 2 & 3 rollback."""
    settings = _settings()
    SessionFactory = build_sessionmaker(db_engine)

    # Order 9a remaining sub-cases -> consume/scrub and redirect oauth_provider_error
    for cb_kwargs in (
        {"error_values": [""], "code_values": ["valid-code"]},  # both error & code present
        {"error_values": ["access_denied", "server_error"]},  # duplicate error
        {"code_values": ["c1", "c2"]},  # duplicate code
        {"error_values": ["e" * 129]},  # len(error) > 128
    ):
        st = _seed_mobile_google_state(SessionFactory, settings)
        with SessionFactory() as db:
            res = handle_oauth_callback(
                db,
                provider="google",
                state_values=[st],
                settings=settings,
                **cb_kwargs,
            )
            assert "error=oauth_provider_error" in res.redirect_url
        with SessionFactory() as s:
            row = s.execute(
                select(OAuthState).where(OAuthState.state_hash == hash_opaque_token(st))
            ).scalar_one()
            assert row.consumed_at is not None
            assert row.pkce_verifier_encrypted == PKCE_VERIFIER_CONSUMED_MARKER

    monkeypatch.setattr(oauth_service, "exchange_google_authorization_code", lambda db, **kw: "id-tok")
    monkeypatch.setattr(
        oauth_service,
        "verify_google_id_token",
        lambda db, **kw: GoogleIdentity("sub-cp-test", "cp.test@example.com", True),
    )
    fake_jwk = object()
    real_snapshot = oauth_service.get_allowed_redirect_uris_snapshot

    # Checkpoint 2: allowlist drifts after Phase 1 and before Phase 3
    st_cp2 = _seed_mobile_google_state(SessionFactory, settings)
    cp2_calls = 0

    def _drift_at_cp2(cfg: Settings, ct: str) -> frozenset[str]:
        nonlocal cp2_calls
        cp2_calls += 1
        if cp2_calls == 2:
            return frozenset({"folio360://drifted/cb"})
        return real_snapshot(cfg, ct)

    monkeypatch.setattr(oauth_service, "get_allowed_redirect_uris_snapshot", _drift_at_cp2)
    with SessionFactory() as db:
        with pytest.raises(OAuthCallbackJsonError) as e_cp2:
            handle_oauth_callback(
                db,
                provider="google",
                state_values=[st_cp2],
                code_values=["valid-cp2"],
                settings=settings,
                jwk_client=fake_jwk,  # type: ignore[arg-type]
            )
        assert e_cp2.value.status_code == 400
        assert e_cp2.value.details == {"code": "INVALID_REDIRECT_URI"}

    with SessionFactory() as s:
        assert s.execute(select(User)).all() == []
        assert s.execute(select(OAuthAccount)).all() == []
        assert s.execute(select(OAuthExchangeCode)).all() == []

    # Checkpoint 3: allowlist drifts after OAuthExchangeCode flush -> PostgreSQL rolls back Phase 3 writes
    st_cp3 = _seed_mobile_google_state(SessionFactory, settings)
    cp3_calls = 0

    def _drift_at_cp3(cfg: Settings, ct: str) -> frozenset[str]:
        nonlocal cp3_calls
        cp3_calls += 1
        if cp3_calls == 3:
            return frozenset({"folio360://drifted/cb"})
        return real_snapshot(cfg, ct)

    monkeypatch.setattr(oauth_service, "get_allowed_redirect_uris_snapshot", _drift_at_cp3)
    with SessionFactory() as db:
        with pytest.raises(OAuthCallbackJsonError) as e_cp3:
            handle_oauth_callback(
                db,
                provider="google",
                state_values=[st_cp3],
                code_values=["valid-cp3"],
                settings=settings,
                jwk_client=fake_jwk,  # type: ignore[arg-type]
            )
        assert e_cp3.value.status_code == 400
        assert e_cp3.value.details == {"code": "INVALID_REDIRECT_URI"}

    with SessionFactory() as s:
        assert s.execute(select(User)).all() == []
        assert s.execute(select(OAuthAccount)).all() == []
        assert s.execute(select(OAuthExchangeCode)).all() == []
