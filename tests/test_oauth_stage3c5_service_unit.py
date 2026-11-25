"""Unit tests for Stage 3C Substage 3C.5 OAuth Service Orchestration (REV12)."""

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import Any
from urllib.parse import parse_qsl, urlsplit
import uuid

import pytest
from sqlalchemy.exc import IntegrityError

from app.core.config import Settings, get_oauth_callback_url
from app.core.exceptions import AppException, ValidationAppError
from app.core.security import (
    PKCE_VERIFIER_CONSUMED_MARKER,
    compute_pkce_s256_challenge,
    decrypt_pkce_verifier,
    encrypt_pkce_verifier,
    generate_pkce_verifier,
    hash_opaque_token,
)
from app.models.oauth import OAuthExchangeCode, OAuthState
from app.models.user import User
from app.services.auth_service import create_session_and_mint_tokens, get_constraint_name
from app.services.oauth_providers import (
    GoogleIdentity,
    OAuthProviderError,
    OAuthTransactionGuardError,
)
import app.services.oauth_service as oauth_service
from app.services.oauth_service import (
    OAuthCallbackJsonError,
    OAuthCallbackResult,
    OAuthStartResult,
    cleanup_expired_oauth_records,
    exchange_oauth_code,
    handle_oauth_callback,
    is_oauth_provider_configured,
    start_oauth_flow,
)

PRIMARY_KEY = secrets.token_urlsafe(32)
PREVIOUS_KEY = secrets.token_urlsafe(32)


def _settings(**overrides: Any) -> Settings:
    params: dict[str, Any] = {
        "_env_file": None,
        "ENVIRONMENT": "testing",
        "JWT_SECRET_KEY": "test-jwt-secret-key-at-least-32-chars-long",
        "OAUTH_PKCE_ENCRYPTION_KEY": PRIMARY_KEY,
        "OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS": PREVIOUS_KEY,
        "GOOGLE_CLIENT_ID": "google-client-3c5",
        "GOOGLE_CLIENT_SECRET": "google-secret-3c5",
        "GITHUB_CLIENT_ID": "github-client-3c5",
        "GITHUB_CLIENT_SECRET": "github-secret-3c5",
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


def _exchange_verifier_and_challenge() -> tuple[str, str]:
    verifier = "v" * 48
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


class _FakeScalarResult:
    def __init__(self, value: Any) -> None:
        self._value = value
        self.rowcount = 0

    def scalar_one_or_none(self) -> Any:
        return self._value


class _FakeNest:
    def __enter__(self) -> "_FakeNest":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None


class _FakeUnitSession:
    """Minimal in-memory SQLAlchemy Session double for unit testing 3C.5 service paths."""

    def __init__(self, query_results: list[Any] | None = None) -> None:
        self._results = list(query_results or [])
        self.added: list[Any] = []
        self.committed = 0
        self.flushed = 0
        self.rolled_back = 0
        self._in_tx = False

    def in_transaction(self) -> bool:
        return self._in_tx

    def execute(self, stmt: Any) -> _FakeScalarResult:
        self._in_tx = True
        if self._results:
            return _FakeScalarResult(self._results.pop(0))
        return _FakeScalarResult(None)

    def add(self, obj: Any) -> None:
        self._in_tx = True
        self.added.append(obj)

    def flush(self) -> None:
        self.flushed += 1

    def commit(self) -> None:
        self.committed += 1
        self._in_tx = False

    def rollback(self) -> None:
        self.rolled_back += 1
        self._in_tx = False

    def begin_nested(self) -> _FakeNest:
        return _FakeNest()


# ---------------------------------------------------------------------------
# 1. Shared auth_service Helpers & Provider Config Check
# ---------------------------------------------------------------------------


def test_create_session_and_mint_tokens_commit_flag_and_constraint_helper() -> None:
    settings = _settings()
    now = datetime.now(timezone.utc)
    user = User(
        id=uuid.uuid4(),
        email="helper@example.com",
        password_hash=None,
        is_active=True,
        is_email_verified=True,
        email_verified_at=now,
        auth_version=3,
    )

    db_no_commit = _FakeUnitSession()
    u1, access_jwt, expires_in, raw_rt, rt_exp = create_session_and_mint_tokens(
        db_no_commit,  # type: ignore[arg-type]
        user=user,
        client_type="mobile",
        user_agent="TestAgent/1.0",
        ip_address="127.0.0.1",
        now=now,
        settings=settings,
        commit=False,
    )
    assert u1 is user
    assert db_no_commit.flushed == 1
    assert db_no_commit.committed == 0
    assert len(db_no_commit.added) == 1
    assert access_jwt and raw_rt and expires_in > 0 and rt_exp > 0

    db_commit = _FakeUnitSession()
    create_session_and_mint_tokens(
        db_commit,  # type: ignore[arg-type]
        user=user,
        client_type="web",
        user_agent=None,
        ip_address=None,
        now=now,
        settings=settings,
        commit=True,
    )
    assert db_commit.committed == 1
    assert db_commit.flushed == 0

    class _Diag:
        constraint_name = "uq_users_email"

    class _Orig:
        diag = _Diag()

    err = IntegrityError("INSERT ...", {}, Exception("DETAIL: secret@example.com"))
    err.orig = _Orig()  # type: ignore[assignment]
    assert get_constraint_name(err) == "uq_users_email"


def test_is_oauth_provider_configured_d18() -> None:
    both = _settings()
    assert is_oauth_provider_configured(both, "google") is True
    assert is_oauth_provider_configured(both, "github") is True
    assert is_oauth_provider_configured(both, "facebook") is False

    google_only = _settings(GITHUB_CLIENT_ID=None, GITHUB_CLIENT_SECRET=None)
    assert is_oauth_provider_configured(google_only, "google") is True
    assert is_oauth_provider_configured(google_only, "github") is False


# ---------------------------------------------------------------------------
# 2. start_oauth_flow Strict Validation Order
# ---------------------------------------------------------------------------


def test_start_oauth_flow_strict_validation_order_and_persistence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(GITHUB_CLIENT_ID=None, GITHUB_CLIENT_SECRET=None)
    _, valid_challenge = _exchange_verifier_and_challenge()
    db = _FakeUnitSession()

    # Step 1: Invalid provider takes precedence over everything
    with pytest.raises(AppException) as e1:
        start_oauth_flow(
            db,  # type: ignore[arg-type]
            provider="facebook",
            client_type="invalid",
            redirect_uri="bad",
            exchange_code_challenge="bad",
            duplicate_params=("client_type",),
            settings=settings,
        )
    assert e1.value.status_code == 400
    assert e1.value.details == {"code": "INVALID_OAUTH_PROVIDER"}

    # Step 2: Unconfigured configured check (503) precedes query params
    with pytest.raises(AppException) as e2:
        start_oauth_flow(
            db,  # type: ignore[arg-type]
            provider="github",
            client_type="invalid",
            redirect_uri="bad",
            exchange_code_challenge="bad",
            duplicate_params=("client_type",),
            settings=settings,
        )
    assert e2.value.status_code == 503
    assert e2.value.details == {"code": "SERVICE_UNAVAILABLE"}

    # Step 3: Duplicate parameter errors
    for dup_key, expected_code in (
        ("client_type", "INVALID_CLIENT_TYPE"),
        ("redirect_uri", "INVALID_REDIRECT_URI"),
        ("exchange_code_challenge", "INVALID_EXCHANGE_CHALLENGE"),
        ("exchange_code_challenge_method", "INVALID_EXCHANGE_CHALLENGE"),
    ):
        with pytest.raises(AppException) as ed:
            start_oauth_flow(
                db,  # type: ignore[arg-type]
                provider="google",
                client_type="web",
                redirect_uri="http://localhost:5173/auth/oauth/callback",
                exchange_code_challenge=valid_challenge,
                duplicate_params=(dup_key,),
                settings=settings,
            )
        assert ed.value.status_code == 400
        assert ed.value.details == {"code": expected_code}

    # Step 4: Invalid client_type
    with pytest.raises(AppException) as e4:
        start_oauth_flow(
            db,  # type: ignore[arg-type]
            provider="google",
            client_type="desktop",
            redirect_uri="http://localhost:5173/auth/oauth/callback",
            exchange_code_challenge=valid_challenge,
            settings=settings,
        )
    assert e4.value.details == {"code": "INVALID_CLIENT_TYPE"}

    # Step 5: Redirect URI mismatch
    with pytest.raises(AppException) as e5:
        start_oauth_flow(
            db,  # type: ignore[arg-type]
            provider="google",
            client_type="web",
            redirect_uri="https://evil.example.com/cb",
            exchange_code_challenge=valid_challenge,
            settings=settings,
        )
    assert e5.value.details == {"code": "INVALID_REDIRECT_URI"}

    # Step 6: Unmodified challenge / S256 check (whitespace-padded fails without stripping)
    for bad_chal, bad_method in (
        (f" {valid_challenge}", "S256"),
        ("short", "S256"),
        (valid_challenge, "plain"),
    ):
        with pytest.raises(AppException) as e6:
            start_oauth_flow(
                db,  # type: ignore[arg-type]
                provider="google",
                client_type="web",
                redirect_uri="http://localhost:5173/auth/oauth/callback",
                exchange_code_challenge=bad_chal,
                exchange_code_challenge_method=bad_method,
                settings=settings,
            )
        assert e6.value.details == {"code": "INVALID_EXCHANGE_CHALLENGE"}

    assert db.added == []

    # Step 7: Success persists hashed state + calls cleanup
    cleanup_calls: list[datetime] = []
    monkeypatch.setattr(
        oauth_service,
        "cleanup_expired_oauth_records",
        lambda _db, *, now=None, **kw: cleanup_calls.append(now) or (0, 0),
    )
    fixed_now = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    res = start_oauth_flow(
        db,  # type: ignore[arg-type]
        provider="google",
        client_type="web",
        redirect_uri="http://localhost:5173/auth/oauth/callback",
        exchange_code_challenge=valid_challenge,
        settings=settings,
        now=fixed_now,
    )
    assert isinstance(res, OAuthStartResult)
    assert res.binding_cookie_value is not None
    assert "binding_cookie_value" not in repr(res)
    assert len(cleanup_calls) == 1 and cleanup_calls[0] == fixed_now
    assert len(db.added) == 1
    persisted: OAuthState = db.added[0]
    q = dict(parse_qsl(urlsplit(res.authorization_url).query))
    assert q["redirect_uri"] == get_oauth_callback_url(settings, "google")
    assert hash_opaque_token(q["state"]) == persisted.state_hash
    assert hash_opaque_token(q["nonce"]) == persisted.nonce_hash
    assert hash_opaque_token(res.binding_cookie_value) == persisted.client_binding_hash
    assert hash_opaque_token(valid_challenge) == persisted.exchange_code_challenge_hash


# ---------------------------------------------------------------------------
# 3. S3C2-F1 Timestamp Forwarding, Rotation Window & Callback Guard
# ---------------------------------------------------------------------------


def test_callback_forwards_state_created_at_s3c2_f1_and_enforces_rotation_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    raw_state = secrets.token_urlsafe(32)
    state_hash = hash_opaque_token(raw_state)
    verifier = generate_pkce_verifier()
    created_at = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Encrypt with PREVIOUS_KEY cleanly
    from app.core.crypto_keys import decode_aes256_base64url_key

    prev_raw = decode_aes256_base64url_key(
        PREVIOUS_KEY, field_name="OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS"
    )
    ciphertext = encrypt_pkce_verifier(
        verifier,
        key=prev_raw,
        provider="github",
        state_hash=state_hash,
    )

    state_row = OAuthState(
        id=uuid.uuid4(),
        state_hash=state_hash,
        provider="github",
        client_type="mobile",
        pkce_verifier_encrypted=ciphertext,
        nonce_hash=None,
        redirect_uri="folio360://auth/callback",
        client_binding_hash=None,
        exchange_code_challenge_hash="a" * 64,
        expires_at=created_at + timedelta(minutes=60),  # active expires_at so Order 5 passes
        consumed_at=None,
    )
    state_row.created_at = created_at

    # 1. Verify spy captures state_created_at == state_row.created_at when called
    captured_args: list[dict[str, Any]] = []
    real_decrypt = oauth_service.decrypt_pkce_verifier_for_settings

    def _spy_decrypt(*args: Any, **kwargs: Any) -> str:
        captured_args.append(kwargs)
        return real_decrypt(*args, **kwargs)

    monkeypatch.setattr(oauth_service, "decrypt_pkce_verifier_for_settings", _spy_decrypt)

    # Outside retention window (15m + 31s) -> Order 11 rejects PREVIOUS_KEY and consumes/scrubs!
    outside_now = created_at + timedelta(minutes=15, seconds=31)
    db_expired_window = _FakeUnitSession(query_results=[state_row])
    res = handle_oauth_callback(
        db_expired_window,  # type: ignore[arg-type]
        provider="github",
        state_values=[raw_state],
        code_values=["valid-code"],
        settings=settings,
        now=outside_now,
    )
    assert len(captured_args) == 1
    assert captured_args[0]["state_created_at"] == created_at
    assert captured_args[0]["now"] == outside_now
    assert isinstance(res, OAuthCallbackResult)
    assert "error=oauth_provider_error" in res.redirect_url
    assert state_row.consumed_at == outside_now
    assert state_row.pkce_verifier_encrypted == PKCE_VERIFIER_CONSUMED_MARKER
    assert db_expired_window.committed == 1


def test_callback_propagates_transaction_guard_error_with_cookie_directive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    raw_state = secrets.token_urlsafe(32)
    state_hash = hash_opaque_token(raw_state)
    binding_cookie = secrets.token_urlsafe(32)
    created_at = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
    verifier = generate_pkce_verifier()

    from app.core.security import encrypt_pkce_verifier_for_settings

    ct = encrypt_pkce_verifier_for_settings(
        verifier, settings=settings, provider="github", state_hash=state_hash
    )
    state_row = OAuthState(
        id=uuid.uuid4(),
        state_hash=state_hash,
        provider="github",
        client_type="web",
        pkce_verifier_encrypted=ct,
        nonce_hash=None,
        redirect_uri="http://localhost:5173/auth/oauth/callback",
        client_binding_hash=hash_opaque_token(binding_cookie),
        exchange_code_challenge_hash="a" * 64,
        expires_at=created_at + timedelta(minutes=10),
        consumed_at=None,
    )
    state_row.created_at = created_at

    def _trip_guard(*args: Any, **kwargs: Any) -> str:
        raise OAuthTransactionGuardError("Simulated open DB transaction")

    monkeypatch.setattr(oauth_service, "exchange_github_authorization_code", _trip_guard)

    db = _FakeUnitSession(query_results=[state_row])
    with pytest.raises(OAuthTransactionGuardError) as exc_info:
        handle_oauth_callback(
            db,  # type: ignore[arg-type]
            provider="github",
            state_values=[raw_state],
            code_values=["valid-code"],
            binding_cookie=binding_cookie,
            settings=settings,
            now=created_at + timedelta(seconds=5),
        )
    assert getattr(exc_info.value, "clear_binding_cookie_mode") == "always"
    assert db.rolled_back >= 1


# ---------------------------------------------------------------------------
# 4. REV12-2 Exchange Proof Comparison & Malformed Input Rejection
# ---------------------------------------------------------------------------


def test_exchange_oauth_code_rev12_2_compare_digest_and_malformed_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    verifier, challenge = _exchange_verifier_and_challenge()
    challenge_hash = hash_opaque_token(challenge)
    raw_code = secrets.token_urlsafe(32)
    raw_cookie = secrets.token_urlsafe(32)
    now = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)

    user = User(
        id=uuid.uuid4(),
        email="rev12.2@example.com",
        password_hash=None,
        is_active=True,
        is_email_verified=True,
        email_verified_at=now,
        auth_version=0,
    )
    code_row = OAuthExchangeCode(
        id=uuid.uuid4(),
        user_id=user.id,
        code_hash=hash_opaque_token(raw_code),
        client_type="web",
        auth_version=0,
        exchange_code_challenge_hash=challenge_hash,
        exchange_binding_hash=hash_opaque_token(raw_cookie),
        expires_at=now + timedelta(seconds=60),
        consumed_at=None,
    )

    # 1. Whitespace-padded or malformed verifiers rejected unmodified with 422 without echoing or hitting DB
    for bad_ver in (f" {verifier}", f"{verifier} ", "short", f"{verifier}!"):
        db_bad = _FakeUnitSession()
        with pytest.raises(ValidationAppError) as exc_val:
            exchange_oauth_code(
                db_bad,  # type: ignore[arg-type]
                code=raw_code,
                exchange_code_verifier=bad_ver,
                client_type="web",
                exchange_cookie=raw_cookie,
                settings=settings,
                now=now,
            )
        assert exc_val.value.status_code == 422
        assert bad_ver not in repr(exc_val.value.details)
        assert db_bad.committed == 0

    # 2. Constant-time hmac.compare_digest verified for BOTH PKCE challenge and web cookie
    compare_calls: list[tuple[str, str]] = []
    real_compare = oauth_service.hmac.compare_digest

    def _spy_compare(a: Any, b: Any) -> bool:
        compare_calls.append((str(a), str(b)))
        return real_compare(a, b)

    monkeypatch.setattr(oauth_service.hmac, "compare_digest", _spy_compare)
    db_ok = _FakeUnitSession(query_results=[user.id, user, code_row])
    out_user, jwt_tok, _, refresh_tok, _ = exchange_oauth_code(
        db_ok,  # type: ignore[arg-type]
        code=raw_code,
        exchange_code_verifier=verifier,
        client_type="web",
        exchange_cookie=raw_cookie,
        settings=settings,
        now=now,
    )
    assert out_user is user and jwt_tok and refresh_tok
    assert code_row.consumed_at == now
    assert db_ok.committed == 1
    assert len(compare_calls) == 2
    assert (challenge_hash, challenge_hash) in compare_calls
    assert (hash_opaque_token(raw_cookie), hash_opaque_token(raw_cookie)) in compare_calls


# ---------------------------------------------------------------------------
# 5. Cleanup Error Isolation & Safe Result Repr
# ---------------------------------------------------------------------------


def test_cleanup_expired_oauth_records_isolated_failure_returns_zero() -> None:
    class _FailingDb:
        rolled_back = 0

        def execute(self, stmt: Any) -> Any:
            raise RuntimeError("transient lock error")

        def rollback(self) -> None:
            self.rolled_back += 1

    db = _FailingDb()
    assert cleanup_expired_oauth_records(db) == (0, 0)  # type: ignore[arg-type]
    assert db.rolled_back == 1

    cb_res = OAuthCallbackResult(
        redirect_url="https://app.folio360.com/auth/oauth/callback?code=abc",
        client_type="web",
        clear_binding_cookie=True,
        exchange_cookie_value="cookie-SECRET-sentinel",
    )
    assert "cookie-SECRET-sentinel" not in repr(cb_res)


def test_google_id_token_timestamp_forwards_explicit_now_or_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S3C5-F2: preserve explicit test `now` and pass `None` when omitted."""
    from app.core.crypto_keys import decode_aes256_base64url_key

    settings = _settings()
    primary_raw = decode_aes256_base64url_key(
        PRIMARY_KEY, field_name="OAUTH_PKCE_ENCRYPTION_KEY"
    )
    recorded_verify_nows: list[Any] = []

    monkeypatch.setattr(
        oauth_service,
        "exchange_google_authorization_code",
        lambda db, **kw: "google-id-token",
    )

    def _spy_verify_google(db: Any, **kw: Any) -> GoogleIdentity:
        recorded_verify_nows.append(kw["now"])
        return GoogleIdentity("sub-ts-test", "ts.test@example.com", True)

    monkeypatch.setattr(oauth_service, "verify_google_id_token", _spy_verify_google)

    def _make_state_and_user(email: str) -> tuple[str, OAuthState, User]:
        raw_state = secrets.token_urlsafe(32)
        state_hash = hash_opaque_token(raw_state)
        verifier = generate_pkce_verifier()
        now_utc = datetime.now(timezone.utc)
        state_row = OAuthState(
            id=uuid.uuid4(),
            state_hash=state_hash,
            provider="google",
            client_type="mobile",
            pkce_verifier_encrypted=encrypt_pkce_verifier(
                verifier, key=primary_raw, provider="google", state_hash=state_hash
            ),
            nonce_hash=hash_opaque_token("n" * 43),
            redirect_uri="folio360://auth/callback",
            client_binding_hash=None,
            exchange_code_challenge_hash="a" * 64,
            expires_at=now_utc + timedelta(minutes=10),
            consumed_at=None,
        )
        state_row.created_at = now_utc - timedelta(seconds=5)
        uid = uuid.uuid4()
        account_row = oauth_service.OAuthAccount(
            id=uuid.uuid4(),
            user_id=uid,
            provider="google",
            provider_user_id="sub-ts-test",
            provider_email=email,
            provider_email_verified=True,
        )
        user_row = User(
            id=uid,
            email=email,
            password_hash=None,
            is_active=True,
            is_email_verified=True,
            email_verified_at=now_utc,
            auth_version=0,
        )
        return raw_state, state_row, (account_row, user_row)  # type: ignore[return-value]

    # 1. Explicit `now` forwarded as timestamp
    explicit_dt = datetime.now(timezone.utc)
    s1, row1, pair1 = _make_state_and_user("ts.test@example.com")
    db1 = _FakeUnitSession(query_results=[row1, pair1[0], pair1[1]])
    res1 = handle_oauth_callback(
        db1,  # type: ignore[arg-type]
        provider="google",
        state_values=[s1],
        code_values=["valid-code-1"],
        settings=settings,
        jwk_client=object(),  # type: ignore[arg-type]
        now=explicit_dt,
    )
    assert "code=" in res1.redirect_url
    assert recorded_verify_nows[-1] == pytest.approx(explicit_dt.timestamp())

    # 2. Omitted `now=None` forwards `None` so verify_google_id_token uses fresh post-HTTP time
    s2, row2, pair2 = _make_state_and_user("ts.test@example.com")
    db2 = _FakeUnitSession(query_results=[row2, pair2[0], pair2[1]])
    res2 = handle_oauth_callback(
        db2,  # type: ignore[arg-type]
        provider="google",
        state_values=[s2],
        code_values=["valid-code-2"],
        settings=settings,
        jwk_client=object(),  # type: ignore[arg-type]
        now=None,
    )
    assert "code=" in res2.redirect_url
    assert recorded_verify_nows[-1] is None
