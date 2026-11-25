"""PostgreSQL integration tests for Stage 3C Substage 3C.3 OAuth ORM models & constraints."""

from datetime import datetime, timedelta, timezone
import hashlib
import os
import uuid

import pytest
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from app.core.security import (
    PKCE_VERIFIER_CONSUMED_MARKER,
    encrypt_pkce_verifier,
    generate_pkce_verifier,
)
from app.models.oauth import OAuthAccount, OAuthExchangeCode, OAuthState
from app.models.user import User
from tests.conftest import committed_db_session

pytestmark = pytest.mark.db


def _sha256_hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _extract_constraint_name(exc: IntegrityError) -> str | None:
    orig = getattr(exc, "orig", None)
    diag = getattr(orig, "diag", None)
    return getattr(diag, "constraint_name", None)


def _extract_sqlstate(exc: IntegrityError) -> str | None:
    orig = getattr(exc, "orig", None)
    return getattr(orig, "sqlstate", None)


def _create_user(db_session: Session, *, email: str) -> User:
    user = User(
        email=email,
        password_hash=None,
        is_active=True,
        is_email_verified=True,
        email_verified_at=datetime.now(timezone.utc),
        auth_version=0,
    )
    db_session.add(user)
    db_session.flush()
    return user


# ---------------------------------------------------------------------------
# 1. oauth_accounts: Defaults, Uniqueness, Cascade Delete & Check Constraints
# ---------------------------------------------------------------------------


def test_oauth_account_crud_uniqueness_cascade_and_constraints(db_session: Session) -> None:
    u1 = _create_user(db_session, email="oauth.u1@example.com")
    u2 = _create_user(db_session, email="oauth.u2@example.com")

    acc = OAuthAccount(
        user_id=u1.id,
        provider="google",
        provider_user_id="google-sub-001",
        provider_email="oauth.u1@example.com",
        provider_email_verified=True,
    )
    db_session.add(acc)
    db_session.flush()
    db_session.refresh(acc)

    assert isinstance(acc.id, uuid.UUID)
    assert acc.provider_email_verified is True
    assert acc.created_at.tzinfo is not None
    assert acc.updated_at.tzinfo is not None

    # Null provider_email allowed with default provider_email_verified=False
    acc_gh = OAuthAccount(
        user_id=u1.id,
        provider="github",
        provider_user_id="123456",
        provider_email=None,
    )
    db_session.add(acc_gh)
    db_session.flush()
    assert acc_gh.provider_email_verified is False

    # Same provider_user_id allowed on a *different* provider (e.g. 'google' vs 'github')
    acc_diff_provider_same_id = OAuthAccount(
        user_id=u2.id,
        provider="google",
        provider_user_id="123456",
        provider_email="oauth.u2@example.com",
        provider_email_verified=True,
    )
    db_session.add(acc_diff_provider_same_id)
    db_session.flush()

    # Duplicate (provider, provider_user_id) rejected
    db_session.add(
        OAuthAccount(
            user_id=u2.id,
            provider="github",
            provider_user_id="123456",
        )
    )
    with pytest.raises(IntegrityError) as exc_subj:
        db_session.flush()
    assert _extract_constraint_name(exc_subj.value) == "uq_oauth_accounts_provider_subject"
    assert "[SQL parameters hidden due to hide_parameters=True]" in str(exc_subj.value)
    db_session.rollback()

    # Re-create u1 + google for user/provider uniqueness & cascade tests
    u1 = _create_user(db_session, email="oauth.u1.uniq@example.com")
    db_session.add(
        OAuthAccount(
            user_id=u1.id,
            provider="google",
            provider_user_id="google-sub-uniq",
        )
    )
    db_session.flush()

    db_session.add(
        OAuthAccount(
            user_id=u1.id,
            provider="google",
            provider_user_id="google-sub-other",
        )
    )
    with pytest.raises(IntegrityError) as exc_up:
        db_session.flush()
    assert _extract_constraint_name(exc_up.value) == "uq_oauth_accounts_user_provider"
    db_session.rollback()

    # Verify ON DELETE CASCADE from users.id -> oauth_accounts
    u_del = _create_user(db_session, email="oauth.cascade@example.com")
    db_session.add(
        OAuthAccount(
            user_id=u_del.id,
            provider="github",
            provider_user_id="gh-cascade-1",
        )
    )
    db_session.flush()
    db_session.execute(text("DELETE FROM users WHERE id = :uid"), {"uid": u_del.id})
    remaining = db_session.execute(
        select(OAuthAccount).where(OAuthAccount.user_id == u_del.id)
    ).all()
    assert remaining == []


@pytest.mark.parametrize(
    ("kwargs", "expected_constraint"),
    [
        (
            {"provider": "gitlab", "provider_user_id": "id-1", "provider_email": None, "provider_email_verified": False},
            "ck_oauth_accounts_provider",
        ),
        (
            {"provider": "google", "provider_user_id": "", "provider_email": None, "provider_email_verified": False},
            "ck_oauth_accounts_provider_user_id_valid",
        ),
        (
            {"provider": "google", "provider_user_id": " sub ", "provider_email": None, "provider_email_verified": False},
            "ck_oauth_accounts_provider_user_id_valid",
        ),
        (
            {"provider": "google", "provider_user_id": "sub\n1", "provider_email": None, "provider_email_verified": False},
            "ck_oauth_accounts_provider_user_id_valid",
        ),
        (
            {"provider": "google", "provider_user_id": "sub\x01id", "provider_email": None, "provider_email_verified": False},
            "ck_oauth_accounts_provider_user_id_valid",
        ),
        (
            {"provider": "google", "provider_user_id": "sub\x07id", "provider_email": None, "provider_email_verified": False},
            "ck_oauth_accounts_provider_user_id_valid",
        ),
        (
            {"provider": "google", "provider_user_id": "sub\x1fid", "provider_email": None, "provider_email_verified": False},
            "ck_oauth_accounts_provider_user_id_valid",
        ),
        (
            {"provider": "google", "provider_user_id": "sub\x7fid", "provider_email": None, "provider_email_verified": False},
            "ck_oauth_accounts_provider_user_id_valid",
        ),
        (
            {"provider": "google", "provider_user_id": "sub-1", "provider_email": "User@Example.com", "provider_email_verified": True},
            "ck_oauth_accounts_provider_email_canonical",
        ),
        (
            {"provider": "google", "provider_user_id": "sub-2", "provider_email": " user@example.com", "provider_email_verified": True},
            "ck_oauth_accounts_provider_email_canonical",
        ),
        (
            {"provider": "google", "provider_user_id": "sub-3", "provider_email": "", "provider_email_verified": False},
            "ck_oauth_accounts_provider_email_canonical",
        ),
        (
            {"provider": "google", "provider_user_id": "sub-4", "provider_email": "a b@example.com", "provider_email_verified": True},
            "ck_oauth_accounts_provider_email_canonical",
        ),
        (
            {"provider": "google", "provider_user_id": "sub-5", "provider_email": None, "provider_email_verified": True},
            "ck_oauth_accounts_email_verified_consistency",
        ),
    ],
)
def test_oauth_account_check_constraints_reject_invalid_rows(
    db_session: Session,
    kwargs: dict[str, object],
    expected_constraint: str,
) -> None:
    user = _create_user(db_session, email="oa.checks@example.com")
    db_session.add(OAuthAccount(user_id=user.id, **kwargs))
    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    assert _extract_constraint_name(exc_info.value) == expected_constraint
    db_session.rollback()


# ---------------------------------------------------------------------------
# 2. oauth_states: Lifecycle, Scrubbing, Consistency & Committed Cleanup
# ---------------------------------------------------------------------------


def test_oauth_state_lifecycle_pkce_scrubbing_and_uniqueness(db_session: Session) -> None:
    now = datetime.now(timezone.utc)
    state_hash = _sha256_hex("state-1")
    encrypted_pkce = encrypt_pkce_verifier(
        generate_pkce_verifier(),
        key=os.urandom(32),
        provider="google",
        state_hash=state_hash,
    )

    st = OAuthState(
        state_hash=state_hash,
        provider="google",
        client_type="web",
        pkce_verifier_encrypted=encrypted_pkce,
        nonce_hash=_sha256_hex("nonce-1"),
        redirect_uri="http://localhost:5173/auth/oauth/callback",
        client_binding_hash=_sha256_hex("binding-1"),
        exchange_code_challenge_hash=_sha256_hex("challenge-1"),
        expires_at=now + timedelta(minutes=10),
        consumed_at=None,
    )
    db_session.add(st)
    db_session.flush()
    db_session.refresh(st)
    assert isinstance(st.id, uuid.UUID)
    assert st.consumed_at is None

    # GitHub mobile valid row (nonce_hash=None, client_binding_hash=None)
    gh_hash = _sha256_hex("state-gh-mobile")
    st_gh = OAuthState(
        state_hash=gh_hash,
        provider="github",
        client_type="mobile",
        pkce_verifier_encrypted=encrypt_pkce_verifier(
            generate_pkce_verifier(),
            key=os.urandom(32),
            provider="github",
            state_hash=gh_hash,
        ),
        nonce_hash=None,
        redirect_uri="folio360://auth/callback",
        client_binding_hash=None,
        exchange_code_challenge_hash=_sha256_hex("challenge-2"),
        expires_at=now + timedelta(minutes=10),
    )
    db_session.add(st_gh)
    db_session.flush()

    # Duplicate state_hash rejected
    db_session.add(
        OAuthState(
            state_hash=state_hash,
            provider="github",
            client_type="mobile",
            pkce_verifier_encrypted="v1:another",
            nonce_hash=None,
            redirect_uri="folio360://auth/callback",
            client_binding_hash=None,
            exchange_code_challenge_hash=_sha256_hex("challenge-3"),
            expires_at=now + timedelta(minutes=10),
        )
    )
    with pytest.raises(IntegrityError) as exc_dup:
        db_session.flush()
    assert _extract_constraint_name(exc_dup.value) == "uq_oauth_states_state_hash"
    db_session.rollback()

    # Atomic consumption + PKCE scrubbing satisfies ck_oauth_states_consumed_pkce_scrubbed
    st_to_consume = OAuthState(
        state_hash=_sha256_hex("state-consume"),
        provider="github",
        client_type="mobile",
        pkce_verifier_encrypted="v1:active",
        nonce_hash=None,
        redirect_uri="folio360://auth/callback",
        client_binding_hash=None,
        exchange_code_challenge_hash=_sha256_hex("challenge-consume"),
        expires_at=now + timedelta(minutes=10),
        consumed_at=None,
    )
    db_session.add(st_to_consume)
    db_session.flush()

    st_to_consume.consumed_at = now
    st_to_consume.pkce_verifier_encrypted = PKCE_VERIFIER_CONSUMED_MARKER
    db_session.flush()


def test_oauth_states_committed_session_fixture_cleanup(
    test_database_url: str,
    db_engine: Engine,
) -> None:
    """Drive committed_db_session directly to prove OAuthState commits and is removed on teardown."""
    fixture_gen = committed_db_session.__wrapped__(test_database_url, db_engine)
    session = next(fixture_gen)
    st_id: uuid.UUID | None = None
    try:
        st = OAuthState(
            state_hash=_sha256_hex("committed-state"),
            provider="github",
            client_type="mobile",
            pkce_verifier_encrypted="v1:committed",
            nonce_hash=None,
            redirect_uri="folio360://auth/callback",
            client_binding_hash=None,
            exchange_code_challenge_hash=_sha256_hex("committed-challenge"),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        session.add(st)
        session.commit()
        st_id = st.id

        with db_engine.connect() as conn:
            pre_teardown_cnt = conn.execute(
                text("SELECT COUNT(*) FROM oauth_states WHERE id = :sid"),
                {"sid": st_id},
            ).scalar_one()
            assert pre_teardown_cnt == 1
    finally:
        fixture_gen.close()

    assert st_id is not None
    with db_engine.connect() as conn:
        post_teardown_cnt = conn.execute(
            text("SELECT COUNT(*) FROM oauth_states WHERE id = :sid"),
            {"sid": st_id},
        ).scalar_one()
        assert post_teardown_cnt == 0


def test_deleting_user_does_not_delete_oauth_state(db_session: Session) -> None:
    """Verify oauth_states intentionally has no user FK/cascade when a user row is deleted."""
    user = _create_user(db_session, email="oauth.state.survives@example.com")
    st = OAuthState(
        state_hash=_sha256_hex("state-survives-user-delete"),
        provider="github",
        client_type="mobile",
        pkce_verifier_encrypted="v1:active-state",
        nonce_hash=None,
        redirect_uri="folio360://auth/callback",
        client_binding_hash=None,
        exchange_code_challenge_hash=_sha256_hex("chal-survives"),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    db_session.add(st)
    db_session.flush()

    db_session.execute(text("DELETE FROM users WHERE id = :uid"), {"uid": user.id})
    deleted_user = db_session.execute(select(User).where(User.id == user.id)).scalar_one_or_none()
    assert deleted_user is None

    surviving = db_session.execute(select(OAuthState).where(OAuthState.id == st.id)).scalar_one_or_none()
    assert surviving is not None
    assert surviving.id == st.id


def test_oauth_state_provider_and_client_type_check_catalog_definitions(
    db_session: Session,
) -> None:
    """Verify ck_oauth_states_provider and ck_oauth_states_client_type exist on public.oauth_states with exact REV12 predicates."""
    rows = (
        db_session.execute(
            text(
                """
                SELECT c.conname,
                       c.contype::text AS contype,
                       c.convalidated,
                       pg_get_constraintdef(c.oid) AS condef
                FROM pg_constraint c
                JOIN pg_class r ON r.oid = c.conrelid
                JOIN pg_namespace n ON n.oid = r.relnamespace
                WHERE n.nspname = 'public'
                  AND r.relname = 'oauth_states'
                  AND c.conname IN ('ck_oauth_states_provider', 'ck_oauth_states_client_type')
                """
            )
        )
        .mappings()
        .all()
    )

    by_name = {str(row["conname"]): row for row in rows}
    assert set(by_name.keys()) == {
        "ck_oauth_states_provider",
        "ck_oauth_states_client_type",
    }

    provider_ck = by_name["ck_oauth_states_provider"]
    assert provider_ck["contype"] == "c"
    assert provider_ck["convalidated"] is True
    assert provider_ck["condef"] == (
        "CHECK (((provider)::text = ANY ("
        "(ARRAY['google'::character varying, 'github'::character varying])::text[]"
        ")))"
    )

    client_type_ck = by_name["ck_oauth_states_client_type"]
    assert client_type_ck["contype"] == "c"
    assert client_type_ck["convalidated"] is True
    assert client_type_ck["condef"] == (
        "CHECK (((client_type)::text = ANY ("
        "(ARRAY['web'::character varying, 'mobile'::character varying])::text[]"
        ")))"
    )


@pytest.mark.parametrize(
    ("overrides", "expected_constraint"),
    [
        # Logical subsumption & PostgreSQL CHECK evaluation order:
        # Any non-NULL provider outside ('google', 'github') makes both disjuncts of
        # ck_oauth_states_nonce_hash_consistency FALSE for every nonce_hash value, and
        # any non-NULL client_type outside ('web', 'mobile') makes both disjuncts of
        # ck_oauth_states_client_binding_consistency FALSE for every client_binding_hash
        # value. PostgreSQL evaluates CHECK constraints in alphabetical conname order, so
        # the consistency constraint ('..._client_binding_consistency' < '..._client_type';
        # '..._nonce_hash_consistency' < '..._provider') is deterministically raised first.
        ({"provider": "facebook", "nonce_hash": None}, "ck_oauth_states_nonce_hash_consistency"),
        ({"provider": "facebook", "nonce_hash": "a" * 64}, "ck_oauth_states_nonce_hash_consistency"),
        ({"client_type": "desktop", "client_binding_hash": None}, "ck_oauth_states_client_binding_consistency"),
        ({"client_type": "desktop", "client_binding_hash": "a" * 64}, "ck_oauth_states_client_binding_consistency"),
        ({"state_hash": "Z" * 64}, "ck_oauth_states_state_hash_hex"),
        ({"state_hash": ("a" * 63) + " "}, "ck_oauth_states_state_hash_hex"),
        ({"state_hash": " " * 64}, "ck_oauth_states_state_hash_hex"),
        ({"exchange_code_challenge_hash": "123"}, "ck_oauth_states_exchange_code_challenge_hash_hex"),
        ({"exchange_code_challenge_hash": ("a" * 63) + " "}, "ck_oauth_states_exchange_code_challenge_hash_hex"),
        ({"exchange_code_challenge_hash": " " * 64}, "ck_oauth_states_exchange_code_challenge_hash_hex"),
        ({"pkce_verifier_encrypted": "   "}, "ck_oauth_states_pkce_not_empty"),
        ({"redirect_uri": " https://example.com/cb"}, "ck_oauth_states_redirect_uri_valid"),
        ({"redirect_uri": "   "}, "ck_oauth_states_redirect_uri_valid"),
        ({"provider": "google", "nonce_hash": None}, "ck_oauth_states_nonce_hash_consistency"),
        ({"provider": "github", "nonce_hash": "a" * 64}, "ck_oauth_states_nonce_hash_consistency"),
        ({"provider": "google", "nonce_hash": "A" * 64}, "ck_oauth_states_nonce_hash_consistency"),
        ({"provider": "google", "nonce_hash": ("a" * 63) + " "}, "ck_oauth_states_nonce_hash_consistency"),
        ({"provider": "google", "nonce_hash": " " * 64}, "ck_oauth_states_nonce_hash_consistency"),
        ({"client_type": "web", "client_binding_hash": None}, "ck_oauth_states_client_binding_consistency"),
        ({"client_type": "mobile", "client_binding_hash": "a" * 64}, "ck_oauth_states_client_binding_consistency"),
        ({"client_type": "web", "client_binding_hash": ("a" * 63) + " "}, "ck_oauth_states_client_binding_consistency"),
        ({"client_type": "web", "client_binding_hash": " " * 64}, "ck_oauth_states_client_binding_consistency"),
        ({"consumed_at": None, "pkce_verifier_encrypted": PKCE_VERIFIER_CONSUMED_MARKER}, "ck_oauth_states_consumed_pkce_scrubbed"),
        ({"consumed_at": datetime.now(timezone.utc), "pkce_verifier_encrypted": "v1:still-here"}, "ck_oauth_states_consumed_pkce_scrubbed"),
    ],
)
def test_oauth_state_check_constraints_reject_invalid_rows(
    db_session: Session,
    overrides: dict[str, object],
    expected_constraint: str,
) -> None:
    base: dict[str, object] = {
        "state_hash": _sha256_hex(f"invalid-{expected_constraint}-{uuid.uuid4()}"),
        "provider": "google",
        "client_type": "web",
        "pkce_verifier_encrypted": "v1:encryptedpayload",
        "nonce_hash": _sha256_hex("nonce-valid"),
        "redirect_uri": "https://app.example.com/oauth/cb",
        "client_binding_hash": _sha256_hex("binding-valid"),
        "exchange_code_challenge_hash": _sha256_hex("challenge-valid"),
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
        "consumed_at": None,
    }
    base.update(overrides)
    db_session.add(OAuthState(**base))
    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    assert _extract_sqlstate(exc_info.value) == "23514"
    assert _extract_constraint_name(exc_info.value) == expected_constraint
    db_session.rollback()


# ---------------------------------------------------------------------------
# 3. oauth_exchange_codes: Uniqueness, Cascade Delete & Check Constraints
# ---------------------------------------------------------------------------


def test_oauth_exchange_code_crud_uniqueness_and_cascade(db_session: Session) -> None:
    user = _create_user(db_session, email="oec.user@example.com")
    now = datetime.now(timezone.utc)
    code_hash = _sha256_hex("exchange-code-1")

    ex_web = OAuthExchangeCode(
        user_id=user.id,
        code_hash=code_hash,
        client_type="web",
        auth_version=0,
        exchange_code_challenge_hash=_sha256_hex("chal-web"),
        exchange_binding_hash=_sha256_hex("ex-bind-web"),
        expires_at=now + timedelta(seconds=60),
    )
    db_session.add(ex_web)
    db_session.flush()

    ex_mobile = OAuthExchangeCode(
        user_id=user.id,
        code_hash=_sha256_hex("exchange-code-mobile"),
        client_type="mobile",
        auth_version=2,
        exchange_code_challenge_hash=_sha256_hex("chal-mobile"),
        exchange_binding_hash=None,
        expires_at=now + timedelta(seconds=60),
    )
    db_session.add(ex_mobile)
    db_session.flush()

    # Duplicate code_hash rejected
    db_session.add(
        OAuthExchangeCode(
            user_id=user.id,
            code_hash=code_hash,
            client_type="mobile",
            auth_version=0,
            exchange_code_challenge_hash=_sha256_hex("chal-dup"),
            exchange_binding_hash=None,
            expires_at=now + timedelta(seconds=60),
        )
    )
    with pytest.raises(IntegrityError) as exc_dup:
        db_session.flush()
    assert _extract_constraint_name(exc_dup.value) == "uq_oauth_exchange_codes_code_hash"
    db_session.rollback()

    # ON DELETE CASCADE from users.id
    u_del = _create_user(db_session, email="oec.cascade@example.com")
    db_session.add(
        OAuthExchangeCode(
            user_id=u_del.id,
            code_hash=_sha256_hex("exchange-cascade"),
            client_type="mobile",
            auth_version=0,
            exchange_code_challenge_hash=_sha256_hex("chal-cascade"),
            exchange_binding_hash=None,
            expires_at=now + timedelta(seconds=60),
        )
    )
    db_session.flush()
    db_session.execute(text("DELETE FROM users WHERE id = :uid"), {"uid": u_del.id})
    remaining = db_session.execute(
        select(OAuthExchangeCode).where(OAuthExchangeCode.user_id == u_del.id)
    ).all()
    assert remaining == []


@pytest.mark.parametrize(
    ("overrides", "expected_constraint"),
    [
        ({"code_hash": "BAD" + ("a" * 61)}, "ck_oauth_exchange_codes_hash_hex"),
        ({"code_hash": ("a" * 63) + " "}, "ck_oauth_exchange_codes_hash_hex"),
        ({"code_hash": " " * 64}, "ck_oauth_exchange_codes_hash_hex"),
        ({"client_type": "tablet", "exchange_binding_hash": None}, "ck_oauth_exchange_codes_client_type"),
        ({"auth_version": -1}, "ck_oauth_exchange_codes_auth_version_non_negative"),
        ({"exchange_code_challenge_hash": "f" * 63}, "ck_oauth_exchange_codes_exchange_code_challenge_hash_hex"),
        ({"exchange_code_challenge_hash": ("a" * 63) + " "}, "ck_oauth_exchange_codes_exchange_code_challenge_hash_hex"),
        ({"exchange_code_challenge_hash": " " * 64}, "ck_oauth_exchange_codes_exchange_code_challenge_hash_hex"),
        ({"client_type": "web", "exchange_binding_hash": None}, "ck_oauth_exchange_codes_exchange_binding_consistency"),
        ({"client_type": "mobile", "exchange_binding_hash": "a" * 64}, "ck_oauth_exchange_codes_exchange_binding_consistency"),
        ({"client_type": "web", "exchange_binding_hash": "A" * 64}, "ck_oauth_exchange_codes_exchange_binding_consistency"),
        ({"client_type": "web", "exchange_binding_hash": ("a" * 63) + " "}, "ck_oauth_exchange_codes_exchange_binding_consistency"),
        ({"client_type": "web", "exchange_binding_hash": " " * 64}, "ck_oauth_exchange_codes_exchange_binding_consistency"),
    ],
)
def test_oauth_exchange_code_check_constraints_reject_invalid_rows(
    db_session: Session,
    overrides: dict[str, object],
    expected_constraint: str,
) -> None:
    user = _create_user(db_session, email=f"oec.ck.{uuid.uuid4()}@example.com")
    base: dict[str, object] = {
        "user_id": user.id,
        "code_hash": _sha256_hex(f"oec-{uuid.uuid4()}"),
        "client_type": "web",
        "auth_version": 0,
        "exchange_code_challenge_hash": _sha256_hex("chal-valid"),
        "exchange_binding_hash": _sha256_hex("bind-valid"),
        "expires_at": datetime.now(timezone.utc) + timedelta(seconds=60),
        "consumed_at": None,
    }
    base.update(overrides)
    db_session.add(OAuthExchangeCode(**base))
    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    assert _extract_constraint_name(exc_info.value) == expected_constraint
    db_session.rollback()


# ---------------------------------------------------------------------------
# 4. FK Orphan, NOT NULL, NUL-Byte, and VARCHAR Boundary / Overflow Checks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("model_kind", "expected_fk"),
    [
        ("oauth_accounts", "fk_oauth_accounts_user_id_users"),
        ("oauth_exchange_codes", "fk_oauth_exchange_codes_user_id_users"),
    ],
)
def test_oauth_foreign_keys_reject_orphan_user_id(
    db_session: Session,
    model_kind: str,
    expected_fk: str,
) -> None:
    orphan_user_id = uuid.uuid4()
    if model_kind == "oauth_accounts":
        db_session.add(
            OAuthAccount(
                user_id=orphan_user_id,
                provider="google",
                provider_user_id="orphan-sub-1",
            )
        )
    else:
        db_session.add(
            OAuthExchangeCode(
                user_id=orphan_user_id,
                code_hash=_sha256_hex("orphan-code"),
                client_type="mobile",
                auth_version=0,
                exchange_code_challenge_hash=_sha256_hex("orphan-chal"),
                exchange_binding_hash=None,
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=60),
            )
        )

    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    assert _extract_constraint_name(exc_info.value) == expected_fk
    db_session.rollback()


@pytest.mark.parametrize(
    ("table_name", "null_column"),
    [
        ("oauth_accounts", "user_id"),
        ("oauth_accounts", "provider"),
        ("oauth_accounts", "provider_user_id"),
        ("oauth_accounts", "provider_email_verified"),
        ("oauth_states", "state_hash"),
        ("oauth_states", "provider"),
        ("oauth_states", "client_type"),
        ("oauth_states", "pkce_verifier_encrypted"),
        ("oauth_states", "redirect_uri"),
        ("oauth_states", "exchange_code_challenge_hash"),
        ("oauth_states", "expires_at"),
        ("oauth_exchange_codes", "user_id"),
        ("oauth_exchange_codes", "code_hash"),
        ("oauth_exchange_codes", "client_type"),
        ("oauth_exchange_codes", "auth_version"),
        ("oauth_exchange_codes", "exchange_code_challenge_hash"),
        ("oauth_exchange_codes", "expires_at"),
    ],
)
def test_oauth_not_null_columns_reject_null_values(
    db_session: Session,
    table_name: str,
    null_column: str,
) -> None:
    user = _create_user(db_session, email=f"notnull.{table_name}.{null_column}@example.com")
    now = datetime.now(timezone.utc)

    if table_name == "oauth_accounts":
        params: dict[str, object] = {
            "user_id": user.id,
            "provider": "google",
            "provider_user_id": "sub-notnull",
            "provider_email": None,
            "provider_email_verified": False,
        }
        sql = (
            "INSERT INTO oauth_accounts "
            "(user_id, provider, provider_user_id, provider_email, provider_email_verified) "
            "VALUES (:user_id, :provider, :provider_user_id, :provider_email, :provider_email_verified)"
        )
    elif table_name == "oauth_states":
        params = {
            "state_hash": _sha256_hex(f"notnull-{null_column}"),
            "provider": "google",
            "client_type": "web",
            "pkce_verifier_encrypted": "v1:encrypted",
            "nonce_hash": _sha256_hex("nonce-notnull"),
            "redirect_uri": "https://app.example.com/oauth/cb",
            "client_binding_hash": _sha256_hex("bind-notnull"),
            "exchange_code_challenge_hash": _sha256_hex("chal-notnull"),
            "expires_at": now + timedelta(minutes=10),
        }
        sql = (
            "INSERT INTO oauth_states "
            "(state_hash, provider, client_type, pkce_verifier_encrypted, nonce_hash, "
            "redirect_uri, client_binding_hash, exchange_code_challenge_hash, expires_at) "
            "VALUES (:state_hash, :provider, :client_type, :pkce_verifier_encrypted, :nonce_hash, "
            ":redirect_uri, :client_binding_hash, :exchange_code_challenge_hash, :expires_at)"
        )
    else:
        params = {
            "user_id": user.id,
            "code_hash": _sha256_hex(f"notnull-code-{null_column}"),
            "client_type": "web",
            "auth_version": 0,
            "exchange_code_challenge_hash": _sha256_hex("chal-notnull-oec"),
            "exchange_binding_hash": _sha256_hex("bind-notnull-oec"),
            "expires_at": now + timedelta(seconds=60),
        }
        sql = (
            "INSERT INTO oauth_exchange_codes "
            "(user_id, code_hash, client_type, auth_version, exchange_code_challenge_hash, "
            "exchange_binding_hash, expires_at) "
            "VALUES (:user_id, :code_hash, :client_type, :auth_version, "
            ":exchange_code_challenge_hash, :exchange_binding_hash, :expires_at)"
        )

    params[null_column] = None
    with pytest.raises(IntegrityError):
        db_session.execute(text(sql), params)
    db_session.rollback()


def test_oauth_account_provider_user_id_rejects_nul_byte(db_session: Session) -> None:
    user = _create_user(db_session, email="oa.nul@example.com")
    db_session.add(
        OAuthAccount(
            user_id=user.id,
            provider="google",
            provider_user_id="sub\x00id",
        )
    )
    with pytest.raises(DBAPIError):
        db_session.flush()
    db_session.rollback()


def test_oauth_varchar_exact_max_lengths_accepted(db_session: Session) -> None:
    user = _create_user(db_session, email="varchar.bounds@example.com")
    exact_email_320 = (
        ("a" * 64) + "@" + ("b" * 63) + "." + ("c" * 63) + "." + ("d" * 63) + "." + ("e" * 63)
    )
    assert len(exact_email_320) == 320

    acc = OAuthAccount(
        user_id=user.id,
        provider="google",
        provider_user_id="u" * 255,
        provider_email=exact_email_320,
        provider_email_verified=True,
    )
    db_session.add(acc)

    exact_redirect_512 = "https://example.com/" + ("r" * 492)
    assert len(exact_redirect_512) == 512
    exact_pkce_512 = "v1:" + ("p" * 509)
    assert len(exact_pkce_512) == 512

    st = OAuthState(
        state_hash=_sha256_hex("state-max-len"),
        provider="github",
        client_type="mobile",
        pkce_verifier_encrypted=exact_pkce_512,
        nonce_hash=None,
        redirect_uri=exact_redirect_512,
        client_binding_hash=None,
        exchange_code_challenge_hash=_sha256_hex("chal-max-len"),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    db_session.add(st)
    db_session.flush()


@pytest.mark.parametrize(
    ("target", "column", "oversized_value"),
    [
        ("oauth_accounts", "provider_user_id", "u" * 256),
        (
            "oauth_accounts",
            "provider_email",
            ("a" * 65) + "@" + ("b" * 63) + "." + ("c" * 63) + "." + ("d" * 63) + "." + ("e" * 63),
        ),
        ("oauth_states", "pkce_verifier_encrypted", "v1:" + ("p" * 510)),
        ("oauth_states", "redirect_uri", "https://example.com/" + ("r" * 493)),
    ],
)
def test_oauth_varchar_overflow_rejected(
    db_session: Session,
    target: str,
    column: str,
    oversized_value: str,
) -> None:
    if target == "oauth_accounts":
        user = _create_user(db_session, email=f"overflow.{column}@example.com")
        kwargs: dict[str, object] = {
            "user_id": user.id,
            "provider": "google",
            "provider_user_id": "sub-valid",
            "provider_email": "valid@example.com",
            "provider_email_verified": True,
        }
        kwargs[column] = oversized_value
        db_session.add(OAuthAccount(**kwargs))
    else:
        kwargs = {
            "state_hash": _sha256_hex(f"overflow-{column}-{uuid.uuid4()}"),
            "provider": "github",
            "client_type": "mobile",
            "pkce_verifier_encrypted": "v1:encryptedpayload",
            "nonce_hash": None,
            "redirect_uri": "folio360://auth/callback",
            "client_binding_hash": None,
            "exchange_code_challenge_hash": _sha256_hex("chal-overflow"),
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
        }
        kwargs[column] = oversized_value
        db_session.add(OAuthState(**kwargs))

    with pytest.raises(DBAPIError):
        db_session.flush()
    db_session.rollback()
