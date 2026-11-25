"""Adversarial unit tests for Stage 3C Substage 3C.2 cryptography primitives (REV12)."""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import logging
import os
import re
import secrets
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import SecretStr
import pytest

from app.core.config import Settings
from app.core.security import (
    AES_GCM_NONCE_BYTES,
    MIN_PKCE_DECODED_CIPHERTEXT_BYTES,
    PKCE_CIPHERTEXT_VERSION_PREFIX,
    PKCE_CODE_CHALLENGE_METHOD,
    PKCE_KEY_ROTATION_SKEW_SECONDS,
    PKCE_VERIFIER_CONSUMED_MARKER,
    PROVIDER_PKCE_VERIFIER_LENGTH,
    PKCEDecryptionError,
    compute_pkce_s256_challenge,
    decrypt_pkce_verifier,
    decrypt_pkce_verifier_for_settings,
    encrypt_pkce_verifier,
    encrypt_pkce_verifier_for_settings,
    generate_pkce_verifier,
    get_pkce_previous_key_retention_seconds,
    is_within_pkce_rotation_window,
    load_pkce_encryption_keys,
    validate_pkce_challenge_method,
    validate_pkce_s256_challenge,
    validate_pkce_verifier,
    validate_provider_pkce_verifier,
    verify_pkce_s256,
)

SAMPLE_STATE_HASH = hashlib.sha256(b"sample-oauth-state").hexdigest()
ALT_STATE_HASH = hashlib.sha256(b"different-oauth-state").hexdigest()


def _make_b64url_key(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _oauth_settings(*, primary_raw: bytes, previous_raw: bytes | None = None, expire_minutes: int = 10) -> Settings:
    return Settings(
        _env_file=None,
        ENVIRONMENT="testing",
        OAUTH_PKCE_ENCRYPTION_KEY=_make_b64url_key(primary_raw),
        OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS=(
            _make_b64url_key(previous_raw) if previous_raw is not None else None
        ),
        OAUTH_STATE_EXPIRE_MINUTES=expire_minutes,
    )


# ---------------------------------------------------------------------------
# 1. Acyclic Module Imports Across crypto_keys, config, security
# ---------------------------------------------------------------------------


def test_acyclic_imports_across_all_module_orders() -> None:
    imports = [
        "import app.core.crypto_keys, app.core.config, app.core.security",
        "import app.core.crypto_keys, app.core.security, app.core.config",
        "import app.core.config, app.core.crypto_keys, app.core.security",
        "import app.core.config, app.core.security, app.core.crypto_keys",
        "import app.core.security, app.core.config, app.core.crypto_keys",
        "import app.core.security, app.core.crypto_keys, app.core.config",
    ]
    for stmt in imports:
        proc = subprocess.run(
            [sys.executable, "-c", stmt],
            check=False,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stderr


# ---------------------------------------------------------------------------
# 2. RFC 7636 PKCE (S256 Exclusively) & Locked 86-Char Provider Format
# ---------------------------------------------------------------------------


def test_generate_pkce_verifier_format_and_entropy() -> None:
    seen: set[str] = set()
    for _ in range(32):
        verifier = generate_pkce_verifier()
        assert isinstance(verifier, str)
        assert len(verifier) == PROVIDER_PKCE_VERIFIER_LENGTH == 86
        assert re.fullmatch(r"[A-Za-z0-9_-]{86}", verifier)
        assert "=" not in verifier
        assert validate_provider_pkce_verifier(verifier) == verifier
        assert validate_pkce_verifier(verifier) == verifier
        seen.add(verifier)
    assert len(seen) == 32


def test_rfc7636_appendix_b_s256_test_vector_and_boundary_lengths() -> None:
    # Exact RFC 7636 Appendix B test vector
    rfc_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    rfc_expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert compute_pkce_s256_challenge(rfc_verifier) == rfc_expected_challenge
    assert verify_pkce_s256(rfc_verifier, rfc_expected_challenge, method="S256") is True

    # Client exchange verifiers may be 43..128 RFC 7636 unreserved chars including ._~-
    v43 = "A._~-" + ("a" * 38)
    v128 = "Z._~-" + ("b" * 123)
    assert len(v43) == 43
    assert len(v128) == 128
    for v in (v43, v128):
        ch = compute_pkce_s256_challenge(v)
        assert len(ch) == 43
        assert re.fullmatch(r"[A-Za-z0-9_-]{43}", ch)
        assert verify_pkce_s256(v, ch) is True

    # Provider PKCE verifier enforces the locked 86-character format strictly
    for non_provider in (v43, v128, "a." + ("b" * 84), "a~" + ("b" * 84), "a" * 85, "a" * 87):
        with pytest.raises(ValueError) as exc_info:
            validate_provider_pkce_verifier(non_provider)
        assert non_provider not in str(exc_info.value)


@pytest.mark.parametrize(
    "bad_verifier",
    [
        "",
        "a" * 42,
        "a" * 129,
        f" {'a' * 86}",
        f"{'a' * 86} ",
        f"{'a' * 43} {'a' * 42}",
        f"{'a' * 85}\n",
        f"{'a' * 85}\x00",
        f"{'a' * 85}=",
        f"{'a' * 85}+",
        f"{'a' * 85}/",
        ("é" * 86),
        PKCE_VERIFIER_CONSUMED_MARKER,
        None,
        12345,
    ],
)
def test_pkce_verifier_validation_rejects_malformed_inputs_unmodified_without_echo(
    bad_verifier: object,
) -> None:
    with pytest.raises(ValueError) as exc_info:
        validate_pkce_verifier(bad_verifier)  # type: ignore[arg-type]
    if isinstance(bad_verifier, str) and len(bad_verifier) >= 8:
        assert bad_verifier not in str(exc_info.value)

    with pytest.raises(ValueError):
        compute_pkce_s256_challenge(bad_verifier)  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        validate_provider_pkce_verifier(bad_verifier)  # type: ignore[arg-type]


def test_pkce_plain_is_unconditionally_rejected_and_compare_digest_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = generate_pkce_verifier()
    challenge = compute_pkce_s256_challenge(verifier)

    assert PKCE_CODE_CHALLENGE_METHOD == "S256"
    assert validate_pkce_challenge_method("S256") == "S256"

    for bad_method in ("plain", "PLAIN", "Plain", "s256", " S256", "S256 ", "", None, 256):
        with pytest.raises(ValueError):
            validate_pkce_challenge_method(bad_method)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            validate_pkce_s256_challenge(challenge, method=bad_method)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            verify_pkce_s256(verifier, challenge, method=bad_method)  # type: ignore[arg-type]

    for bad_challenge in (
        "",
        challenge[:-1],
        f"{challenge}=",
        f"{challenge}A",
        f" {challenge}",
        f"{challenge} ",
        ("a" * 42) + "+",
        ("a" * 42) + "/",
        ("a" * 42) + ".",
        None,
    ):
        with pytest.raises(ValueError) as exc_info:
            validate_pkce_s256_challenge(bad_challenge)  # type: ignore[arg-type]
        if isinstance(bad_challenge, str) and len(bad_challenge) >= 8:
            assert bad_challenge not in str(exc_info.value)

    # Verify constant-time hmac.compare_digest invocation in verify_pkce_s256
    compare_calls: list[tuple[object, object]] = []
    real_compare = hmac.compare_digest

    def _spy_compare(a, b):
        compare_calls.append((a, b))
        return real_compare(a, b)

    monkeypatch.setattr(hmac, "compare_digest", _spy_compare)
    assert verify_pkce_s256(verifier, challenge) is True
    other_verifier = generate_pkce_verifier()
    assert verify_pkce_s256(other_verifier, challenge) is False
    assert compare_calls == [
        (challenge, challenge),
        (compute_pkce_s256_challenge(other_verifier), challenge),
    ]


# ---------------------------------------------------------------------------
# 3. AES-256-GCM Encryption, Nonce Freshness, Format & Tamper Detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", ["google", "github"])
def test_aes256_gcm_encrypt_decrypt_roundtrip_and_v1_format(provider: str) -> None:
    key = os.urandom(32)
    verifier = generate_pkce_verifier()

    token = encrypt_pkce_verifier(
        verifier,
        key=key,
        provider=provider,
        state_hash=SAMPLE_STATE_HASH,
    )
    assert token.startswith(PKCE_CIPHERTEXT_VERSION_PREFIX)
    b64_part = token[len("v1:") :]
    assert "=" not in b64_part
    # 12B nonce + 86B verifier + 16B tag = 114 bytes -> 152 unpadded base64url chars
    assert len(b64_part) == 152
    assert len(token) == 155 <= 512

    decoded_raw = base64.urlsafe_b64decode(f"{b64_part}==")
    assert len(decoded_raw) == 12 + 86 + 16

    decrypted = decrypt_pkce_verifier(
        token,
        primary_key=key,
        previous_key=None,
        provider=provider,
        state_hash=SAMPLE_STATE_HASH,
    )
    assert decrypted == verifier


def test_aes256_gcm_uses_fresh_12byte_nonce_on_every_encryption() -> None:
    key = os.urandom(32)
    verifier = generate_pkce_verifier()

    seen_nonces: set[bytes] = set()
    seen_ciphertexts: set[str] = set()
    for _ in range(64):
        ct = encrypt_pkce_verifier(
            verifier,
            key=key,
            provider="google",
            state_hash=SAMPLE_STATE_HASH,
        )
        b64_part = ct[len("v1:") :]
        raw = base64.urlsafe_b64decode(b64_part + ("=" * (-len(b64_part) % 4)))
        nonce = raw[:AES_GCM_NONCE_BYTES]
        assert len(nonce) == 12
        seen_nonces.add(nonce)
        seen_ciphertexts.add(ct)
    assert len(seen_nonces) == 64
    assert len(seen_ciphertexts) == 64


def test_aes256_gcm_rejects_tampering_aad_mismatch_consumed_and_bad_versions() -> None:
    key = os.urandom(32)
    verifier = generate_pkce_verifier()
    token = encrypt_pkce_verifier(
        verifier,
        key=key,
        provider="google",
        state_hash=SAMPLE_STATE_HASH,
    )
    b64_part = token[len("v1:") :]
    raw = bytearray(base64.urlsafe_b64decode(f"{b64_part}=="))

    # 1. Bit-flip in nonce, ciphertext body, GCM tag, and truncated payload
    for flip_idx in (0, 12, 50, len(raw) - 1):
        tampered_raw = bytearray(raw)
        tampered_raw[flip_idx] ^= 0x01
        tampered_tok = "v1:" + base64.urlsafe_b64encode(bytes(tampered_raw)).rstrip(b"=").decode("ascii")
        with pytest.raises(PKCEDecryptionError):
            decrypt_pkce_verifier(
                tampered_tok,
                primary_key=key,
                previous_key=None,
                provider="google",
                state_hash=SAMPLE_STATE_HASH,
            )

    truncated_raw = bytes(raw[:-1])
    truncated_tok = "v1:" + base64.urlsafe_b64encode(truncated_raw).rstrip(b"=").decode("ascii")
    with pytest.raises(PKCEDecryptionError):
        decrypt_pkce_verifier(
            truncated_tok,
            primary_key=key,
            previous_key=None,
            provider="google",
            state_hash=SAMPLE_STATE_HASH,
        )

    # 2. Too short payload (< 29 decoded bytes)
    short_raw = os.urandom(MIN_PKCE_DECODED_CIPHERTEXT_BYTES - 1)
    short_tok = "v1:" + base64.urlsafe_b64encode(short_raw).rstrip(b"=").decode("ascii")
    with pytest.raises(PKCEDecryptionError):
        decrypt_pkce_verifier(
            short_tok,
            primary_key=key,
            previous_key=None,
            provider="google",
            state_hash=SAMPLE_STATE_HASH,
        )

    # 3. Non-canonical trailing bits on otherwise valid-length v1 payload
    trailing_noncanonical_raw = b"\x00" * 30  # 30 bytes % 3 == 0, add 1 byte -> 31 bytes (len%4==2 wait -> 29 bytes)
    nc_raw = b"\x00" * 29  # 29 bytes -> 39 b64 chars, trailing 4 unused bits on last char 'A' (val 0 -> 'B' flips bit)
    canonical_29 = base64.urlsafe_b64encode(nc_raw).rstrip(b"=").decode("ascii")
    assert canonical_29.endswith("A")
    non_canonical_tok = f"v1:{canonical_29[:-1]}B"
    with pytest.raises(PKCEDecryptionError):
        decrypt_pkce_verifier(
            non_canonical_tok,
            primary_key=key,
            previous_key=None,
            provider="google",
            state_hash=SAMPLE_STATE_HASH,
        )

    # 4. Bad markers, unsupported versions, padding, invalid chars
    for bad_token in (
        PKCE_VERIFIER_CONSUMED_MARKER,
        "",
        b64_part,
        f"v2:{b64_part}",
        f"v0:{b64_part}",
        f"V1:{b64_part}",
        f"v1:{b64_part}==",
        f"v1: {b64_part}",
        f"v1:+{b64_part[1:]}",
        f"v1:/{b64_part[1:]}",
        "v1:abcde",  # len % 4 == 1 impossible in Base64
        "v1:",
        None,
    ):
        with pytest.raises(PKCEDecryptionError) as exc_info:
            decrypt_pkce_verifier(
                bad_token,  # type: ignore[arg-type]
                primary_key=key,
                previous_key=None,
                provider="google",
                state_hash=SAMPLE_STATE_HASH,
            )
        if isinstance(bad_token, str) and len(bad_token) >= 8:
            assert bad_token not in str(exc_info.value)

    # 5. AAD mismatches: cross-provider swap, modified state_hash, bad AAD inputs
    with pytest.raises(PKCEDecryptionError):
        decrypt_pkce_verifier(
            token,
            primary_key=key,
            previous_key=None,
            provider="github",
            state_hash=SAMPLE_STATE_HASH,
        )
    with pytest.raises(PKCEDecryptionError):
        decrypt_pkce_verifier(
            token,
            primary_key=key,
            previous_key=None,
            provider="google",
            state_hash=ALT_STATE_HASH,
        )
    for bad_provider in ("gitlab", "GOOGLE", "", "google "):
        with pytest.raises(PKCEDecryptionError):
            decrypt_pkce_verifier(
                token,
                primary_key=key,
                previous_key=None,
                provider=bad_provider,
                state_hash=SAMPLE_STATE_HASH,
            )
        with pytest.raises(ValueError):
            encrypt_pkce_verifier(verifier, key=key, provider=bad_provider, state_hash=SAMPLE_STATE_HASH)

    for bad_hash in (SAMPLE_STATE_HASH.upper(), SAMPLE_STATE_HASH[:-1], "z" * 64, ""):
        with pytest.raises(PKCEDecryptionError):
            decrypt_pkce_verifier(
                token,
                primary_key=key,
                previous_key=None,
                provider="google",
                state_hash=bad_hash,
            )
        with pytest.raises(ValueError):
            encrypt_pkce_verifier(verifier, key=key, provider="google", state_hash=bad_hash)

    # 6. Plaintext not matching locked 86-char provider verifier format rejected post-decrypt
    nonce = os.urandom(12)
    aad = f"google:{SAMPLE_STATE_HASH}".encode("utf-8")
    non86_ct = AESGCM(key).encrypt(nonce, b"short-verifier", aad)
    forged_non86 = "v1:" + base64.urlsafe_b64encode(nonce + non86_ct).rstrip(b"=").decode("ascii")
    with pytest.raises(PKCEDecryptionError):
        decrypt_pkce_verifier(
            forged_non86,
            primary_key=key,
            previous_key=None,
            provider="google",
            state_hash=SAMPLE_STATE_HASH,
        )


def test_aes256_gcm_rejects_bad_raw_key_types_and_lengths() -> None:
    verifier = generate_pkce_verifier()
    valid_key = os.urandom(32)
    token = encrypt_pkce_verifier(verifier, key=valid_key, provider="google", state_hash=SAMPLE_STATE_HASH)

    for bad_key in (os.urandom(16), os.urandom(31), os.urandom(33), bytearray(32), "a" * 32, None):
        with pytest.raises(ValueError):
            encrypt_pkce_verifier(verifier, key=bad_key, provider="google", state_hash=SAMPLE_STATE_HASH)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            decrypt_pkce_verifier(token, primary_key=bad_key, previous_key=None, provider="google", state_hash=SAMPLE_STATE_HASH)  # type: ignore[arg-type]
        if bad_key is not None:
            with pytest.raises(ValueError):
                decrypt_pkce_verifier(token, primary_key=valid_key, previous_key=bad_key, provider="google", state_hash=SAMPLE_STATE_HASH)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 4. Key Rotation, Crypto-Keys Decoder Integration & Timing Window Rule
# ---------------------------------------------------------------------------


def test_settings_key_rotation_and_timing_window(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)

    old_raw = os.urandom(32)
    new_raw = os.urandom(32)
    third_raw = os.urandom(32)
    verifier = generate_pkce_verifier()

    # Phase A: Old key is primary
    settings_old = _oauth_settings(primary_raw=old_raw, expire_minutes=10)
    assert get_pkce_previous_key_retention_seconds(settings_old) == 900
    ct_old = encrypt_pkce_verifier_for_settings(
        verifier,
        settings=settings_old,
        provider="github",
        state_hash=SAMPLE_STATE_HASH,
    )

    # Phase B: Rotated -> new_raw is primary, old_raw is _PREVIOUS
    settings_rotated = _oauth_settings(primary_raw=new_raw, previous_raw=old_raw, expire_minutes=10)
    p_key, prev_key = load_pkce_encryption_keys(settings_rotated)
    assert p_key == new_raw
    assert prev_key == old_raw

    created_at = datetime(2026, 11, 25, 10, 0, 0, tzinfo=timezone.utc)

    # Within state-expiry (10m) + skew (30s) window: previous key decrypts old ciphertext
    for offset in (
        timedelta(seconds=-PKCE_KEY_ROTATION_SKEW_SECONDS),
        timedelta(seconds=0),
        timedelta(minutes=10),
        timedelta(minutes=10, seconds=PKCE_KEY_ROTATION_SKEW_SECONDS),
    ):
        now = created_at + offset
        assert is_within_pkce_rotation_window(state_created_at=created_at, now=now, state_expire_minutes=10) is True
        assert (
            decrypt_pkce_verifier_for_settings(
                ct_old,
                settings=settings_rotated,
                provider="github",
                state_hash=SAMPLE_STATE_HASH,
                state_created_at=created_at,
                now=now,
            )
            == verifier
        )

    # Past expiry + skew window: previous key fallback is disallowed (fail closed)
    expired_now = created_at + timedelta(minutes=10, seconds=PKCE_KEY_ROTATION_SKEW_SECONDS + 1)
    assert is_within_pkce_rotation_window(state_created_at=created_at, now=expired_now, state_expire_minutes=10) is False
    with pytest.raises(PKCEDecryptionError):
        decrypt_pkce_verifier_for_settings(
            ct_old,
            settings=settings_rotated,
            provider="github",
            state_hash=SAMPLE_STATE_HASH,
            state_created_at=created_at,
            now=expired_now,
        )

    # Encryption under rotated settings always uses the new primary key
    ct_new = encrypt_pkce_verifier_for_settings(
        verifier,
        settings=settings_rotated,
        provider="github",
        state_hash=SAMPLE_STATE_HASH,
    )
    assert decrypt_pkce_verifier(ct_new, primary_key=new_raw, previous_key=None, provider="github", state_hash=SAMPLE_STATE_HASH) == verifier
    with pytest.raises(PKCEDecryptionError):
        decrypt_pkce_verifier(ct_new, primary_key=old_raw, previous_key=None, provider="github", state_hash=SAMPLE_STATE_HASH)

    # Primary key ciphertext still decrypts regardless of age once authenticated
    assert (
        decrypt_pkce_verifier_for_settings(
            ct_new,
            settings=settings_rotated,
            provider="github",
            state_hash=SAMPLE_STATE_HASH,
            state_created_at=created_at,
            now=expired_now,
        )
        == verifier
    )

    # Retention seconds adapts cleanly when OAUTH_STATE_EXPIRE_MINUTES > 15m
    settings_20m = _oauth_settings(primary_raw=new_raw, previous_raw=old_raw, expire_minutes=20)
    assert get_pkce_previous_key_retention_seconds(settings_20m) == 20 * 60 + PKCE_KEY_ROTATION_SKEW_SECONDS

    # Unrelated key fails closed
    ct_third = encrypt_pkce_verifier(verifier, key=third_raw, provider="github", state_hash=SAMPLE_STATE_HASH)
    with pytest.raises(PKCEDecryptionError) as dec_exc:
        decrypt_pkce_verifier_for_settings(
            ct_third,
            settings=settings_rotated,
            provider="github",
            state_hash=SAMPLE_STATE_HASH,
        )
    assert verifier not in str(dec_exc.value)
    assert ct_third not in str(dec_exc.value)

    # Phase C: _PREVIOUS removed -> old ciphertext rejected
    settings_final = _oauth_settings(primary_raw=new_raw, previous_raw=None, expire_minutes=10)
    with pytest.raises(PKCEDecryptionError):
        decrypt_pkce_verifier_for_settings(
            ct_old,
            settings=settings_final,
            provider="github",
            state_hash=SAMPLE_STATE_HASH,
        )

    # Missing primary key in Settings fails closed
    settings_unset = Settings(_env_file=None, ENVIRONMENT="testing")
    with pytest.raises(RuntimeError):
        load_pkce_encryption_keys(settings_unset)

    # Naive datetimes rejected fail-closed
    with pytest.raises(ValueError):
        is_within_pkce_rotation_window(state_created_at=datetime(2026, 11, 25, 10, 0, 0))
    with pytest.raises(ValueError):
        decrypt_pkce_verifier_for_settings(
            ct_old,
            settings=settings_rotated,
            provider="github",
            state_hash=SAMPLE_STATE_HASH,
            state_created_at=created_at,
            now=datetime(2026, 11, 25, 10, 5, 0),
        )

    # Cryptographic operations never emit logs containing keys, verifiers, or ciphertexts
    assert caplog.records == []


def test_load_pkce_encryption_keys_consumes_strict_crypto_keys_decoder_without_secret_leak() -> None:
    # Force an unvalidated Settings object via model_construct to prove load_pkce_encryption_keys
    # still enforces decode_aes256_base64url_key from app.core.crypto_keys.
    bad_b64 = ("A" * 42) + "B"  # non-zero unused trailing bits
    valid_padded = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")

    constructed = Settings.model_construct(
        OAUTH_PKCE_ENCRYPTION_KEY=SecretStr(bad_b64),
        OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS=None,
    )
    with pytest.raises(ValueError) as exc_primary:
        load_pkce_encryption_keys(constructed)
    assert "OAUTH_PKCE_ENCRYPTION_KEY" in str(exc_primary.value)
    assert bad_b64 not in str(exc_primary.value)

    constructed_prev = Settings.model_construct(
        OAUTH_PKCE_ENCRYPTION_KEY=SecretStr(valid_padded),
        OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS=SecretStr(bad_b64),
    )
    with pytest.raises(ValueError) as exc_prev:
        load_pkce_encryption_keys(constructed_prev)
    assert "OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS" in str(exc_prev.value)
    assert bad_b64 not in str(exc_prev.value)
    assert valid_padded not in str(exc_prev.value)
