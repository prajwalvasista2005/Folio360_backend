# F360-S3C-SPEC-REV3 — Stage 3C OAuth Authentication

**Specification ID:** `F360-S3C-SPEC-REV3`  
**Project:** Student360 / Folio360 Backend  
**Stage:** 3C — OAuth Authentication  
**Status:** Draft prepared for independent technical review  
**Baseline Commit:** `71bea17e6e533b013ddd04bd6146b35357f108c5` (verified read-only via `git rev-parse HEAD`)  
**Supersedes:** `F360-S3C-SPEC-REV2` (and `F360-S3C-SPEC-REV1`)  
**Review Basis:** Independent Technical Review Report — `F360-S3C-SPEC-REV2` (`R2-1`–`R2-4`) and REV1 (`C-1`–`L-2`)  
**Implementation Status:** Not authorized

---

# 1. Objective and Scope

Stage 3C introduces Google and GitHub OAuth authentication into the existing Folio360 backend.

OAuth supplements existing email/password authentication. It does not replace or rewrite the established authentication architecture.

The implementation must preserve:

- Existing user identity and account ownership ([`app/models/user.py`](app/models/user.py)).
- Existing HS256 access-token construction and validation ([`app/core/security.py`](app/core/security.py)).
- Existing refresh-token rotation and family revocation ([`app/models/refresh_session.py`](app/models/refresh_session.py), [`app/services/auth_service.py`](app/services/auth_service.py)).
- Existing web (`HttpOnly` cookie) and mobile (JSON, zero cookies) token-delivery contracts ([`app/api/routes/auth.py`](app/api/routes/auth.py)).
- Existing strict web `Origin` CSRF validation ([`app/api/deps/auth.py`](app/api/deps/auth.py)).
- Existing global database row-lock hierarchy (`users` first, then child tables).
- Existing Stage 1, 2, 3A, and 3B API, migration, security, and test contracts.

## 1.1 Supported Providers

1. **Google OAuth 2.0 with OpenID Connect (OIDC)** identity validation.
2. **GitHub OAuth 2.0** with immutable user-ID resolution and bounded paginated verified-email retrieval.

## 1.2 Non-Negotiable Security Principles

1. Provider identity is determined solely by an immutable `(provider, provider_user_id)` pair.
2. Email matching never causes automatic account merging.
3. Explicit authenticated account linking is deferred.
4. OAuth `state` is validated on every callback.
5. PKCE `S256` is mandatory for both Google and GitHub flows (`plain` is forbidden).
6. Client redirect destinations must match configured allowlists by exact raw string equality.
7. Access tokens, refresh tokens, provider authorization codes, OAuth state, and ID tokens never appear in client redirect URLs.
8. OAuth exchange codes are opaque, single-use, and valid for exactly 60 seconds.
9. External HTTP operations never execute inside an open database transaction (`not db.in_transaction()`).
10. Database row locks and pooled connections are never held during provider HTTP or JWKS requests.
11. OAuth sessions are issued through the existing Folio360 session-creation implementation (`_create_session_and_mint_tokens`, refactored to a shared service helper).
12. Existing Stage 1, 2, 3A, and 3B functionality remains backward-compatible.

---

# 2. Binding Architectural Decisions

All 23 approved architectural decisions remain locked:

| ID | Binding Decision |
| :--- | :--- |
| **D01** | Support Google and GitHub OAuth. |
| **D02** | New GitHub accounts require a suitable verified email; otherwise reject with `verified_email_required`. |
| **D03** | Existing GitHub identities authenticate by immutable provider ID, regardless of subsequent email changes. |
| **D04** | Explicit account linking is deferred. |
| **D05** | Automatic account merging is prohibited (`email_already_registered`). |
| **D06** | Validate OAuth `state` on every callback. |
| **D07** | Use PKCE `S256` where supported (both Google and GitHub). |
| **D08** | Enforce exact redirect URI allowlists. |
| **D09** | Exchange codes are opaque, single-use, and valid for exactly 60 seconds. |
| **D10** | Exchange codes are consumed exclusively through `POST /api/v1/auth/oauth/exchange`. |
| **D11** | Never expose access or refresh tokens in redirect URLs. |
| **D12** | Reuse existing `httpx` (`0.28.1`) and `PyJWT[crypto]` (`PyJWT==2.15.1`, `cryptography==50.0.2`). |
| **D13** | Do not introduce `Authlib`, `itsdangerous`, or `Redis`. |
| **D14** | Preserve existing JWT, refresh-session, and session-revocation architecture. |
| **D15** | Extend `GET /api/v1/auth/me` with alphabetically sorted `oauth_providers: list[str]`. |
| **D16** | Missing or unknown callback `state` returns JSON HTTP `400 INVALID_OAUTH_STATE` with no redirect. |
| **D17** | Bind exchange codes to the user's `auth_version` at issuance. |
| **D18** | Google and GitHub credentials are independently optional. |
| **D19** | Web OAuth redirect origins must be a subset of `CORS_ORIGINS` whenever at least one OAuth provider is configured. |
| **D20** | Refresh provider-email metadata only when fresh verified information is available; never automatically change `users.email`. |
| **D21** | Default mobile callback URI is `folio360://auth/callback`; Expo Go `exp://` support is deferred. |
| **D22** | Store Google OIDC `nonce` exclusively as a lowercase hex SHA-256 digest (`nonce_hash`). |
| **D23** | Implement safe, bounded PostgreSQL cleanup for expired `oauth_states` and `oauth_exchange_codes` records. |

## 2.1 Locked Policy Refinements

1. **Returning Google Identity:** An existing Google identity is resolved by its validated immutable `sub`. For a returning Google user, `email_verified=False` or an absent `email` claim is permitted provided all other OIDC validations succeed and no present claim has a malformed type (§6.5). For new-account creation, a valid `email` and strict boolean `email_verified is True` are mandatory.
2. **Mandatory PKCE Encryption Key When OAuth Is Enabled:** Whenever either Google or GitHub credentials are configured, `OAUTH_PKCE_ENCRYPTION_KEY` is mandatory and must be valid in `development`, `testing`, and `production`. Missing or invalid encryption keys fail `Settings` validation / startup immediately rather than degrading to request-time `503`.
3. **Consume-on-Mismatch Policy for Active States:** For an **active** (`consumed_at IS NULL AND expires_at > now`) known `oauth_states` row:
   - Wrong `provider` consumes and scrubs the state row (`consumed_at = now`, `pkce_verifier_encrypted = '[CONSUMED]'`) and rejects the callback with `302` -> `{redirect_uri}?error=invalid_oauth_state`.
   - Missing or mismatched web `folio360_oauth_binding` cookie consumes and scrubs the state row and rejects the callback with `302` -> `{redirect_uri}?error=invalid_oauth_state`.
   - Already-consumed (`consumed_at IS NOT NULL`) and expired (`expires_at <= now`) rows are **never modified** on replay (transaction rolls back untouched).

---

# 3. Existing Architecture Compatibility

Stage 3C integrates into the verified baseline at commit `71bea17e6e533b013ddd04bd6146b35357f108c5`:

| Component | Verified Baseline Implementation | Contract Preserved in Stage 3C |
| :--- | :--- | :--- |
| **Framework & ASGI3** | `FastAPI==0.163.1`, `uvicorn==0.54.0` (`Folio360FastAPI`, `VerifiedUvicornConfig` in [`app/main.py`](app/main.py), [`app/server.py`](app/server.py)) | Synchronous `def` route handlers in Starlette threadpool; ASGI3 production gates intact. |
| **Database & ORM** | PostgreSQL 17, synchronous `SQLAlchemy==2.0.38`, `psycopg==3.3.9` ([`app/db/base.py`](app/db/base.py), [`app/db/session.py`](app/db/session.py)) | `autocommit=False`, `autoflush=False`, `expire_on_commit=False`, `hide_parameters=True`, `Base`, `TimestampMixin`, `POSTGRES_NAMING_CONVENTION`. |
| **Split DB Roles** | [`docker/postgres/init-least-privilege.sh`](docker/postgres/init-least-privilege.sh) | Runtime `*_app` role has DML-only privileges (inherited via `ALTER DEFAULT PRIVILEGES`); `*_migrator` role owns all tables and runs Alembic DDL. |
| **User & Sessions** | [`app/models/user.py`](app/models/user.py), [`app/models/refresh_session.py`](app/models/refresh_session.py) | UUID PKs, canonical email CHECKs, nullable `password_hash`, `auth_version`, 14d rolling / 30d absolute rotating refresh families. |
| **Security & JWT** | `argon2-cffi==25.1.0`, `PyJWT==2.15.1`, `cryptography==50.0.2`, `httpx==0.28.1` ([`app/core/security.py`](app/core/security.py)) | Existing Argon2id, SHA-256 `hash_opaque_token`, and HS256 JWT (`sub`, `ver`, `type="access"`, `iss`, `aud`, `iat`, `exp`, `jti`) unchanged; zero new packages added. |
| **Client Transport & CSRF** | [`app/api/deps/auth.py`](app/api/deps/auth.py), [`app/api/routes/auth.py`](app/api/routes/auth.py) | `X-Client-Type: web \| mobile`, exact `Origin` match in `CORS_ORIGINS` for web, API-prefix-derived refresh cookie path. |
| **Errors, Rate Limiting & Logging** | [`app/core/exceptions.py`](app/core/exceptions.py), [`app/core/rate_limit.py`](app/core/rate_limit.py), [`app/core/logging.py`](app/core/logging.py) | `{"error": {"message", "status_code", "details": {"code": ...}}}` envelope, 422 `input` stripping, `SlidingWindowRateLimiter`, `resolve_client_ip()`, `SecurityFilter`/`SecurityFormatter`. |

## 3.1 Existing Authentication Routes

All 11 existing routes under `/api/v1/auth` preserve their established HTTP status codes, response schemas, cookie behavior, and error codes—except the approved additive `oauth_providers` field on `GET /api/v1/auth/me` (§16):

- `POST /register`, `POST /verify-email`, `POST /resend-verification`, `POST /login`, `POST /refresh`, `POST /logout`, `POST /logout-all`, `GET /me`, `POST /forgot-password`, `POST /reset-password`, `POST /change-password`.

## 3.2 OAuth-Only Account Behavior

New OAuth-provisioned users are persisted with:

- `password_hash = NULL`
- `is_email_verified = TRUE`
- `email_verified_at = now` (UTC, satisfying `ck_users_email_verified_at_consistency`)
- `is_active = TRUE`
- `auth_version = 0`
- `password_changed_at = NULL`

Existing Stage 3A/3B behavior for OAuth-only accounts remains unchanged:

| Operation | Behavior |
| :--- | :--- |
| `POST /api/v1/auth/login` | Runs `DUMMY_PASSWORD_HASH` Argon2id check -> `401 INVALID_CREDENTIALS`. |
| `POST /api/v1/auth/forgot-password` | Generic `202 Accepted`; zero email sent; zero `password_reset_tokens` inserted. |
| `POST /api/v1/auth/reset-password` | Defensive rejection -> `400 INVALID_RESET_TOKEN`. |
| `POST /api/v1/auth/change-password` | `400 PASSWORD_NOT_SET`. |
| `GET /api/v1/auth/me` | `has_password: false`, `oauth_providers: ["google"]` / `["github"]`. |

---

# 4. Database Schema and Constraints

## 4.1 Migration Plan (`0004_add_oauth_tables`)

Create `alembic/versions/0004_add_oauth_tables.py`:

- **Revision:** `0004_add_oauth_tables`
- **Down revision:** `0003_add_password_reset_tokens`
- **Upgrade scope:** Create exactly three tables: `oauth_accounts`, `oauth_states`, `oauth_exchange_codes` (with all constraints and indexes below).
- **Downgrade scope:** Drop indexes and tables in reverse order (`oauth_exchange_codes`, `oauth_states`, `oauth_accounts`).

Existing migrations `0001_create_users`, `0002_add_core_auth_tables`, and `0003_add_password_reset_tokens` are immutable. Existing tables (`users`, `email_verification_tokens`, `password_reset_tokens`, `refresh_sessions`) require zero schema modifications.

All new ORM models live in `app/models/oauth.py`, inherit from `Base` and `TimestampMixin` ([`app/db/base.py`](app/db/base.py)), follow `POSTGRES_NAMING_CONVENTION`, use `Uuid(as_uuid=True)` primary keys (`default=uuid.uuid4`, `server_default=text("gen_random_uuid()")`), and are exported through [`app/models/__init__.py`](app/models/__init__.py) for `alembic check` parity.

## 4.2 Table: `oauth_accounts`

Persists external immutable OAuth provider identities linked to a Folio360 user.

| Column | SQL Type | Null | Default / Constraint |
| :--- | :--- | :--- | :--- |
| `id` | `UUID` | `NO` | PK `pk_oauth_accounts`, `server_default=gen_random_uuid()` |
| `user_id` | `UUID` | `NO` | FK `fk_oauth_accounts_user_id_users` -> `users.id ON DELETE CASCADE` |
| `provider` | `VARCHAR(32)` | `NO` | `ck_oauth_accounts_provider` |
| `provider_user_id` | `VARCHAR(255)` | `NO` | `ck_oauth_accounts_provider_user_id_valid` |
| `provider_email` | `VARCHAR(320)` | `YES` | `ck_oauth_accounts_provider_email_canonical` |
| `provider_email_verified` | `BOOLEAN` | `NO` | `server_default=false`, `ck_oauth_accounts_email_verified_consistency` |
| `created_at` | `TIMESTAMPTZ` | `NO` | `TimestampMixin` (`now()`) |
| `updated_at` | `TIMESTAMPTZ` | `NO` | `TimestampMixin` (`now()`) |

**Unique Constraints:**
- `uq_oauth_accounts_provider_subject` on `(provider, provider_user_id)`
- `uq_oauth_accounts_user_provider` on `(user_id, provider)`

**Index:**
- `ix_oauth_accounts_user_id` on `(user_id)`

**PostgreSQL `CHECK` Constraints** (short names under `POSTGRES_NAMING_CONVENTION` yield `ck_oauth_accounts_<name>`):
- `provider`: `provider IN ('google', 'github')`
- `provider_user_id_valid`: `provider_user_id = btrim(provider_user_id) AND provider_user_id <> '' AND provider_user_id !~ '[[:space:][:cntrl:]]'`
- `provider_email_canonical`: `provider_email IS NULL OR (provider_email = lower(btrim(provider_email)) AND provider_email <> '' AND provider_email !~ '[[:space:]]')`
- `email_verified_consistency`: `provider_email IS NOT NULL OR provider_email_verified = false`

**Identity & Metadata Rules:**
- `(provider, provider_user_id)` is immutable and is the sole key for resolving returning OAuth users.
- `provider_email` is informational metadata only and never triggers account merging or modifies `users.email`.
- **Google returning user:** refresh `provider_email` and `provider_email_verified = True` only when the validated ID token supplies a valid canonical email with `email_verified is True` (skip no-op writes when unchanged).
- **GitHub returning user:** the returning-user fast path must **not** call `/user/emails` merely to refresh metadata, and must **never** copy unverified `/user.email` into `provider_email`.

## 4.3 Table: `oauth_states`

Persists cross-worker single-use authorization state and AES-256-GCM-encrypted PKCE verifiers. Has no foreign key to `users`.

| Column | SQL Type | Null | Default / Constraint |
| :--- | :--- | :--- | :--- |
| `id` | `UUID` | `NO` | PK `pk_oauth_states`, `server_default=gen_random_uuid()` |
| `state_hash` | `CHAR(64)` | `NO` | UNIQUE `uq_oauth_states_state_hash`, `ck_oauth_states_state_hash_hex` |
| `provider` | `VARCHAR(32)` | `NO` | `ck_oauth_states_provider` |
| `client_type` | `VARCHAR(16)` | `NO` | `ck_oauth_states_client_type` |
| `pkce_verifier_encrypted` | `VARCHAR(512)` | `NO` | `ck_oauth_states_pkce_not_empty`, `ck_oauth_states_consumed_pkce_scrubbed` |
| `nonce_hash` | `CHAR(64)` | `YES` | `ck_oauth_states_nonce_hash_consistency` |
| `redirect_uri` | `VARCHAR(512)` | `NO` | `ck_oauth_states_redirect_uri_valid` |
| `client_binding_hash` | `CHAR(64)` | `YES` | `ck_oauth_states_client_binding_consistency` |
| `expires_at` | `TIMESTAMPTZ` | `NO` | Default 10 minutes (`OAUTH_STATE_EXPIRE_MINUTES`) |
| `consumed_at` | `TIMESTAMPTZ` | `YES` | Single-use consumption timestamp |
| `created_at` | `TIMESTAMPTZ` | `NO` | `TimestampMixin` (`now()`) |
| `updated_at` | `TIMESTAMPTZ` | `NO` | `TimestampMixin` (`now()`) |

**Index:**
- `ix_oauth_states_expires_at` on `(expires_at)`

**PostgreSQL `CHECK` Constraints:**
- `provider`: `provider IN ('google', 'github')`
- `client_type`: `client_type IN ('web', 'mobile')`
- `state_hash_hex`: `state_hash ~ '^[0-9a-f]{64}$'`
- `pkce_not_empty`: `length(btrim(pkce_verifier_encrypted)) > 0`
- `redirect_uri_valid`: `length(btrim(redirect_uri)) > 0 AND redirect_uri = btrim(redirect_uri)`
- `nonce_hash_consistency`: `(provider = 'google' AND nonce_hash IS NOT NULL AND nonce_hash ~ '^[0-9a-f]{64}$') OR (provider = 'github' AND nonce_hash IS NULL)`
- `client_binding_consistency`: `(client_type = 'web' AND client_binding_hash IS NOT NULL AND client_binding_hash ~ '^[0-9a-f]{64}$') OR (client_type = 'mobile' AND client_binding_hash IS NULL)`
- `consumed_pkce_scrubbed`:
  ```sql
  CHECK (
      (consumed_at IS NULL AND pkce_verifier_encrypted <> '[CONSUMED]')
      OR
      (consumed_at IS NOT NULL AND pkce_verifier_encrypted = '[CONSUMED]')
  )
  ```

**Invariants:**
- Raw `state`, raw `nonce`, raw browser-binding token, and plaintext PKCE verifier are never persisted or logged.
- Every state-consumption branch in §11 must set `consumed_at = now` and `pkce_verifier_encrypted = '[CONSUMED]'` together in the same transaction so `ck_oauth_states_consumed_pkce_scrubbed` is always satisfied.

## 4.4 Table: `oauth_exchange_codes`

Stores single-use 60-second opaque exchange codes bound to `user_id`, `client_type`, and `auth_version`.

| Column | SQL Type | Null | Default / Constraint |
| :--- | :--- | :--- | :--- |
| `id` | `UUID` | `NO` | PK `pk_oauth_exchange_codes`, `server_default=gen_random_uuid()` |
| `user_id` | `UUID` | `NO` | FK `fk_oauth_exchange_codes_user_id_users` -> `users.id ON DELETE CASCADE` |
| `code_hash` | `CHAR(64)` | `NO` | UNIQUE `uq_oauth_exchange_codes_code_hash`, `ck_oauth_exchange_codes_hash_hex` |
| `client_type` | `VARCHAR(16)` | `NO` | `ck_oauth_exchange_codes_client_type` |
| `auth_version` | `INTEGER` | `NO` | `ck_oauth_exchange_codes_auth_version_non_negative` |
| `expires_at` | `TIMESTAMPTZ` | `NO` | Fixed `now + timedelta(seconds=60)` |
| `consumed_at` | `TIMESTAMPTZ` | `YES` | Single-use consumption timestamp |
| `created_at` | `TIMESTAMPTZ` | `NO` | `TimestampMixin` (`now()`) |
| `updated_at` | `TIMESTAMPTZ` | `NO` | `TimestampMixin` (`now()`) |

**Indexes:**
- `ix_oauth_exchange_codes_user_id` on `(user_id)`
- `ix_oauth_exchange_codes_expires_at` on `(expires_at)`

**PostgreSQL `CHECK` Constraints:**
- `hash_hex`: `code_hash ~ '^[0-9a-f]{64}$'`
- `client_type`: `client_type IN ('web', 'mobile')`
- `auth_version_non_negative`: `auth_version >= 0`

**Lifecycle:**
- No `revoked_at` column is required. Global invalidation (`/logout-all`, `/reset-password`, `/change-password`) increments `users.auth_version`, immediately invalidating any unconsumed exchange code whose recorded `auth_version != user.auth_version`.

---

# 5. Cryptographic Design

All new cryptographic utilities live in [`app/core/security.py`](app/core/security.py) and reuse already-pinned `cryptography==50.0.2` and Python stdlib `secrets`, `hashlib`, `base64`, `hmac`.

## 5.1 PKCE (`S256` Only)

Implement:
- `generate_pkce_verifier() -> str`: returns `secrets.token_urlsafe(64)` (86 ASCII URL-safe characters from `[A-Za-z0-9_-]`, 512 bits of entropy, satisfying RFC 7636 §4.1's `43..128` character requirement).
- `compute_pkce_s256_challenge(verifier: str) -> str`: validates `verifier` is an ASCII string of length `43..128` containing only RFC 7636 unreserved characters (`^[A-Za-z0-9._~-]{43,128}$`), computes `SHA-256(verifier.encode("ascii"))`, and returns unpadded Base64url (`base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")`).
- `PKCE_VERIFIER_CONSUMED_MARKER = "[CONSUMED]"`.

The `plain` PKCE method is strictly prohibited on both Google and GitHub flows.

## 5.2 AES-256-GCM Encryption of PKCE Verifiers at Rest

Implement:
- `decode_aes256_base64url_key(raw_key: str, *, field_name: str) -> bytes` — **one shared decoder** imported by both [`app/core/config.py`](app/core/config.py) and [`app/core/security.py`](app/core/security.py).
- `encrypt_pkce_verifier(verifier: str, *, key: bytes, provider: str, state_hash: str) -> str`
- `decrypt_pkce_verifier(ciphertext: str, *, primary_key: bytes, previous_key: bytes | None, provider: str, state_hash: str) -> str`

### Exact Key Format & Strict Validation (`decode_aes256_base64url_key`)

Both `OAUTH_PKCE_ENCRYPTION_KEY` and `OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS` must encode exactly **32 raw bytes** using canonical URL-safe Base64:

- **Accepted canonical forms:**
  - 43-character unpadded Base64url (e.g., `secrets.token_urlsafe(32)`).
  - 44-character Base64url with exactly one trailing `=` (e.g., `base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")`).
- **Canonical regex:** `^[A-Za-z0-9_-]{43}=?$`
- **Strict rejections:**
  - Standard Base64 characters `+` or `/`.
  - Any leading, trailing, or embedded whitespace.
  - Two or more trailing `=` characters or internal `=`.
  - Non-canonical trailing bits (verified by round-trip re-encoding: decoded 32 bytes re-encoded with `urlsafe_b64encode` stripped of `=` must exactly equal `raw_key.rstrip("=")`).
  - Any decoded length other than exactly 32 bytes.
  - Never silently normalize, strip, truncate, pad, or hash arbitrary strings into keys.

### Ciphertext Construction & Verification

- **Primitive:** `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
- **Nonce:** Fresh 12-byte random nonce per row (`os.urandom(12)`).
- **Associated Authenticated Data (AAD):** `f"{provider}:{state_hash}".encode("utf-8")`.
- **Storage Format:** `f"v1:{base64.urlsafe_b64encode(nonce + ct_with_tag).rstrip(b'=').decode('ascii')}"` (for an 86-byte verifier: `12 + 86 + 16 = 114` raw bytes -> `152` b64url chars -> `155` chars total, well within `VARCHAR(512)`).
- **Decryption:**
  - Immediately reject `PKCE_VERIFIER_CONSUMED_MARKER` (`"[CONSUMED]"`), missing `"v1:"` prefix, malformed Base64url, or decoded payloads shorter than `12 + 16 + 1` bytes.
  - Attempt decryption with `primary_key` first; if `InvalidTag` and `previous_key is not None`, attempt `previous_key`; raise a dedicated `PKCEDecryptionError` on failure.
- **Key Rotation Procedure:**
  1. Generate a new 32-byte Base64url key and install as `OAUTH_PKCE_ENCRYPTION_KEY`.
  2. Move the former primary key to `OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS`.
  3. Wait at least `OAUTH_STATE_EXPIRE_MINUTES` plus clock-skew margin (minimum 15 minutes).
  4. Remove `OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS` once all prior states have expired or been consumed.

## 5.3 State, Nonce, and Browser-Binding Hashing

- `raw_state = generate_opaque_token()` -> persist only `state_hash = hash_opaque_token(raw_state)`.
- `raw_nonce = generate_opaque_token()` (Google only) -> send `raw_nonce` in Google authorize query; persist only `nonce_hash = hash_opaque_token(raw_nonce)`; on callback validate `hmac.compare_digest(hash_opaque_token(claims["nonce"]), state_row.nonce_hash)`.
- `raw_binding = generate_opaque_token()` (web only) -> set in `folio360_oauth_binding` cookie; persist only `client_binding_hash = hash_opaque_token(raw_binding)`; on callback validate `hmac.compare_digest(hash_opaque_token(cookie_val), state_row.client_binding_hash)`.

---

# 6. Google OpenID Connect Protocol

## 6.1 Authoritative Endpoints & Transport

| Operation | Endpoint | Method & Headers |
| :--- | :--- | :--- |
| **Authorization** | `https://accounts.google.com/o/oauth2/v2/auth` | Browser `302` redirect; query: `client_id`, `redirect_uri` (backend callback), `response_type=code`, `scope=openid email profile`, `state`, `nonce`, `code_challenge`, `code_challenge_method=S256` |
| **Token Exchange** | `https://oauth2.googleapis.com/token` | `POST`, `Content-Type: application/x-www-form-urlencoded`, body: `code`, `client_id`, `client_secret`, `redirect_uri` (backend callback), `grant_type=authorization_code`, `code_verifier` |
| **JWKS** | `https://www.googleapis.com/oauth2/v3/certs` | `GET` via `HttpxJWKClient` (§6.6) |

All outbound `httpx` requests enforce `timeout=settings.OAUTH_HTTP_TIMEOUT_SECONDS` (`5.0s` default) and `follow_redirects=False`. Require HTTP `200` JSON containing a non-empty string `id_token`.

## 6.2 Pre-JWKS Unverified JWT Header Validation

Before calling `HttpxJWKClient`, parse the unverified JWT header (`jwt.get_unverified_header(id_token)`):

- Require `header.get("alg") == "RS256"`.
- Require `kid = header.get("kid")` with `type(kid) is str`, `len(kid) > 0`, and `kid == kid.strip()`.

Reject invalid headers immediately as `oauth_provider_error` without invoking JWKS lookup or triggering cooldown-gated network refreshes.

## 6.3 Signature, Issuer, Temporal, Audience (`aud`), and `azp` Validation

Using `PyJWT==2.15.1` (`jwt.decode`):

1. **Algorithm Pinning:** `algorithms=["RS256"]` exclusively (never `none`, `HS256`, or dynamic algorithms).
2. **Temporal Claims (`leeway=30`):** Require `exp` and `iat` (`options={"require": ["iss", "sub", "aud", "exp", "iat"], "verify_signature": True, "verify_exp": True, "verify_iat": True, "verify_nbf": True, "verify_aud": False, "verify_iss": False}`), validated with `leeway=30` seconds. *(Verified in `PyJWT==2.15.1`: `_validate_iat` enforces integer `iat <= now + leeway`, and `verify_nbf` enforces `nbf` when present.)*
3. **Issuer (`iss`):** Strictly `type(iss) is str` and `iss in {"https://accounts.google.com", "accounts.google.com"}`.
4. **Audience (`aud`) & Authorized Party (`azp`) — OIDC Core 1.0 §3.1.3.7:**
   - Reject missing or `None` `aud`.
   - If `type(aud) is str`: reject empty or leading/trailing whitespace; `aud_list = [aud]`.
   - Else if `type(aud) is list`: reject empty list or any item where `type(item) is not str`, empty, or leading/trailing whitespace; `aud_list = aud`.
   - Else reject.
   - Reject duplicate values (`len(aud_list) != len(set(aud_list))`).
   - Require configured `GOOGLE_CLIENT_ID` present via `any(hmac.compare_digest(a, expected_client_id) for a in aud_list)`.
   - Let `trusted = {expected_client_id} | set(settings.GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES)`. Reject if any element in `aud_list` is not in `trusted` (**even when `azp == expected_client_id`**).
   - If `len(aud_list) > 1`, require `"azp"` present and non-`None`.
   - Whenever `"azp"` is present (single or multiple audiences), require `type(azp) is str`, `len(azp) > 0`, `azp == azp.strip()`, and `hmac.compare_digest(azp, expected_client_id)`.
5. **Nonce (`nonce`):** Require `type(claims.get("nonce")) is str`, non-empty, and `hmac.compare_digest(hash_opaque_token(claims["nonce"]), expected_nonce_hash)`.

## 6.4 Subject (`sub`) Validation

Require `sub = claims.get("sub")` where:
- `type(sub) is str`
- `1 <= len(sub) <= 255`
- `sub == sub.strip()`
- No whitespace or control characters (`not any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in sub)`).

Malformed subjects are rejected as `oauth_provider_error` before any database operation.

## 6.5 Google Email & Claim-Type Rules

1. **Strict Claim-Type Validation (applies to ALL Google logins — new and returning):**
   - If `"email_verified"` is present in claims, require `type(claims["email_verified"]) is bool`. A non-boolean value (e.g., `"true"`, `1`, `None`) is malformed -> reject with `oauth_provider_error`.
   - If `"email"` is present in claims, require `type(claims["email"]) is str` and syntactically valid normalized email (`1 <= len <= 320`, no whitespace, valid `EmailStr`). A non-string or syntactically malformed email claim -> reject with `oauth_provider_error`.
2. **Existing Linked Google Identity (`(google, sub)` found in `oauth_accounts`):**
   - Authenticate via validated immutable `sub`.
   - `email_verified=False` or absent `email` / absent `email_verified` is permitted (does not block login).
   - Never modify `users.email`.
   - Refresh `oauth_accounts.provider_email` and `oauth_accounts.provider_email_verified = True` only when fresh valid `email` AND `email_verified is True` are present.
3. **New Google Account (`(google, sub)` not found):**
   - Require valid `email` AND strict boolean `email_verified is True`.
   - If `email` is absent, `email_verified` is absent, or `email_verified is False` -> redirect `302` with `error=verified_email_required` (zero DB rows created).

## 6.6 HTTPX-Backed JWKS Client (`HttpxJWKClient`)

Implement `HttpxJWKClient(PyJWKClient)` (verified against `PyJWT==2.15.1`'s `PyJWKClient` interface):

- **Explicit Cache Settings:**
  - `uri = "https://www.googleapis.com/oauth2/v3/certs"`
  - `cache_jwk_set = True`
  - `cache_keys = False` (Tier-2 LRU has no TTL; keeping it disabled guarantees revoked keys expire with the 300s JWK Set TTL)
  - `lifespan = 300`
  - `cooldown_duration = 30`
  - `timeout = settings.OAUTH_HTTP_TIMEOUT_SECONDS`
- **Response Size Limit:** `MAX_JWKS_RESPONSE_BYTES = 65_536`. Enforce byte cap while reading response body **before** `json.loads()` (reject oversized payloads with `PyJWKClientError`).
- **Socket Lifecycle & HTTP Transport:** Inside `fetch_data()`, open a short-lived context-managed `with httpx.Client(timeout=self.timeout, follow_redirects=False) as client:` so sockets are closed deterministically immediately after each fetch and no persistent `httpx.Client` leaks sockets across `create_app()` lifespans.
- **Validation & Last-Good Cache Preservation:**
  - Require HTTP `200` (non-200, redirect `3xx`, timeout, or network error raises `PyJWKClientConnectionError`).
  - Parse JSON, verify top-level `dict`, and validate structure via `PyJWKSet.from_dict(payload)` **before** updating cache.
  - Never overwrite a valid cached JWK Set with an invalid payload. Preserve a last-known-good `PyJWKSet` reference (`_last_known_good_jwk_set`) on transient fetch failures during cache refresh so temporary JWKS blips do not wipe valid keys (while still failing closed if no matching key exists or no prior cache was ever fetched).
- **Scoping:** Attach `HttpxJWKClient` to `app.state.google_jwk_client` (initialized lazily or in `create_app()`/`lifespan`, never as an unbounded module-level global) so separate `create_app()` instances and tests never share stale JWKS caches.
- **Concurrency & DB Isolation:** `PyJWKClient._client_lock` serializes concurrent refreshes; `not db.in_transaction()` must hold before any JWKS lookup.

---

# 7. GitHub OAuth 2.0 Protocol

## 7.1 Authoritative Endpoints & Headers

| Operation | Endpoint | Method & Required Headers |
| :--- | :--- | :--- |
| **Authorization** | `https://github.com/login/oauth/authorize` | Browser `302` redirect; query: `client_id`, `redirect_uri` (backend callback), `scope=read:user user:email`, `state`, `code_challenge`, `code_challenge_method=S256` |
| **Token Exchange** | `https://github.com/login/oauth/access_token` | `POST`, `Content-Type: application/x-www-form-urlencoded`, `Accept: application/json`, `User-Agent: <APP_NAME>/<APP_VERSION>`, body: `client_id`, `client_secret`, `code`, `redirect_uri`, `code_verifier` |
| **User Profile** | `https://api.github.com/user` | `GET`, `Authorization: Bearer <access_token>`, `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`, `User-Agent: <APP_NAME>/<APP_VERSION>` |
| **Verified Emails** | `https://api.github.com/user/emails?per_page=<N>&page=1` | `GET`, same API headers as `/user` |

All outbound `httpx` requests enforce `timeout=settings.OAUTH_HTTP_TIMEOUT_SECONDS` and `follow_redirects=False`.

- **GitHub HTTP 200 Error Quirk:** GitHub frequently returns HTTP `200` with `{"error": "bad_verification_code", ...}` on invalid codes or PKCE mismatches. Explicitly reject any response containing a truthy `"error"` key OR missing/non-string/blank `"access_token"` as `oauth_provider_error`.
- **Token Hygiene:** GitHub access tokens are kept strictly in local memory during Phase 2 and are never persisted or logged.

## 7.2 Immutable Provider Identity (`/user`)

Validate `data = response.json()` is a `dict` and inspect `raw_id = data.get("id")`:
- Require `type(raw_id) is int` (strictly rejecting `bool`, since `isinstance(True, int)` is `True` in Python) and `raw_id > 0`.
- Convert to `provider_user_id = str(raw_id)`.
- Never read or use `/user`'s `email` field for account creation or `provider_email` metadata updates (it lacks a `verified` boolean).

## 7.3 Returning-User Fast Path & Mandatory Transaction Termination

After retrieving and validating `provider_user_id` from `GET /user`:

1. Execute a short read-only lookup for `OAuthAccount` by `("github", provider_user_id)`.
2. **If found (returning GitHub user):** Skip `GET /user/emails` completely and proceed directly to Phase 3 (§11.5). Existing GitHub accounts continue authenticating even if their GitHub email changed, became private/unverified, or switched to a noreply address.
3. **If NOT found (new GitHub user):**
   - Because SQLAlchemy 2.x uses `autobegin=True`, the fast-path `SELECT` implicitly opened a transaction and checked out a pooled PostgreSQL connection.
   - **Mandatory immediately after fast-path miss:** call `db.rollback()`, ensuring `not db.in_transaction()` and returning the connection to `QueuePool` **before** calling `GET /user/emails`.
   - The identical rule (`not db.in_transaction()`, zero checked-out connections, zero row locks) applies before every outbound HTTP operation across both Google and GitHub flows.

## 7.4 Bounded Paginated Verified-Email Retrieval & Selection (`/user/emails`)

1. Start at `https://api.github.com/user/emails?per_page={settings.GITHUB_EMAILS_PER_PAGE}&page=1` (`GITHUB_EMAILS_PER_PAGE = 100`, `GITHUB_EMAILS_MAX_PAGES = 10`).
2. Track `visited_urls: set[str]` and `all_entries: list[dict]`.
3. For `page_idx` in `1..GITHUB_EMAILS_MAX_PAGES`:
   - Record current URL in `visited_urls`.
   - Execute `GET` (`follow_redirects=False`, timeout `OAUTH_HTTP_TIMEOUT_SECONDS`). On timeout, network error, non-`200` status, or non-`list` JSON -> fail closed with `oauth_provider_error`.
   - Validate elements (require `dict` items; non-dict items fail closed as `oauth_provider_error`) and append to `all_entries`.
   - Inspect RFC 8288 `Link` header (`response.links.get("next")`). If absent, exit loop.
   - Validate `next_url = response.links["next"]["url"]` via `urllib.parse.urlsplit`:
     - `scheme == "https"`
     - `hostname == "api.github.com"`
     - `port is None`
     - `username is None` and `password is None`
     - `path == "/user/emails"`
     - `fragment == ""`
     - `next_url not in visited_urls` (prevents loops)
     - Any violation -> fail closed with `oauth_provider_error`.
   - If `page_idx == GITHUB_EMAILS_MAX_PAGES` while a valid `"next"` link still exists -> fail closed with `oauth_provider_error` (never register from a truncated email list).
4. **Deterministic Selection of Suitable Verified Email:**
   - Keep entries where `entry.get("verified") is True` (strict boolean) and `type(entry.get("email")) is str`.
   - Normalize `email = normalize_email(entry["email"])`; validate `1 <= len(email) <= 320`, no whitespace, valid `EmailStr`.
   - Extract domain `domain = email.rsplit("@", 1)[1].lower()` and **reject** GitHub noreply domains:
     - `domain == "users.noreply.github.com"`
     - `domain.endswith(".users.noreply.github.com")`
     - `domain == "noreply.github.com"`
   - Deduplicate across pages by canonical `email`; if **any** verified occurrence of a duplicated address has `entry.get("primary") is True`, preserve `primary = True`.
   - Select the suitable verified email with `primary is True`; if none is primary, select the lexicographically smallest canonical `email`.
   - If zero suitable emails remain -> redirect `302` with `error=verified_email_required` (zero user or `oauth_accounts` rows created).

---

# 8. Configuration and Validation

Extend `Settings` in [`app/core/config.py`](app/core/config.py) while preserving `Settings(_env_file=None)` with zero OAuth environment variables configured and keeping all existing Stage 1–3B tests ([`tests/test_config.py`](tests/test_config.py), [`tests/test_auth_security_unit.py`](tests/test_auth_security_unit.py), [`tests/test_uri_policy.py`](tests/test_uri_policy.py)) green.

## 8.1 Stage 3C Settings Table

| Setting | Type | Default in `Settings` | Bounds / Format |
| :--- | :--- | :--- | :--- |
| `BACKEND_BASE_URL` | `str` | `"http://localhost:8000"` *(verified against [`Dockerfile`](Dockerfile#L22-L24), [`docker-compose.yml`](docker-compose.yml#L89), [`app/server.py`](app/server.py#L496))* | Exact `scheme://host[:port]` (§10) |
| `OAUTH_BINDING_COOKIE_NAME` | `str` | `"folio360_oauth_binding"` | Non-empty, no whitespace, `!= REFRESH_COOKIE_NAME` |
| `OAUTH_PKCE_ENCRYPTION_KEY` | `SecretStr \| None` | `None` | Canonical 32-byte Base64url (`^[A-Za-z0-9_-]{43}=?$`) |
| `OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS` | `SecretStr \| None` | `None` | Optional canonical 32-byte Base64url (requires primary key) |
| `GOOGLE_CLIENT_ID` | `str \| None` | `None` | Stripped non-empty when set; paired with secret |
| `GOOGLE_CLIENT_SECRET` | `SecretStr \| None` | `None` | Non-empty when set; paired with client ID |
| `GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES` | `list[str]` | `[]` | Parsed via `_parse_string_list_setting`; no `"*"`, blanks, whitespace, or duplicates |
| `GITHUB_CLIENT_ID` | `str \| None` | `None` | Stripped non-empty when set; paired with secret |
| `GITHUB_CLIENT_SECRET` | `SecretStr \| None` | `None` | Non-empty when set; paired with client ID |
| `OAUTH_ALLOWED_WEB_REDIRECT_URIS` | `list[str]` | `[]` | Parsed via `_parse_string_list_setting`; validated via web URI policy (§9.1) |
| `OAUTH_ALLOWED_MOBILE_REDIRECT_URIS` | `list[str]` | `["folio360://auth/callback"]` | Parsed via `_parse_string_list_setting`; validated via mobile URI policy (§9.2) |
| `OAUTH_STATE_EXPIRE_MINUTES` | `int` | `10` | `ge=1, le=30` |
| `OAUTH_HTTP_TIMEOUT_SECONDS` | `float` | `5.0` | `ge=1.0, le=15.0` |
| `GITHUB_EMAILS_PER_PAGE` | `int` | `100` | `ge=1, le=100` |
| `GITHUB_EMAILS_MAX_PAGES` | `int` | `10` | `ge=1, le=20` |

- **Exchange-code expiry** is a fixed security constant `OAUTH_EXCHANGE_CODE_EXPIRE_SECONDS = 60` (not freely configurable).
- **Local development defaults:** Do not hardcode `http://localhost:5173/auth/oauth/callback` in `Settings.OAUTH_ALLOWED_WEB_REDIRECT_URIS` (preserving production and custom-CORS test compatibility). Document and configure `OAUTH_ALLOWED_WEB_REDIRECT_URIS=["http://localhost:5173/auth/oauth/callback"]` in [`.env.example`](.env.example) and [`docker-compose.yml`](docker-compose.yml) instead.

## 8.2 String-List Parsing Rules (`_parse_string_list_setting`)

Reuse existing `_parse_string_list_setting` ([`app/core/config.py`](app/core/config.py#L50-L104)) with `allow_empty_string=True` for `GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES`, `OAUTH_ALLOWED_WEB_REDIRECT_URIS`, and `OAUTH_ALLOWED_MOBILE_REDIRECT_URIS`:

- Accepts native `list[str]`, JSON array strings, or CSV strings per existing convention; trims surrounding whitespace per `_parse_string_list_setting`.
- Rejects non-string entries, empty entries, malformed JSON, and **duplicate entries** (fail validation rather than silently dropping duplicates).
- For `GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES`: additionally reject `"*"` and entries containing internal whitespace.
- For redirect allowlists: validate each entry against §9 and preserve exact canonical strings for raw-string matching at request time.

## 8.3 Unconditional vs. Provider-Gated Validation

### Always Validated During `Settings` Construction (Even When Both Providers Are Disabled)
1. **Provider credential pairing:** `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` must both be set or both be unset (`None`/blank normalized to `None`); same for `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`. Half-configured providers fail validation immediately.
2. **Cookie-name validity & collision:** `OAUTH_BINDING_COOKIE_NAME` must be non-empty without whitespace and must satisfy `OAUTH_BINDING_COOKIE_NAME != REFRESH_COOKIE_NAME`.
3. **Explicitly non-empty OAuth settings:** Whenever non-empty/non-`None`, validate:
   - `OAUTH_PKCE_ENCRYPTION_KEY` via `decode_aes256_base64url_key`.
   - `OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS` via `decode_aes256_base64url_key`, and reject if `OAUTH_PKCE_ENCRYPTION_KEY` is unset.
   - `OAUTH_ALLOWED_WEB_REDIRECT_URIS` via web URI policy (§9.1) for active `ENVIRONMENT`.
   - `OAUTH_ALLOWED_MOBILE_REDIRECT_URIS` via mobile URI policy (§9.2) for active `ENVIRONMENT`.
   - `GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES` (no `"*"`, whitespace, blanks, or duplicates).
   - `BACKEND_BASE_URL` format rules (§10).

### Conditional Validation When At Least One OAuth Provider Is Configured
Let `oauth_enabled = bool(GOOGLE_CLIENT_ID) or bool(GITHUB_CLIENT_ID)`. When `oauth_enabled` is `True`:
1. **In ALL environments (`development`, `testing`, `production`):**
   - `OAUTH_PKCE_ENCRYPTION_KEY` is **mandatory** and valid (fails `Settings` validation if missing/invalid—never degrades to request-time `503`).
   - **D19 Web Origin Subset Check:** For every URI in `OAUTH_ALLOWED_WEB_REDIRECT_URIS`, its extracted origin (`scheme://host[:port]`) must be an exact member of `CORS_ORIGINS`.
2. **In `ENVIRONMENT == "production"` (`validate_runtime_requirements()`):**
   - `BACKEND_BASE_URL` must use `https://`.
   - Every entry in `OAUTH_ALLOWED_WEB_REDIRECT_URIS` must use `https://` (already enforced by §9.1).
   - Every entry in `OAUTH_ALLOWED_MOBILE_REDIRECT_URIS` must use `https://` or an approved custom scheme (zero `http://`, already enforced by §9.2).

When `oauth_enabled` is `False`: application startup succeeds in all environments, D19 is not enforced against implicit defaults, default `BACKEND_BASE_URL = "http://localhost:8000"` does not fail non-OAuth production startup, and requests for unconfigured recognized providers return `503 SERVICE_UNAVAILABLE`.

---

# 9. URI Policy

Extend [`app/core/uri_policy.py`](app/core/uri_policy.py) with dedicated web and mobile OAuth redirect validators sharing the existing strict RFC 3986 pre-parse and canonicalization rules (ASCII-only, no whitespace/control chars, no `\`, `*`, `@`, `?`, `#`, no `%2f`/`%5c`/`%2e`/`%00`, no dot segments or `//`, no redundant default ports `:443`/`:80`, no trailing `/` unless `/`, no punycode `xn--`, no dangerous schemes):

## 9.1 Web OAuth Redirect URIs (`parse_and_canonicalize_web_redirect_uri`)
- **Permitted schemes:** `https` in all environments; `http` **only** when `ENVIRONMENT in {"development", "testing"}` AND host is an explicit loopback host (`localhost`, `127.0.0.1`, `[::1]`).
- **Strictly forbidden:** All custom schemes (e.g., `folio360://`), all external `http://` in every environment, all `http://` (including loopback) in `production`, credentials, query strings, fragments, and traversal.
- Requires a non-empty path starting with `/`.

## 9.2 Mobile OAuth Redirect URIs (`parse_and_canonicalize_mobile_redirect_uri`)
- Reuses the exact scheme/host/path rules of `parse_and_canonicalize_mobile_login_uri` ([`app/core/uri_policy.py`](app/core/uri_policy.py#L145-L218)):
  - Permits `https://` Universal/App Links and explicitly configured RFC 3986 custom application schemes (`^[a-z][a-z0-9+.-]*$`, **no port permitted** on custom schemes).
  - Rejects dangerous schemes, credentials, query strings, fragments, traversal, external `http://`, and all `http://` in `production`.
- Default: `folio360://auth/callback`. Expo Go `exp://` with port is deferred (D21).

## 9.3 Exact Raw-String Matching & Safe Query Builder
- At request time (`GET /oauth/{provider}/start` and defensive re-check on `/callback`), caller `redirect_uri` must match an entry in the configured canonical allowlist via **exact raw string equality** (`redirect_uri in allowlist`)—never silently normalize caller input before comparison.
- **`build_oauth_redirect_url(redirect_uri, *, allowlist, code=None, error=None)`:**
  - Verifies `redirect_uri in allowlist` (raising internal error / failing closed without redirecting if untrue) and exactly one of `code` or `error` is provided.
  - Parses via `urllib.parse.urlsplit` + `parse_qsl(parts.query, keep_blank_values=True)`, strips any existing `"code"` or `"error"` keys, appends the single `("code", code)` or `("error", error)` pair, re-encodes via `urlencode`, and reconstructs with `urlunsplit`.

---

# 10. `BACKEND_BASE_URL`

Validated with rules mirroring `validate_frontend_base_url` ([`app/core/config.py`](app/core/config.py#L433-L455)):

- **Default:** `"http://localhost:8000"`.
- **Format rules (all environments):** Absolute `http://` or `https://` URL, non-empty host, no whitespace, no credentials (`username`/`password`), no path, no trailing `/`, no query string, no fragment.
- **Environment rules:**
  - `ENVIRONMENT in {"development", "testing"}`: `https://` or loopback `http://` (`localhost`, `127.0.0.1`, `[::1]`) accepted (external non-loopback `http://` rejected).
  - `ENVIRONMENT == "production"` (when OAuth is enabled): strictly `https://` required.
- **Provider Callback URL Construction:** Built exclusively from server configuration using normalized `API_V1_PREFIX` (same normalization as `_get_refresh_cookie_path` in [`app/api/routes/auth.py`](app/api/routes/auth.py#L51-L58)):
  `f"{settings.BACKEND_BASE_URL}{prefix}/auth/oauth/{provider}/callback"`
  Never derived from `Host` or `X-Forwarded-Host` headers.

---

# 11. Complete Callback State Machine and Transaction Sequencing

## 11.1 Routes & Parameter Validation

| Route | Method | Rate Limit | Path / Query Validation |
| :--- | :--- | :--- | :--- |
| `/api/v1/auth/oauth/{provider}/start` | `GET` | `20 / 15m / IP` | `provider: str`, `client_type: str \| None = Query(default=None)`, `redirect_uri: str \| None = Query(default=None)` |
| `/api/v1/auth/oauth/{provider}/callback` | `GET` | `20 / 15m / IP` | `provider: str`, `state: str \| None = Query(default=None)`, `code: str \| None = Query(default=None)`, `error: str \| None = Query(default=None)` |
| `/api/v1/auth/oauth/exchange` | `POST` | `10 / 15m / IP` | `X-Client-Type: web \| mobile` (+ `Origin` on `web`), JSON `OAuthExchangeRequest` (§13) |

Declaring `provider` as `str` (not `Literal`) and query params as optional `str | None` guarantees missing or invalid values return exact `auth_error` HTTP `400` responses (`INVALID_OAUTH_PROVIDER`, `INVALID_CLIENT_TYPE`, `INVALID_REDIRECT_URI`, `INVALID_OAUTH_STATE`) instead of FastAPI's automatic `422`.

## 11.2 Start Flow (`GET /api/v1/auth/oauth/{provider}/start`)

Mandatory validation order:
1. Validate `provider in {"google", "github"}` -> else `400 INVALID_OAUTH_PROVIDER`.
2. Check whether `provider` credentials are configured -> else `503 SERVICE_UNAVAILABLE`.
3. Validate `client_type in {"web", "mobile"}` -> else `400 INVALID_CLIENT_TYPE`.
4. Validate `redirect_uri` is present and matches an exact entry in `OAUTH_ALLOWED_WEB_REDIRECT_URIS` (for `web`) or `OAUTH_ALLOWED_MOBILE_REDIRECT_URIS` (for `mobile`) -> else `400 INVALID_REDIRECT_URI`.
5. Generate `raw_state`, `code_verifier = generate_pkce_verifier()`, `code_challenge = compute_pkce_s256_challenge(code_verifier)`, `raw_nonce` (Google only), and `raw_binding` (web only).
6. Encrypt `code_verifier` with AES-256-GCM (AAD `f"{provider}:{state_hash}".encode("utf-8")`).
7. Persist `OAuthState` (`expires_at = now + timedelta(minutes=settings.OAUTH_STATE_EXPIRE_MINUTES)`) and `db.commit()`.
8. Execute bounded best-effort cleanup in a **separate** transaction (§15.2).
9. Return `302 Found` to provider authorize URL with `Cache-Control: no-store`, `Pragma: no-cache`, `Referrer-Policy: no-referrer`, and (for `web` only) set the browser-binding cookie (§11.3).

## 11.3 Browser-Binding Cookie (`folio360_oauth_binding`)

For `client_type == "web"` only:
- **Name:** `settings.OAUTH_BINDING_COOKIE_NAME` (default `"folio360_oauth_binding"`).
- **Attributes:** `httponly=True`, `samesite="lax"` **unconditionally** (never derived from `REFRESH_COOKIE_SAMESITE`, because `strict` breaks top-level cross-site provider redirects), `secure=settings.REFRESH_COOKIE_SECURE` (enforced `True` in `production`), `domain=None` (host-only), `max_age=settings.OAUTH_STATE_EXPIRE_MINUTES * 60`, `path=f"{prefix}/auth/oauth"` (derived from normalized `API_V1_PREFIX`).
- **Clearing:** Clear with matching `key`, `path`, `domain=None`, `secure`, `httponly=True`, `samesite="lax"` on **every** web callback response (success and error). Mobile callbacks never set or clear this cookie.

## 11.4 Complete Callback Decision Table (`GET /api/v1/auth/oauth/{provider}/callback`)

Checks execute in this **strict, mandatory order**. All callback responses include `Cache-Control: no-store`, `Pragma: no-cache`, `Referrer-Policy: no-referrer`:

| Order | Condition | DB State Mutation | HTTP Response & Error Code | Web Cookie Cleared? | Phase 2 HTTP? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `provider` not in `{"google", "github"}` | None | JSON `400 INVALID_OAUTH_PROVIDER` | No | **No** |
| **2** | Recognized `provider` credentials not configured | None | JSON `503 SERVICE_UNAVAILABLE` | No | **No** |
| **3** | `state` missing or blank/whitespace | None | JSON `400 INVALID_OAUTH_STATE` (no redirect) | Clear if present | **No** |
| **4** | `state_hash` not found in `oauth_states` | None (`rollback`) | JSON `400 INVALID_OAUTH_STATE` (no redirect) | Clear if present | **No** |
| **5** | Known row: `consumed_at IS NOT NULL` (already consumed) | **None (`rollback` — row untouched)** | `302` -> `{redirect_uri}?error=invalid_oauth_state`\* | Yes if `client_type == "web"` | **No** |
| **6** | Known row: `expires_at <= now` (expired) | **None (`rollback` — row untouched)** | `302` -> `{redirect_uri}?error=invalid_oauth_state`\* | Yes if `client_type == "web"` | **No** |
| **7** | Active row: `state_row.provider != provider` | **Consume & scrub** (`consumed_at=now`, `pkce='[CONSUMED]'`, `commit`) | `302` -> `{redirect_uri}?error=invalid_oauth_state`\* | Yes if `client_type == "web"` | **No** |
| **8** | Active `web` row: binding cookie missing or digest mismatch | **Consume & scrub** (`consumed_at=now`, `pkce='[CONSUMED]'`, `commit`) | `302` -> `{redirect_uri}?error=invalid_oauth_state`\* | Yes | **No** |
| **9** | Active valid row: provider query `error == "access_denied"` | **Consume & scrub** (`commit`; **skip PKCE decrypt**) | `302` -> `{redirect_uri}?error=oauth_cancelled`\* | Yes if `client_type == "web"` | **No** |
| **10** | Active valid row: other provider `error` OR missing/blank `code` | **Consume & scrub** (`commit`; **skip PKCE decrypt**) | `302` -> `{redirect_uri}?error=oauth_provider_error`\* | Yes if `client_type == "web"` | **No** |
| **11** | Active valid row + `code`: PKCE AES-256-GCM decrypt/AAD fails | **Consume & scrub** (`commit`; never leave replayable) | `302` -> `{redirect_uri}?error=oauth_provider_error`\* | Yes if `client_type == "web"` | **No** |
| **12** | Active valid row + `code` + valid PKCE decryption | **Consume & scrub** (`commit`) | Proceed to Phase 2 -> Phase 3 -> `302` `{redirect_uri}?code=<60s_code>` or safe error\* | Yes if `client_type == "web"` | **Yes** |

\* **Defensive `redirect_uri` Trust Guard:** Before issuing any `302`, `build_oauth_redirect_url` re-verifies that `state_row.redirect_uri` is still an exact member of the configured allowlist for `state_row.client_type`. If it cannot be validated (e.g., allowlist changed mid-flow), **do not redirect**—return JSON `400 INVALID_REDIRECT_URI` (still clearing the web binding cookie if `client_type == "web"`).

**Closed Callback Redirect Error Enum:** `oauth_cancelled`, `invalid_oauth_state`, `oauth_provider_error`, `verified_email_required`, `email_already_registered`, `account_inactive`. Never forward provider-supplied `error_description` strings.

## 11.5 Three-Phase Callback Transaction Sequencing

### Phase 1 — State Validation & Consumption Transaction
1. After Order 1–3 pass, compute `state_hash = hash_opaque_token(state.strip())`.
2. Lock row: `select(OAuthState).where(OAuthState.state_hash == state_hash).with_for_update().execution_options(populate_existing=True)`.
3. If `None` -> `db.rollback()`, return JSON `400 INVALID_OAUTH_STATE` (Order 4).
4. If `state_row.consumed_at is not None` -> `db.rollback()` (untouched), redirect `invalid_oauth_state` (Order 5).
5. If `state_row.expires_at <= now` -> `db.rollback()` (untouched), redirect `invalid_oauth_state` (Order 6).
6. Capture `encrypted_verifier = state_row.pkce_verifier_encrypted`, `nonce_hash = state_row.nonce_hash`, `redirect_uri = state_row.redirect_uri`, `client_type = state_row.client_type`.
7. Validate `state_row.provider == provider` (Order 7) and (if `client_type == "web"`) constant-time binding digest match (Order 8). On mismatch: set `state_row.consumed_at = now` and `state_row.pkce_verifier_encrypted = "[CONSUMED]"`, `db.commit()`, redirect `invalid_oauth_state`.
8. Mark `state_row.consumed_at = now` and `state_row.pkce_verifier_encrypted = "[CONSUMED]"`.
9. If `error == "access_denied"` -> `db.commit()` (no PKCE decrypt), redirect `oauth_cancelled` (Order 9).
10. If `error` is present or `code` is missing/blank -> `db.commit()` (no PKCE decrypt), redirect `oauth_provider_error` (Order 10).
11. Attempt `code_verifier = decrypt_pkce_verifier(encrypted_verifier, primary_key=..., previous_key=..., provider=provider, state_hash=state_hash)`.
    - On decryption/AAD failure: `db.commit()` (persisting consumed & scrubbed row), emit sanitized warning (`event="oauth_pkce_decrypt_failed"`, `provider`, `state_id`), redirect `oauth_provider_error` (Order 11).
12. `db.commit()` (persisting consumed & scrubbed row and releasing DB lock + connection) before entering Phase 2. Decrypted `code_verifier` remains strictly in local function memory.

### Phase 2 — External Provider HTTP (Strictly Outside Any DB Transaction)
- Skipped unconditionally for Orders 1–11.
- Assert `not db.in_transaction()` before **every** outbound `httpx` or JWKS call.
- **Google:** Exchange code + `code_verifier` at `oauth2.googleapis.com/token` -> verify RS256 ID token via `HttpxJWKClient` + §6 checks.
- **GitHub:** Exchange code + `code_verifier` at `github.com/login/oauth/access_token` -> `GET /user` -> short read-only `oauth_accounts` fast-path lookup -> if miss, **immediately `db.rollback()`** (verify `not db.in_transaction()`) -> bounded paginated `GET /user/emails` + deterministic email selection (§7.4).

### Phase 3 — Account Resolution & Exchange-Code Issuance Transaction
Start a new transaction:
- **Existing `(provider, provider_user_id)` found:**
  1. Lock `users` row first: `select(User).where(User.id == oauth_account.user_id).with_for_update().execution_options(populate_existing=True)`.
  2. Check `user.is_active` -> if `False`, `db.rollback()`, redirect `account_inactive`.
  3. Defensively check `user.is_email_verified` -> if `False`, `db.rollback()`, redirect `verified_email_required` (do not issue an exchange code).
  4. Apply permitted metadata refresh (§4.2, §6.5) while holding the user lock; never modify `users.email`.
  5. Read `user.auth_version` under lock, insert `OAuthExchangeCode` (`expires_at = now + timedelta(seconds=60)`, `auth_version = user.auth_version`), `db.commit()`.
- **New provider identity:**
  1. Validate provider verified email requirements (§6.5 / §7.4).
  2. Provision atomically inside a `SAVEPOINT` (§12), inserting `User`, `OAuthAccount`, and `OAuthExchangeCode` (`auth_version = user.auth_version`), `db.commit()`.
- Return `302 Found` to `build_oauth_redirect_url(redirect_uri, allowlist=..., code=raw_exchange_code)` (clearing web binding cookie if `client_type == "web"`).

---

# 12. SAVEPOINT and Account-Provisioning Recovery

Wrap new-account `User` + `OAuthAccount` insertion inside `with db.begin_nested():`:
1. Add `User(email=canonical_email, password_hash=None, is_active=True, is_email_verified=True, email_verified_at=now, auth_version=0, password_changed_at=None)` and `db.flush()`.
2. Add `OAuthAccount(user_id=user.id, provider=provider, provider_user_id=provider_user_id, provider_email=canonical_email, provider_email_verified=True)` and `db.flush()`.

On `IntegrityError`:
1. The `SAVEPOINT` rolls back automatically while keeping the outer transaction usable.
2. Inspect **only** `constraint_name = get_constraint_name(exc)` (exposing existing `_get_constraint_name` from [`app/services/auth_service.py`](app/services/auth_service.py#L39-L43), which reads `exc.orig.diag.constraint_name`—never parse raw exception strings or PostgreSQL `DETAIL:`).
3. If `constraint_name in {"uq_users_email", "uq_oauth_accounts_provider_subject"}`:
   - Re-query `OAuthAccount` by `(provider, provider_user_id)` (visible under PostgreSQL `READ COMMITTED` if a concurrent twin callback just committed).
   - **If found:** Acquire `users FOR UPDATE` (`populate_existing=True`), verify `user.is_active` (`account_inactive`) and `user.is_email_verified` (`verified_email_required`), read `user.auth_version` under lock, insert `OAuthExchangeCode`, and `db.commit()`.
   - **If not found (`uq_users_email`):** The email belongs to a different existing account (password account or other OAuth provider). Execute `db.rollback()` and redirect `302` with `error=email_already_registered` (strict no-auto-merge).
4. **Any unexpected or missing `constraint_name`:** Log only `constraint_name or "unknown"`, execute `db.rollback()`, and redirect `302` with `error=oauth_provider_error`.

No partial `users` or `oauth_accounts` rows may survive any failed provisioning attempt.

---

# 13. OAuth Exchange and `auth_version` Concurrency

**Endpoint:** `POST /api/v1/auth/oauth/exchange`  
**Headers:** Mandatory `X-Client-Type: web | mobile` (`require_client_type`) + exact `Origin` in `CORS_ORIGINS` when `web` (`enforce_web_origin_if_web`).  
**Rate Limit:** `10 / 15 minutes / IP` (`auth:oauth-exchange`).  
**Response Headers:** `Cache-Control: no-store`, `Pragma: no-cache`, `Referrer-Policy: no-referrer`.

## 13.1 Request & Response Schemas (`app/schemas/oauth.py`)

- **`OAuthExchangeRequest(BaseModel)`:**
  - `model_config = ConfigDict(extra="forbid")`
  - `code: str = Field(min_length=1, max_length=512)`
  - `@field_validator("code", mode="before")` reusing `_strip_nonempty_token` ([`app/schemas/auth.py`](app/schemas/auth.py#L180-L187)) — rejects non-string or whitespace-only codes; Stage 3A's `validation_exception_handler` strips `input` so submitted codes are never echoed in `422` responses.
- **Responses:** Reuse `WebAuthTokenResponse` (web: refresh token set exclusively via `_set_refresh_cookie` with API-prefix-derived `Path`, omitted from JSON) and `MobileAuthTokenResponse` (mobile: refresh token in JSON, zero cookies) from [`app/schemas/auth.py`](app/schemas/auth.py#L158-L172).

## 13.2 Atomic Exchange Transaction (`users`-First Lock Order)

1. Compute `code_hash = hash_opaque_token(payload.code)`.
2. Scalar lookup `OAuthExchangeCode.user_id` by `code_hash`. If `None` -> `db.rollback()`, raise `400 INVALID_OAUTH_EXCHANGE_CODE`.
3. **Lock `users` FIRST:** `select(User).where(User.id == code_user_id).with_for_update().execution_options(populate_existing=True)`. If `None` -> `db.rollback()`, raise `400 INVALID_OAUTH_EXCHANGE_CODE`.
4. **Lock `oauth_exchange_codes` SECOND:** `select(OAuthExchangeCode).where(OAuthExchangeCode.code_hash == code_hash, OAuthExchangeCode.user_id == user.id).with_for_update().execution_options(populate_existing=True)`.
5. Validate exchange-code state **before** exposing account status:
   - `code_row is None`, `code_row.consumed_at is not None`, `code_row.expires_at <= now`, `code_row.client_type != client_type`, or `code_row.auth_version != user.auth_version` -> `db.rollback()`, raise `400 INVALID_OAUTH_EXCHANGE_CODE`.
6. Independently validate account status (rolling back **without** consuming the code on failure):
   - `not user.is_active` -> `db.rollback()`, raise `403 ACCOUNT_INACTIVE`.
   - `not user.is_email_verified` -> `db.rollback()`, raise `403 EMAIL_NOT_VERIFIED`.
7. Mark `code_row.consumed_at = now`.
8. Delegate session creation, commit, and HS256 JWT minting directly to shared `auth_service.create_session_and_mint_tokens(...)` (refactored from `_create_session_and_mint_tokens` at [`app/services/auth_service.py`](app/services/auth_service.py#L234-L278)), preserving identical 14d rolling / 30d absolute refresh families and JWT claims.

## 13.3 Dual-Order `auth_version` Concurrency Contract

For concurrent `POST /api/v1/auth/oauth/exchange` racing against `POST /logout-all`, `POST /reset-password`, or `POST /change-password` (all locking `users` first):

- **Case A — Invalidation wins `users` lock first:** Invalidation increments `users.auth_version` and commits. Exchange then acquires `users` lock (`populate_existing=True`), detects `code_row.auth_version != user.auth_version`, rolls back, and returns `400 INVALID_OAUTH_EXCHANGE_CODE` with **zero** refresh sessions created.
- **Case B — Exchange wins `users` lock first:** Exchange validates matching `auth_version`, consumes the code, inserts 1 `RefreshSession`, commits, and returns `200 OK`. Invalidation then acquires `users` lock, increments `users.auth_version`, and revokes all active `refresh_sessions`—including the just-created session. Both the returned access JWT (stale `ver`) and refresh token (revoked session) immediately fail with `401`.

---

# 14. Logging and Secret Redaction

Extend [`app/core/logging.py`](app/core/logging.py) without breaking existing logging tests or `uvicorn.logging.AccessFormatter`.

## 14.1 Idempotent Uvicorn Access-Log Sanitization

In `uvicorn==0.54.0`, `uvicorn.logging.AccessFormatter.formatMessage()` unpacks the 5-element tuple `record.args = (client_addr, method, full_path, http_version, status_code)`. Existing `SecurityFilter` collapses `record.args = None`, so it **must not** be attached directly to `uvicorn.access`.

Implement a dedicated `UvicornAccessSanitizingFilter(logging.Filter)` attached idempotently in `setup_logging()` to `logging.getLogger("uvicorn.access")` and each of its handlers:
- When `isinstance(record.args, tuple) and len(record.args) == 5`: sanitize `full_path` (index `2`) via query-scoped redaction + `sanitize_log_text`, preserving the 5-element tuple and leaving `client_addr`, `method`, `http_version`, and `status_code` intact for `AccessFormatter`.
- **Fail-safe fallback:** If `record.args` is not a 5-tuple or sanitization raises an exception, suppress the record message using `FAILSAFE_FALLBACK_MESSAGE` and safely neutralize `record.args` without crashing or leaking unsanitized data.
- **Zero duplicate emission & idempotency:** Set `logging.getLogger("uvicorn.access").propagate = False` (replacing current line 262's `propagate = True` which duplicates Uvicorn's own `access` handler output into root console logging), protect `uvicorn` and `uvicorn.error` handlers via `protect_handler()`, and ensure repeated `setup_logging()` calls attach no duplicate filters or handlers (preserving `test_setup_logging_idempotent_no_duplicates` in [`tests/test_logging.py`](tests/test_logging.py#L192-L212)).

## 14.2 Query-Scoped Redaction & Key-Value Patterns

1. **Query-parameter boundary regex:**
   `([?&](?:code|state|token|id_token|access_token|refresh_token|error_description)=)([^&\s"']+)` -> `\1[REDACTED]`
   Redacts sensitive query parameters in access logs and URLs without corrupting non-secret keys such as `status_code`, `error_code`, or `client_type`.
2. **Additional `KEY_VALUE_PATTERN` entries** (supplementing Stage 3A's existing entries):
   - `oauth_pkce_encryption_key_previous`
   - `folio360_oauth_binding` / `oauth_binding`
   - `oauth_state` / `authorization_code`
   - Existing entries already cover `oauth_pkce_encryption_key`, `pkce_verifier_encrypted`, `pkce_verifier`, `code_verifier`, `id_token`, `exchange_code`, `oauth_code`, `client_secret`, `access_token`, `refresh_token`, `cookie`, `set-cookie`.
3. **Exception Details Hygiene:** Keep all `AppException.details` limited to `{"code": "..."}` via `auth_error()`—never add keys containing `"auth"` or `"token"` (which trigger `SENSITIVE_KEY_SUBSTRINGS` in [`app/core/exceptions.py`](app/core/exceptions.py#L30-L43)).

---

# 15. Bounded Expired-Record Cleanup

Constants:
- `OAUTH_CLEANUP_BATCH_SIZE = 100`
- `OAUTH_CLEANUP_GRACE_SECONDS = 60` (`cutoff = now - timedelta(seconds=60)`)

Unexpired rows—including consumed rows whose `expires_at` has not yet passed the 60-second grace window—are intentionally retained until `expires_at < cutoff`.

## 15.1 PostgreSQL `SKIP LOCKED` CTE Query

Because PostgreSQL does not support `DELETE ... LIMIT`, execute parameterized CTE deletes utilizing `ix_oauth_states_expires_at` and `ix_oauth_exchange_codes_expires_at`:

```sql
WITH expired AS (
    SELECT id
    FROM oauth_states
    WHERE expires_at < :cutoff
    ORDER BY expires_at ASC
    LIMIT :batch_size
    FOR UPDATE SKIP LOCKED
)
DELETE FROM oauth_states
WHERE id IN (SELECT id FROM expired);
```

Execute the equivalent CTE against `oauth_exchange_codes`.

## 15.2 Transaction Isolation During Opportunistic Cleanup

During `GET /api/v1/auth/oauth/{provider}/start`:
1. Persist and `db.commit()` the new `oauth_states` row first.
2. In a separate `try / except Exception:` block, run the two bounded CTE deletes and `db.commit()`.
3. On any exception: `db.rollback()` only the cleanup transaction, log a sanitized warning (`type(exc).__name__` only), and still return the valid `302` authorization redirect.

`FOR UPDATE SKIP LOCKED` ensures cleanup never blocks concurrent callback or exchange transactions.

---

# 16. `/me` Response Extension

Extend `MeResponse` ([`app/schemas/auth.py`](app/schemas/auth.py#L131-L134)) with:

- `oauth_providers: list[str]` (alphabetically sorted via `select(OAuthAccount.provider).where(OAuthAccount.user_id == current_user.id).order_by(OAuthAccount.provider.asc())`).
- Returns `[]`, `["github"]`, `["google"]`, or `["github", "google"]`.
- `UserPublicResponse` (embedded in `/register`, `/login`, `/refresh`, `/change-password`, and `/oauth/exchange`) remains **completely unchanged**.
- No provider tokens, emails, or secrets are exposed on `/me`.

**Known Existing Test Updates Required in Stage 3C:**
- [`tests/test_migrations.py`](tests/test_migrations.py#L101-L106) (Substage 3C.3): replace deferred Stage 3C table-absence assertion with full `0004` schema, constraint, index, FK, reversibility, and split-role DML assertions.
- [`tests/test_auth_flows.py`](tests/test_auth_flows.py#L217) (Substage 3C.6): update `assert "oauth_providers" not in me_data` to `assert me_data["oauth_providers"] == []`.

---

# 17. Rate Limits and Security Headers

Reuse `rate_limit_dependency` and `resolve_client_ip` ([`app/api/deps/auth.py`](app/api/deps/auth.py))—never trust raw `X-Forwarded-For`:

| Endpoint | Bucket | Limit |
| :--- | :--- | :--- |
| `GET /api/v1/auth/oauth/{provider}/start` | `auth:oauth-start` | `20 / 15 minutes / IP` |
| `GET /api/v1/auth/oauth/{provider}/callback` | `auth:oauth-callback` | `20 / 15 minutes / IP` |
| `POST /api/v1/auth/oauth/exchange` | `auth:oauth-exchange` | `10 / 15 minutes / IP` |

All OAuth `/start`, `/callback`, and `/exchange` responses must emit:
- `Cache-Control: no-store`
- `Pragma: no-cache`
- `Referrer-Policy: no-referrer`

---

# 18. Complete Test Matrix

All automated tests run synchronously via `TestClient` against disposable `folio360_test` (`*_test_app` DML role) using mocked provider HTTP / JWKS boundaries (zero live network calls).

## 18.1 Google OIDC Tests
- New-account login; returning-user login; valid RS256 signature; invalid signature; wrong/missing `alg` (`HS256`, `none`); missing/blank/whitespace `kid` rejected pre-JWKS; invalid `iss`; expired `exp`; `30s` leeway boundary; future `nbf` (>30s); future `iat` (>30s); missing/empty/oversized/whitespace/control-char `sub`; invalid/oversized `email`; new account with `email_verified=False` or absent -> `verified_email_required`; returning identity with `email_verified=False` or absent `email` succeeds; malformed claim types (`email_verified="true"`, `email_verified=1`, non-string `email`) -> `oauth_provider_error` (both new and returning); invalid `nonce`; string `aud`, 1-element list `aud`, multi-aud with `GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES` + valid `azp`, untrusted extra `aud` rejected even with valid `azp`, missing/wrong `azp` on multi-aud, unexpected `azp` on single-aud, empty/duplicate/whitespace/non-str `aud`; JWKS timeout, non-200, redirect, >`65_536`-byte response rejection, invalid JSON, last-known-good cache preservation, app-scoped isolation; PKCE mismatch (`invalid_grant`).

## 18.2 GitHub OAuth Tests
- New-account login; returning-user login; returning identity with changed, private, unverified, or noreply email skips `/user/emails`; invalid/missing/zero/negative/bool (`True`) `/user` `id` rejected; verified primary email selection; deterministic lexicographical fallback; rejection of `users.noreply.github.com`, `*.users.noreply.github.com`, `noreply.github.com` -> `verified_email_required` (zero DB rows); cross-page deduplication preserving `primary=True`; multi-page `Link: rel="next"` success; pagination loop, cross-host, non-HTTPS, wrong-path, credentialed, fragment, and `GITHUB_EMAILS_MAX_PAGES` fail-closed rejections; HTTP `200` `{"error": ...}` JSON rejected; outgoing GitHub API requests include required `User-Agent`, `Accept`, and `X-GitHub-Api-Version` headers; `/user.email` never used for `provider_email` metadata; fast-path miss terminates implicit DB transaction (`db.rollback()`) before `/user/emails`.

## 18.3 State, Callback Sequencing & Cryptography Tests
- All 12 rows of the §11.4 decision table: unknown provider (`400`, NOT `503`), unconfigured recognized provider (`503`), missing/blank `state` (JSON `400`, no redirect), unknown `state` (JSON `400`, no redirect), already-consumed known state (`302 invalid_oauth_state`, `consumed_at` NOT overwritten), expired known state (`302 invalid_oauth_state`, row untouched), active wrong-provider (consumes & scrubs -> `302 invalid_oauth_state`), active web binding missing/mismatch (consumes & scrubs -> `302 invalid_oauth_state`), provider `error=access_denied` (consumes & scrubs without requiring PKCE decrypt -> `302 oauth_cancelled`), other provider error or missing/blank `code` (consumes & scrubs without PKCE decrypt -> `302 oauth_provider_error`), AEAD decryption/AAD failure (consumes & scrubs -> `302 oauth_provider_error`), defensive unallowlisted stored `redirect_uri` guard (JSON `400 INVALID_REDIRECT_URI`, no redirect).
- Zero Phase 2 HTTP calls for Orders 1–11; web binding cookie cleared on every web callback (never touched on mobile).
- `generate_pkce_verifier()` (`len == 86`, RFC 7636 charset), `compute_pkce_s256_challenge`, AES-256-GCM round-trip, primary & previous key rotation, AAD mismatch, `[CONSUMED]` rejection, strict `^[A-Za-z0-9_-]{43}=?$` Base64url decoder rejecting `+`, `/`, whitespace, `==`, non-canonical trailing bits, and wrong byte lengths.

## 18.4 Transaction & Connection-Pool Isolation Tests
For every mocked outbound HTTP boundary (Google token, Google JWKS, GitHub token, GitHub `/user`, GitHub `/user/emails` after fast-path miss):
- Assert `not db.in_transaction()`.
- Verify zero checked-out request-session connections / `idle in transaction` PostgreSQL backends and zero held row locks (`FOR UPDATE NOWAIT` probe).

## 18.5 Account Provisioning & SAVEPOINT Concurrency Tests
- New Google & GitHub accounts; returning Google & GitHub accounts; email match without matching `(provider, provider_user_id)` (existing password account or other OAuth provider) -> `email_already_registered` (no auto-merge); inactive linked user -> `account_inactive`; defensively unverified linked user in Phase 3 -> `verified_email_required`; concurrent first-time callbacks for same external identity (`SAVEPOINT` recovery acquires `users FOR UPDATE`, verifies `is_active`/`is_email_verified`, reads `auth_version`, creates 1 user + 1 `oauth_accounts`); concurrent OAuth vs. `/register` for same email; unexpected `IntegrityError` constraint -> sanitized log + `oauth_provider_error` (zero `DETAIL:` leakage); mid-transaction rollback atomicity (zero partial rows).

## 18.6 Exchange-Code & Dual-Order Concurrency Tests
- Web exchange (`X-Client-Type: web` + `Origin` -> `WebAuthTokenResponse` + `HttpOnly` cookie, no `refresh_token` in JSON, `403 CSRF_ORIGIN_MISMATCH` on bad/missing `Origin`); mobile exchange (`MobileAuthTokenResponse`, zero cookies, no `Origin` required); `Cache-Control: no-store`, `Pragma: no-cache`, `Referrer-Policy: no-referrer`; `OAuthExchangeRequest` `extra="forbid"`, whitespace rejection, 422 `input` stripping.
- Unknown, expired (>60s), replayed, cross-channel (`web` vs. `mobile`), and stale-`auth_version` codes -> `400 INVALID_OAUTH_EXCHANGE_CODE`.
- Inactive (`403 ACCOUNT_INACTIVE`) and unverified (`403 EMAIL_NOT_VERIFIED`) roll back without consuming code; code validity checked before exposing account status.
- Deterministic lock-wait concurrency tests (reusing `_wait_for_pg_lock_wait` from [`tests/test_password_flows.py`](tests/test_password_flows.py#L82-L107)):
  - Concurrent duplicate exchange -> `[200, 400]`, exactly 1 `RefreshSession`.
  - Dual-order races (both Case A and Case B of §13.3): exchange vs. `/logout-all`, exchange vs. `/reset-password`, exchange vs. `/change-password` (seeding a hybrid test user with `password_hash`, `oauth_accounts`, and `oauth_exchange_codes` for reset/change races).

## 18.7 Cleanup, Logging, Config, `/me`, Regression & Migration Tests
- **Cleanup:** deletes only `expires_at < now - 60s`; retains unexpired & unexpired-consumed rows; caps batch at `OAUTH_CLEANUP_BATCH_SIZE = 100`; `SKIP LOCKED` does not block active callback/exchange; cleanup exception rolls back cleanup only and does not fail `/start`.
- **Logging:** `UvicornAccessSanitizingFilter` preserves 5-tuple, `AccessFormatter` does not crash, redacts callback `?code=...&state=...` and multiple sensitive params, preserves `status_code`/`error_code`, fails safely on non-5-tuple args, no duplicate emission, idempotent `setup_logging()` (`test_setup_logging_idempotent_no_duplicates` passes), zero secret leakage in exception/service logs.
- **Configuration:** `Settings(_env_file=None)` passes; Google-only, GitHub-only, both-enabled; half-configured provider rejected; missing/invalid PKCE key rejected when any provider configured (all envs) and invalid non-empty key rejected even when OAuth disabled; `_PREVIOUS` without primary rejected; `OAUTH_BINDING_COOKIE_NAME == REFRESH_COOKIE_NAME` rejected; D19 enforced when OAuth enabled and not on non-OAuth defaults; `BACKEND_BASE_URL` env rules (`development`/`testing` vs. `production`); `GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES` rejects `"*"`/duplicates; custom `API_V1_PREFIX` cookie path & backend callback URL; rate limits (`429` + `Retry-After`) on `/start` (20), `/callback` (20), `/exchange` (10).
- **`/me` & Regression:** `oauth_providers` empty, single, sorted multi-provider; `UserPublicResponse` unchanged; OAuth-created users integrate cleanly with `/me`, `/refresh`, `/logout`, `/logout-all`, `/login`, `/forgot-password`, `/reset-password`, `/change-password`; all existing Stage 1, 2, 3A, and 3B tests pass.
- **Fixture Cleanup:** Stage 3C DB fixtures explicitly execute `DELETE FROM oauth_states` in addition to `DELETE FROM users` (since `oauth_states` has no FK to `users`).
- **Migrations (`@pytest.mark.migration`):** clean `base -> head`, populated `0001 -> head`, `0004 -> 0003 -> 0004` round-trip, `alembic check` exit `0`, model/migration parity including `ck_oauth_states_consumed_pkce_scrubbed`, split-role `*_app` DML grants and DDL/`TRUNCATE` denial, migrations `0001`–`0003` unchanged.

---

# 19. Live Provider Verification (Pre-Production Release Gate)

Mocked tests do not prove live provider interoperability. Before production release acceptance:

1. **Google Confidential Web-Server Live Check:** Against a real Google Cloud Web Application OAuth client, verify: (a) valid authorization code + PKCE `S256` `code_verifier` + `client_secret` succeeds; (b) mismatched `code_verifier` fails (`invalid_grant`); (c) exact backend callback URI matches registered redirect URI; (d) RS256 JWKS signature, `iss`, `aud`/`azp`, and `nonce_hash` validate against live Google ID tokens; (e) zero auth tokens appear in redirect URLs.
2. **GitHub OAuth App Live Check:** Against a real GitHub OAuth App, verify: (a) code + PKCE `S256` `code_verifier` exchange succeeds; (b) `/user` immutable numeric `id` retrieval works with required headers; (c) `/user/emails` pagination and verified-email selection succeed; (d) returning-user fast path authenticates without calling `/user/emails`.

---

# 20. Seven-Substage Implementation Plan

| Substage | Scope |
| :--- | :--- |
| **3C.1** | Configuration (`app/core/config.py`, `.env.example`, `docker-compose.yml`), URI policy (`app/core/uri_policy.py`), and Uvicorn/query log redaction (`app/core/logging.py`) |
| **3C.2** | PKCE `S256`, shared Base64url 32-byte key decoder, and AES-256-GCM utilities (`app/core/security.py`) |
| **3C.3** | OAuth ORM models (`app/models/oauth.py`, `app/models/__init__.py`), Alembic migration `0004_add_oauth_tables`, and `tests/test_migrations.py` updates |
| **3C.4** | Google OIDC (`HttpxJWKClient`, token/ID-token validation) and GitHub OAuth clients (`app/services/oauth_providers.py`) |
| **3C.5** | OAuth state machine, `SAVEPOINT` account resolution, exchange-code service, bounded cleanup (`app/services/oauth_service.py`), and shared helper export in `app/services/auth_service.py` |
| **3C.6** | OAuth routes, `OAuthExchangeRequest` schema (`app/schemas/oauth.py`, `app/api/routes/auth.py`), `/me` `oauth_providers` extension, and `tests/test_auth_flows.py:217` update |
| **3C.7** | Complete security, concurrency, transaction-isolation, cleanup, logging, migration, and Stage 1–3B regression verification |

**Per-Substage Governance:** (1) read-only inspection -> (2) findings & options -> (3) recommendation -> (4) explicit user approval -> (5) approved implementation -> (6) testing -> (7) independent audit -> (8) formal acceptance. Git `add`, `commit`, and `push` each require separate explicit authorization.

---

# 21. Non-Goals

Excluded from Stage 3C: Apple/Microsoft OAuth, explicit account-linking endpoints, automatic account merging, provider access-token persistence, calling provider APIs on behalf of users post-login, institutional identity verification, replacing email/password auth, rewriting refresh sessions, Redis/external job queues, and Expo Go `exp://` redirect support.

---

# 22. Acceptance Criteria

Stage 3C is accepted only when all 17 criteria pass:
1. Google new-user and returning-user authentication succeed (including returning-user unverified-email policy and strict malformed-claim rejection).
2. GitHub new-user and returning-user authentication succeed (including fast path without `/user/emails`).
3. Immutable provider subject identity and zero-auto-merge rules are enforced.
4. All 12 callback state-machine branches match §11.4 and `ck_oauth_states_consumed_pkce_scrubbed`.
5. Expired and already-consumed states are never mutated on replay.
6. Active provider/binding mismatch consumes and scrubs state exactly once without Phase 2 HTTP.
7. PKCE `S256` + AES-256-GCM encryption/rotation pass all cryptographic tests.
8. Exchange codes are opaque, single-use, fixed 60-second expiry, and `auth_version`-bound.
9. Dual-order concurrency races (`exchange` vs. `logout-all`/`reset-password`/`change-password`) match §13.3 deterministically.
10. Web (`HttpOnly` cookie + strict `Origin`) and mobile (JSON, zero cookies) contracts are preserved.
11. Zero outbound HTTP occurs inside open DB transactions or while holding connections/locks.
12. Bounded `SKIP LOCKED` cleanup runs isolated from `/start` and passes concurrency/failure tests.
13. Uvicorn `uvicorn.access` redacts callback query strings without crashing `AccessFormatter` or duplicating logs.
14. `GET /me` returns sorted `oauth_providers` while `UserPublicResponse` remains unchanged.
15. Migration `0004` passes clean, populated, round-trip, `alembic check`, and split-role tests.
16. All existing Stage 1, 2, 3A, and 3B regression tests remain green.
17. Independent review reports zero unresolved blocking defects, and live Google/GitHub verification (§19) completes prior to production release.

---

# 23. Revision History and Finding-Resolution Matrix

## 23.1 Revision History

| Revision | Basis | Summary |
| :--- | :--- | :--- |
| **REV1** | Stage 3C Read-Only Architecture Inspection | Initial Stage 3C specification locking D01–D23. |
| **REV2** | Independent Technical Review of REV1 (`C-1`–`L-2`) | Addressed Uvicorn access logging, GitHub fast-path DB rollback, web redirect defaults/D19, callback sequencing, `SAVEPOINT`/dual-order concurrency, returning Google policy, key validation, and cleanup CTE. |
| **REV3** | Independent Technical Review of REV2 (`R2-1`–`R2-4`) | Corrected callback state-machine ordering and exact HTTP response matrix, aligned DB consumed-marker `CHECK`, added explicit defaults/key-padding/protocol constants/JWKS socket bounds, fixed Uvicorn idempotency/propagation and GitHub test wording. |

## 23.2 REV2 Finding-Resolution Matrix (`R2-1`–`R2-4`)

| Finding | REV3 Section(s) | Resolution |
| :--- | :--- | :--- |
| **`R2-1`** (Blocking) | §2.1, §4.3, §11.1–11.5, §18.3 | Fixed provider-validation precedence (`400 INVALID_OAUTH_PROVIDER` before `503 SERVICE_UNAVAILABLE` on `/start` and `/callback`); reordered callback state checks so already-consumed (`Order 5`) and expired (`Order 6`) rows roll back untouched before active provider/binding checks (`Orders 7–8`); specified exact HTTP status, error code, redirect target, defensive allowlist guard, and web cookie clearing for every branch (`Orders 1–12`); aligned Phase 1 consumption/scrubbing with `ck_oauth_states_consumed_pkce_scrubbed` (skipping PKCE decrypt on cancellation/missing code; committing consumed marker on AEAD failure); explicitly listed all branches skipping Phase 2 HTTP. |
| **`R2-2`** (Medium) | §5.1–5.2, §8.1–8.3, §10, §18.7 | Specified exact `BACKEND_BASE_URL = "http://localhost:8000"` default (verified against `Dockerfile`, `docker-compose.yml`, `app/server.py`) and `ENVIRONMENT in {"development", "testing"}` loopback scope; clarified unconditional format/policy validation for non-empty OAuth settings vs. provider-gated requirements (mandatory PKCE key, prod HTTPS `BACKEND_BASE_URL`, D19); specified `_parse_string_list_setting` duplicate/`"*"` rejection; locked canonical 32-byte Base64url regex `^[A-Za-z0-9_-]{43}=?$` with round-trip verification and `secrets.token_urlsafe(64)` PKCE verifier. |
| **`R2-3`** (Medium) | §4.3, §6.1–6.6, §7.1–7.4, §11.5, §12, §13.1–13.2, §18.1–18.6 | Added exact Google and GitHub endpoint URLs, form-encoded token exchange, `Accept`/`X-GitHub-Api-Version: 2022-11-28`/`User-Agent` headers, and exact GitHub noreply domain list; specified strict claim-type rejection (`oauth_provider_error`) for malformed `email`/`email_verified` on returning Google users; added explicit `ck_oauth_states_consumed_pkce_scrubbed` SQL `CHECK`; capped JWKS responses at `65_536` bytes with short-lived per-fetch `httpx.Client` inside `HttpxJWKClient.fetch_data()`; specified `OAuthExchangeRequest` (`extra="forbid"`, `1..512`, `_strip_nonempty_token`); mandated `get_constraint_name(exc)`-only `IntegrityError` handling and defensive Phase 3 `user.is_email_verified` check (`verified_email_required`). |
| **`R2-4`** (Low) | §14.1–14.2, §18.2, §18.7 | Specified idempotent `UvicornAccessSanitizingFilter` preserving 5-tuple `record.args` with fail-safe fallback and `uvicorn.access.propagate = False` (preventing duplicate stdout logs and preserving `test_setup_logging_idempotent_no_duplicates`); corrected GitHub test wording to inspect Folio360's outgoing `User-Agent`, `Accept`, and `X-GitHub-Api-Version` headers. |

## 23.3 Retained REV1 Finding-Resolution History (`C-1`–`L-2`)

| REV1 Finding | Status & REV3 Section(s) |
| :--- | :--- |
| **`C-1`** Uvicorn `uvicorn.access` leakage & `AccessFormatter` 5-tuple crash | Resolved (§14.1–14.2, §18.7) |
| **`C-2`** GitHub fast-path implicit SQLAlchemy Tx during `/user/emails` | Resolved (§7.3, §11.5, §18.4) |
| **`C-3`** Web redirect defaults & D19 breaking Stage 1/3A `Settings` tests | Resolved (§8.1, §8.3, §18.7) |
| **`H-1`** Callback sequencing, cancellation, and D16 alignment | Resolved (§11.4–11.5, §18.3) |
| **`H-2`** `SAVEPOINT` recovery lock, dual-order `auth_version`, hybrid test setup | Resolved (§12, §13.2–13.3, §18.5–18.6) |
| **`H-3`** Google returning-user email rules, `30s` leeway, untrimmed `sub` | Resolved (§2.1, §6.3–6.5, §18.1) |
| **`H-4`** PKCE key encoding, DB constraints, cookie-name collision | Resolved (§4.2–4.4, §5.2, §8.3) |
| **`M-1`–`M-4`** `HttpxJWKClient`, FastAPI `400` params, `SKIP LOCKED` cleanup, URI policy split | Resolved (§6.6, §9, §11.1–11.3, §15) |
| **`L-1`–`L-2`** Test matrix completeness, `DELETE FROM oauth_states` cleanup, `UserPublicResponse` scope | Resolved (§16, §18.7, §20) |

---

# Concise `R2-1` through `R2-4` Resolution Summary

1. **`R2-1` (Callback State Machine):** Provider validation (`400 INVALID_OAUTH_PROVIDER`) now precedes provider-config availability (`503 SERVICE_UNAVAILABLE`) on both `/start` and `/callback`. Already-consumed (`Order 5`) and expired (`Order 6`) states roll back untouched before active provider/binding mismatch checks (`Orders 7–8`). All 12 callback branches have explicit HTTP status codes, error codes, redirect vs. JSON behavior, defensive stored-URI validation, and web cookie-clearing rules. Phase 1 skips PKCE decryption on `error=access_denied`/missing code, consumes and scrubs on AEAD failure, and satisfies `ck_oauth_states_consumed_pkce_scrubbed` on every branch.
2. **`R2-2` (Config & Key Format):** Set explicit `BACKEND_BASE_URL = "http://localhost:8000"` default and `ENVIRONMENT in {"development", "testing"}` loopback scope; separated unconditional format validation (non-empty OAuth fields) from provider-gated rules (mandatory PKCE key, prod HTTPS, D19); locked `_parse_string_list_setting` duplicate/`"*"` rejection, canonical 32-byte Base64url `^[A-Za-z0-9_-]{43}=?$` with round-trip verification, and `secrets.token_urlsafe(64)` PKCE verifiers.
3. **`R2-3` (Protocol, Constraints & Schemas):** Documented exact Google/GitHub endpoints, headers (`X-GitHub-Api-Version: 2022-11-28`, `Accept`, `User-Agent`), and GitHub noreply domains; enforced strict claim-type rejection on returning Google logins; added explicit `ck_oauth_states_consumed_pkce_scrubbed` SQL `CHECK`; capped JWKS responses at `65_536` bytes with short-lived per-fetch `httpx.Client`; specified `OAuthExchangeRequest` (`extra="forbid"`, `1..512`, `_strip_nonempty_token`), `get_constraint_name(exc)`-only `IntegrityError` diagnostics, and defensive Phase 3 `is_email_verified` checking.
4. **`R2-4` (Logging & Test Wording):** Specified idempotent `UvicornAccessSanitizingFilter` with 5-tuple preservation, fail-safe fallback, and `uvicorn.access.propagate = False`; updated the GitHub header test requirement to verify Folio360's outgoing `User-Agent`, `Accept`, and `X-GitHub-Api-Version` headers.

---

# Review Readiness Statement

**`F360-S3C-SPEC-REV3` is complete, internally consistent across its database constraints, callback state machine, transaction boundaries, and verified baseline repository contracts, and is ready for independent technical review.**

REV3 is a specification draft only. No application code, configuration, database, dependencies or Git state were modified. Implementation remains unauthorized pending independent review and explicit user approval.
