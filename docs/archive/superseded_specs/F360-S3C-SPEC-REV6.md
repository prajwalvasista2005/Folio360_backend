# F360-S3C-SPEC-REV6 — Stage 3C OAuth Authentication

**Specification ID:** `F360-S3C-SPEC-REV6` | **Project:** Student360 / Folio360 Backend | **Stage:** 3C — OAuth Authentication  
**Status:** Draft prepared for independent technical review | **Baseline Commit:** `71bea17e6e533b013ddd04bd6146b35357f108c5`  
**Supersedes:** `F360-S3C-SPEC-REV5` (and `REV1`–`REV4`) | **Review Basis:** Targeted REV6 Corrections (Exact D16 Preservation & Web Retry Clarification) | **Implementation Status:** Not authorized

---

# 1. Objective and Scope

Stage 3C adds **Google OAuth 2.0 (OIDC)** and **GitHub OAuth 2.0** (immutable ID + bounded paginated verified-email retrieval) alongside email/password auth while preserving `app/models/user.py` identity/ownership, `app/core/security.py` HS256 JWTs, `app/models/refresh_session.py` / `app/services/auth_service.py` rotation & revocation, web (`HttpOnly` cookie + `Origin` CSRF) vs. mobile (JSON, zero cookies) contracts, `users`-first row-lock ordering, and Stage 1–3B compatibility.

**Non-Negotiable Principles:** (1) Immutable `(provider, provider_user_id)` identity; (2) zero email-based auto-merging; (3) explicit linking deferred; (4) `state` validated on every callback; (5) PKCE `S256` mandatory (`plain` forbidden); (6) exact raw-string redirect URI allowlist matching; (7) never expose access/refresh/ID tokens, provider codes, or OAuth `state` in client redirect URLs; (8) opaque single-use `60s` exchange codes; (9) zero outbound HTTP inside open DB transactions (`not db.in_transaction()`) or while holding locks/pooled connections; (10) session issuance reuses `_create_session_and_mint_tokens` (exported as `create_session_and_mint_tokens`).

---

# 2. Binding Architectural Decisions (`D01`–`D23`)

| ID | Binding Decision | ID | Binding Decision |
| :--- | :--- | :--- | :--- |
| **D01** | Support Google and GitHub OAuth. | **D13** | Do not introduce `Authlib`, `itsdangerous`, or `Redis`. |
| **D02** | New GitHub accounts require a suitable verified email (`verified_email_required`). | **D14** | Preserve existing JWT, refresh-session, and revocation architecture. |
| **D03** | Returning GitHub identities authenticate by immutable provider ID. | **D15** | Extend `GET /api/v1/auth/me` with sorted `oauth_providers: list[str]`. |
| **D04** | Explicit account linking is deferred. | **D16** | Missing or unknown callback `state` returns JSON `400 INVALID_OAUTH_STATE` with no redirect. |
| **D05** | Auto-merging prohibited (`email_already_registered`). | **D17** | Bind exchange codes to `users.auth_version` at issuance. |
| **D06** | Validate OAuth `state` on every callback. | **D18** | Google and GitHub credentials are independently optional. |
| **D07** | Use PKCE `S256` on Google and GitHub. | **D19** | Web redirect origins must be a subset of `CORS_ORIGINS` when any provider is configured. |
| **D08** | Enforce exact redirect URI allowlists. | **D20** | Refresh `provider_email` only from fresh verified info; never alter `users.email`. |
| **D09** | Exchange codes: opaque, single-use, fixed `60s` expiry. | **D21** | Default mobile URI `folio360://auth/callback`; Expo Go `exp://` deferred. |
| **D10** | Consume exchange codes only via `POST /api/v1/auth/oauth/exchange`. | **D22** | Store Google `nonce` only as lowercase hex SHA-256 (`nonce_hash`). |
| **D11** | Never expose access/refresh tokens in redirect URLs. | **D23** | Bounded PostgreSQL cleanup for expired `oauth_states` and `oauth_exchange_codes`. |
| **D12** | Reuse existing `httpx==0.28.1`, `PyJWT==2.15.1`, `cryptography==50.0.2`. | | |

## 2.1 Locked Policy Refinements
1. **Returning Google Identity:** Resolved by validated immutable `sub`. Returning login permits `email_verified=False` or absent `email` if all other OIDC checks pass and no present claim has a malformed type (§6.5); new accounts require valid `email` and `email_verified is True`.
2. **Mandatory PKCE Key:** When Google or GitHub is configured, `OAUTH_PKCE_ENCRYPTION_KEY` is mandatory/valid in all environments (`development`/`testing`/`production`), failing `Settings` startup immediately rather than request-time `503`.
3. **Active-State Consume-on-Mismatch:** Active (`consumed_at IS NULL AND expires_at > now`) state with wrong `provider` or missing/mismatched web binding cookie is consumed/scrubbed (`consumed_at=now`, `pkce_verifier_encrypted='[CONSUMED]'`) and redirected `302` `{redirect_uri}?error=invalid_oauth_state`; consumed (`consumed_at IS NOT NULL`) and expired (`expires_at <= now`) rows roll back untouched.

---

# 3. Existing Architecture Compatibility

Integrates at commit `71bea17e6e533b013ddd04bd6146b35357f108c5`:
- **Framework/ASGI3 (`app/main.py`, `app/server.py`):** `FastAPI==0.163.1`, `uvicorn==0.54.0` (`Folio360FastAPI`, `VerifiedUvicornConfig`), synchronous `def` routes in Starlette threadpool.
- **DB/ORM (`app/db/base.py`, `app/db/session.py`):** PostgreSQL 17, sync `SQLAlchemy==2.0.38`, `psycopg==3.3.9` (`autocommit=False`, `autoflush=False`, `expire_on_commit=False`, `hide_parameters=True`, `Base`, `TimestampMixin`, `POSTGRES_NAMING_CONVENTION`). Split roles (`docker/postgres/init-least-privilege.sh`): `*_app` DML-only (inherited via `ALTER DEFAULT PRIVILEGES`), `*_migrator` owner/DDL.
- **Security/Transport/Ops:** `argon2-cffi==25.1.0`, `PyJWT==2.15.1`, `cryptography==50.0.2`, `httpx==0.28.1`, `hash_opaque_token`, HS256 JWT (`sub`, `ver`, `type="access"`, `iss`, `aud`, `iat`, `exp`, `jti`), `require_client_type`, `enforce_web_origin_if_web`, `app/core/exceptions.py` (422 `input` stripping), `SlidingWindowRateLimiter`, `resolve_client_ip()`, `SecurityFilter`/`SecurityFormatter`.
- **Existing Auth Routes:** All 11 routes (`/register`, `/verify-email`, `/resend-verification`, `/login`, `/refresh`, `/logout`, `/logout-all`, `/me`, `/forgot-password`, `/reset-password`, `/change-password`) unchanged except additive `oauth_providers` on `/me` (§16).
- **OAuth-Only Accounts:** Created with `password_hash=None`, `is_email_verified=True`, `email_verified_at=now`, `is_active=True`, `auth_version=0`, `password_changed_at=None`. Existing behaviors preserved: `/login` runs `DUMMY_PASSWORD_HASH` -> `401 INVALID_CREDENTIALS`; `/forgot-password` -> `202` (no email/token); `/reset-password` -> `400 INVALID_RESET_TOKEN`; `/change-password` -> `400 PASSWORD_NOT_SET`; `/me` -> `has_password: false`, `oauth_providers`.

---

# 4. Database Schema and Constraints

## 4.1 Migration Plan (`0004_add_oauth_tables`)
- `alembic/versions/0004_add_oauth_tables.py` (`revision="0004_add_oauth_tables"`, `down_revision="0003_add_password_reset_tokens"`): upgrade creates `oauth_accounts`, `oauth_states`, `oauth_exchange_codes` + constraints/indexes; downgrade drops in reverse order. Migrations `0001`–`0003` and existing tables untouched.
- ORM models in `app/models/oauth.py` (`Base`, `TimestampMixin`, `Uuid(as_uuid=True)` PKs with `default=uuid.uuid4`, `server_default=text("gen_random_uuid()")`), exported via `app/models/__init__.py` for `alembic check`.

## 4.2 Table: `oauth_accounts`
- **Columns:** `id` (`UUID` PK `pk_oauth_accounts`), `user_id` (`UUID` NOT NULL FK `fk_oauth_accounts_user_id_users` -> `users.id ON DELETE CASCADE`), `provider` (`VARCHAR(32)` NOT NULL), `provider_user_id` (`VARCHAR(255)` NOT NULL), `provider_email` (`VARCHAR(320)` NULL), `provider_email_verified` (`BOOLEAN` NOT NULL `server_default=false`), `created_at`/`updated_at` (`TIMESTAMPTZ` NOT NULL).
- **Unique/Index:** `uq_oauth_accounts_provider_subject(provider, provider_user_id)`, `uq_oauth_accounts_user_provider(user_id, provider)`, `ix_oauth_accounts_user_id(user_id)`.
- **Checks (`ck_oauth_accounts_<name>`):**
  - `provider`: `provider IN ('google', 'github')`
  - `provider_user_id_valid`: `provider_user_id = btrim(provider_user_id) AND provider_user_id <> '' AND provider_user_id !~ '[[:space:][:cntrl:]]'`
  - `provider_email_canonical`: `provider_email IS NULL OR (provider_email = lower(btrim(provider_email)) AND provider_email <> '' AND provider_email !~ '[[:space:]]')`
  - `email_verified_consistency`: `provider_email IS NOT NULL OR provider_email_verified = false`
- **Metadata Rules:** Only `(provider, provider_user_id)` resolves returning users; `provider_email` never merges or alters `users.email`. Google refreshes `provider_email`/`provider_email_verified=True` only when fresh valid email + `email_verified is True` (skip no-op writes); GitHub fast path never calls `/user/emails` or uses `/user.email`.

## 4.3 Table: `oauth_states` (no FK to `users`)
- **Columns:** `id` (`UUID` PK `pk_oauth_states`), `state_hash` (`CHAR(64)` NOT NULL UNIQUE `uq_oauth_states_state_hash`), `provider` (`VARCHAR(32)` NOT NULL), `client_type` (`VARCHAR(16)` NOT NULL), `pkce_verifier_encrypted` (`VARCHAR(512)` NOT NULL), `nonce_hash` (`CHAR(64)` NULL), `redirect_uri` (`VARCHAR(512)` NOT NULL), `client_binding_hash` (`CHAR(64)` NULL), `expires_at` (`TIMESTAMPTZ` NOT NULL), `consumed_at` (`TIMESTAMPTZ` NULL), `created_at`/`updated_at` (`TIMESTAMPTZ` NOT NULL).
- **Index:** `ix_oauth_states_expires_at(expires_at)`.
- **Checks (`ck_oauth_states_<name>`):**
  - `provider`: `provider IN ('google', 'github')`
  - `client_type`: `client_type IN ('web', 'mobile')`
  - `state_hash_hex`: `state_hash ~ '^[0-9a-f]{64}$'`
  - `pkce_not_empty`: `length(btrim(pkce_verifier_encrypted)) > 0`
  - `redirect_uri_valid`: `length(btrim(redirect_uri)) > 0 AND redirect_uri = btrim(redirect_uri)`
  - `nonce_hash_consistency`: `(provider = 'google' AND nonce_hash IS NOT NULL AND nonce_hash ~ '^[0-9a-f]{64}$') OR (provider = 'github' AND nonce_hash IS NULL)`
  - `client_binding_consistency`: `(client_type = 'web' AND client_binding_hash IS NOT NULL AND client_binding_hash ~ '^[0-9a-f]{64}$') OR (client_type = 'mobile' AND client_binding_hash IS NULL)`
  - `consumed_pkce_scrubbed`:
    ```sql
    CHECK ((consumed_at IS NULL AND pkce_verifier_encrypted <> '[CONSUMED]')
        OR (consumed_at IS NOT NULL AND pkce_verifier_encrypted = '[CONSUMED]'))
    ```
- **Invariants:** Never persist/log raw `state`, `nonce`, binding token, or plaintext PKCE verifier; every state consumption sets `consumed_at = now` and `pkce_verifier_encrypted = '[CONSUMED]'` together.

## 4.4 Table: `oauth_exchange_codes`
- **Columns:** `id` (`UUID` PK `pk_oauth_exchange_codes`), `user_id` (`UUID` NOT NULL FK `fk_oauth_exchange_codes_user_id_users` -> `users.id ON DELETE CASCADE`), `code_hash` (`CHAR(64)` NOT NULL UNIQUE `uq_oauth_exchange_codes_code_hash`), `client_type` (`VARCHAR(16)` NOT NULL), `auth_version` (`INTEGER` NOT NULL), `expires_at` (`TIMESTAMPTZ` NOT NULL, fixed `now + 60s`), `consumed_at` (`TIMESTAMPTZ` NULL), `created_at`/`updated_at` (`TIMESTAMPTZ` NOT NULL).
- **Indexes:** `ix_oauth_exchange_codes_user_id(user_id)`, `ix_oauth_exchange_codes_expires_at(expires_at)`.
- **Checks:** `hash_hex`: `code_hash ~ '^[0-9a-f]{64}$'`; `client_type`: `client_type IN ('web', 'mobile')`; `auth_version_non_negative`: `auth_version >= 0`. Global invalidation increments `users.auth_version` (no `revoked_at` column needed).

---

# 5. Cryptographic Design

- **PKCE (`S256` Only, `app/core/security.py`):** `generate_pkce_verifier() -> str` returns `secrets.token_urlsafe(64)` (`86` chars, 512-bit); `compute_pkce_s256_challenge(verifier: str) -> str` validates `^[A-Za-z0-9._~-]{43,128}$` and returns unpadded Base64url(SHA-256); `PKCE_VERIFIER_CONSUMED_MARKER = "[CONSUMED]"`. `plain` is forbidden.
- **Acyclic Key Decoder (`app/core/crypto_keys.py`):** Pure stdlib (`base64`, `binascii`, `re`) leaf module imported by both `app/core/config.py` and `app/core/security.py` (`security` imports `Settings` from `config`, preventing circular imports). `decode_aes256_base64url_key(raw_key: str, *, field_name: str) -> bytes` enforces exact regex `^[A-Za-z0-9_-]{43}=?$`, 32 raw bytes, no `+`/`/`/whitespace/`==`, and round-trip canonical bit check (`urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") == raw_key.rstrip("=")`). Never strip, pad, truncate, or hash arbitrary strings.
- **AES-256-GCM (`app/core/security.py`):** `encrypt_pkce_verifier(verifier, *, key, provider, state_hash)` & `decrypt_pkce_verifier(ciphertext, *, primary_key, previous_key, provider, state_hash)` use `AESGCM`, fresh 12-byte `os.urandom(12)` nonce, AAD `f"{provider}:{state_hash}".encode("utf-8")`, format `"v1:" + unpadded_b64url(nonce + ct_with_tag)`. `decrypt_pkce_verifier` rejects `"[CONSUMED]"`, missing `"v1:"`, short payloads (`< 29` bytes), or invalid Base64url; tries `primary_key` then `previous_key` on `InvalidTag`, else raises `PKCEDecryptionError`. Key rotation: set new primary + move old to `_PREVIOUS` -> wait >= `OAUTH_STATE_EXPIRE_MINUTES` + skew (>=15m) -> remove `_PREVIOUS`.
- **Unmodified Token Hashing:** Never strip, lowercase, or normalize `state`, `nonce`, or `folio360_oauth_binding` before `hash_opaque_token(...)` or `hmac.compare_digest(...)`. Callback `state.strip()` is used solely to reject missing/empty/whitespace-only inputs, then `hash_opaque_token(state)` hashes the exact unmodified input.

---

# 6. Google OpenID Connect Protocol

- **Endpoints (`timeout=OAUTH_HTTP_TIMEOUT_SECONDS`, `follow_redirects=False`):**
  - Auth: `https://accounts.google.com/o/oauth2/v2/auth` (`client_id`, `redirect_uri` backend callback, `response_type=code`, `scope=openid email profile`, `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`).
  - Token: `POST https://oauth2.googleapis.com/token` (`application/x-www-form-urlencoded`: `code`, `client_id`, `client_secret`, `redirect_uri`, `grant_type=authorization_code`, `code_verifier`) -> require HTTP `200` JSON with non-empty `str` `id_token`.
  - JWKS: `GET https://www.googleapis.com/oauth2/v3/certs` via `HttpxJWKClient` (§6.6).
- **Pre-JWKS Header Check:** `jwt.get_unverified_header(id_token)` must have `alg == "RS256"` and `kid` non-empty `str` with `kid == kid.strip()`, else reject as `oauth_provider_error` before JWKS lookup.
- **Claims (`jwt.decode`, `algorithms=["RS256"]`, `leeway=30`):** Require `iss`, `sub`, `aud`, `exp`, `iat`; verify signature, `exp`, `iat` (`<= now + 30`), `nbf` (if present). `iss`: `type(iss) is str` in `{"https://accounts.google.com", "accounts.google.com"}`.
  - `aud` / `azp` (OIDC Core 1.0 §3.1.3.7): non-`None`; `str` (non-empty, stripped) or non-empty `list[str]` (non-empty stripped elements, no duplicates); must contain `GOOGLE_CLIENT_ID` (`compare_digest`); every `aud` element must be in `{GOOGLE_CLIENT_ID} | set(GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES)` even when `azp == GOOGLE_CLIENT_ID`; require non-`None` `azp` if `len(aud_list) > 1`; whenever `azp` present require non-empty stripped `str` matching `GOOGLE_CLIENT_ID`.
  - `nonce`: non-empty `str` matching `expected_nonce_hash` via `hmac.compare_digest(hash_opaque_token(claims["nonce"]), ...)`.
  - `sub`: `type(sub) is str`, `1 <= len(sub) <= 255`, `sub == sub.strip()`, no whitespace or control chars (`ord < 0x20` or `== 0x7F`).
- **Email & Claim Types:** For ALL logins (new & returning), if `"email_verified"` is present require `type is bool`; if `"email"` is present require `str` valid canonical `EmailStr` (`1 <= len <= 320`, no whitespace)—malformed types reject as `oauth_provider_error`. Returning identity (`(google, sub)` found) allows `email_verified=False` or absent email/flag and never touches `users.email`; new identity requires valid `email` + `email_verified is True`, else `302 error=verified_email_required`.

## 6.6 HTTPX-Backed JWKS Client (`HttpxJWKClient(PyJWKClient)`)
- **Settings:** `uri="https://www.googleapis.com/oauth2/v3/certs"`, `cache_jwk_set=True`, `cache_keys=False`, `lifespan=300`, `cooldown_duration=30`, `timeout=settings.OAUTH_HTTP_TIMEOUT_SECONDS`. Scoped to `app.state.google_jwk_client` (never unbounded module global); `_client_lock` serializes refreshes; `not db.in_transaction()` asserted pre-lookup.
- **Raw-Body Streaming Cap (`MAX_JWKS_RESPONSE_BYTES = 65_536`) & Identity Encoding inside `fetch_data()`:**
  1. Send explicit `request_headers = {**(self.headers or {}), "Accept-Encoding": "identity"}` on every `GET`.
  2. Open nested context managers `with httpx.Client(timeout=self.timeout, follow_redirects=False) as client:` -> `with client.stream("GET", self.uri, headers=request_headers) as response:` so both close deterministically on every success/failure path.
  3. Require `response.status_code == 200` (non-200 / `3xx` raises `PyJWKClientConnectionError`).
  4. **Strict `Content-Encoding` check pre-read:** Inspect `response.headers.get_list("content-encoding", split_commas=False)` and comma-split values; accept **only** absent, empty/whitespace-only, or single case-insensitive `"identity"`. Immediately raise `PyJWKClientError` (exiting context managers without reading body) on `gzip`, `deflate`, `br`, `zstd`, multi-value headers, or unknown encodings.
  5. **Stream raw body excluding headers:** Read `response.iter_raw(chunk_size=8192)`, accumulate into `bytearray`, and immediately abort (`PyJWKClientError`) if `total_bytes + len(chunk) > MAX_JWKS_RESPONSE_BYTES` (`65_536`). Never touch `response.content`, `response.text`, `response.iter_bytes()`, `response.iter_text()`, or `response.json()` before completing the loop.
  6. Decode UTF-8, `json.loads(...)`, verify `dict` and `PyJWKSet.from_dict(payload)` before updating cache; preserve `_last_known_good_jwk_set` on transient/encoding/oversize/malformed refresh failures (still failing closed if no matching key exists or no prior cache exists).

---

# 7. GitHub OAuth 2.0 Protocol

- **Endpoints (`timeout=OAUTH_HTTP_TIMEOUT_SECONDS`, `follow_redirects=False`):**
  - Auth: `https://github.com/login/oauth/authorize` (`client_id`, `redirect_uri`, `scope=read:user user:email`, `state`, `code_challenge`, `code_challenge_method=S256`).
  - Token: `POST https://github.com/login/oauth/access_token` (`Accept: application/json`, `User-Agent: <APP_NAME>/<APP_VERSION>`, form params incl. `code_verifier`). Reject truthy `"error"` (GitHub HTTP `200` quirk) or missing/non-str/blank `"access_token"` as `oauth_provider_error`. Keep token in local memory only.
  - Profile: `GET https://api.github.com/user` (`Authorization: Bearer <token>`, `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`, `User-Agent: <APP_NAME>/<APP_VERSION>`). Require JSON `dict`, `type(raw_id) is int` (rejecting `bool`), `raw_id > 0`, `provider_user_id = str(raw_id)`. Ignore `/user.email`.
- **Returning Fast Path & Mandatory Transaction Termination:** Query `OAuthAccount` by `("github", provider_user_id)`. Found -> skip `/user/emails` completely and go to Phase 3. Not found -> **immediately `db.rollback()`** (`not db.in_transaction()`, returning pooled connection) **before** calling `/user/emails`.
- **Bounded Email Pagination (`GET https://api.github.com/user/emails?per_page={GITHUB_EMAILS_PER_PAGE}&page=1`, defaults `100` / `10` max pages):** Track `visited_urls`; fail closed (`oauth_provider_error`) on non-200, non-list JSON, non-dict items, or truncated list at `GITHUB_EMAILS_MAX_PAGES` with remaining `Link` `next`. Validate `response.links["next"]["url"]` via `urlsplit`: `scheme=="https"`, `hostname=="api.github.com"`, `port is None`, no user/pass, `path=="/user/emails"`, `fragment==""`, not in `visited_urls`. Keep `verified is True` + `str` email -> `normalize_email`, `1 <= len <= 320`, valid `EmailStr`, reject domains `users.noreply.github.com`, `*.users.noreply.github.com`, `noreply.github.com`; deduplicate keeping `primary is True` across duplicates; select `primary` else lexicographically smallest; if empty -> `302 error=verified_email_required`.

---

# 8. Configuration and Validation (`app/core/config.py`)

`Settings(_env_file=None)` passes cleanly with zero OAuth env vars configured.

| Setting | Type | Default | Bounds / Rule |
| :--- | :--- | :--- | :--- |
| `BACKEND_BASE_URL` | `str` | `"http://localhost:8000"` | Exact `scheme://host[:port]` (§10) |
| `OAUTH_BINDING_COOKIE_NAME` | `str` | `"folio360_oauth_binding"` | Non-empty, no whitespace, `!= REFRESH_COOKIE_NAME` |
| `OAUTH_PKCE_ENCRYPTION_KEY` | `SecretStr \| None` | `None` | Canonical 32B b64url `^[A-Za-z0-9_-]{43}=?$` via `crypto_keys.py` |
| `OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS` | `SecretStr \| None` | `None` | Optional canonical 32B b64url (requires primary key) |
| `GOOGLE_CLIENT_ID` / `_SECRET` | `str \| SecretStr \| None` | `None` | Strictly paired (both set or both unset/None) |
| `GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES` | `list[str]` | `[]` | `_parse_string_list_setting`; no `"*"`, whitespace, blanks, dups |
| `GITHUB_CLIENT_ID` / `_SECRET` | `str \| SecretStr \| None` | `None` | Strictly paired |
| `OAUTH_ALLOWED_WEB_REDIRECT_URIS` | `list[str]` | `[]` | `_parse_string_list_setting`; §9.1 web policy (set localhost in `.env.example`/`docker-compose.yml`, not `Settings`) |
| `OAUTH_ALLOWED_MOBILE_REDIRECT_URIS` | `list[str]` | `["folio360://auth/callback"]` | `_parse_string_list_setting`; §9.2 mobile policy |
| `OAUTH_STATE_EXPIRE_MINUTES` | `int` | `10` | `ge=1, le=30` |
| `OAUTH_HTTP_TIMEOUT_SECONDS` | `float` | `5.0` | `ge=1.0, le=15.0` |
| `GITHUB_EMAILS_PER_PAGE` / `_MAX_PAGES` | `int` | `100` / `10` | `ge=1, le=100` / `ge=1, le=20` |

- Fixed constant: `OAUTH_EXCHANGE_CODE_EXPIRE_SECONDS = 60`. `_parse_string_list_setting(..., allow_empty_string=True)` rejects non-strings, empty items, bad JSON, and duplicates.
- **Unconditional checks:** Credential pairing, cookie name validity/`!= REFRESH_COOKIE_NAME`, and any non-empty/non-None OAuth setting (`_PKCE_ENCRYPTION_KEY*`, redirect URIs, additional audiences, `BACKEND_BASE_URL`).
- **When `oauth_enabled = bool(GOOGLE_CLIENT_ID) or bool(GITHUB_CLIENT_ID)`:** PKCE key mandatory in all environments; D19 subset check (`origin in CORS_ORIGINS` for all web redirect URIs); in `production`, `validate_runtime_requirements()` enforces `BACKEND_BASE_URL` `https://`, web URIs `https://`, zero `http://` mobile URIs.
- **When `oauth_enabled` is `False`:** Non-OAuth startup succeeds in all envs (including default `BACKEND_BASE_URL` in production without D19 error). `/start` for unconfigured recognized providers returns `503 SERVICE_UNAVAILABLE`. `/callback` strictly follows `Orders 0–12` (§11.4): unknown provider -> `400 INVALID_OAUTH_PROVIDER`; missing/blank/unknown state -> JSON `400 INVALID_OAUTH_STATE` per D16 regardless of provider configuration; consumed/expired -> safe redirect untouched; active cross-provider mismatch -> consume/scrub & safe redirect even if unconfigured; only active matching-provider on unconfigured callback returns `503` (row untouched).

---

# 9. URI Policy (`app/core/uri_policy.py`) & 10. `BACKEND_BASE_URL`

- **§9.1 Web (`parse_and_canonicalize_web_redirect_uri`):** `https` in all envs; `http` only in `development`/`testing` on `localhost`/`127.0.0.1`/`[::1]`; non-empty `/` path; existing RFC 3986 strict checks (ASCII, no `?`/`#`/`@`/`\`/`*`, no encoded traversal `%2f`/`%5c`/`%2e`/`%00`, no dot segments/`//`/punycode/redundant ports/trailing `/`). Custom schemes forbidden.
- **§9.2 Mobile (`parse_and_canonicalize_mobile_redirect_uri`):** Same rules as `parse_and_canonicalize_mobile_login_uri` (`https://` Universal/App Links or `^[a-z][a-z0-9+.-]*$` without port; no `http://` in production). Default `folio360://auth/callback`; Expo `exp://` deferred (D21).
- **§9.3 Request Matching & Redirect Builder:** Exact raw-string equality `redirect_uri in allowlist` (never normalize caller input). `build_oauth_redirect_url(redirect_uri, *, allowlist, code=None, error=None)` re-verifies `redirect_uri in allowlist` (failing closed if false), requires XOR `(code, error)`, strips existing `code`/`error` params via `urlsplit`+`parse_qsl`, appends single param via `urlencode`, and reconstructs via `urlunsplit`.
- **§10 `BACKEND_BASE_URL`:** Mirrors `validate_frontend_base_url` (no path/trailing slash/query/fragment/credentials/whitespace; `https` required in production when OAuth enabled, loopback `http` allowed in dev/test). Callback URL built solely from server config: `f"{settings.BACKEND_BASE_URL}{prefix}/auth/oauth/{provider}/callback"` (normalized `API_V1_PREFIX`, never `Host`/`X-Forwarded-Host`).

---

# 11. Complete Callback State Machine and Transaction Sequencing

## 11.1 Routes & Param Validation
- `GET /api/v1/auth/oauth/{provider}/start` (`20 / 15m / IP`), `provider: str`, optional `client_type: str | None`, `redirect_uri: str | None`.
- `GET /api/v1/auth/oauth/{provider}/callback` (`20 / 15m / IP`), `provider: str`, optional `state/code/error: str | None`.
- `POST /api/v1/auth/oauth/exchange` (`10 / 15m / IP`), `X-Client-Type: web | mobile` (+ `Origin` on `web`), `OAuthExchangeRequest`.
- Declaring optional `str | None` prevents FastAPI `422` and guarantees exact `auth_error` `400` codes (`INVALID_OAUTH_PROVIDER`, `INVALID_CLIENT_TYPE`, `INVALID_REDIRECT_URI`, `INVALID_OAUTH_STATE`).

## 11.2 `/start` Order
(1) `provider in {"google", "github"}` else `400 INVALID_OAUTH_PROVIDER`; (2) configured else `503 SERVICE_UNAVAILABLE`; (3) `client_type in {"web", "mobile"}` else `400 INVALID_CLIENT_TYPE`; (4) exact `redirect_uri` in allowlist else `400 INVALID_REDIRECT_URI`; (5) generate `raw_state`, `code_verifier`, `S256` challenge, `raw_nonce` (Google), `raw_binding` (web); (6) AES-256-GCM encrypt verifier (`AAD = f"{provider}:{state_hash}"`); (7) insert `OAuthState` + `db.commit()`; (8) isolated bounded cleanup (§15.2); (9) `302` to provider with security headers + web binding cookie (§11.3).

## 11.3 Browser-Binding Cookie (`folio360_oauth_binding`)
- **Set (`/start`, `web` only):** `key=settings.OAUTH_BINDING_COOKIE_NAME`, `httponly=True`, `samesite="lax"` (unconditionally), `secure=settings.REFRESH_COOKIE_SECURE` (`True` in production), `domain=None`, `max_age=OAUTH_STATE_EXPIRE_MINUTES*60`, `path=f"{prefix}/auth/oauth"`.
- **Clear (`/callback`, matching attributes):**
  - **Clause A — Known `web` state:** Always clear on every callback response (success, redirect errors, defensive JSON `400 INVALID_REDIRECT_URI`, and `Order 7` `503 SERVICE_UNAVAILABLE`).
  - **Clause B — Known `mobile` state:** Never set or clear across all branches (including `Order 7` `503`).
  - **Clause C — Pre-lookup failures (`Order 0` `429 RATE_LIMIT_EXCEEDED`, `Order 1` `400 INVALID_OAUTH_PROVIDER`):** Clear **only if present** on incoming request; emit **no** `Set-Cookie` header if absent.
  - **Clause D — Missing/blank/unknown `state` (`Orders 2`–`3` `400 INVALID_OAUTH_STATE`, regardless of provider configuration):** Clear **only if present**; emit **no** `Set-Cookie` if absent; never infer state from cookie.
  - **Clause E — Unconfigured matching active state (`Order 7` `503 SERVICE_UNAVAILABLE`):** Follow known `client_type`. For `web`, clearing the binding cookie means **the original web OAuth flow cannot safely resume** even though the DB row stays unconsumed; user **must initiate a fresh `/start`** once configured (never reuse original state as retry). Mobile callbacks remain cookie-independent.
- **Parallel Web Starts / Multi-Tab Cascading Behavior:** Single shared cookie is preserved. Starting Tab 2 overwrites Tab 1's cookie; completing Tab 1 fails `Order 8` binding check, consumes/scrubs Tab 1 state, **clears** `folio360_oauth_binding`, and redirects `invalid_oauth_state` (zero Phase 2 HTTP); completing Tab 2 next sees missing cookie, fails `Order 8` identically, consumes/scrubs Tab 2 state, and redirects `invalid_oauth_state`. Both fail closed cleanly.

## 11.4 Complete Callback Decision Table (`GET /api/v1/auth/oauth/{provider}/callback`)

Strict mandatory order `0 -> 12`. Provider configuration checks must **never** precede state lookup (`Orders 2–3`), replay checks (`4–5`), or cross-provider mismatch consumption (`6`). All responses emit `Cache-Control: no-store`, `Pragma: no-cache`, `Referrer-Policy: no-referrer`:

| Order | Condition | DB State Mutation | HTTP Response & Error | Binding Cookie Cleared? | Ph2 HTTP? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **0** | Rate limit exceeded | None | JSON `429 RATE_LIMIT_EXCEEDED` | If present (none if absent) | No |
| **1** | `provider` not in `{"google", "github"}` | None | JSON `400 INVALID_OAUTH_PROVIDER` | If present (none if absent) | No |
| **2** | `state` missing/empty/whitespace-only (recognized `provider`, configured or unconfigured — D16) | None (no create/mutate) | JSON `400 INVALID_OAUTH_STATE` (no redirect) | If present (none if absent) | No |
| **3** | Exact unmodified `state_hash` not in `oauth_states` (recognized `provider`, configured or unconfigured — D16) | None (`rollback`) | JSON `400 INVALID_OAUTH_STATE` (no redirect) | If present (none if absent) | No |
| **4** | Known row (configured or unconfigured): `consumed_at IS NOT NULL` | **None (`rollback` — untouched)** | `302` `{redirect_uri}?error=invalid_oauth_state`\* | Yes if `web`; never `mobile` | No |
| **5** | Known row (configured or unconfigured): `expires_at <= now` | **None (`rollback` — untouched)** | `302` `{redirect_uri}?error=invalid_oauth_state`\* | Yes if `web`; never `mobile` | No |
| **6** | Active row (configured or unconfigured): `state_row.provider != provider` | **Consume & scrub** (`consumed_at=now`, `pkce='[CONSUMED]'`, `commit`) | `302` `{redirect_uri}?error=invalid_oauth_state`\* | Yes if `web`; never `mobile` | No |
| **7** | Active row: `state_row.provider == provider` AND `provider` unconfigured | **None (`rollback` — untouched/unconsumed)** | JSON `503 SERVICE_UNAVAILABLE` | Yes if `web`†; never `mobile` | No |
| **8** | Active `web` row (configured, provider matches): cookie missing or digest mismatch | **Consume & scrub** (`commit`) | `302` `{redirect_uri}?error=invalid_oauth_state`\* | Yes | No |
| **9** | Active valid row: `error == "access_denied"` | **Consume & scrub** (`commit`; skip PKCE decrypt) | `302` `{redirect_uri}?error=oauth_cancelled`\* | Yes if `web`; never `mobile` | No |
| **10** | Active valid row: other `error` OR missing/blank `code` | **Consume & scrub** (`commit`; skip PKCE decrypt) | `302` `{redirect_uri}?error=oauth_provider_error`\* | Yes if `web`; never `mobile` | No |
| **11** | Active valid row + `code`: PKCE decrypt/AAD fails | **Consume & scrub** (`commit`) | `302` `{redirect_uri}?error=oauth_provider_error`\* | Yes if `web`; never `mobile` | No |
| **12** | Active valid row + `code` + valid PKCE decrypt | **Consume & scrub** (`commit`) | Phase 2 -> Phase 3 -> `302` `code=<60s>` or safe error\* | Yes if `web`; never `mobile` | **Yes** |

\* **Allowlist Guard (`Orders 4–6`, `8–12`):** `build_oauth_redirect_url` re-verifies exact membership in allowlist; on mismatch do not redirect—return JSON `400 INVALID_REDIRECT_URI` (clear cookie if `web`, never `mobile`).  
† **`Order 7` Web Non-Resumability:** Clearing the `web` cookie prevents resuming the original flow despite untouched DB state; fresh `/start` required.  
**Closed Redirect Error Enum:** `oauth_cancelled`, `invalid_oauth_state`, `oauth_provider_error`, `verified_email_required`, `email_already_registered`, `account_inactive` (never forward provider `error_description`).

## 11.5 Three-Phase Sequencing
- **Phase 1 (State Validation & Consumption):** (1) Pass `Order 0` (`429`) and `Order 1` (`400 INVALID_OAUTH_PROVIDER`) without checking provider configuration; (2) `if not state or not state.strip():` return JSON `400 INVALID_OAUTH_STATE` (`Order 2`, clear cookie if present, regardless of provider config), else `state_hash = hash_opaque_token(state)` unmodified; (3) lock `OAuthState` `FOR UPDATE` (`populate_existing=True`); (4) if `None` -> `db.rollback()`, clear cookie if present, return JSON `400 INVALID_OAUTH_STATE` (`Order 3`, regardless of provider config); (5) capture fields; (6–7) `consumed_at` (`Order 4`) / `expires_at <= now` (`Order 5`) -> `db.rollback()`, safe redirect; (8) `state_provider != provider` -> consume/scrub, `commit`, safe redirect (`Order 6`, even if unconfigured); (9) `if not is_oauth_provider_configured(provider):` -> `db.rollback()` (untouched/unconsumed), clear cookie iff `web` (`Order 7` web needs fresh `/start`), JSON `503`; (10) `web` binding mismatch -> consume/scrub, `commit`, safe redirect (`Order 8`); (11–14) set `consumed_at=now` & `pkce_verifier_encrypted='[CONSUMED]'` -> `access_denied` (`Order 9`), error/missing code (`Order 10`), or PKCE decrypt fail (`Order 11`, sanitized warning `event="oauth_pkce_decrypt_failed"`) -> `commit` & safe redirect; (15) `commit` releasing lock/connection before Phase 2 (`Order 12`), keeping `code_verifier` in local memory only.
- **Phase 2 (External HTTP):** Unconditionally skipped for `Orders 0–11`. Assert `not db.in_transaction()` before every `httpx` / JWKS call. Google: token exchange + RS256 JWKS/OIDC (§6); GitHub: token + `/user` + fast-path `OAuthAccount` lookup -> if miss, `db.rollback()` immediately (`not db.in_transaction()`) -> bounded `/user/emails` (§7).
- **Phase 3 (Account Resolution & Exchange Code):** Single outer Tx. **Existing `(provider, provider_user_id)`:** lock `users` first (`FOR UPDATE`, `populate_existing=True`); `not is_active` -> `rollback`, `account_inactive`; `not is_email_verified` -> `rollback`, `verified_email_required`; permitted metadata refresh; read `auth_version` under lock, insert `OAuthExchangeCode` (`60s`), `commit`. **New identity:** validate verified email -> `SAVEPOINT` (`§12`) -> insert `OAuthExchangeCode` in same outer Tx -> `commit()` atomically. Return `302` (`build_oauth_redirect_url`) clearing web cookie only.

---

# 12. SAVEPOINT and Account-Provisioning Recovery

New-account provisioning uses **one outer Tx** with inner `with db.begin_nested():`:
1. Inside `SAVEPOINT`: insert `User` (`password_hash=None`, `is_active=True`, `is_email_verified=True`, `email_verified_at=now`, `auth_version=0`, `password_changed_at=None`) + `flush()`, then `OAuthAccount` + `flush()`.
2. After `SAVEPOINT` release (same outer Tx): insert `OAuthExchangeCode(user_id, code_hash, client_type, auth_version=user.auth_version, expires_at=now+60s)`, then outer `db.commit()` commits all 3 rows atomically.
- **On `IntegrityError` inside `SAVEPOINT`:** Inspect **only** `constraint_name = get_constraint_name(exc)` (`_get_constraint_name` from `app/services/auth_service.py`, reading `exc.orig.diag.constraint_name`; never parse strings or leak `DETAIL:`):
  - **Case 1 (`constraint_name == "uq_oauth_accounts_provider_subject"`):** Re-query `OAuthAccount` by `(provider, provider_user_id)`. Found -> lock `users FOR UPDATE`, verify `is_active`/`is_email_verified`, insert `OAuthExchangeCode` in same outer Tx, `commit()`. Not found -> `rollback()`, log sanitized `constraint_name`, `302 oauth_provider_error`.
  - **Case 2 (`constraint_name == "uq_users_email"`):** Re-query `OAuthAccount` strictly by immutable `(provider, provider_user_id)` (never by email). Found (concurrent twin first-time callback) -> same locked recovery + `commit()`; not found -> `rollback()`, `302 email_already_registered`.
  - **Case 3 (Unrelated constraint e.g. `uq_oauth_accounts_user_provider` or missing/`"unknown"`):** Never recover -> `rollback()`, log sanitized constraint only, `302 oauth_provider_error`. Zero partial rows survive failure.

---

# 13. OAuth Exchange and `auth_version` Concurrency

- **`POST /api/v1/auth/oauth/exchange`:** `require_client_type` + `enforce_web_origin_if_web`, `10 / 15m / IP`, emits `Cache-Control: no-store`, `Pragma: no-cache`, `Referrer-Policy: no-referrer` on all responses.
- **Schemas (`app/schemas/oauth.py`):** `OAuthExchangeRequest` (`ConfigDict(extra="forbid")`, `code: str` `1..512`, `@field_validator("code", mode="before")` via `_strip_nonempty_token` from `app/schemas/auth.py`; `422` strips `input`). Reuses `WebAuthTokenResponse` (refresh cookie only, via `_set_refresh_cookie`) and `MobileAuthTokenResponse` (JSON only, zero cookies).
- **Atomic Exchange (`users`-first lock):** Hash `payload.code` -> scalar lookup `user_id` -> lock `users FOR UPDATE` (`populate_existing=True`) -> lock `oauth_exchange_codes FOR UPDATE` -> check `code_row` exists, unconsumed, unexpired (`> now`), matching `client_type`, `code_row.auth_version == user.auth_version` BEFORE account status (on fail: `rollback`, `400 INVALID_OAUTH_EXCHANGE_CODE`) -> check `user.is_active` (`403 ACCOUNT_INACTIVE`) & `user.is_email_verified` (`403 EMAIL_NOT_VERIFIED`, `rollback` without consuming) -> set `consumed_at=now` -> delegate session/JWT creation & commit to shared `auth_service.create_session_and_mint_tokens(...)`.
- **Dual-Order Races vs. `/logout-all`, `/reset-password`, `/change-password`:** (Case A: invalidation locks `users` first -> increments `auth_version` & commits -> exchange detects mismatch -> `400`, 0 sessions; Case B: exchange wins -> consumes & creates session -> invalidation locks `users` -> increments `auth_version` & revokes all sessions incl. new one -> tokens fail `401`).

---

# 14. Logging and Secret Redaction (`app/core/logging.py`)

- **`UvicornAccessSanitizingFilter(logging.Filter)`:** Idempotently attached in `setup_logging()` to `logging.getLogger("uvicorn.access")` and handlers (`propagate = False` preventing duplicate root logs; `protect_handler()` on `uvicorn`/`uvicorn.error`; preserves `test_setup_logging_idempotent_no_duplicates`). For 5-tuple `record.args = (client_addr, method, full_path, http_version, status_code)`, sanitizes `full_path` (index 2) so `AccessFormatter` never crashes; non-5-tuple or error suppresses via `FAILSAFE_FALLBACK_MESSAGE`.
- **Patterns:** Query regex `([?&](?:code|state|token|id_token|access_token|refresh_token|error_description)=)([^&\s"']+)` -> `\1[REDACTED]` (preserves `status_code`, `error_code`, `client_type`); add `oauth_pkce_encryption_key_previous`, `folio360_oauth_binding`, `oauth_binding`, `oauth_state`, `authorization_code` to `KEY_VALUE_PATTERN`; keep `AppException.details` strictly `{"code": "..."}` via `auth_error()`.

---

# 15. Bounded Expired-Record Cleanup

- `OAUTH_CLEANUP_BATCH_SIZE = 100`, `OAUTH_CLEANUP_GRACE_SECONDS = 60` (`cutoff = now - timedelta(seconds=60)`), retaining unexpired & consumed-within-grace rows.
- Parameterized CTE for `oauth_states` (and equivalent for `oauth_exchange_codes`):
  ```sql
  WITH expired AS (
      SELECT id FROM oauth_states WHERE expires_at < :cutoff
      ORDER BY expires_at ASC LIMIT :batch_size FOR UPDATE SKIP LOCKED
  ) DELETE FROM oauth_states WHERE id IN (SELECT id FROM expired);
  ```
- During `/start`: commit new `oauth_states` row first, then execute cleanup in a separate `try/except Exception:` block (`db.rollback()` cleanup only on error, log `type(exc).__name__`, still return `302`).

---

# 16. `/me` Response & 17. Rate Limits / Headers

- **§16 `/me`:** Add `oauth_providers: list[str]` to `MeResponse` (sorted `SELECT provider ... ORDER BY provider ASC`: `[]`, `["github"]`, `["google"]`, or `["github", "google"]`). `UserPublicResponse` unchanged; zero tokens/emails/secrets exposed. Update `tests/test_migrations.py` (3C.3) and `tests/test_auth_flows.py:217` (3C.6).
- **§17 Rate Limits (`rate_limit_dependency` + `resolve_client_ip`):** `/start` `auth:oauth-start` `20 / 15m / IP`; `/callback` `auth:oauth-callback` `20 / 15m / IP`; `/exchange` `auth:oauth-exchange` `10 / 15m / IP`. Every `/start`, `/callback`, and `/exchange` response (redirects, error redirects, JSON `400`/`403`/`422`/`503`, `429 RATE_LIMIT_EXCEEDED`) unconditionally sets `Cache-Control: no-store`, `Pragma: no-cache`, `Referrer-Policy: no-referrer` (and `/callback` `429` clears binding cookie only if present).

---

# 18. Complete Test Matrix

Synchronous `TestClient` against `folio360_test` (`*_test_app` DML role) with mocked provider HTTP / JWKS boundaries (zero live network):

- **18.1 Google OIDC & JWKS (11 JWKS streaming tests + OIDC):** All OIDC claim/signature/`alg`/`kid`/`iss`/`exp`/`nbf`/`iat`/`leeway=30`/`aud`/`azp`/`GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES`/`sub`/`nonce`/PKCE tests; new `email_verified=False`->`verified_email_required`, returning `email_verified=False`/absent succeeds, malformed claim types rejected for both. `HttpxJWKClient`: (1) sends `Accept-Encoding: identity`; (2) absent/blank/`identity` `Content-Encoding` accepted; (3) `gzip`/`deflate`/`br`/`zstd`/`gzip, identity` rejected pre-read preserving cache; (4) `< 65_536` succeeds; (5) exact `65_536`-byte raw body succeeds even if headers+body > `65_536`; (6) `> 65_536` raw body fails preserving cache; (7) early abort via `iter_raw(8192)` without reading extra chunks or accessing `content`/`text`/`iter_bytes`/`iter_text`/`json`; (8) gzip-bomb simulation rejected by `Content-Encoding` pre-decompression; (9) bad UTF-8/JSON/JWKS `<= 65_536` fails safely preserving cache; (10) deterministic `response` & `httpx.Client` close on all paths + `_last_known_good_jwk_set` + `app.state` isolation; (11) `_client_lock` concurrency with `not db.in_transaction()`.
- **18.2 GitHub:** Returning fast path skips `/user/emails`; miss calls `db.rollback()` pre-`/user/emails`; invalid/bool/non-pos `id`; primary/lexicographic selection; noreply domains -> `verified_email_required`; cross-page dedup & `Link` `urlsplit` security rejections + `MAX_PAGES` truncation; HTTP `200` `"error"` JSON rejected; required headers; `/user.email` ignored.
- **18.3 Callback State Machine, Cookies & Crypto (asserting persisted DB `consumed_at` and `pkce_verifier_encrypted`):**
  1. Missing `state` on unconfigured recognized provider -> JSON `400 INVALID_OAUTH_STATE` (no redirect, zero DB mutation, cookie clear iff present).
  2. Unknown `state` (incl. whitespace-padded valid state `" <raw> "` hashed unmodified) on unconfigured provider -> JSON `400 INVALID_OAUTH_STATE` (DB row untouched).
  3. Empty/whitespace-only `state` on unconfigured provider -> JSON `400 INVALID_OAUTH_STATE`.
  4. Missing `state` on configured provider -> JSON `400 INVALID_OAUTH_STATE`.
  5. Unknown/whitespace-padded `state` on configured provider -> JSON `400 INVALID_OAUTH_STATE` (original row untouched).
  6. Active Google state -> unconfigured GitHub callback -> asserts DB `consumed_at IS NOT NULL` & `pkce_verifier_encrypted == "[CONSUMED]"`, `302 invalid_oauth_state` (replay on Google -> Order 4).
  7. Active GitHub state -> unconfigured Google callback -> asserts DB consume/scrub & `302 invalid_oauth_state` (+ configured mismatch variant).
  8. Active matching-provider state -> unconfigured callback -> `503 SERVICE_UNAVAILABLE`, asserts DB `consumed_at IS NULL` & ciphertext unchanged.
  9. Matching-provider `web` `503` -> clears `folio360_oauth_binding` & proves original state cannot resume post-configuration (fails closed at `Order 8` -> consumes/scrubs); fresh `/start` succeeds.
  10. Matching-provider `mobile` `503` -> emits zero `Set-Cookie` headers.
  11. Unknown provider (`Order 1`) -> JSON `400 INVALID_OAUTH_PROVIDER` prior to config checks (NOT `503`).
  12. Consumed (`Order 4`) & expired (`Order 5`) -> DB unmodified, safe `302` redirect (incl. unconfigured callback).
  13. Pre-state `429 RATE_LIMIT_EXCEEDED` (`Order 0`) -> conditional cookie clear (clear iff present).
  - Plus `Orders 8–11` (incl. multi-tab cascading `Order 8` failure on both Tab 1 & Tab 2), defensive unallowlisted `redirect_uri` `400 INVALID_REDIRECT_URI`, zero Phase 2 HTTP for `Orders 0–11`, security headers on all endpoints/errors, PKCE & AES-GCM/rotation/AAD/`crypto_keys.py` unit tests.
- **18.4 Tx/Pool Isolation:** Assert `not db.in_transaction()`, zero `idle in transaction` connections, zero held locks (`FOR UPDATE NOWAIT`) at every mocked HTTP boundary.
- **18.5 Provisioning & `SAVEPOINT`:** Single outer Tx atomicity (all 3 rows); `email_already_registered`, `account_inactive`, `verified_email_required`; all 4 conflict-discrimination cases (`uq_oauth_accounts_provider_subject` recovered vs. unrecovered, `uq_users_email` twin-callback vs. distinct user, unrelated/missing constraint bypassing recovery); concurrent OAuth vs. `/register`.
- **18.6 Exchange & Concurrency:** Web cookie+`Origin` vs. mobile JSON; error codes & `403` before/after code checks; deterministic `_wait_for_pg_lock_wait` duplicate exchange `[200, 400]` and dual-order Case A/B races vs. `/logout-all`, `/reset-password`, `/change-password` (hybrid user).
- **18.7 Cleanup, Logging, Config, `/me`, Fixtures & Migrations:** `SKIP LOCKED` cleanup + failure isolation; `UvicornAccessSanitizingFilter` + idempotent `setup_logging()`; all `Settings` validation/D19/`BACKEND_BASE_URL`/rate-limit tests; `/me` & Stage 1–3B regressions; `DELETE FROM oauth_states` in fixture teardown; `@pytest.mark.migration` clean/populated/downgrade/`alembic check`/split-role tests.

---

# 19. Live Provider Verification, 20. Plan, 21. Non-Goals, 22. Acceptance & 23. History

- **§19 Live Pre-Production Gate:** Real Google & GitHub client checks verifying PKCE `S256` success & mismatch rejection, exact callback URI, live RS256 JWKS/claims, `/user` `id`, `/user/emails` selection, fast path, and zero tokens in URLs.
- **§20 Seven-Substage Plan (`3C.1`–`3C.7`):** `3C.1` config/`crypto_keys.py`/URI policy/logging -> `3C.2` PKCE/AES-GCM (`security.py`) -> `3C.3` models/`0004` migration/migration tests -> `3C.4` Google (`HttpxJWKClient`) & GitHub clients -> `3C.5` `oauth_service.py` & `auth_service.py` helper -> `3C.6` routes/`schemas/oauth.py`/`/me`/test update -> `3C.7` full verification. Per-substage 8-step governance; explicit approval per `git add/commit/push`.
- **§21 Non-Goals:** Apple/Microsoft, explicit linking, auto-merge, storing provider access tokens, post-login provider calls, institutional checks, replacing password auth/refresh sessions, Redis/queues, Expo `exp://`.
- **§22 Acceptance Criteria (all 17 required):** (1) Google new/returning + `HttpxJWKClient` `Accept-Encoding: identity`/strict `Content-Encoding`/`iter_raw()` `65_536`B raw limit; (2) GitHub new/returning + fast path; (3) immutable identity/no auto-merge; (4) `Orders 0–12` matching §11.4 incl. D16 `400` regardless of provider config, `Order 6` consume before `503`, `Order 7` unconfigured `503` (DB untouched, `web` cookie cleared/non-resumable, `mobile` untouched), `ck_oauth_states_consumed_pkce_scrubbed`, §11.3 cookies; (5) replay immutability; (6) single consume-on-mismatch without Phase 2 HTTP; (7) PKCE/AES-GCM/rotation; (8) exchange code `60s`/`auth_version`; (9) §13.3 dual-order concurrency; (10) web vs. mobile contracts; (11) zero HTTP in open DB Tx/locks; (12) `SKIP LOCKED` cleanup isolation; (13) Uvicorn tuple log redaction; (14) `/me` `oauth_providers`; (15) `0004` migration/split-role; (16) Stage 1–3B regression green; (17) independent review + §19 live checks pre-prod.
- **§23 Revision History:**
  - `REV1`: Initial spec (`D01`–`D23`). `REV2`: Uvicorn filter, GitHub fast-path rollback, D19 defaults, `SAVEPOINT`/dual-order concurrency, returning Google policy, key validation, CTE cleanup. `REV3`: Callback precedence, `ck_oauth_states_consumed_pkce_scrubbed`, defaults/headers. `REV4`: Cookie consistency, unmodified `state` hashing, single outer Tx `SAVEPOINT` + 3-way conflict, `client.stream` JWKS cap, `crypto_keys.py`, security headers. `REV5`: Cross-provider mismatch before `503` (`Order 6`), JWKS raw-body `iter_raw()`/`Accept-Encoding: identity`, pre-state/multi-tab cookies.
  - **`REV6` Changes:** Removed REV5's pre-state `503` exception for missing/blank/unknown state so D16 (`400 INVALID_OAUTH_STATE`) holds regardless of provider configuration (`Orders 2–3`); preserved `Order 6` cross-provider consumption before `503`; made `Order 7` unconfigured matching-provider `web` `503` non-resumability explicit (cookie cleared -> fresh `/start` required) while `mobile` `503` stays cookie-free; added all 13 DB-asserted regression tests (§18.3); kept REV5 JWKS raw-body protections intact.

# Review Readiness Statement

**`F360-S3C-SPEC-REV6` is complete, preserves `D16` unconditionally across configured and unconfigured recognized providers (`Orders 0–12`), clarifies unconfigured-provider web non-resumability (`Order 7`), retains all REV1–REV5 security, transaction, JWKS, and cookie controls, and is ready for independent technical review.** REV6 is a specification draft only (`Implementation Status: Not authorized`).
