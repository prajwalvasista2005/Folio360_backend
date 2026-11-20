# Folio360 — Product Phase 0: Authentication Architecture Specification (`F360-P0-AUTH-SPEC-REV5`)

---

## 1. Document Status, Scope, Baseline, and Revision History

- **Document ID:** `F360-P0-AUTH-SPEC-REV5` (Final Targeted Corrections Revision)
- **Project:** Folio360 (Student360) Backend — Modular Monolith
- **Repository:** `C:\Users\vasista0305\OneDrive\Desktop\folio360_backend` (`https://github.com/prajwalvasista2005/Folio360_backend.git`)
- **Approved Git Baseline:**
  - **Branch:** `main`
  - **Commit:** `206970f5923bd19d445cce905e6bbaf0b5c697ff`
  - **Commit Message:** `feat(stage2): add database foundation`
  - **Completed Prerequisite Stages:** Stage 0 (Environment & Repository), Stage 1 (FastAPI Application Foundation — 43 tests), Stage 2 (PostgreSQL 17 + Synchronous SQLAlchemy 2.x + Alembic Foundation — 38 tests; 81 total tests passing).
- **Status:** Complete, implementation-ready Phase 0 authentication specification awaiting independent review and explicit approval from the project owner before any Stage 3 implementation begins.
- **Scope:** End-to-end backend authentication for **web** (React/Vite) and **mobile** (React Native / Expo) clients covering email/password registration, email verification via Resend, login, JWT access tokens, rotating opaque refresh sessions, logout / logout-all, password recovery and authenticated password change, and Google OIDC + GitHub OAuth 2.0 login.
- **Out of Scope:** Frontend UI implementation, user profiles/portfolios, RBAC/roles, MFA/2FA, explicit cross-provider account linking (schema-prepared, endpoints deferred), session listing/individual revocation UI (`GET /sessions`, `DELETE /sessions/{id}` deferred), and Redis/message-broker/KMS infrastructure.

### Revision History
- **Rev 0:** Initial architecture review, existing repository audit, and 11 architectural decision proposals (Q1–Q11).
- **Rev 1 (`F360-P0-AUTH-SPEC-REV1`):** Locked approved Q1–Q11 decisions; separated Alembic migrations by stage (`0002`, `0003`, `0004`); formalized Resend delivery-failure/recovery contract; replaced timestamp JWT invalidation with integer `users.auth_version`; hardened 422 validation stripping, logging redaction, PostgreSQL `DETAIL:` mapping, and OAuth concurrency handling.
- **Rev 2 (`F360-P0-AUTH-SPEC-REV2`):** Added deployment-aware refresh-cookie policy (Development, Mode 1 Same-Site Production, Mode 2 Cross-Site Production); defined deadlock-free `users`-first row locking for `change-password` and `reset-password`; standardized `folio360_oauth_binding` cookie naming; refined GitHub email suitability terminology; added official OAuth/OIDC references; added AES-256-GCM PKCE verifier encryption at rest; added token-bearing frontend page referrer controls, safe `urllib.parse` OAuth redirect query building, and separate Git authorization governance.
- **Rev 3 (`F360-P0-AUTH-SPEC-REV3`):** Adopted single Uvicorn `ProxyHeadersMiddleware` trust boundary; added Google OIDC `aud`/`azp` validation; classified Google confidential web-server PKCE evidence with pre-release live verification gate; specified bounded GitHub `/user/emails` pagination; clarified Resend immediate first-retry vs. 10-second subsequent-failure backoff.
- **Rev 4 (`F360-P0-AUTH-SPEC-REV4`):** Introduced `app/server.py` launcher + `PROXY_HEADERS_ENABLED` / `TRUSTED_PROXY_IPS` settings and Google OIDC `GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES` allowlist (`[]` default).
- **Rev 5 (`F360-P0-AUTH-SPEC-REV5` — This Document):** Narrowly scoped security correction closing the Rev4 `create_verified_app` Uvicorn `--factory` and programmatic `uvicorn.Config` verification-stamp bypass (Modified Sections: §2, §5, §6, §16.3, §17.3, §19.1, §20, §22, §23):
  1. **Eliminated Factory-Level Self-Stamping (`create_verified_app` Removed):** Removed `create_verified_app()`. The sole application factory `create_app()` in [app/main.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/main.py) **never** issues a proxy verification stamp because a factory cannot inspect the enclosing `uvicorn.Config` or outer `ProxyHeadersMiddleware`.
  2. **Explicit Separation of Three Verification Concepts (§19.1):** Separated (a) validation of the application's configured proxy policy (`validate_proxy_policy`), (b) validation of the effective `uvicorn.Config` (`validate_effective_uvicorn_config`), and (c) verification of the post-load outer ASGI middleware wrapper (`verify_loaded_asgi_middleware`).
  3. **Post-Load `VerifiedUvicornConfig` & Unforgeable Process-Local Registry Binding (§19.1):** Introduced `VerifiedUvicornConfig(uvicorn.Config)` in `app/server.py`. Verification runs inside `VerifiedUvicornConfig.load()` **after** `super().load()` constructs `self.loaded_app` (both in single-worker mode and inside every spawned worker process in multi-worker `Multiprocess` mode), registering a weakref-backed `_VerifiedBindingRecord` in a module-private registry `_VERIFIED_APP_REGISTRY[id(fastapi_app)]`.
  4. **Live Re-Verification in Production `lifespan` (§19.1):** During `lifespan(app)` startup in `ENVIRONMENT == "production"`, `verify_production_asgi_trust_boundary(app, settings)` looks up `_VERIFIED_APP_REGISTRY[id(app)]`, dereferences the live `VerifiedUvicornConfig` and `config.loaded_app` weakrefs, and re-runs all three checks — failing closed (`RuntimeError` -> `LifespanOn` `startup_failed` -> `Server.startup()` `sys.exit(STARTUP_FAILURE)`) on any raw `uvicorn` CLI call, raw `uvicorn.Config(...)` call, post-load config mutation, or multi-worker mismatch.
  5. **Expanded Regression Test Suite (§20.4):** Added 14 explicit regression tests with full Setup, Action, Expected Result, and Protected Security Property specifications.

---

## 2. Existing Backend & Installed Uvicorn Inspection Findings

Direct read-only inspection of the repository at commit `206970f5923bd19d445cce905e6bbaf0b5c697ff` and the installed `uvicorn==0.54.0` package in `venv` confirms the following baseline contracts:

| Component | Inspected File | Key Findings & Stage 3 Impact |
| :--- | :--- | :--- |
| Application factory, CORS & lifespan | [app/main.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/main.py) | `create_app(settings=None)` is import-safe; module-level `app = create_app()` requires no DB or auth secrets at import time. Lifespan runs `settings.validate_runtime_requirements()`, initializes synchronous engine, `NullPool` readiness engine, `sessionmaker`, and readiness `BoundedSemaphore`. `CORSMiddleware` configures `allow_origins=settings.CORS_ORIGINS` and `allow_credentials=True` (lines 111–118). Stage 3A mounts `auth.router`, attaches `app.state.rate_limiter`, and invokes `verify_production_asgi_trust_boundary(app, settings)` inside `lifespan` when `settings.ENVIRONMENT == "production"`. `create_app()` **never** issues a proxy verification stamp. |
| Configuration | [app/core/config.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/core/config.py) | `Settings(BaseSettings)` uses `UPPER_SNAKE_CASE`, `SecretStr`, `hide_input_in_errors=True`, and `ENVIRONMENT: Literal["development", "testing", "production"]`. `Settings()` remains constructible with zero auth env vars in dev/test; production checks run in `validate_runtime_requirements()`. |
| Exception handling | [app/core/exceptions.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/core/exceptions.py) | Defines `AppException`, `ResourceNotFoundError`, `ValidationAppError`, and `{"error": {"message", "status_code", "details"}}`. Stage 3A adds: (1) custom `RequestValidationError` handler stripping Pydantic v2's `input` key; (2) optional `headers: Optional[dict[str, str]] = None` on `AppException`; (3) error codes placed strictly under `details["code"]` so `SENSITIVE_KEY_SUBSTRINGS` (`"auth"`, `"token"`, etc.) never redact them. |
| Security logging | [app/core/logging.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/core/logging.py) | `SecurityFilter`, `SecurityFormatter`, and `sanitize_log_text()` redact credentials, DB URIs, and heuristic SQL. Extend for `api_key`, `code_verifier`, `pkce_verifier`, `pkce_verifier_encrypted`, `oauth_pkce_encryption_key`, `id_token`, `cookie`, `set-cookie`, `exchange_code`, `oauth_code`, `new_password`, `current_password`, and Resend keys `\bre_[A-Za-z0-9_]{16,}\b`. |
| Database base, session & `users` | [app/db/base.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/db/base.py), [app/db/session.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/db/session.py), [app/models/user.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/models/user.py), [alembic/versions/0001_create_users.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/alembic/versions/0001_create_users.py) | Synchronous SQLAlchemy 2.x with `psycopg` v3, deterministic constraint naming (`pk_`, `uq_`, `ck_`, `ix_`, `fk_`), `TimestampMixin`, synchronous `get_db()`, and baseline `users` table (`id`, `email`, `is_active`, `created_at`, `updated_at` + 3 email `CHECK` constraints). |
| Installed Uvicorn (`0.54.0`) internals | [uvicorn/__init__.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/__init__.py), [uvicorn/main.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/main.py), [uvicorn/config.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/config.py), [uvicorn/middleware/proxy_headers.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/middleware/proxy_headers.py), [uvicorn/lifespan/on.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/lifespan/on.py), [uvicorn/server.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/server.py), [uvicorn/_subprocess.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/_subprocess.py), [uvicorn/supervisors/multiprocess.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/supervisors/multiprocess.py) | Direct source inspection of `uvicorn==0.54.0` confirms: (1) `Config.load()` invokes the app factory (lines 511–524) **before** wrapping `self.loaded_app = ProxyHeadersMiddleware(self.loaded_app, trusted_hosts=self.forwarded_allow_ips)` (lines 543–544), proving a factory cannot inspect the outer middleware at factory-call time; (2) in multi-worker mode (`config.workers > 1`), `Multiprocess` pickles `config: Config` across `spawn.Process` (`_subprocess.py` lines 18, 44–51) and each child worker calls `Server._serve()` -> `config.load()` -> `self.lifespan.startup()` inside the worker process (`server.py` lines 95–118); (3) when a worker's `lifespan` fails (`sys.exit(STARTUP_FAILURE)` where `STARTUP_FAILURE == 3`), `Multiprocess.keep_subprocess_alive()` (lines 225–231) detects `process.exitcode == STARTUP_FAILURE` and immediately terminates the parent supervisor (`self.should_exit.set()`). |
| Pinned dependencies | [requirements.in](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/requirements.in), [requirements.txt](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/requirements.txt) | **Zero new Python dependencies required:** `argon2-cffi==25.1.0`, `PyJWT==2.15.1`, `cryptography==50.0.2` (`AESGCM`), `httpx==0.28.1`, `resend==2.53.2`, `email-validator==2.4.0`, `fastapi==0.163.1`, `pydantic==2.14.3`, `SQLAlchemy==2.0.38`, `psycopg==3.3.9`, `alembic==1.20.1`, `uvicorn==0.54.0`, `pytest==9.2.0`, `pytest-mock==3.17.0`. |

---

## 3. Mandatory Product Requirements

1. **Dual-Client Support:** First-class support for web (React/Vite) and native mobile (React Native / Expo) clients without introducing Redis or separate auth microservices.
2. **Synchronous Architecture Preservation:** Synchronous SQLAlchemy 2.x (`psycopg` v3) and synchronous FastAPI route functions (`def`) executed in Starlette's worker threadpool. No async SQLAlchemy.
3. **Email/Password Registration & Mandatory Verification:** Registration with email + password, Resend verification email, and mandatory email verification before password login succeeds.
4. **Short-Lived Access JWTs + Rotating Opaque Refresh Sessions:** 15-minute access JWTs paired with PostgreSQL-backed single-use rotating refresh tokens (14-day rolling TTL, 30-day absolute family cap) with family-wide replay revocation.
5. **Immediate Global Access-Token Invalidation:** Integer `users.auth_version` matched against JWT `"ver"` claim in `get_current_user` (zero timestamp-precision race window).
6. **Password Recovery & Atomic Password Change:** Forgot-password / reset-password via Resend + deadlock-free atomic authenticated password change.
7. **Social Login (Google OIDC & GitHub OAuth 2.0):** Server-driven Authorization Code + PKCE (`S256`) using pinned `httpx`, `PyJWT[crypto]`, and `cryptography` (`AESGCM` for PKCE verifier encryption at rest), returning a 60-second single-use `oauth_exchange_code` (never tokens in redirect URLs).
8. **Deployment-Aware Web Cookie Policy:** Explicitly supports development, same-site production, and cross-site production without assuming a hosting provider, leaving Expo mobile JSON transport unchanged.
9. **Backward Compatibility:** Preserves all Stage 1 and Stage 2 routes, lifespan/readiness contracts, and all 81 existing tests with zero regressions.

---

## 4. Approved Q1–Q11 Decisions (Binding)

| ID | Topic | Binding Decision |
| :--- | :--- | :--- |
| **Q1** | GitHub email policy | **Option A:** Require a **verified, syntactically valid, non-noreply email suitable for registration** (retrieved across all paginated `/user/emails` pages) for **new** GitHub OAuth accounts. Reject `@users.noreply.github.com` (and subdomains) with `verified_email_required`. Existing linked GitHub users authenticate by `(github, provider_user_id)` even if their GitHub email changes or disappears. |
| **Q2** | Account linking & auto-merge | **Option A:** Never auto-merge OAuth sign-ins into an existing `users` row solely by email equality; reject with `email_already_registered`. Explicit authenticated account-linking endpoints are deferred; `oauth_accounts` supports future multi-provider links. |
| **Q3** | Email verification HTTP method | **Option A:** `POST /api/v1/auth/verify-email` with JSON `{"token": "..."}`. Emails link to `{FRONTEND_BASE_URL}/verify-email?token=...`; frontend captures, scrubs URL, and submits `POST`. |
| **Q4** | Token storage & hashing | **Option A:** Random opaque tokens (`secrets.token_urlsafe(32)`) stored exclusively as lowercase hex SHA-256 (`CHAR(64)`) in PostgreSQL for email verification (24h), password reset (30m), refresh sessions, and OAuth exchange codes (60s). Single-use + explicit revocation. Argon2id exclusively for passwords. |
| **Q5** | Refresh token rotation & replay | **Option A:** Single-use rotation grouped by `family_id`, serialized via `SELECT ... FOR UPDATE`. Replay of a rotated token revokes the affected `family_id` (unrelated families untouched). 14-day rolling TTL, 30-day absolute `family_expires_at` cap. Clients implement single-flight refresh deduplication. |
| **Q6** | Web vs. mobile token transport | **Option A:** `X-Client-Type: web \| mobile`. **Web:** HttpOnly refresh cookie (deployment-aware `SameSite`/`Secure` per §12.3) + in-memory access JWT (never `localStorage`) + CSRF `X-Client-Type: web` and strict `Origin` allowlist checks. **Mobile:** access + refresh tokens in JSON stored in Expo `SecureStore`, zero cookies. |
| **Q7** | OAuth token handoff to client | **Option A:** Backend callback redirects to allowlisted client URI with safely appended 60-second single-use `code=<oauth_exchange_code>` (never auth tokens in redirect URLs), exchanged via `POST /api/v1/auth/oauth/exchange`. |
| **Q8** | OAuth & JWT library choice | **Option A:** Direct implementation with pinned `httpx`, `PyJWT[crypto]`, and `cryptography`. No `Authlib` or `itsdangerous`. |
| **Q9** | Rate limiting & email cooldown | **Option A:** Process-local thread-safe sliding-window IP rate limiter (consuming Uvicorn-normalized ASGI client IP verified via §19.1) + PostgreSQL-backed per-account email cooldowns (`>= 60s` between `'sent'`, `<= 3/hr`). No Redis. |
| **Q10** | Password reset & change sessions | **Option A:** Password reset atomically revokes **all** refresh sessions and increments `users.auth_version`. Password change atomically verifies `current_password` on the locked `users` row, rejects OAuth-only accounts (`400 PASSWORD_NOT_SET`), revokes old sessions, increments `users.auth_version`, and issues one fresh session + access JWT for the current client. |
| **Q11** | Enumeration policy & session UI | Duplicate `POST /register` returns `409 EMAIL_ALREADY_REGISTERED`. `POST /forgot-password` and `POST /resend-verification` always return generic `202 Accepted`. Defer `GET /sessions` and `DELETE /sessions/{session_id}`; retain `POST /logout-all`. |

---

## 5. Final Authentication Architecture

```mermaid
flowchart TD
    Web["Web Client (React/Vite)\nAccess JWT in Memory\nHttpOnly Refresh Cookie (Deployment-Aware SameSite/Secure)"]
    Mobile["Mobile Client (React Native/Expo)\nAccess JWT + Refresh Token in Expo SecureStore"]

    subgraph ASGI["Authoritative Launcher & ASGI Boundary (app/server.py + VerifiedUvicornConfig)"]
        ServerPy["app/server.py (VerifiedUvicornConfig / build_uvicorn_config / run_server)\n1. Validates Settings proxy policy & ambient env\n2. Validates effective Config (proxy_headers & forwarded_allow_ips)\n3. After super().load(), verifies outer ProxyHeadersMiddleware on loaded_app\n4. Registers weakref binding in module-private _VERIFIED_APP_REGISTRY"]
        ProxyMW["Uvicorn ProxyHeadersMiddleware\n(Verified post-load inside every worker process)"]
    end

    subgraph API["FastAPI Application (Synchronous Route Handlers in Threadpool)"]
        Lifespan["app/main.py (lifespan)\nCalls verify_production_asgi_trust_boundary(app, settings)\nDereferences live Config & loaded_app weakrefs in _VERIFIED_APP_REGISTRY\nFails closed on raw uvicorn CLI, raw Config, or post-load tampering"]
        Router["app/api/routes/auth.py\n(/api/v1/auth/*)"]
        Deps["app/api/deps/auth.py\n(get_current_user, require_client_type, verify_web_origin, resolve_client_ip)"]
        Limiter["app/core/rate_limit.py\n(Process-Local Thread-Safe Sliding Window)"]
        Services["app/services/\n(auth_service, email_service, oauth_service, oauth_providers)"]
        Security["app/core/security.py\n(Argon2id, SHA-256, PyJWT HS256/RS256, PKCE S256, AES-256-GCM)"]
    end

    subgraph External["External Services (Always Outside DB Transactions)"]
        Resend["Resend REST API\n(Verification & Reset Emails)"]
        Google["Google OIDC\n(Token + JWKS Certs)"]
        GitHub["GitHub OAuth + API\n(/user + paginated /user/emails)"]
    end

    PG[("PostgreSQL 17\nusers, refresh_sessions,\nemail_verification_tokens,\npassword_reset_tokens,\noauth_accounts, oauth_states,\noauth_exchange_codes")]

    ServerPy --> ProxyMW
    ServerPy --> Lifespan
    Web -->|"HTTPS + X-Client-Type: web + Origin"| ProxyMW
    Mobile -->|"HTTPS + X-Client-Type: mobile"| ProxyMW
    ProxyMW -->|"Normalized scope['client'] & scope['scheme']"| Router
    Router --> Limiter
    Router --> Deps
    Router --> Services
    Deps --> Security
    Deps --> PG
    Services --> Security
    Services -->|"Synchronous SQLAlchemy 2.x\n(psycopg v3)"| PG
    Services -->|"Post-commit HTTP calls"| Resend
    Services -->|"httpx (strict timeouts)"| Google
    Services -->|"httpx (strict timeouts, bounded pagination)"| GitHub
```

### Core Architectural Invariants
1. **Unforgeable Post-Load Uvicorn Proxy Verification:** `create_app()` in [app/main.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/main.py) **never** stamps or certifies Uvicorn proxy state. Only `VerifiedUvicornConfig.load()` in `app/server.py` — running **after** `super().load()` has constructed the outer `config.loaded_app` inside the serving worker process — can verify all three layers (policy, effective `Config`, and outer `ProxyHeadersMiddleware`) and register the instance in `_VERIFIED_APP_REGISTRY`. In production, `lifespan(app)` live-verifies that registry binding before accepting requests (§19.1).
2. **Strict DB-Transaction / External-Network Separation:** Resend, Google, and GitHub HTTP calls **never** execute inside an open PostgreSQL transaction or while holding `SELECT ... FOR UPDATE` locks.
3. **Threadpool Execution:** All routes in `app/api/routes/auth.py` are synchronous `def` handlers so synchronous SQLAlchemy, Argon2id, and `httpx`/Resend I/O run in Starlette's worker threadpool without blocking the asyncio event loop.
4. **PostgreSQL as Single Source of Security Truth:** Refresh rotation, replay detection, token single-use, email cooldowns, OAuth state/exchange-code consumption, and `auth_version` invalidation are all enforced atomically in PostgreSQL.

---

## 6. Module Responsibilities and Proposed Folder Structure

```text
app/
├── main.py                          # [Modified 3A] create_app() (never self-stamps!), mount auth.router, call verify_production_asgi_trust_boundary in lifespan
├── server.py                        # [3A] VerifiedUvicornConfig, build_uvicorn_config, run_server, _VERIFIED_APP_REGISTRY, & 3-layer proxy verifier
├── api/
│   ├── deps/
│   │   ├── __init__.py
│   │   └── auth.py                  # [3A] get_current_user, require_client_type, verify_web_origin, resolve_client_ip, rate-limit deps
│   └── routes/
│       ├── health.py                # [Existing Stage 1/2 — unchanged]
│       └── auth.py                  # [3A, extended in 3B & 3C] /api/v1/auth/* synchronous endpoints
├── core/
│   ├── config.py                    # [Modified 3A, 3B, 3C] Auth, JWT, proxy policy, deployment-aware cookies, Resend, OAuth settings
│   ├── exceptions.py                # [Modified 3A] RequestValidationError input stripper, headers support, auth error classes
│   ├── logging.py                   # [Modified 3A, 3C] Extended secret/token/cookie/Resend/PKCE redaction patterns
│   ├── rate_limit.py                # [3A] Thread-safe in-memory sliding-window IP limiter
│   └── security.py                  # [3A, extended in 3C] Argon2id + dummy hash, SHA-256 tokens, PyJWT HS256, PKCE S256, AES-256-GCM
├── models/
│   ├── __init__.py                  # [Modified 3A, 3B, 3C] Export all ORM models for Alembic metadata
│   ├── user.py                      # [Modified 3A] Additive auth columns + constraints
│   ├── refresh_session.py           # [3A] RefreshSession ORM model
│   ├── email_verification_token.py  # [3A] EmailVerificationToken ORM model
│   ├── password_reset_token.py      # [3B] PasswordResetToken ORM model
│   └── oauth.py                     # [3C] OAuthAccount, OAuthState, OAuthExchangeCode ORM models
├── schemas/
│   ├── __init__.py
│   ├── auth.py                      # [3A, extended in 3B] Pydantic v2 request/response schemas
│   └── oauth.py                     # [3C] OAuth exchange schemas & provider identity DTOs
└── services/
    ├── __init__.py
    ├── auth_service.py              # [3A, extended in 3B] Core auth, sessions, atomic password reset & change, resend cooldown logic
    ├── email_service.py             # [3A, extended in 3B] Resend wrapper + templates + sanitized result
    ├── oauth_providers.py           # [3C] Google OIDC (JWKS + trusted-audience/azp validation) & GitHub OAuth (/user + paginated /user/emails)
    └── oauth_service.py             # [3C] Encrypted PKCE state, binding cookie, safe redirect builder, atomic provisioning, exchange code
```

---

## 7. Database Schema and Relationships

```mermaid
erDiagram
    users ||--o{ refresh_sessions : "owns"
    users ||--o{ email_verification_tokens : "receives"
    users ||--o{ password_reset_tokens : "requests"
    users ||--o{ oauth_accounts : "links"
    users ||--o{ oauth_exchange_codes : "receives"
    refresh_sessions ||--o| refresh_sessions : "parent_session_id"
    refresh_sessions ||--o| refresh_sessions : "replaced_by_session_id"

    users {
        uuid id PK
        varchar_320 email UK
        varchar_255 password_hash
        boolean is_active
        boolean is_email_verified
        timestamptz email_verified_at
        integer auth_version
        timestamptz password_changed_at
        timestamptz created_at
        timestamptz updated_at
    }

    refresh_sessions {
        uuid id PK
        uuid user_id FK
        uuid family_id
        char_64 token_hash UK
        uuid parent_session_id FK
        uuid replaced_by_session_id FK
        varchar_16 client_type
        varchar_512 user_agent
        varchar_45 ip_address
        timestamptz expires_at
        timestamptz family_expires_at
        timestamptz last_used_at
        timestamptz revoked_at
        varchar_64 revoke_reason
        timestamptz created_at
        timestamptz updated_at
    }

    email_verification_tokens {
        uuid id PK
        uuid user_id FK
        char_64 token_hash UK
        varchar_16 delivery_status
        timestamptz delivery_attempted_at
        timestamptz expires_at
        timestamptz consumed_at
        timestamptz revoked_at
        timestamptz created_at
        timestamptz updated_at
    }

    password_reset_tokens {
        uuid id PK
        uuid user_id FK
        char_64 token_hash UK
        varchar_16 delivery_status
        timestamptz delivery_attempted_at
        varchar_45 requested_ip
        timestamptz expires_at
        timestamptz consumed_at
        timestamptz revoked_at
        timestamptz created_at
        timestamptz updated_at
    }

    oauth_accounts {
        uuid id PK
        uuid user_id FK
        varchar_32 provider
        varchar_255 provider_user_id
        varchar_320 provider_email
        boolean provider_email_verified
        timestamptz created_at
        timestamptz updated_at
    }

    oauth_states {
        uuid id PK
        char_64 state_hash UK
        varchar_32 provider
        varchar_16 client_type
        varchar_512 pkce_verifier_encrypted
        varchar_128 nonce
        varchar_512 redirect_uri
        char_64 client_binding_hash
        timestamptz expires_at
        timestamptz consumed_at
        timestamptz created_at
        timestamptz updated_at
    }

    oauth_exchange_codes {
        uuid id PK
        uuid user_id FK
        char_64 code_hash UK
        varchar_16 client_type
        timestamptz expires_at
        timestamptz consumed_at
        timestamptz created_at
        timestamptz updated_at
    }
```

### Detailed Table & Constraint Specifications

All tables inherit `TimestampMixin` (`created_at`, `updated_at`) and use `Base`'s deterministic naming conventions (`pk_`, `uq_`, `ck_`, `ix_`, `fk_`).

#### 7.1 `users` (Extended in Stage 3A)
- **Existing (`0001_create_users`):** `id` (`UUID`, PK), `email` (`VARCHAR(320)`, `NOT NULL`, `UNIQUE`), `is_active` (`BOOLEAN`, `NOT NULL`, `server_default=true`), `created_at`, `updated_at`, plus `ck_users_email_lowercase_trimmed`, `ck_users_email_not_empty`, `ck_users_email_no_whitespace`.
- **Added (`0002_add_core_auth_tables`):**
  - `password_hash`: `VARCHAR(255)`, `NULL` (Argon2id hash; `NULL` for OAuth-only users).
  - `is_email_verified`: `BOOLEAN`, `NOT NULL`, `server_default=false`.
  - `email_verified_at`: `TIMESTAMPTZ`, `NULL`.
  - `auth_version`: `INTEGER`, `NOT NULL`, `server_default=0` (matched against JWT `"ver"` claim).
  - `password_changed_at`: `TIMESTAMPTZ`, `NULL` (audit timestamp only).
- **New Constraints:**
  - `ck_users_email_verified_at_consistency`: `(is_email_verified = false AND email_verified_at IS NULL) OR (is_email_verified = true AND email_verified_at IS NOT NULL)`
  - `ck_users_auth_version_non_negative`: `auth_version >= 0`

#### 7.2 `email_verification_tokens` (Stage 3A)
- Columns: `id` (`UUID`, PK), `user_id` (`UUID`, `NOT NULL`, `FK -> users.id ON DELETE CASCADE`), `token_hash` (`CHAR(64)`, `NOT NULL`, `UNIQUE`), `delivery_status` (`VARCHAR(16)`, `NOT NULL`, `server_default='pending'`), `delivery_attempted_at` (`TIMESTAMPTZ`, `NULL`), `expires_at` (`TIMESTAMPTZ`, `NOT NULL`), `consumed_at` (`TIMESTAMPTZ`, `NULL`), `revoked_at` (`TIMESTAMPTZ`, `NULL`), `created_at`, `updated_at`.
- Constraints: `ck_email_verification_tokens_delivery_status` (`delivery_status IN ('pending', 'sent', 'failed')`), `ck_email_verification_tokens_hash_hex` (`token_hash ~ '^[0-9a-f]{64}$'`), `ck_email_verification_tokens_not_both_consumed_revoked` (`NOT (consumed_at IS NOT NULL AND revoked_at IS NOT NULL)`).
- Indexes: `ix_email_verification_tokens_user_created` on `(user_id, created_at DESC)`; `ix_email_verification_tokens_expires_at` on `(expires_at)`.

#### 7.3 `refresh_sessions` (Stage 3A)
- Columns: `id` (`UUID`, PK), `user_id` (`UUID`, `NOT NULL`, `FK -> users.id ON DELETE CASCADE`), `family_id` (`UUID`, `NOT NULL`), `token_hash` (`CHAR(64)`, `NOT NULL`, `UNIQUE`), `parent_session_id` (`UUID`, `NULL`, `FK -> refresh_sessions.id ON DELETE SET NULL`), `replaced_by_session_id` (`UUID`, `NULL`, `FK -> refresh_sessions.id ON DELETE SET NULL`), `client_type` (`VARCHAR(16)`, `NOT NULL`), `user_agent` (`VARCHAR(512)`, `NULL`), `ip_address` (`VARCHAR(45)`, `NULL`), `expires_at` (`TIMESTAMPTZ`, `NOT NULL`), `family_expires_at` (`TIMESTAMPTZ`, `NOT NULL`), `last_used_at` (`TIMESTAMPTZ`, `NULL`), `revoked_at` (`TIMESTAMPTZ`, `NULL`), `revoke_reason` (`VARCHAR(64)`, `NULL`), `created_at`, `updated_at`.
- Constraints: `ck_refresh_sessions_client_type` (`client_type IN ('web', 'mobile')`), `ck_refresh_sessions_hash_hex` (`token_hash ~ '^[0-9a-f]{64}$'`), `ck_refresh_sessions_expiry_bounds` (`expires_at <= family_expires_at`), `ck_refresh_sessions_revoke_reason_consistency` (`(revoked_at IS NULL AND revoke_reason IS NULL) OR (revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)`).
- Indexes: `ix_refresh_sessions_user_active` on `(user_id, revoked_at)`; `ix_refresh_sessions_family_id` on `(family_id)`; `ix_refresh_sessions_expires_at` on `(expires_at)`.

#### 7.4 `password_reset_tokens` (Stage 3B)
- Columns: `id` (`UUID`, PK), `user_id` (`UUID`, `NOT NULL`, `FK -> users.id ON DELETE CASCADE`), `token_hash` (`CHAR(64)`, `NOT NULL`, `UNIQUE`), `delivery_status` (`VARCHAR(16)`, `NOT NULL`, `server_default='pending'`), `delivery_attempted_at` (`TIMESTAMPTZ`, `NULL`), `requested_ip` (`VARCHAR(45)`, `NULL`), `expires_at` (`TIMESTAMPTZ`, `NOT NULL`), `consumed_at` (`TIMESTAMPTZ`, `NULL`), `revoked_at` (`TIMESTAMPTZ`, `NULL`), `created_at`, `updated_at`.
- Constraints: `ck_password_reset_tokens_delivery_status` (`delivery_status IN ('pending', 'sent', 'failed')`), `ck_password_reset_tokens_hash_hex` (`token_hash ~ '^[0-9a-f]{64}$'`), `ck_password_reset_tokens_not_both_consumed_revoked` (`NOT (consumed_at IS NOT NULL AND revoked_at IS NOT NULL)`).
- Indexes: `ix_password_reset_tokens_user_created` on `(user_id, created_at DESC)`; `ix_password_reset_tokens_expires_at` on `(expires_at)`.

#### 7.5 `oauth_accounts` (Stage 3C)
- Columns: `id` (`UUID`, PK), `user_id` (`UUID`, `NOT NULL`, `FK -> users.id ON DELETE CASCADE`), `provider` (`VARCHAR(32)`, `NOT NULL`), `provider_user_id` (`VARCHAR(255)`, `NOT NULL`), `provider_email` (`VARCHAR(320)`, `NULL`), `provider_email_verified` (`BOOLEAN`, `NOT NULL`, `server_default=false`), `created_at`, `updated_at`.
- Constraints: `uq_oauth_accounts_provider_subject` (`UNIQUE (provider, provider_user_id)`), `uq_oauth_accounts_user_provider` (`UNIQUE (user_id, provider)`), `ck_oauth_accounts_provider` (`provider IN ('google', 'github')`), `ck_oauth_accounts_provider_user_id_not_empty`.
- Index: `ix_oauth_accounts_user_id` on `(user_id)`.

#### 7.6 `oauth_states` (Stage 3C)
- Columns: `id` (`UUID`, PK), `state_hash` (`CHAR(64)`, `NOT NULL`, `UNIQUE`), `provider` (`VARCHAR(32)`, `NOT NULL`), `client_type` (`VARCHAR(16)`, `NOT NULL`), `pkce_verifier_encrypted` (`VARCHAR(512)`, `NOT NULL` — AES-256-GCM ciphertext per §17.1; scrubbed to `'[CONSUMED]'` on use), `nonce` (`VARCHAR(128)`, `NULL`), `redirect_uri` (`VARCHAR(512)`, `NOT NULL`), `client_binding_hash` (`CHAR(64)`, `NULL` — SHA-256 hex of **`folio360_oauth_binding`** cookie value; raw value never stored), `expires_at` (`TIMESTAMPTZ`, `NOT NULL` — 10 minutes), `consumed_at` (`TIMESTAMPTZ`, `NULL`), `created_at`, `updated_at`.
- Constraints: `ck_oauth_states_provider`, `ck_oauth_states_client_type`, `ck_oauth_states_state_hash_hex`, `ck_oauth_states_client_binding_hash_hex`, `ck_oauth_states_google_nonce`, `ck_oauth_states_pkce_not_empty`.
- Index: `ix_oauth_states_expires_at` on `(expires_at)`.

#### 7.7 `oauth_exchange_codes` (Stage 3C)
- Columns: `id` (`UUID`, PK), `user_id` (`UUID`, `NOT NULL`, `FK -> users.id ON DELETE CASCADE`), `code_hash` (`CHAR(64)`, `NOT NULL`, `UNIQUE`), `client_type` (`VARCHAR(16)`, `NOT NULL`), `expires_at` (`TIMESTAMPTZ`, `NOT NULL` — 60 seconds), `consumed_at` (`TIMESTAMPTZ`, `NULL`), `created_at`, `updated_at`.
- Constraints: `ck_oauth_exchange_codes_client_type`, `ck_oauth_exchange_codes_hash_hex`.
- Indexes: `ix_oauth_exchange_codes_user_id`, `ix_oauth_exchange_codes_expires_at`.

---

## 8. Migration Plan (Separated by Stage: 3A, 3B, 3C)

```text
0001_create_users (Stage 2 baseline — immutable)
  └── 0002_add_core_auth_tables (Stage 3A)
        └── 0003_add_password_reset_tokens (Stage 3B)
              └── 0004_add_oauth_tables (Stage 3C)
```

| Stage | Revision ID & Filename | Down Revision | Upgrade Scope | Downgrade Scope |
| :--- | :--- | :--- | :--- | :--- |
| **3A** | `0002_add_core_auth_tables` (`alembic/versions/0002_add_core_auth_tables.py`) | `0001_create_users` | `ALTER TABLE users` (5 columns + 2 CHECK constraints); `CREATE TABLE email_verification_tokens`; `CREATE TABLE refresh_sessions` | `DROP TABLE refresh_sessions`, `email_verification_tokens`; drop 2 constraints & 5 columns on `users` |
| **3B** | `0003_add_password_reset_tokens` (`alembic/versions/0003_add_password_reset_tokens.py`) | `0002_add_core_auth_tables` | `CREATE TABLE password_reset_tokens` | `DROP TABLE password_reset_tokens` |
| **3C** | `0004_add_oauth_tables` (`alembic/versions/0004_add_oauth_tables.py`) | `0003_add_password_reset_tokens` | `CREATE TABLE oauth_accounts`, `oauth_states` (`pkce_verifier_encrypted`), `oauth_exchange_codes` | `DROP TABLE oauth_exchange_codes`, `oauth_states`, `oauth_accounts` |

### Mandatory Migration Verification Rules (Every Stage)
1. Clean DB `alembic upgrade head` from empty `base`.
2. Upgrade from populated Stage 2 `0001_create_users` baseline (`is_email_verified=False`, `email_verified_at=None`, `auth_version=0`, `password_hash=None` via `server_default`).
3. Round-trip reversibility: `upgrade head -> downgrade <parent_rev> -> upgrade head`.
4. `alembic check` returns exit code `0`.
5. Least-privilege `folio360_app` DML permissions verified on all new tables created by `folio360_migrator`.

---

## 9. Complete API Contract

All endpoints live under `API_V1_PREFIX` (`/api/v1`) and preserve the Stage 1 error envelope:

```json
{
  "error": {
    "message": "Human-readable safe public message",
    "status_code": 401,
    "details": {
      "code": "INVALID_CREDENTIALS"
    }
  }
}
```

### 9.1 Endpoint Matrix

| Stage | Method & Path | Auth | Required Headers / Params | Success Status |
| :--- | :--- | :--- | :--- | :--- |
| 3A | `POST /api/v1/auth/register` | Public | — | `201 Created` |
| 3A | `POST /api/v1/auth/verify-email` | Public | — | `200 OK` |
| 3A | `POST /api/v1/auth/resend-verification` | Public | — | `202 Accepted` |
| 3A | `POST /api/v1/auth/login` | Public | `X-Client-Type: web \| mobile` | `200 OK` |
| 3A | `POST /api/v1/auth/refresh` | Refresh token (cookie/body) | `X-Client-Type` (+ `Origin` on web) | `200 OK` |
| 3A | `POST /api/v1/auth/logout` | Refresh token (cookie/body) | `X-Client-Type` (+ `Origin` on web) | `200 OK` |
| 3A | `POST /api/v1/auth/logout-all` | Bearer Access JWT | `Authorization: Bearer <jwt>` (+ `Origin` if `X-Client-Type: web`) | `200 OK` |
| 3A | `GET /api/v1/auth/me` | Bearer Access JWT | `Authorization: Bearer <jwt>` | `200 OK` |
| 3B | `POST /api/v1/auth/forgot-password` | Public | — | `202 Accepted` |
| 3B | `POST /api/v1/auth/reset-password` | Public | — | `200 OK` |
| 3B | `POST /api/v1/auth/change-password` | Bearer Access JWT | `Authorization`, `X-Client-Type` (+ `Origin` on web) | `200 OK` |
| 3C | `GET /api/v1/auth/oauth/{provider}/start` | Public | Query: `client_type`, `redirect_uri` | `302 Found` |
| 3C | `GET /api/v1/auth/oauth/{provider}/callback` | Provider redirect | Query: `code`, `state` (or `error`) | `302 Found` |
| 3C | `POST /api/v1/auth/oauth/exchange` | Public (exchange code) | `X-Client-Type` (+ `Origin` on web) | `200 OK` |

### 9.2 Stable Machine-Readable Error Code Catalog (`error.details.code`)

| HTTP Status | `error.details.code` | Meaning / Trigger |
| :--- | :--- | :--- |
| `400` | `INVALID_CLIENT_TYPE` | Missing or invalid `X-Client-Type` header (`web` or `mobile`). |
| `400` | `INVALID_VERIFICATION_TOKEN` | Verification token invalid, expired, revoked, or already consumed. |
| `400` | `INVALID_RESET_TOKEN` | Password reset token invalid, expired, revoked, or already consumed. |
| `400` | `PASSWORD_NOT_SET` | `change-password` attempted on an OAuth-only account (`password_hash IS NULL`). |
| `400` | `SAME_PASSWORD_NOT_ALLOWED` | New password matches current password in `change-password`. |
| `400` | `INVALID_OAUTH_PROVIDER` | Provider path param is not `google` or `github`. |
| `400` | `INVALID_REDIRECT_URI` | `redirect_uri` not an exact match in configured allowlist for `client_type`. |
| `400` | `INVALID_OAUTH_EXCHANGE_CODE` | Exchange code unknown, expired, consumed, or `client_type` mismatch. |
| `401` | `INVALID_CREDENTIALS` | Wrong email/password on login, or wrong `current_password` on `change-password`. |
| `401` | `INVALID_ACCESS_TOKEN` | Missing/malformed/expired JWT, signature/iss/aud failure, `auth_version` mismatch, or unknown user (`WWW-Authenticate: Bearer`). |
| `401` | `INVALID_REFRESH_TOKEN` | Missing/unknown/expired/revoked refresh token, or `client_type` mismatch. |
| `401` | `REFRESH_TOKEN_REUSE_DETECTED` | Previously rotated refresh token replayed; entire session family revoked. |
| `403` | `EMAIL_NOT_VERIFIED` | Password login before email verification (checked only after valid password verification). |
| `403` | `ACCOUNT_INACTIVE` | User has `is_active = false`. |
| `403` | `CSRF_ORIGIN_MISMATCH` | Web cookie-bearing request failed strict `Origin` allowlist check. |
| `409` | `EMAIL_ALREADY_REGISTERED` | `POST /register` email already exists. |
| `422` | `VALIDATION_ERROR` | Pydantic validation failure (`input` stripped). |
| `429` | `RATE_LIMIT_EXCEEDED` | IP rate limit triggered (`Retry-After` header included). |
| `503` | `SERVICE_UNAVAILABLE` | Downstream dependency unavailable. |

> **OAuth Callback Error Redirect Query Codes** (appended safely via §17.2 as `error=<code>` on `redirect_uri`): `oauth_cancelled`, `invalid_oauth_state`, `oauth_provider_error`, `verified_email_required`, `email_already_registered`, `account_inactive`.

### 9.3 Detailed Endpoint Contracts

1. **`POST /api/v1/auth/register` (3A):** Request `{"email", "password"}` (email trimmed/lowercased, valid `EmailStr`, `<= 320` chars; password 12–128 chars, UTF-8 bytes `<= 128`, non-whitespace, `!= email`). Returns `201 Created` with `{"message", "user": {id, email, is_active, is_email_verified, has_password, created_at}, "verification_email_sent": true | false}`. Errors: `409 EMAIL_ALREADY_REGISTERED`, `422`, `429`.
2. **`POST /api/v1/auth/verify-email` (3A):** Request `{"token"}`. Locks `users` row then token row (`FOR UPDATE`), verifies active/unexpired and `user.is_active`, consumes token, sets `is_email_verified=True` and `email_verified_at=now()`, revokes other active verification tokens, commits. Returns `200 OK` `{"message": "Email verified successfully.", "email_verified": true}`. Does not auto-login.
3. **`POST /api/v1/auth/resend-verification` (3A):** Request `{"email"}`. Always returns `202 Accepted` `{"message": "If an unverified account exists for this email, a verification link has been sent."}` following the exact retry/cooldown rules in §11.
4. **`POST /api/v1/auth/login` (3A):** Header `X-Client-Type: web | mobile`; body `{"email", "password"}`. Always runs Argon2id verification (against dummy hash if missing / OAuth-only) before checking `is_email_verified` or `is_active`. Web sets `folio360_refresh_token` cookie (§12.3) and returns `{"access_token", "token_type": "bearer", "expires_in": 900, "user": {...}}`; mobile sets zero cookies and adds `"refresh_token"` and `"refresh_expires_in": 1209600`.
5. **`POST /api/v1/auth/refresh` (3A):** Header `X-Client-Type` (+ `Origin` on web). Web reads `folio360_refresh_token` cookie; mobile reads `{"refresh_token"}`. Serializes via `FOR UPDATE`, rotates session, revokes family on replay (`401 REFRESH_TOKEN_REUSE_DETECTED`, clears web cookie), returns same shape as `/login`.
6. **`POST /api/v1/auth/logout` (3A):** Header `X-Client-Type` (+ `Origin` on web). Idempotently revokes active session (`logout`), clears web cookie with matching attributes, returns `200 OK`.
7. **`POST /api/v1/auth/logout-all` (3A):** Bearer Access JWT (+ `Origin` if `X-Client-Type: web`). Locks `users` (`FOR UPDATE`), increments `auth_version += 1`, revokes all active refresh sessions (`logout_all`), commits, clears web cookie if web. Returns `200 OK`.
8. **`GET /api/v1/auth/me` (3A):** Bearer Access JWT. Returns `id`, `email`, `is_active`, `is_email_verified`, `has_password`, `created_at`, `updated_at` (plus `oauth_providers: list[str]` in 3C).
9. **`POST /api/v1/auth/forgot-password` (3B):** Body `{"email"}`. Always returns `202 Accepted`. Eligible only when `is_active=True`, `is_email_verified=True`, `password_hash IS NOT NULL`. Uses identical §11 delivery/retry state machine.
10. **`POST /api/v1/auth/reset-password` (3B):** Body `{"token", "new_password"}`. Atomic `users`-first locked transaction (§13.1). Returns `200 OK`.
11. **`POST /api/v1/auth/change-password` (3B):** Bearer Access JWT + `X-Client-Type` (+ `Origin` on web); body `{"current_password", "new_password"}`. Atomic `users`-first locked transaction (§13.2). Returns `200 OK` with `"message"` + fresh client-specific access JWT and refresh session.
12. **`GET /api/v1/auth/oauth/{provider}/start` (3C):** Query `client_type`, `redirect_uri`. `302 Found` to provider; sets **`folio360_oauth_binding`** cookie on `web`.
13. **`GET /api/v1/auth/oauth/{provider}/callback` (3C):** Validates state + **`folio360_oauth_binding`** (web), clears **`folio360_oauth_binding`**, exchanges code, provisions/resolves user, redirects `302 Found` with safely appended `code=...` or `error=...` (§17.2).
14. **`POST /api/v1/auth/oauth/exchange` (3C):** Header `X-Client-Type` (+ `Origin` on web); body `{"code"}`. Consumes 60s code atomically (`FOR UPDATE`), creates fresh `refresh_session`, returns same shape as `/login`.

---

## 10. Email Registration, Verification Flow, and Frontend Token Hygiene

```mermaid
sequenceDiagram
    participant Client as "Web / Mobile Client"
    participant API as "FastAPI (/api/v1/auth)"
    participant DB as "PostgreSQL 17"
    participant Resend as "Resend API"

    Client->>API: "POST /register {email, password}"
    API->>API: "Normalize email, validate password, Argon2id hash"
    API->>DB: "BEGIN: INSERT users + INSERT email_verification_tokens (delivery_status='pending') -> COMMIT"
    alt "UniqueViolation on users.email"
        DB-->>API: "IntegrityError (uq_users_email)"
        API-->>Client: "409 Conflict {code: EMAIL_ALREADY_REGISTERED}"
    else "Committed"
        API->>Resend: "Send verification email ({FRONTEND_BASE_URL}/verify-email?token=<raw>)"
        alt "Resend 2xx"
            API->>DB: "UPDATE token SET delivery_status='sent', delivery_attempted_at=now() -> COMMIT"
            API-->>Client: "201 Created {user, verification_email_sent: true}"
        else "Resend error / timeout"
            API->>DB: "UPDATE token SET delivery_status='failed', delivery_attempted_at=now() -> COMMIT"
            API-->>Client: "201 Created {user, verification_email_sent: false}"
        end
    end

    Note over Client,API: "Frontend /verify-email enforces Referrer-Policy: no-referrer, clears URL, submits POST"
    Client->>API: "POST /verify-email {token}"
    API->>DB: "BEGIN: lock user -> lock token -> consumed_at, is_email_verified=true -> COMMIT"
    API-->>Client: "200 OK {email_verified: true}"
```

### Mandatory Frontend Rules for Token-Bearing Pages (`/verify-email`, `/reset-password`, `/auth/oauth/callback`)
1. Serve with HTTP header `Referrer-Policy: no-referrer` (plus `<meta name="referrer" content="no-referrer">`).
2. Load **zero** third-party analytics, telemetry, session-replay, or advertising scripts on token-bearing pages.
3. Avoid unnecessary external subresources that could receive the URL through referrer leakage.
4. Never log token-bearing URLs in client telemetry or server/proxy access logs.
5. Capture `token` (or `code`) into JS memory on mount and immediately strip it from browser URL/history via `window.history.replaceState({}, document.title, window.location.pathname)`.
6. Consume tokens exclusively via the approved `POST` APIs (`/verify-email`, `/reset-password`, `/oauth/exchange`).

---

## 11. Resend Delivery-Failure, First-Retry, and Recovery Contract

### 11.1 Four Explicit Delivery States
1. **Pending delivery (in-flight):** `delivery_status = 'pending'` AND `created_at >= now() - EMAIL_PENDING_STALE_SECONDS` (`30s`).
2. **Stale pending delivery (crashed process):** `delivery_status = 'pending'` AND `created_at < now() - EMAIL_PENDING_STALE_SECONDS` (`30s`).
3. **Failed delivery:** `delivery_status = 'failed'` with `delivery_attempted_at` set.
4. **Successful delivery:** `delivery_status = 'sent'` with `delivery_attempted_at` set.

```mermaid
stateDiagram-v2
    [*] --> pending : "Tx 1 COMMIT (token inserted under users FOR UPDATE)"
    pending --> sent : "Resend 2xx -> Tx 2 UPDATE ('sent')"
    pending --> failed : "Resend error/timeout -> Tx 2 UPDATE ('failed')"
    pending --> stale_pending : "Process crash before Tx 2 (>30s)"
    sent --> [*] : "Resets failure streak to 0; enforces 60s gap & 3/hr cap"
    failed --> [*] : "1st failure -> 0s immediate retry; 2nd+ consecutive failure -> 10s backoff"
    stale_pending --> [*] : "Revoked on retry (>30s); allows fresh send"
```

### 11.2 End-to-End Retry Sequence & Transaction Boundaries
1. **Initial Delivery (`POST /register` or first `POST /forgot-password`):**
   - **Tx 1:** Insert `User` (on `/register`) + token (`delivery_status='pending'`) and commit.
   - **External Call (outside transaction):** Call Resend (`5.0s` timeout).
   - **Tx 2:** Update token to `'sent'` or `'failed'`, `delivery_attempted_at = now()`, commit.
   - `/register` returns `201 Created` with `verification_email_sent: true | false` (unverified account stays committed, never duplicated or rolled back). `/forgot-password` returns `202 Accepted`.
2. **Retry Evaluation (`POST /resend-verification` & subsequent `POST /forgot-password`):**
   - **Tx 1 (Serialized Under `users` Row Lock):**
     - Look up `User`; if missing or ineligible -> return `202 Accepted`.
     - `SELECT * FROM users WHERE id = :uid FOR UPDATE` (serializes concurrent resend requests).
     - Check in order:
       1. **In-Flight Pending Guard:** Latest non-revoked token has `delivery_status = 'pending'` and `created_at >= now() - 30s` -> suppress (`202`).
       2. **Successful-Send Limits:** `COUNT(*) WHERE delivery_status = 'sent' AND delivery_attempted_at > now() - 60 minutes >= 3` -> suppress (`202`); latest `'sent'` token has `delivery_attempted_at > now() - 60 seconds` -> suppress (`202`).
       3. **Consecutive-Failure Sequence:** Let `last_sent_at` be `created_at` of the latest `'sent'` token (or `-infinity` if none), and `consecutive_failures = COUNT(*) WHERE user_id = :uid AND delivery_status = 'failed' AND created_at > last_sent_at`:
          - `consecutive_failures == 0` (normal send or recovery from stale `'pending'` `> 30s`) -> **allowed immediately**.
          - `consecutive_failures == 1` (**First Retry After Known Initial Failure**) -> **allowed immediately (0s wait; no 10s delay)**.
          - `consecutive_failures >= 2` (**Subsequent Failed Retries**) -> require `latest_failed.delivery_attempted_at <= now() - 10 seconds` (`EMAIL_FAILED_RETRY_BACKOFF_SECONDS = 10`); otherwise suppress (`202`).
       4. Revoke prior unconsumed/unrevoked tokens for `user.id`, insert new `'pending'` token, **commit Tx 1** (releasing lock before network I/O).
   - **External Call (outside transaction):** Call Resend (`5.0s` timeout).
   - **Tx 2:** Update token to `'sent'` or `'failed'`, `delivery_attempted_at = now()`, commit, return `202 Accepted`.

---

## 12. Login, Access-Token, Refresh-Session, and Deployment-Aware Cookie Design

### 12.1 Access Token (JWT) & `auth_version` Invalidation
- **Algorithm:** `HS256` with `JWT_SECRET_KEY` (`>= 32` chars in production); lifetime `15` minutes (`900s`).
- **Required Claims:** `sub` (User UUID), `ver` (integer `users.auth_version`), `type` (`"access"`), `iss`, `aud`, `iat`, `exp`, `jti`.
- **`get_current_user` Validation:** Enforces `algorithms=["HS256"]`, `issuer`, `audience`, required claims, `payload["type"] == "access"`, strict `type(payload["ver"]) is int` (rejecting `bool`/`str`/`float`), `user.auth_version == payload["ver"]` (`401 INVALID_ACCESS_TOKEN`), and `user.is_active is True` (`403 ACCOUNT_INACTIVE`).

### 12.2 Refresh-Session Rotation, Replay Detection & Concurrency
- Opaque random tokens stored solely as lowercase hex SHA-256 (`CHAR(64)`).
- Rolling `expires_at = min(now + 14 days, family_expires_at)`; absolute `family_expires_at = initial_login_time + 30 days`.
- `POST /refresh` locks `refresh_sessions` by `token_hash` (`SELECT ... FOR UPDATE`), validates `client_type`, revokes entire `family_id` on replay of any rotated token (`401 REFRESH_TOKEN_REUSE_DETECTED`; unrelated families untouched), validates expiry and `user.is_active`, inserts child session, marks parent `revoked_at = now()`, `revoke_reason = 'rotated'`, `replaced_by_session_id = child.id`, and commits atomically.
- Concurrent `/refresh` calls with the same token serialize on `FOR UPDATE`; clients **must** implement single-flight refresh deduplication (§18.3).

### 12.3 Deployment-Aware Web Refresh-Cookie Policy

| Deployment Profile | Example Topology | `REFRESH_COOKIE_SAMESITE` | `REFRESH_COOKIE_SECURE` | `HttpOnly` & `Path` | CORS & CSRF Controls |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Development / Testing** | `http://localhost:5173` + `http://localhost:8000` | `"lax"` (default) | `False` (default) | `HttpOnly=True`, `Path=/api/v1/auth` | `CORS_ORIGINS` + `allow_credentials=True` + `X-Client-Type: web` + `Origin` check |
| **Mode 1 — Same-Site Production** (`COOKIE_DEPLOYMENT_MODE="same_site"`) | `https://app.folio360.com` + `https://api.folio360.com` or reverse-proxied same origin | `"lax"` (default) or `"strict"` | **`True` (mandatory)** | `HttpOnly=True`, `Path=/api/v1/auth`, optional `Domain` | Exact `https://` `CORS_ORIGINS` (no `"*"`), `Access-Control-Allow-Credentials: true`, strict `Origin` + `X-Client-Type: web` |
| **Mode 2 — Cross-Site Production** (`COOKIE_DEPLOYMENT_MODE="cross_site"`) | `https://frontend.host-a.app` + `https://api.host-b.com` (different registrable sites) | **`"none"` (mandatory)** | **`True` (mandatory)** | `HttpOnly=True`, `Path=/api/v1/auth`, `Domain=None` | Exact `https://` `CORS_ORIGINS` (no `"*"`), `Access-Control-Allow-Credentials: true`, strict `Origin` + `X-Client-Type: web` |

- **Browser Third-Party Cookie Restriction Caveat (Mode 2):** `SameSite=None; Secure` is necessary for cross-site cookies, **not** a guarantee of universal browser compatibility. Safari ITP, Firefox ETP, Brave Shields, and Chrome privacy settings may still block/partition cross-site cookies. **Mode 1 (same-site deployment)** is strongly recommended in production whenever feasible; Mode 2 is supported for split-origin/preview setups with this documented caveat.
- **`folio360_oauth_binding` Cookie:** Always `HttpOnly=True`, `SameSite=Lax`, `Path=/api/v1/auth/oauth`, `Max-Age=600`, `Secure=True` in production (works in both Mode 1 and Mode 2 because `/oauth/{provider}/start` and `/callback` are top-level `GET` navigations on the backend's own origin).
- **Mobile Contract Unchanged:** Expo clients (`X-Client-Type: mobile`) never receive or send cookies in any deployment mode.
- **Startup Validation:** Reject `SameSite=None` with `Secure=False` in all environments; in `production`, reject `Secure=False`, `cross_site` without `SameSite=None`, `same_site` with `SameSite=None`, `cross_site` with non-`None` `Domain`, or `CORS_ORIGINS` containing `"*"`, HTTP origins, or trailing slashes.

---

## 13. Password Recovery and Password-Change Concurrency & Transaction Safety

All credential-mutating and global-revocation operations (`change-password`, `reset-password`, `logout-all`) obey one strict deadlock-free lock hierarchy: **always lock `users` (`SELECT ... FROM users WHERE id = :uid FOR UPDATE`) first** before modifying `password_hash`, `auth_version`, `password_reset_tokens`, or `refresh_sessions`.

### 13.1 Password Reset (`POST /api/v1/auth/reset-password`)
1. Hash token; lightweight read maps `token_hash -> user_id` (missing -> `400 INVALID_RESET_TOKEN`).
2. **Single atomic transaction:**
   - Lock `users` row first (`FOR UPDATE`); verify `user.is_active` (`403 ACCOUNT_INACTIVE`).
   - Lock `password_reset_tokens` row (`WHERE token_hash = :h AND user_id = :uid FOR UPDATE`); verify `consumed_at IS NULL`, `revoked_at IS NULL`, `expires_at > now()` (else `400 INVALID_RESET_TOKEN`).
   - Hash `new_password` with Argon2id; update `user.password_hash`, `user.password_changed_at = now()`, `user.auth_version += 1`; mark token `consumed_at = now()`; revoke all other active reset tokens for `user.id`; revoke **all** active `refresh_sessions` (`password_reset`).
   - Commit atomically.

### 13.2 Authenticated Password Change (`POST /api/v1/auth/change-password`)
1. `get_current_user` validates Bearer JWT and extracts `user.id` and `token_ver`.
2. **Single atomic transaction:**
   - Lock `users` row (`FOR UPDATE`).
   - Re-verify on the locked row: `user.is_active is True` (`403`), `user.auth_version == token_ver` (`401 INVALID_ACCESS_TOKEN` if raced by a concurrent change/reset), and `user.password_hash is not None` (`400 PASSWORD_NOT_SET`).
   - Verify `current_password` via Argon2id against `user.password_hash` **from the locked row** (`401 INVALID_CREDENTIALS` on mismatch).
   - Reject identical password (`400 SAME_PASSWORD_NOT_ALLOWED`).
   - Hash `new_password` with Argon2id; update `user.password_hash`, `user.password_changed_at = now()`, `user.auth_version += 1`; revoke **all** existing active `refresh_sessions` (`password_changed`); insert **one fresh** `refresh_session` (new `family_id`, `client_type`) for the current client.
   - Commit atomically.
3. Post-commit: mint fresh access JWT with the committed post-increment `user.auth_version` and return client-specific credentials.

---

## 14. Google OAuth / OIDC Flow & Additional-Audience Trust Policy (Stage 3C)

1. **`GET /api/v1/auth/oauth/google/start`:** Validates `client_type` and exact allowlisted `redirect_uri`; generates `state`, `nonce`, and PKCE `code_verifier` -> `S256` `code_challenge`; encrypts `code_verifier` with AES-256-GCM (AAD `f"google:{state_hash}"`, §17.1); sets **`folio360_oauth_binding`** on `web` (storing only `sha256` in `client_binding_hash`); persists `oauth_states` (10m TTL); redirects `302` to `https://accounts.google.com/o/oauth2/v2/auth` with `scope=openid email profile`, `response_type=code`, `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`.
2. **`GET /api/v1/auth/oauth/google/callback`:**
   - **Tx 1 (Before External I/O):** Lock `oauth_states` (`FOR UPDATE`), validate `provider == 'google'`, unconsumed, unexpired, and (on `web`) constant-time match of `sha256(request.cookies.get("folio360_oauth_binding")) == client_binding_hash`. Decrypt `pkce_verifier_encrypted` with AAD `f"google:{state_hash}"` (any decryption failure -> `?error=invalid_oauth_state`). Mark `consumed_at = now()`, set `pkce_verifier_encrypted = '[CONSUMED]'`, commit. Always clear **`folio360_oauth_binding`** on web response.
   - **External HTTP (Outside DB Transaction, 5s timeout):** `POST https://oauth2.googleapis.com/token` with `code`, `client_id`, `client_secret`, backend `redirect_uri`, `grant_type=authorization_code`, `code_verifier`.

### 14.1 Complete Google ID-Token, Audience (`aud`), and Authorized-Presenter (`azp`) Trust Policy
- **Selected Policy: Option B — Explicit Trusted-Audience Allowlist (`GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES: list[str] = []`, Default Empty `[]`):**
  - By default (`GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES = []`), enforces a strict single-client policy where any audience other than `settings.GOOGLE_CLIENT_ID` is rejected.
  - Rejects wildcard `"*"`, empty/whitespace strings, non-string primitives, malformed JSON, or duplicates in `GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES` at startup.
- **Validation Sequence (`validate_google_id_token` & `validate_google_audience_and_azp`):**
  1. **Signature:** Verify `RS256` signature via Google JWKS (`https://www.googleapis.com/oauth2/v3/certs`, cached via `PyJWKClient`).
  2. **Issuer (`iss`):** Strictly in `{"https://accounts.google.com", "accounts.google.com"}`.
  3. **Temporal (`exp`, `iat`, `nbf`):** `exp` and `iat` required and valid; `nbf` validated if present; leeway `<= 30s`.
  4. **Audience (`aud`) & Authorized Presenter (`azp`) — OIDC Core 1.0 §3.1.3.7:**
     - Reject if `"aud"` is missing or `None`.
     - If `isinstance(aud, str)`: reject if empty or leading/trailing whitespace; `aud_list = [aud]`.
     - Else if `isinstance(aud, list)`: reject if empty (`len(aud) == 0`) or if any item is not a `str` (`type(item) is not str`) or is empty/whitespace-padded; `aud_list = aud`.
     - Else: reject.
     - **Duplicate Check:** Reject if `len(aud_list) != len(set(aud_list))`.
     - **Primary Client Presence:** Reject unless `any(hmac.compare_digest(item, expected_client_id) for item in aud_list)`.
     - **Additional-Audience Trust Check:** Let `trusted_audiences = {expected_client_id} | set(trusted_additional_audiences)`. Reject if any `item` in `aud_list` is not in `trusted_audiences` (**even when `azp == expected_client_id`**).
     - **`azp` Check:** If `len(aud_list) > 1`, require `"azp"` present and non-`None`. Whenever `"azp"` is present in `claims` (single or multiple audiences), require `type(azp) is str`, `bool(azp.strip())`, and `hmac.compare_digest(azp, expected_client_id)`.
  5. **Nonce, Subject & Verified Email:** Constant-time `nonce` match, non-empty `sub`, syntactically valid `email`, and strict boolean `email_verified is True`.
  6. **Tx 2:** Resolve `(google, sub)` or atomically provision via `SAVEPOINT` with strict no-auto-merge (`email_already_registered`), issue 60s `oauth_exchange_code`, and redirect `302` to safely constructed `redirect_uri` (§17.2).

---

## 15. GitHub OAuth 2.0 Flow & Bounded Email Pagination (Stage 3C)

1. **`GET /api/v1/auth/oauth/github/start`:** Identical allowlist validation, `state`, AES-256-GCM encrypted PKCE `S256` (`code_challenge` + `code_challenge_method=S256`), and **`folio360_oauth_binding`** web cookie (`nonce = None`). Redirects `302` to `https://github.com/login/oauth/authorize` with `scope=read:user user:email`.
2. **`GET /api/v1/auth/oauth/github/callback`:**
   - **Tx 1:** Single-use state lock/consumption, **`folio360_oauth_binding`** check (web), AES-256-GCM decryption (AAD `f"github:{state_hash}"`), scrub to `'[CONSUMED]'`, commit, clear **`folio360_oauth_binding`** on web response.
   - **External HTTP (`5.0s` timeout, `follow_redirects=False`):**
     - `POST https://github.com/login/oauth/access_token` (`Accept: application/json`) with `client_id`, `client_secret`, `code`, backend `redirect_uri`, `code_verifier`.
     - `GET https://api.github.com/user` (`Accept: application/vnd.github+json`, `Authorization: Bearer <token>`, `X-GitHub-Api-Version: 2022-11-28`) -> immutable numeric `id` as `str(data["id"])`.
   - **Existing Linked User Fast-Path:** If `(provider='github', provider_user_id=str(github_id))` exists in `oauth_accounts`, authenticate directly (checking `user.is_active`) regardless of subsequent GitHub email changes.
   - **Bounded, Validated Paginated Retrieval of `GET /user/emails` (New Account Creation):**
     1. Start at `https://api.github.com/user/emails?per_page=100&page=1` (`GITHUB_EMAILS_PER_PAGE = 100`, `GITHUB_EMAILS_MAX_PAGES = 10`, `follow_redirects=False`).
     2. Track `visited_urls: set[str]` and `all_entries: list[dict]`.
     3. Loop `page_idx` in `1..GITHUB_EMAILS_MAX_PAGES`:
        - Record current URL in `visited_urls`; `GET` with `5.0s` timeout. Timeout, network error, non-200 status, or non-list JSON -> fail safely (`error=oauth_provider_error`).
        - Append validated dict items to `all_entries`.
        - Inspect RFC 8288 `Link` header via `response.links.get("next")`: if absent, exit loop.
        - Validate `next_url = response.links["next"]["url"]` via `urllib.parse.urlsplit`: must have `username is None`, `password is None`, exact GitHub API scheme+host (`https://api.github.com`), exact `path == "/user/emails"`, and `next_url not in visited_urls` (rejects loops/SSRF/token exfiltration -> `error=oauth_provider_error`).
        - If `page_idx == GITHUB_EMAILS_MAX_PAGES` while a valid `"next"` link still exists -> fail safely (`error=oauth_provider_error`), never creating an account from an incomplete list.
   - **Deterministic Selection of Verified, Syntactically Valid, Non-Noreply Email Suitable for Registration:**
     - Filter across all retrieved pages for strict boolean `verified is True`, normalize `email = entry["email"].strip().lower()`, require `length <= 320`, no whitespace, valid `EmailStr`, and reject noreply domains (`users.noreply.github.com`, `*.users.noreply.github.com`, `noreply.github.com`).
     - Deduplicate across pages by normalized `email` (preserving `primary = True` if any verified occurrence has `primary is True`).
     - Prefer suitable verified `primary is True`; otherwise lexicographically smallest lowercase `email`; if none -> `error=verified_email_required` (zero partial account created).
     - Provision atomically via `SAVEPOINT` with strict no-auto-merge (`email_already_registered`).

---

## 16. Official OAuth/OIDC Documentation and Uvicorn Technical References

### 16.1 Google Identity References

| Official URL | Documented Behavior | Folio360 Requirement |
| :--- | :--- | :--- |
| https://developers.google.com/identity/protocols/oauth2/web-server | Confidential server-side Authorization Code flow (`https://accounts.google.com/o/oauth2/v2/auth`, `POST https://oauth2.googleapis.com/token`), `client_secret`, `state`, exact `redirect_uri`. *(See §16.4 for PKCE evidence classification.)* | Backend-initiated `/oauth/google/start` and `/callback` exchanging `code` server-side with `client_secret` and exact backend `redirect_uri`. |
| https://developers.google.com/identity/protocols/oauth2/native-app | Documents PKCE (`code_challenge`, `code_challenge_method=S256` / `plain`, `code_verifier`) for installed/native apps and external system browsers. | Mobile uses `expo-web-browser`; PKCE `S256` generation follows RFC 7636. |
| https://developers.google.com/identity/openid-connect/openid-connect | OIDC `scope=openid email profile`, `nonce`, immutable `sub`, `email_verified`, Discovery document `https://accounts.google.com/.well-known/openid-configuration` (`"code_challenge_methods_supported": ["plain", "S256"]`, `"jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"`), `iss` (`https://accounts.google.com` or `accounts.google.com`). | Store/verify `nonce`, key on `sub`, require strict boolean `email_verified is True`, validate `RS256` signature via Google JWKS. |
| https://developers.google.com/identity/gsi/web/guides/verify-google-id-token | Server-side ID token verification: RS256 signature with Google public keys, `iss`, `aud`, `exp`. | Verified via `PyJWT[crypto]` + `PyJWKClient` + explicit `validate_google_audience_and_azp` (§14.1). |

### 16.2 GitHub OAuth & REST API References

| Official URL | Documented Behavior | Folio360 Requirement |
| :--- | :--- | :--- |
| https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps | Web application flow (`GET https://github.com/login/oauth/authorize`, `POST https://github.com/login/oauth/access_token`), `Accept: application/json`, `state`, 10-minute code expiry, PKCE parameters. | 10-minute `oauth_states`, single-use `state`, JSON token exchange, PKCE `S256`. |
| https://github.blog/changelog/2025-07-14-pkce-support-for-oauth-and-github-app-authentication/ | July 14, 2025 official changelog: RFC 7636 PKCE supported for both OAuth Apps and GitHub Apps authorization code flow; **only `S256` accepted** (`plain` rejected); `code_verifier` required on exchange whenever `code_challenge` was sent. | Enforce `code_challenge_method=S256` + `code_verifier` on GitHub OAuth flow. |
| https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps | `user:email` grants read-only access to primary/secondary/private email addresses; `read:user` grants read-only profile access. | Request least-privilege `scope=read:user user:email`. |
| https://docs.github.com/en/rest/users/users | `GET https://api.github.com/user` returns authenticated user profile with immutable numeric `id`. | Key `oauth_accounts.provider_user_id` on `str(id)`. |
| https://docs.github.com/en/rest/users/emails | `GET https://api.github.com/user/emails` (`user:email` scope, supports `per_page` max 100 and `page`) returns `{email, primary, verified, visibility}`. | Request `per_page=100&page=1`, paginate completely within bounds, apply deterministic suitability filter (§15). |
| https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api | Official REST pagination via RFC 8288 `Link` header (`rel="next"`), `per_page` up to `100`. | Follow validated `Link` `rel="next"` URLs up to `GITHUB_EMAILS_MAX_PAGES = 10` (§15). |

### 16.3 Protocol Standards & Verified Uvicorn (`0.54.0`) References
- **OpenID Connect Core 1.0, Section 3.1.3.7 (ID Token Validation):** https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
- **RFC 7636 (PKCE)** & **RFC 9700 (OAuth 2.0 Security Best Current Practice):** https://datatracker.ietf.org/doc/html/rfc7636 and https://datatracker.ietf.org/doc/html/rfc9700
- **RFC 8288 (Web Linking):** https://datatracker.ietf.org/doc/html/rfc8288
- **Official Uvicorn Settings Documentation:** https://www.uvicorn.org/settings/ and https://www.uvicorn.org/deployment/
- **Directly Verified Installed Uvicorn (`uvicorn==0.54.0`) Source Files:**
  - [uvicorn/__init__.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/__init__.py) (line 4: `__version__ = "0.54.0"`).
  - [uvicorn/main.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/main.py) (line 61: Click `auto_envvar_prefix="UVICORN"`; lines 232–257: `--proxy-headers` default `True`, `--forwarded-allow-ips`; lines 561–640: `uvicorn.run()`, `Multiprocess`, `Server`).
  - [uvicorn/config.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/config.py) (line 24: `STARTUP_FAILURE = 3`; line 225: `proxy_headers: bool = True`; lines 361–365: `forwarded_allow_ips = os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1,::1")`; lines 439–546: `Config.load()` — imports app on line 511, invokes `--factory` callable on line 514, wraps `self.loaded_app = ProxyHeadersMiddleware(self.loaded_app, trusted_hosts=self.forwarded_allow_ips)` on lines 543–544, sets `self.loaded = True` on line 546).
  - [uvicorn/middleware/proxy_headers.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/middleware/proxy_headers.py) (lines 24–27: `ProxyHeadersMiddleware.__init__` storing `self.app` and `self.trusted_hosts = _TrustedHosts(trusted_hosts)`; lines 105–187: `_TrustedHosts` storing `self.always_trust`, `self.trusted_literals`, `self.trusted_hosts`, `self.trusted_networks`, and `get_trusted_client_address()`).
  - [uvicorn/lifespan/on.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/lifespan/on.py) (lines 47–63: `LifespanOn.startup()` setting `self.should_exit = True` on startup failure; lines 78–101: `LifespanOn.main()` passing `scope = {"type": "lifespan", "asgi": ..., "state": self.state}`).
  - [uvicorn/server.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/server.py) (lines 92–119: `Server._serve()` calling `config.load()` if `not config.loaded`, then `Server.startup()` calling `await self.lifespan.startup()` and `if self.lifespan.should_exit: sys.exit(STARTUP_FAILURE)`).
  - [uvicorn/_subprocess.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/_subprocess.py) (lines 18–81: `spawn = multiprocessing.get_context("spawn")`; `get_subprocess()` passing `config` to child `subprocess_started()`, which calls `target(sockets=sockets)`).
  - [uvicorn/supervisors/multiprocess.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/supervisors/multiprocess.py) (lines 26–130: `Process.target()` running `self.server.run(sockets)` where `self.server = Server(config=self.config)`; lines 214–232: `Multiprocess.keep_subprocess_alive()` checking `if process.exitcode == STARTUP_FAILURE: self.should_exit.set(); return`).

### 16.4 Explicit Evidence Classification — Google Confidential Web-Server PKCE

| Classification | Statement |
| :--- | :--- |
| **Confirmed Provider Behaviour** | Google's OIDC Discovery document (`https://accounts.google.com/.well-known/openid-configuration`) advertises `"code_challenge_methods_supported": ["plain", "S256"]`; Google documents PKCE `S256` for installed/native apps (`native-app`); Google documents confidential server-side authorization code exchange with `client_secret` (`web-server`). |
| **Protocol-Level Requirement / Recommendation** | RFC 7636 and RFC 9700 recommend PKCE `S256` for confidential clients alongside `client_secret`. |
| **Folio360 Security Policy** | Stage 3C sends `code_challenge` + `code_challenge_method=S256` on `/oauth/google/start` and `code_verifier` alongside `client_secret` on token exchange. |
| **Unverified Assumption (Mandatory Pre-Release Verification Gate)** | Google's `web-server` page does not explicitly document combining `client_secret` + PKCE `code_verifier` for confidential Web Application credentials, and no live Google OAuth credentials were exercised during this read-only specification. **Before Stage 3C production release acceptance**, execute a controlled live integration verification against a real Google Cloud Web Application OAuth client confirming (1) valid `code_verifier` + `client_secret` succeeds, and (2) mismatched `code_verifier` is rejected (`invalid_grant`). |

---

## 17. Security Analysis, Cryptographic Design, and Threat Mitigations

### 17.1 PKCE Verifier Protection at Rest (AES-256-GCM)
- **Algorithm:** AES-256-GCM via installed `cryptography.hazmat.primitives.ciphers.aead.AESGCM` (zero new dependencies).
- **Key:** 256-bit (32 raw bytes) base64url-encoded in `OAUTH_PKCE_ENCRYPTION_KEY` (`SecretStr`); optional `OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS` for zero-downtime key rotation across the 10-minute `oauth_states` window.
- **Nonce & AAD:** Fresh 12-byte `os.urandom(12)` nonce per row; AAD `f"{provider}:{state_hash}".encode("utf-8")`.
- **Storage & Scrubbing:** Stored in `oauth_states.pkce_verifier_encrypted` as `v1:<urlsafe_b64_no_padding(nonce || ciphertext || tag)>`, scrubbed to `'[CONSUMED]'` on use. Any decryption failure logs only sanitized metadata (`event="oauth_pkce_decrypt_failed"`, `provider`, `state_id`) and redirects with `error=invalid_oauth_state`.

### 17.2 Safe OAuth Redirect URI Query Construction
Prohibit string concatenation. `build_oauth_redirect_url(redirect_uri, *, code=None, error=None)` validates exact string match against `OAUTH_ALLOWED_WEB_REDIRECT_URIS` / `OAUTH_ALLOWED_MOBILE_REDIRECT_URIS`, parses via `urllib.parse.urlsplit` + `parse_qsl(parts.query, keep_blank_values=True)`, strips any existing `"code"`/`"error"` keys, appends the single `("code", code)` or `("error", error)` pair, re-encodes with `urlencode`, and reconstructs via `urlunsplit`.

### 17.3 Threat-Mitigation Summary

| Threat | Mitigation |
| :--- | :--- |
| **Plaintext secret echo in 422** | Custom `RequestValidationError` handler in [app/core/exceptions.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/core/exceptions.py) strips Pydantic v2 `input` and sanitizes `ctx`. |
| **PostgreSQL `DETAIL:` leakage** | Inspect only `exc.orig.diag.constraint_name` on `IntegrityError`; map known constraints to safe `AppException` codes. |
| **Log secret leakage** | Extended [app/core/logging.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/core/logging.py) redaction (`re_...`, `code_verifier`, `pkce_verifier*`, `oauth_pkce_encryption_key`, `id_token`, `cookie`, `set-cookie`, `exchange_code`, `oauth_code`, `new_password`, `current_password`). |
| **CSRF on web refresh cookies** | Deployment-aware `SameSite` (`Lax` or `None; Secure`) + mandatory `X-Client-Type: web` + strict `Origin` match against exact `CORS_ORIGINS` allowlist. |
| **OAuth Login CSRF** | **`folio360_oauth_binding`** cookie (`HttpOnly`, `SameSite=Lax`, `Path=/api/v1/auth/oauth`, 10m TTL, `Secure` in prod) verified via SHA-256 against `oauth_states.client_binding_hash`, then cleared. |
| **OIDC multi-audience token substitution** | Every audience in `aud` must belong to `{GOOGLE_CLIENT_ID} \| set(GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES)` (default empty allowlist), duplicates rejected, and `azp == GOOGLE_CLIENT_ID` enforced (§14.1). |
| **Raw Uvicorn CLI `--factory` or programmatic `uvicorn.Config` proxy-verification bypass** | `create_app()` never issues a verification stamp; only `VerifiedUvicornConfig.load()` in `app/server.py` registers a weakref-bound record in `_VERIFIED_APP_REGISTRY` **after** `super().load()` wraps `config.loaded_app`, and production `lifespan` live-verifies the policy, `Config`, and outer `ProxyHeadersMiddleware` wrapper before serving requests (§19.1). |

---

## 18. Web and Mobile Client Integration Contract

- **Web Client (React / Vite):** Send `X-Client-Type: web` and `credentials: "include"` on cookie-bearing routes; hold `access_token` in JS memory only (never `localStorage`/`sessionStorage`); enforce §10 referrer/script/history rules on `/verify-email`, `/reset-password`, and `/auth/oauth/callback`.
- **Mobile Client (React Native / Expo):** Send `X-Client-Type: mobile` (zero cookies); store `access_token` and `refresh_token` in `expo-secure-store`; OAuth via `WebBrowser.openAuthSessionAsync`.
- **Single-Flight Refresh Deduplication (Both):** Deduplicate concurrent 401 refresh retries behind a single shared in-flight `refreshPromise` so concurrent requests never trigger replay revocation (`401 REFRESH_TOKEN_REUSE_DETECTED`).

---

## 19. Unbypassable Uvicorn Proxy Configuration Enforcement & Rate-Limiting (Rev5 Correction)

### 19.1 Three Distinct Verification Concepts (Never Interchangeable)

To eliminate the Rev4 factory self-stamping bypass, the specification strictly separates three distinct verification stages:

| Concept | Function in `app/server.py` | What It Inspects | What It Certifies |
| :--- | :--- | :--- | :--- |
| **1. Configured Proxy Policy Validation** | `validate_proxy_policy(settings: Settings, environ: Mapping[str, str]) -> VerifiedProxyPolicy` | `settings.PROXY_HEADERS_ENABLED`, `settings.TRUSTED_PROXY_IPS`, and ambient `environ` (`FORWARDED_ALLOW_IPS`, `UVICORN_FORWARDED_ALLOW_IPS`, `UVICORN_PROXY_HEADERS`). | That the application's configured policy and ambient environment variables are internally consistent, contain no wildcards (`"*"`), no hostname literals, no empty entries, and only valid IPv4/IPv6 addresses or CIDR networks. **Does NOT certify Uvicorn's `Config` or middleware.** |
| **2. Effective `uvicorn.Config` Validation** | `validate_effective_uvicorn_config(config: uvicorn.Config, policy: VerifiedProxyPolicy) -> None` | The live `config.proxy_headers` and `config.forwarded_allow_ips` attributes on the `uvicorn.Config` instance. | That `isinstance(config, VerifiedUvicornConfig)` is `True`, `config.proxy_headers == policy.proxy_headers`, and `config.forwarded_allow_ips == policy.forwarded_allow_ips_csv`. |
| **3. Post-Load ASGI Middleware Wrapper Verification** | `verify_loaded_asgi_middleware(loaded_app: ASGIApplication, fastapi_app: FastAPI, policy: VerifiedProxyPolicy) -> None` | The actual post-`config.load()` outer ASGI callable (`config.loaded_app`) and its internal `_TrustedHosts` structure (`ProxyHeadersMiddleware.app`, `trusted_hosts.always_trust`, `trusted_hosts.trusted_literals`, `trusted_hosts.trusted_hosts`, `trusted_hosts.trusted_networks`). | When `policy.proxy_headers is True`: that `loaded_app` is a `ProxyHeadersMiddleware` directly wrapping `fastapi_app` (`loaded_app.app is fastapi_app`), `always_trust is False`, `trusted_literals == set()`, and the parsed IP/network sets match `policy.trusted_hosts` and `policy.trusted_networks` exactly. When `policy.proxy_headers is False`: that `loaded_app is fastapi_app` and `not isinstance(loaded_app, ProxyHeadersMiddleware)`. |

---

### 19.2 Factory Trust Boundary (`create_app` in [app/main.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/main.py))
1. **`create_verified_app()` is removed completely.** There is only one application factory: `create_app(settings: Settings | None = None) -> FastAPI` in [app/main.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/main.py).
2. **Why a Factory Must Never Issue a Verification Stamp:** As verified in [uvicorn/config.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/config.py) lines 511–544, `Config.load()` invokes the application factory (line 514) **before** wrapping `self.loaded_app = ProxyHeadersMiddleware(self.loaded_app, trusted_hosts=self.forwarded_allow_ips)` (lines 543–544), and passes zero arguments to the factory. A factory therefore has no visibility into the enclosing `uvicorn.Config` or outer `ProxyHeadersMiddleware`.
3. **Strict Factory Rule:** `create_app()` constructs the `FastAPI` instance and attaches `app.state.settings = settings`, but **never** creates, attaches, or registers any proxy-configuration verification stamp.

---

### 19.3 Controlled Launcher, `VerifiedUvicornConfig`, and Module-Private Binding Registry (`app/server.py`)

#### A. Authoritative Policy Rules (`validate_proxy_policy`)
- **Mode 1 — Direct Deployment (`settings.PROXY_HEADERS_ENABLED is False`, Default):**
  - `settings.TRUSTED_PROXY_IPS` must be empty (`[]`).
  - Ambient `FORWARDED_ALLOW_IPS` and `UVICORN_FORWARDED_ALLOW_IPS` must be unset or empty (`""`).
  - Ambient `UVICORN_PROXY_HEADERS` must not be truthy (`"1"`, `"true"`, `"yes"`, `"on"`).
  - Produces `VerifiedProxyPolicy(proxy_headers=False, forwarded_allow_ips_csv="", trusted_hosts=frozenset(), trusted_networks=frozenset())`.
- **Mode 2 — Trusted Reverse-Proxy Deployment (`settings.PROXY_HEADERS_ENABLED is True`):**
  - `settings.TRUSTED_PROXY_IPS` must be non-empty.
  - Rejects `"*"`, empty strings, whitespace-only entries, or hostname literals.
  - Every entry must parse cleanly via `ipaddress.ip_address(entry)` (when `"/" not in entry`) or `ipaddress.ip_network(entry, strict=False)` (when `"/" in entry`). Any `ValueError` raises a configuration error immediately (preventing Uvicorn `_TrustedHosts` from silently storing malformed entries in `trusted_literals`).
  - If ambient `FORWARDED_ALLOW_IPS` or `UVICORN_FORWARDED_ALLOW_IPS` is set in `environ`, it must parse to the exact same canonical IP/network set (and never `"*"`).
  - If ambient `UVICORN_PROXY_HEADERS` is set in `environ`, it must not be falsy (`"0"`, `"false"`, `"no"`, `"off"`).
  - Produces `VerifiedProxyPolicy(proxy_headers=True, forwarded_allow_ips_csv=",".join(canonical_entries), trusted_hosts=frozenset(ips), trusted_networks=frozenset(nets))`.

#### B. `VerifiedUvicornConfig(uvicorn.Config)` & Post-Load Verification
`app/server.py` defines a module-private registry and a `uvicorn.Config` subclass:

```python
_VERIFIED_APP_REGISTRY: dict[int, _VerifiedBindingRecord] = {}
```

where `_VerifiedBindingRecord` is a frozen dataclass holding:
- `app_id: int` (`id(fastapi_app)`)
- `pid: int` (`os.getpid()`)
- `app_ref: weakref.ReferenceType[FastAPI]`
- `config_ref: weakref.ReferenceType[VerifiedUvicornConfig]`
- `loaded_app_ref: weakref.ReferenceType[Any]`
- `policy: VerifiedProxyPolicy`

**Lifecycle of `VerifiedUvicornConfig`:**
1. **`VerifiedUvicornConfig.__init__(self, app, *, settings: Settings | None = None, **kwargs)`:**
   - Resolves `effective_settings = settings or (app.state.settings if isinstance(app, FastAPI) else get_settings())`.
   - Runs **Concept 1:** `policy = validate_proxy_policy(effective_settings, os.environ)`.
   - If caller passed `proxy_headers` or `forwarded_allow_ips` in `kwargs` that differ from `policy.proxy_headers` or `policy.forwarded_allow_ips_csv` (including `"*"` or conflicting booleans), raises `RuntimeError` immediately **before** calling `super().__init__(...)`.
   - Calls `super().__init__(app, proxy_headers=policy.proxy_headers, forwarded_allow_ips=policy.forwarded_allow_ips_csv, **kwargs)`.
   - Runs **Concept 2:** `validate_effective_uvicorn_config(self, policy)`.
2. **`VerifiedUvicornConfig.load(self) -> None`:**
   - Calls `super().load()` (which loads `FastAPI`, invokes `create_app()` if `factory=True`, and wraps `self.loaded_app` in `ProxyHeadersMiddleware` when `self.proxy_headers` is `True`).
   - Unwraps `fastapi_app`:
     - If `isinstance(self.loaded_app, ProxyHeadersMiddleware)`, `fastapi_app = self.loaded_app.app`.
     - Else `fastapi_app = self.loaded_app`.
     - Verifies `isinstance(fastapi_app, FastAPI)` (else raises `RuntimeError`).
   - Re-reads `app_settings: Settings = fastapi_app.state.settings`.
   - Runs **Concept 1:** `policy = validate_proxy_policy(app_settings, os.environ)`.
   - Runs **Concept 2:** `validate_effective_uvicorn_config(self, policy)`.
   - Runs **Concept 3:** `verify_loaded_asgi_middleware(self.loaded_app, fastapi_app, policy)`.
   - Registers `_VERIFIED_APP_REGISTRY[id(fastapi_app)] = _VerifiedBindingRecord(...)` for the current worker `os.getpid()`.

#### C. Live Re-Verification in FastAPI Production `lifespan` (`verify_production_asgi_trust_boundary`)
Inside `lifespan(app)` ([app/main.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/main.py)), right after `settings.validate_runtime_requirements()`:
1. Always runs **Concept 1** (`policy = validate_proxy_policy(settings, os.environ)`).
2. When `settings.ENVIRONMENT == "production"`, calls `verify_production_asgi_trust_boundary(app, settings)`:
   - Looks up `record = _VERIFIED_APP_REGISTRY.get(id(app))`.
   - If `record is None` or `record.pid != os.getpid()` or `record.app_ref() is not app`:
     - Raises `RuntimeError("Unverified ASGI startup: production application must be launched via app.server (VerifiedUvicornConfig).")`.
   - Dereferences `live_config = record.config_ref()` and `live_loaded_app = record.loaded_app_ref()`.
   - If `live_config is None` or `live_loaded_app is None` or `live_config.loaded_app is not live_loaded_app`:
     - Raises `RuntimeError("ASGI verification record does not match live Uvicorn Config / loaded_app.")`.
   - Re-runs **Concept 1** (`current_policy = validate_proxy_policy(settings, os.environ)`), checks `current_policy == record.policy`, re-runs **Concept 2** (`validate_effective_uvicorn_config(live_config, current_policy)`), and re-runs **Concept 3** (`verify_loaded_asgi_middleware(live_loaded_app, app, current_policy)`).
   - If any check raises an exception inside `lifespan(app)`, Uvicorn's `LifespanOn.startup()` ([uvicorn/lifespan/on.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/lifespan/on.py) lines 58–60) sets `self.should_exit = True`, and `Server.startup()` ([uvicorn/server.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/server.py) lines 116–118) immediately executes `sys.exit(STARTUP_FAILURE)` (`exitcode = 3`) before accepting any HTTP request.

---

### 19.4 Why Both Attack Scenarios and Multi-Worker Launches Are Completely Closed

#### 1. How Raw CLI Launch Bypass (Attack Scenario A) Is Prevented
- Suppose a deployment executes raw Uvicorn CLI:
  - `uvicorn app.main:create_app --factory --forwarded-allow-ips="*"`
  - `uvicorn app.main:app --forwarded-allow-ips="*"`
  - `uvicorn app.main:create_app --factory --proxy-headers` (when `PROXY_HEADERS_ENABLED=False`)
  - `uvicorn app.main:create_app --factory --no-proxy-headers` (when `PROXY_HEADERS_ENABLED=True`)
- **Result:**
  1. `create_verified_app` does not exist.
  2. Raw `uvicorn` CLI instantiates standard `uvicorn.Config` (not `VerifiedUvicornConfig`), so `VerifiedUvicornConfig.load()` never runs and `_VERIFIED_APP_REGISTRY` has no entry for `id(app)`.
  3. Furthermore, if unsafe ambient env vars (`FORWARDED_ALLOW_IPS="*"`, `UVICORN_FORWARDED_ALLOW_IPS="*"`, or conflicting `UVICORN_PROXY_HEADERS`) are present, Concept 1 (`validate_proxy_policy`) also fails immediately.
  4. In `ENVIRONMENT == "production"`, `lifespan(app)` calls `verify_production_asgi_trust_boundary(app, settings)`, finds `_VERIFIED_APP_REGISTRY.get(id(app)) is None`, raises `RuntimeError`, and Uvicorn exits with `STARTUP_FAILURE` (`3`) before serving any request.

#### 2. How Raw Programmatic Launch Bypass (Attack Scenario B) Is Prevented
- Suppose code constructs:
  - `uvicorn.Config(create_app(settings), proxy_headers=True, forwarded_allow_ips="*")`
  - `uvicorn.Config(create_app(settings), proxy_headers=not settings.PROXY_HEADERS_ENABLED)`
- **Result:**
  1. `create_app(settings)` never stamps or registers the `FastAPI` instance.
  2. Standard `uvicorn.Config` is not `VerifiedUvicornConfig`, so `_VERIFIED_APP_REGISTRY` has no entry for `id(app)`.
  3. When `LifespanOn` / `Server.startup()` runs `lifespan(app)` in production, `verify_production_asgi_trust_boundary(app, settings)` raises `RuntimeError` and aborts startup.
  4. If code instead passes unsafe overrides to `build_uvicorn_config(settings, forwarded_allow_ips="*")` or `VerifiedUvicornConfig(..., forwarded_allow_ips="*")`, `VerifiedUvicornConfig.__init__` rejects the override immediately before `Config` construction; and if `config.forwarded_allow_ips` or `config.loaded_app` is mutated after `build_uvicorn_config()`, `lifespan(app)` catches the live mismatch via `config_ref()` and `loaded_app_ref()` and aborts startup.

#### 3. How Multi-Worker Verification Works (`workers > 1`)
Verified directly against `uvicorn==0.54.0` ([uvicorn/main.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/main.py) lines 614–631, [uvicorn/_subprocess.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/_subprocess.py) lines 18–81, [uvicorn/supervisors/multiprocess.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/supervisors/multiprocess.py) lines 26–232, and [uvicorn/server.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/server.py) lines 92–119):
1. **Parent Process (`python -m app.server --workers N` / `run_server`):**
   - `build_uvicorn_config(settings, app="app.main:create_app", factory=True, workers=N)` validates Concept 1 (`validate_proxy_policy`) and Concept 2 (`validate_effective_uvicorn_config`) on the parent `VerifiedUvicornConfig` instance before binding the listening socket.
   - When `workers > 1`, `build_uvicorn_config` leaves `config.loaded = False` in the parent so `Multiprocess(config, sockets=[sock])` can pickle the `VerifiedUvicornConfig` instance across `spawn.Process` to each child worker.
2. **Each Spawned Worker Process:**
   - Python's `spawn` pickler deserializes `config` as a `VerifiedUvicornConfig` instance inside the child worker.
   - `Process.target()` creates `Server(config=self.config)` and calls `Server._serve()`, which invokes `config.load()` (`VerifiedUvicornConfig.load()`) **inside that worker process**.
   - `VerifiedUvicornConfig.load()` runs `super().load()` (calling `app.main:create_app` and wrapping `self.loaded_app` in `ProxyHeadersMiddleware` if `proxy_headers=True`), then executes **Concept 1**, **Concept 2**, and **Concept 3** inside that worker process and registers `_VERIFIED_APP_REGISTRY[id(fastapi_app)]` for that worker's `os.getpid()`.
   - `Server.startup()` then enters `lifespan(fastapi_app)` in that worker, which runs `verify_production_asgi_trust_boundary(fastapi_app, settings)` against the worker's live `Config` and `loaded_app`.
   - **Worker Failure Propagation:** If any worker's environment or effective `Config` is mismatched or unsafe, `VerifiedUvicornConfig.load()` or `lifespan()` fails, `Server.startup()` calls `sys.exit(STARTUP_FAILURE)` (`exitcode == 3`), and `Multiprocess.keep_subprocess_alive()` (lines 225–231 of [uvicorn/supervisors/multiprocess.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/venv/Lib/site-packages/uvicorn/supervisors/multiprocess.py)) detects `process.exitcode == STARTUP_FAILURE` and immediately terminates the parent supervisor process (`self.should_exit.set()`).

#### 4. Dependency on Uvicorn Internal Attributes & Protection Strategy
Inspecting `ProxyHeadersMiddleware.app` and `ProxyHeadersMiddleware.trusted_hosts` (`always_trust`, `trusted_literals`, `trusted_hosts`, `trusted_networks`) and overriding `Config.load()` depends on `uvicorn==0.54.0` internal structure. This dependency is protected by:
1. Exact version pinning (`uvicorn==0.54.0`) in [requirements.txt](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/requirements.txt).
2. Fail-closed attribute inspection in `verify_loaded_asgi_middleware` (missing or renamed attributes raise `RuntimeError` rather than passing silently).
3. The 14 mandatory regression tests (§20.4), which fail immediately in CI if a future Uvicorn upgrade alters `Config.load()` or `ProxyHeadersMiddleware`.

---

### 19.5 Supported Production Launch Contract & Deployment Examples

**One Authoritative Production Launch Entrypoint:** Production deployments (Docker, systemd, PaaS) **must** start the server via `python -m app.server` (which uses `build_uvicorn_config` + `VerifiedUvicornConfig`).

#### 1. Direct Deployment (No Reverse Proxy)
```bash
export ENVIRONMENT=production
export PROXY_HEADERS_ENABLED=false
export TRUSTED_PROXY_IPS=""
python -m app.server --host 0.0.0.0 --port 8000
```

#### 2. Behind a Trusted Reverse Proxy (Single Worker)
```bash
export ENVIRONMENT=production
export PROXY_HEADERS_ENABLED=true
export TRUSTED_PROXY_IPS="10.0.0.1,172.16.0.0/12"
python -m app.server --host 0.0.0.0 --port 8000
```

#### 3. Multi-Worker Deployment (Behind a Trusted Reverse Proxy)
```bash
export ENVIRONMENT=production
export PROXY_HEADERS_ENABLED=true
export TRUSTED_PROXY_IPS="10.0.0.1,172.16.0.0/12"
python -m app.server --host 0.0.0.0 --port 8000 --workers 4
```

#### Unsupported Raw Uvicorn Commands (Rejected by Fail-Closed Production Lifespan)
The following raw Uvicorn CLI invocations are **unsupported in production** and will abort during `lifespan` startup (`RuntimeError` -> `sys.exit(3)`):
- `uvicorn app.main:app ...`
- `uvicorn app.main:create_app --factory ...`
- Any invocation with `--forwarded-allow-ips="*"` or `FORWARDED_ALLOW_IPS="*"` or `UVICORN_FORWARDED_ALLOW_IPS="*"`.

---

### 19.6 Request-Time Client IP Resolution & Process-Local IP Rate Limiter
- `resolve_client_ip(request: Request) -> str` reads **only** normalized `request.client.host` (never reads `X-Forwarded-For`).
- Parses `ipaddress.ip_address(request.client.host)` and returns canonical `str(ip)`; returns `"unknown"` if `request.client` is `None`/empty, or `"invalid-client-ip"` (with a sanitized warning) if `request.client.host` is not a valid IP address.
- Sliding-window IP rate limits (`429 RATE_LIMIT_EXCEEDED` + `Retry-After`, max 50,000 keys):
  - `/register`, `/resend-verification`, `/forgot-password`: **5 / 15 min / IP**.
  - `/login`, `/verify-email`, `/reset-password`, `/oauth/exchange`: **10 / 15 min / IP**.
  - `/oauth/{provider}/start`, `/oauth/{provider}/callback`: **20 / 15 min / IP**.
  - `/refresh`, `/change-password`: **30 / 15 min / IP**.

---

## 20. Testing Strategy and Acceptance Criteria

All tests execute against the isolated test PostgreSQL database (`folio360_test`) using synchronous `TestClient` and mocked external HTTP boundaries (zero live Resend/Google/GitHub calls in automated tests).

### 20.1–20.3 Baseline, Migration & Cookie Tests
1. **Stage 1 & Stage 2 Regression:** All 81 existing tests pass with 0 failures and 0 skips.
2. **Per-Stage Migration Tests:** Clean DB `upgrade head`, populated Stage 2 `0001_create_users` upgrade, `upgrade -> downgrade -> upgrade`, `alembic check` exit code `0`, and least-privilege `folio360_app` DML permissions.
3. **Deployment-Aware Cookie & Startup Validation Tests (3A):** Dev defaults, Mode 1 same-site prod, Mode 2 cross-site prod, rejection of incompatible cookie/CORS configs, and zero cookies for `X-Client-Type: mobile`.

### 20.4 Mandatory Uvicorn Proxy Configuration & Bypass Regression Tests (Stage 3A — 14 Required Tests)

| # | Test Scenario | Setup | Action | Expected Result | Security Property Protected |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **Raw Uvicorn CLI with `--factory` and wildcard forwarded trust** | `ENVIRONMENT="production"`, valid production settings (`PROXY_HEADERS_ENABLED=True`, `TRUSTED_PROXY_IPS=["10.0.0.1"]`). | Invoke raw `uvicorn.Config("app.main:create_app", factory=True, proxy_headers=True, forwarded_allow_ips="*")` (or CLI runner) and execute `LifespanOn(config).startup()`. | `LifespanOn.startup()` fails (`startup_failed is True`, `should_exit is True`) with `RuntimeError` before any request is served; `create_verified_app` does not exist. | Prevents raw `uvicorn --factory --forwarded-allow-ips="*"` CLI bypass (Attack Scenario A). |
| **2** | **Raw Uvicorn CLI with conflicting `--proxy-headers` value** | `ENVIRONMENT="production"`, `PROXY_HEADERS_ENABLED=False`, `TRUSTED_PROXY_IPS=[]` (or `PROXY_HEADERS_ENABLED=True` with `--no-proxy-headers`). | Run raw `uvicorn.Config("app.main:create_app", factory=True, proxy_headers=True, forwarded_allow_ips="10.0.0.1")` or `app.server` CLI with conflicting `--proxy-headers` / `--no-proxy-headers`. | Rejected before serving requests (`RuntimeError` / non-zero CLI exit; `LifespanOn.should_exit is True`). | Prevents CLI `--proxy-headers` / `--no-proxy-headers` drift from authoritative `Settings`. |
| **3** | **Raw programmatic `uvicorn.Config` with wildcard forwarded trust** | `ENVIRONMENT="production"`, valid `settings` (`PROXY_HEADERS_ENABLED=True`, `TRUSTED_PROXY_IPS=["10.0.0.1"]`). | Construct `app = create_app(settings)` and raw `config = uvicorn.Config(app, proxy_headers=True, forwarded_allow_ips="*")`, then run `LifespanOn(config).startup()`. | `lifespan(app)` raises `RuntimeError`; `LifespanOn.startup_failed is True` and `should_exit is True`. | Prevents raw programmatic `uvicorn.Config(..., forwarded_allow_ips="*")` bypass (Attack Scenario B). |
| **4** | **Raw programmatic `uvicorn.Config` with conflicting proxy-header configuration** | `ENVIRONMENT="production"`, `settings` with `PROXY_HEADERS_ENABLED=True`, `TRUSTED_PROXY_IPS=["10.0.0.1"]`. | Construct raw `config = uvicorn.Config(create_app(settings), proxy_headers=False)` (or `forwarded_allow_ips="10.0.0.2"`) and run `LifespanOn(config).startup()`. | `lifespan(app)` raises `RuntimeError`; startup aborts (`should_exit is True`). | Prevents raw programmatic `uvicorn.Config` from overriding `PROXY_HEADERS_ENABLED` or `TRUSTED_PROXY_IPS`. |
| **5** | **Safe `Settings` policy combined with unsafe programmatic override on launcher** | Valid `settings` (`PROXY_HEADERS_ENABLED=True`, `TRUSTED_PROXY_IPS=["10.0.0.1"]`). | Call `build_uvicorn_config(settings, forwarded_allow_ips="*")`, `build_uvicorn_config(settings, proxy_headers=False)`, or `VerifiedUvicornConfig(create_app(settings), settings=settings, forwarded_allow_ips="*")`. | Raises `RuntimeError` immediately during config construction before `config.load()` or `Server.run()`. | Prevents unsafe keyword overrides passed to the controlled launcher. |
| **6** | **Factory-created application cannot self-certify outer Uvicorn configuration** | `ENVIRONMENT="production"`, valid `settings`. | Call `app = create_app(settings)` directly and inspect `_VERIFIED_APP_REGISTRY.get(id(app))` and `app.state`. | `_VERIFIED_APP_REGISTRY.get(id(app))` is `None`; no verification stamp exists on `app.state`; entering `TestClient(app)` in production mode raises `RuntimeError`. | Enforces the factory trust boundary: a factory never certifies an uninspected outer Uvicorn `Config`. |
| **7** | **Production lifespan rejects application without valid effective-configuration verification** | `ENVIRONMENT="production"`, valid `settings`, `app = create_app(settings)`. | Enter `TestClient(app)` (or run `LifespanOn` without `VerifiedUvicornConfig.load()`). | `lifespan(app)` raises `RuntimeError("Unverified ASGI startup...")` before yielding. | Guarantees fail-closed production startup whenever `VerifiedUvicornConfig.load()` did not verify the app. |
| **8** | **Production lifespan rejects verification record that does not match actual application/configuration** | `ENVIRONMENT="production"`, valid `config = build_uvicorn_config(settings)` (so `config.load()` registers the app). | Mutate `config.forwarded_allow_ips = "*"`, or `config.proxy_headers = not settings.PROXY_HEADERS_ENABLED`, or replace `config.loaded_app` with an unverified wrapper (or look up a record belonging to another `app` instance / PID) before entering `lifespan(app)`. | `verify_production_asgi_trust_boundary(app, settings)` detects the live mismatch via `config_ref()` / `loaded_app_ref()` and raises `RuntimeError`. | Prevents post-load mutation or cross-instance replay of a verification record. |
| **9** | **Controlled launcher starts valid direct deployment** | `ENVIRONMENT="production"`, `PROXY_HEADERS_ENABLED=False`, `TRUSTED_PROXY_IPS=[]`. | Call `config = build_uvicorn_config(settings)` and run `LifespanOn(config).startup()`. | `config.proxy_headers is False`, `config.loaded_app is app` (no `ProxyHeadersMiddleware`), `LifespanOn.startup_failed is False`, and requests ignore spoofed `X-Forwarded-For`. | Preserves safe direct-deployment startup and IP resolution. |
| **10** | **Controlled launcher starts valid trusted-reverse-proxy deployment** | `ENVIRONMENT="production"`, `PROXY_HEADERS_ENABLED=True`, `TRUSTED_PROXY_IPS=["10.0.0.1", "172.16.0.0/12"]`. | Call `config = build_uvicorn_config(settings)` and run `LifespanOn(config).startup()`. | `isinstance(config.loaded_app, ProxyHeadersMiddleware)` is `True`, `always_trust is False`, `trusted_literals == set()`, and `LifespanOn.startup_failed is False`. | Preserves safe reverse-proxy deployment startup. |
| **11** | **Multi-worker startup validates each worker's effective configuration** | `ENVIRONMENT="production"`, `PROXY_HEADERS_ENABLED=True`, `TRUSTED_PROXY_IPS=["10.0.0.1"]`, `workers=2`. | Build `config = build_uvicorn_config(settings, app="app.main:create_app", factory=True, workers=2)` (`config.loaded is False` in parent), simulate/spawn worker execution (`pickle.loads(pickle.dumps(config))`), call `worker_config.load()` and `LifespanOn(worker_config).startup()`. | Deserialized `worker_config` is a `VerifiedUvicornConfig`; `worker_config.load()` verifies policy, `Config`, and `ProxyHeadersMiddleware` inside the worker, registers `_VERIFIED_APP_REGISTRY` for the worker PID, and `LifespanOn` succeeds. | Guarantees every multi-worker child process independently verifies its effective configuration and middleware. |
| **12** | **Worker with mismatched or unsafe configuration fails before serving requests** | `ENVIRONMENT="production"`, multi-worker `worker_config = pickle.loads(pickle.dumps(config))`. | Inject a conflicting worker environment (`FORWARDED_ALLOW_IPS="*"` or `UVICORN_FORWARDED_ALLOW_IPS="*"`) or mutate `worker_config.forwarded_allow_ips = "*"` in the worker before `worker_config.load()` / `Server.startup()`. | Worker `worker_config.load()` / `LifespanOn.startup()` fails (`RuntimeError`, `Server.startup()` exits with `STARTUP_FAILURE == 3`), causing `Multiprocess` parent supervisor to stop. | Prevents a compromised or misconfigured worker subprocess from serving traffic. |
| **13** | **Valid single-hop and multi-hop trusted proxy resolution** | `config = build_uvicorn_config(settings)` with `PROXY_HEADERS_ENABLED=True`, `TRUSTED_PROXY_IPS=["10.0.0.1", "10.0.0.2"]`. | Send requests through `config.loaded_app` from peer `10.0.0.1` with single-hop `X-Forwarded-For: spoof, 203.0.113.10` and multi-hop `X-Forwarded-For: spoof, 203.0.113.10, 10.0.0.2`, plus malformed/missing `X-Forwarded-For`. | Single-hop and multi-hop resolve `203.0.113.10`; missing header keeps `10.0.0.1`; malformed non-IP maps to `"invalid-client-ip"`. | Preserves accurate right-to-left client-IP extraction and rate-limit bucket integrity. |
| **14** | **Existing Stage 1 and Stage 2 regression tests remain unaffected** | Full Stage 1 (43 tests) and Stage 2 (38 tests) suite (`ENVIRONMENT="development"` / `"testing"`). | Execute `pytest` across all existing test files. | All 81 existing tests pass with 0 failures and 0 skips (`create_app()` remains import-safe and usable in dev/test `TestClient` without requiring `build_uvicorn_config`). | Preserves Stage 1 and Stage 2 backward compatibility. |

### 20.5–20.10 Remaining Stage 3A, 3B, and 3C Mandatory Test Suites (Preserved Intact)
- **Resend Delivery Failure, First-Retry & Cooldown Tests (3A & 3B):** Initial failure (`verification_email_sent: false`, unverified user preserved) -> immediate 0s first retry succeeds -> second consecutive failure enforces 10s backoff -> retry after 10s succeeds -> `'sent'` enforces 60s gap and 3/hr cap -> stale `'pending'` (`>30s`) recovers -> two-thread concurrent resend requests serialize via `users` `FOR UPDATE` -> failure never duplicates user account.
- **`auth_version` & Refresh Rotation Concurrency Tests (3A):** Integer `ver` checks, same-second `logout-all` invalidation, family replay revocation, and two-thread concurrent `/refresh` serialization.
- **Deterministic Password Change & Reset Concurrency Tests (3B):** Two-thread concurrent `change-password` vs `change-password`, concurrent `reset-password` vs `reset-password` (same token and two distinct tokens), concurrent `reset-password` vs `change-password`, mid-transaction rollback atomicity, and OAuth-only rejection (`400 PASSWORD_NOT_SET` / silent `202` on forgot-password).
- **Google OIDC Audience (`aud`), Trusted Additional Audiences & Authorized-Presenter (`azp`) Tests (3C — All 10 Tests):** (1) `aud` as expected client ID string; (2) `aud` as 1-element array; (3) multi-audience with only allowlisted `GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES` + valid `azp`; (4) multi-audience with untrusted additional audience rejected even when `azp == GOOGLE_CLIENT_ID`; (5) missing `azp` on multi-audience token rejected; (6) incorrect `azp` rejected; (7) unexpected `azp` on single-audience token rejected; (8) empty audience rejected; (9) malformed audience types rejected; (10) duplicate audience values rejected (`len(aud) != len(set(aud))`); plus `iss`, `exp`, `nbf`, `nonce`, `sub`, `email_verified is True`, AES-256-GCM AEAD + `_PREVIOUS` rotation, **`folio360_oauth_binding`** cookie lifecycle, and safe `urllib.parse` redirect query builder.
- **GitHub Paginated `/user/emails` & OAuth Provisioning Tests (3C — All 9 Tests):** First-page match, later-page match (`Link` `rel="next"`), no suitable email across pages (`verified_email_required`), cross-page duplicate handling, repeated pagination link loop rejection, malformed/cross-host pagination URL rejection, page-limit reached (`GITHUB_EMAILS_MAX_PAGES`) fail-closed rejection, timeout rejection, non-200 rejection, existing linked user login bypass, no auto-merge (`email_already_registered`), and two-thread concurrent first-time OAuth callback.
- **Security & Redaction Tests (3A–3C):** 422 `RequestValidationError` never echoes secrets; `SecurityFilter` / `sanitize_log_text` redacts `re_...`, PKCE/verifier/key fields, `id_token`, cookies, and passwords.

---

## 21. Configuration and Environment Variables

All new fields live in `Settings` ([app/core/config.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/core/config.py)) using `SecretStr` for secrets. `Settings()` remains constructible with zero auth env vars in dev/test; production requirements are enforced in `validate_runtime_requirements()`.

| Env Variable | Type | Default (Dev/Test) | Production Requirement | Stage |
| :--- | :--- | :--- | :--- | :--- |
| `JWT_SECRET_KEY` | `SecretStr \| None` | `None` | **Required**, `>= 32` chars | 3A |
| `JWT_ISSUER` | `str` | `"folio360"` | Non-empty | 3A |
| `JWT_AUDIENCE` | `str` | `"folio360-api"` | Non-empty | 3A |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `int` | `15` (`ge=1, le=60`) | Same | 3A |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `int` | `14` (`ge=1, le=30`) | Same | 3A |
| `REFRESH_TOKEN_ABSOLUTE_EXPIRE_DAYS` | `int` | `30` (`ge=1, le=90`, `>= REFRESH_TOKEN_EXPIRE_DAYS`) | Same | 3A |
| `COOKIE_DEPLOYMENT_MODE` | `Literal["same_site", "cross_site"]` | `"same_site"` | Explicit `"same_site"` or `"cross_site"` | 3A |
| `REFRESH_COOKIE_NAME` | `str` | `"folio360_refresh_token"` | Non-empty | 3A |
| `REFRESH_COOKIE_SECURE` | `bool` | `False` | **Must be `True`** | 3A |
| `REFRESH_COOKIE_SAMESITE` | `Literal["lax", "strict", "none"]` | `"lax"` | `"lax"`/`"strict"` in `same_site`; `"none"` in `cross_site` | 3A |
| `REFRESH_COOKIE_DOMAIN` | `str \| None` | `None` | Optional in `same_site`; must be `None` in `cross_site` | 3A |
| `FRONTEND_BASE_URL` | `str` | `"http://localhost:5173"` | **Required**, `https://` | 3A |
| `EMAIL_VERIFICATION_EXPIRE_HOURS` | `int` | `24` (`ge=1, le=72`) | Same | 3A |
| `EMAIL_COOLDOWN_SECONDS` | `int` | `60` | Same | 3A |
| `EMAIL_MAX_PER_HOUR` | `int` | `3` | Same | 3A |
| `EMAIL_FAILED_RETRY_BACKOFF_SECONDS` | `int` | `10` | Applies to 2nd+ consecutive failed retries | 3A |
| `EMAIL_PENDING_STALE_SECONDS` | `int` | `30` | Same | 3A |
| `EMAIL_SEND_TIMEOUT_SECONDS` | `float` | `5.0` (`ge=1.0, le=15.0`) | Same | 3A |
| `RESEND_API_KEY` | `SecretStr \| None` | `None` | **Required** | 3A |
| `EMAIL_FROM_ADDRESS` | `str` | `"no-reply@folio360.local"` | **Required**, verified Resend sender | 3A |
| `RATE_LIMIT_ENABLED` | `bool` | `True` | **Must be `True`** | 3A |
| `PROXY_HEADERS_ENABLED` | `bool` | `False` | `False` (direct) or `True` (with valid `TRUSTED_PROXY_IPS`) | 3A |
| `TRUSTED_PROXY_IPS` | `list[str]` | `[]` | Empty when `PROXY_HEADERS_ENABLED=False`; exact IPs/CIDRs (never `"*"` or hostnames) when `True` | 3A |
| `PASSWORD_RESET_EXPIRE_MINUTES` | `int` | `30` (`ge=5, le=120`) | Same | 3B |
| `BACKEND_BASE_URL` | `str` | `"http://localhost:8000"` | **Required**, `https://` | 3C |
| `OAUTH_BINDING_COOKIE_NAME` | `str` | `"folio360_oauth_binding"` | Default `"folio360_oauth_binding"` | 3C |
| `OAUTH_PKCE_ENCRYPTION_KEY` | `SecretStr \| None` | `None` | **Required** when OAuth enabled; base64url 32 bytes | 3C |
| `OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS` | `SecretStr \| None` | `None` | Optional 32-byte rotation key | 3C |
| `GOOGLE_CLIENT_ID` | `str \| None` | `None` | Required when Google OAuth enabled | 3C |
| `GOOGLE_CLIENT_SECRET` | `SecretStr \| None` | `None` | Required when Google OAuth enabled | 3C |
| `GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES` | `list[str]` | `[]` | Default `[]` (strict single-client); exact non-empty client IDs if configured (never `"*"`) | 3C |
| `GITHUB_CLIENT_ID` | `str \| None` | `None` | Required when GitHub OAuth enabled | 3C |
| `GITHUB_CLIENT_SECRET` | `SecretStr \| None` | `None` | Required when GitHub OAuth enabled | 3C |
| `OAUTH_ALLOWED_WEB_REDIRECT_URIS` | `list[str]` | `["http://localhost:5173/auth/oauth/callback"]` | Exact `https://` URLs only | 3C |
| `OAUTH_ALLOWED_MOBILE_REDIRECT_URIS` | `list[str]` | `["folio360://auth/callback"]` | Exact app deep-link / universal-link URIs | 3C |
| `OAUTH_STATE_EXPIRE_MINUTES` | `int` | `10` | Same | 3C |
| `OAUTH_EXCHANGE_CODE_EXPIRE_SECONDS` | `int` | `60` | Same | 3C |
| `OAUTH_HTTP_TIMEOUT_SECONDS` | `float` | `5.0` | Same | 3C |
| `GITHUB_EMAILS_PER_PAGE` | `int` | `100` (`ge=1, le=100`) | Same | 3C |
| `GITHUB_EMAILS_MAX_PAGES` | `int` | `10` (`ge=1, le=20`) | Same | 3C |

---

## 22. Incremental Implementation Plan, Stage Gates, and Git Governance

### Stage Execution Gates
1. **Stage 3A — Core Auth, Email Verification & Rotating Refresh Sessions (`0002_add_core_auth_tables`):**
   - Scope: 422 `RequestValidationError` input stripping, `AppException.headers`, extended log redaction, `app/server.py` (`VerifiedUvicornConfig`, `build_uvicorn_config`, `run_server`, `_VERIFIED_APP_REGISTRY`, 3-layer proxy verification) + `lifespan` `verify_production_asgi_trust_boundary` + `resolve_client_ip` + sliding-window IP rate limiter, deployment-aware cookies, `security.py`, `email_service.py` (Resend + first-retry/10s-subsequent-backoff state machine), and 8 endpoints (`/register`, `/verify-email`, `/resend-verification`, `/login`, `/refresh`, `/logout`, `/logout-all`, `/me`).
   - Technical Gate: All 81 Stage 1/2 tests + all Stage 3A tests (including all 14 Uvicorn proxy-bypass regression tests, first-retry vs 10s-backoff tests, concurrent resend tests, cookie-mode tests, and `0002` migration tests) pass; `alembic check` exits `0`; independent read-only review passes.
2. **Stage 3B — Password Recovery & Authenticated Password Change (`0003_add_password_reset_tokens`):**
   - Scope: `password_reset_tokens`, reset email template, `/forgot-password`, `/reset-password`, `/change-password` with strict `users`-first row locking and atomic session/version updates.
   - Technical Gate: All Stage 1/2/3A tests + all Stage 3B tests (including change/change, reset/reset, reset/change concurrency tests, rollback atomicity, and `0003` migration tests) pass; `alembic check` exits `0`; independent read-only review passes.
3. **Stage 3C — Google OIDC & GitHub OAuth 2.0 (`0004_add_oauth_tables`):**
   - Scope: `oauth_accounts`, `oauth_states` (`pkce_verifier_encrypted`), `oauth_exchange_codes`, AES-256-GCM PKCE encryption, **`folio360_oauth_binding`** cookie, safe `urllib.parse` redirect builder, Google OIDC (with `GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES` + full `aud`/`azp` validation), GitHub PKCE `S256` + bounded paginated `/user/emails` + deterministic email selection, `/oauth/{provider}/start`, `/oauth/{provider}/callback`, `/oauth/exchange`, and `oauth_providers` on `/me`.
   - Technical Gate: All Stage 1/2/3A/3B tests + all Stage 3C tests (including all 10 `aud`/`azp` additional-audience trust tests, all 9 GitHub pagination tests, AEAD tests, binding-cookie tests, concurrent OAuth provisioning tests, and `0004` migration tests) pass; `alembic check` exits `0`; independent read-only review passes; **controlled live Google confidential web-server PKCE verification (§16.4) executed before production release acceptance**.

### Mandatory Git Operation Authorization Governance
Passing a technical stage gate or receiving implementation authorization **never** implies permission for Git operations. Each category requires separate, explicit owner authorization:
1. **Implementation Authorization:** Editing/creating approved stage files, running migrations on dev/test DBs, executing tests.
2. **Git Staging Authorization (`git add`):** Separate explicit authorization listing exact files.
3. **Local Commit Authorization (`git commit`):** Separate explicit authorization after staging inspection.
4. **Remote Push Authorization (`git push`):** Separate explicit authorization.
5. **Branch, Remote, or History Operations (`checkout`, `branch`, `rebase`, `amend`, `reset`, `remote`):** Separate explicit authorization.

---

## 23. Risks, Limitations, Deferred Features, and Consistency Checklist

### Known Risks & Accepted MVP Limitations
1. **Cross-Site Third-Party Cookie Blocking (Mode 2):** Safari ITP, Firefox ETP, Brave Shields, and Chrome privacy settings may block `SameSite=None` cookies; Mode 1 (same-site deployment) is recommended in production.
2. **Google Confidential Web-Server PKCE Live Verification:** Requires controlled live verification with a real Google Cloud Web Application OAuth client prior to Stage 3C production release (§16.4).
3. **Uvicorn Internal Attribute Dependency (`uvicorn==0.54.0`):** `verify_loaded_asgi_middleware` inspects `ProxyHeadersMiddleware.app` and `trusted_hosts` (`always_trust`, `trusted_literals`, `trusted_hosts`, `trusted_networks`); protected by pinning `uvicorn==0.54.0` in `requirements.txt`, fail-closed attribute access, and the 14 mandatory regression tests (§19.4, §20.4).
4. **Process-Local IP Rate Limiter:** Per-IP allowance scales with worker count $W$; PostgreSQL email cooldowns and token revocations are globally shared.
5. **Resend Crash Window:** Process crash between Tx 1 commit (`'pending'`) and Tx 2 requires user retry after `30s` stale-pending threshold (outbox deferred).
6. **Expired Token Accumulation:** Periodic cleanup job deferred post-Phase 0 (`expires_at` indexes are in place).
7. **Deferred Features (Schema-Prepared):** Explicit authenticated account linking, local password creation for OAuth-only accounts, `GET /sessions` & `DELETE /sessions/{id}`, MFA/passkeys, RBAC/profiles, Redis rate limiting, and transactional email outbox.

### Rev5 Consistency and Regression Checklist
- [x] **Q1–Q11 Preserved Unchanged:** All 11 owner-approved architectural decisions remain intact without reopening or weakening.
- [x] **Factory Self-Stamping Eliminated:** `create_verified_app()` is removed; `create_app()` never issues a proxy verification stamp.
- [x] **Three Verification Concepts Separated:** Configured proxy policy (`validate_proxy_policy`), effective Uvicorn `Config` (`validate_effective_uvicorn_config`), and post-load ASGI middleware wrapper (`verify_loaded_asgi_middleware`) are validated distinctly.
- [x] **Attack Scenario A & B Closed:** Both raw `uvicorn --factory --forwarded-allow-ips="*"` CLI launches and raw `uvicorn.Config(create_app(settings), forwarded_allow_ips="*")` programmatic launches fail closed during production `lifespan` startup before serving any request.
- [x] **Multi-Worker Verification Verified:** `VerifiedUvicornConfig` is pickled across `spawn.Process` to each worker, where `VerifiedUvicornConfig.load()` and `lifespan()` validate that worker's effective `Config` and outer `ProxyHeadersMiddleware` independently, aborting parent supervisor startup on `STARTUP_FAILURE` (`3`).
- [x] **All Rev4 Controls Preserved:** Google OIDC `GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES` (`[]` default) + 10 `aud`/`azp` tests, GitHub bounded pagination + 9 tests, Resend 0s first-retry / 10s subsequent-failure backoff, `users`-first locked password change/reset, AES-256-GCM PKCE encryption, deployment-aware cookies, and Stage 3A/3B/3C migration separation remain intact.

---

## Final Rev5 Revision Report

### 1. What Changed (Rev4 -> Rev5)
- **Removed `create_verified_app()` and Factory-Level Stamping (§2, §5, §6, §19.2):** `create_app()` in [app/main.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/main.py) is the sole application factory and never certifies or stamps Uvicorn proxy state.
- **Separated Three Verification Concepts (§19.1):** Defined separate validators for (1) configured proxy policy (`validate_proxy_policy`), (2) effective Uvicorn `Config` (`validate_effective_uvicorn_config`), and (3) post-load ASGI middleware wrapper (`verify_loaded_asgi_middleware`).
- **Introduced `VerifiedUvicornConfig(uvicorn.Config)` & `_VERIFIED_APP_REGISTRY` (§19.3):** Verification runs inside `VerifiedUvicornConfig.load()` **after** `super().load()` constructs the outer `ProxyHeadersMiddleware`, recording a weakref-backed `_VerifiedBindingRecord` in module-private `_VERIFIED_APP_REGISTRY[id(fastapi_app)]` keyed by `id(app)` and `os.getpid()`.
- **Added Live Re-Verification in Production `lifespan` (§19.3.C):** `verify_production_asgi_trust_boundary(app, settings)` dereferences the live `VerifiedUvicornConfig` and `config.loaded_app` weakrefs during `lifespan` startup and re-runs all three checks.
- **Added 14 Explicit Regression Tests (§20.4):** Documented Setup, Action, Expected Result, and Protected Security Property for every CLI, programmatic, factory, post-load mutation, and multi-worker bypass scenario.

### 2. How the Raw CLI Bypass Is Prevented
Because `create_verified_app()` no longer exists and `create_app()` never registers an entry in `_VERIFIED_APP_REGISTRY`, any raw `uvicorn` CLI invocation (e.g., `uvicorn app.main:create_app --factory --forwarded-allow-ips="*"` or `uvicorn app.main:app --proxy-headers`) uses standard `uvicorn.Config` rather than `VerifiedUvicornConfig`. When Uvicorn enters `LifespanOn.startup()` in `ENVIRONMENT == "production"`, `verify_production_asgi_trust_boundary(app, settings)` finds no `_VerifiedBindingRecord` for `id(app)` (and also rejects any wildcard/conflicting `FORWARDED_ALLOW_IPS` or `UVICORN_*` env vars), raises `RuntimeError`, and causes `Server.startup()` to exit immediately with `STARTUP_FAILURE` (`3`) before serving any request.

### 3. How the Raw Programmatic Bypass Is Prevented
Constructing `uvicorn.Config(create_app(settings), proxy_headers=True, forwarded_allow_ips="*")` passes an unverified `FastAPI` instance to standard `uvicorn.Config`. Because `VerifiedUvicornConfig.load()` never ran, `_VERIFIED_APP_REGISTRY.get(id(app))` is `None`, and production `lifespan` fails closed with `RuntimeError`. Passing unsafe overrides to `build_uvicorn_config(settings, forwarded_allow_ips="*")` or `VerifiedUvicornConfig(..., forwarded_allow_ips="*")` is rejected immediately in `VerifiedUvicornConfig.__init__`, and any post-load mutation of `config.forwarded_allow_ips`, `config.proxy_headers`, or `config.loaded_app` is caught when `lifespan` dereferences `config_ref()` and `loaded_app_ref()` and re-verifies Concepts 1–3 live.

### 4. How Multi-Worker Verification Works
In `uvicorn==0.54.0`, `Multiprocess` spawns worker subprocesses via `multiprocessing.get_context("spawn")` (`uvicorn/_subprocess.py` lines 18, 44–51), pickling the `VerifiedUvicornConfig` instance to each child worker with `config.loaded == False`. Inside each child worker process, `Server._serve()` calls `config.load()` (`VerifiedUvicornConfig.load()`) **before** `self.lifespan.startup()` (`uvicorn/server.py` lines 96–118). Each worker therefore independently runs `super().load()`, executes Concepts 1, 2, and 3 against its own process environment, its own `VerifiedUvicornConfig`, and its own `ProxyHeadersMiddleware` wrapper, registers its worker-local `_VerifiedBindingRecord` for `os.getpid()`, and re-verifies it inside `lifespan`. If any worker fails verification, `Server.startup()` exits with `STARTUP_FAILURE` (`3`), and `Multiprocess.keep_subprocess_alive()` (`uvicorn/supervisors/multiprocess.py` lines 225–231) immediately terminates the parent supervisor process.

### 5. Verified Official Uvicorn Implementation Details (`uvicorn==0.54.0`)
- `uvicorn/__init__.py` (line 4): `__version__ = "0.54.0"`.
- `uvicorn/main.py` (lines 61, 232–257, 561–640): Click `auto_envvar_prefix="UVICORN"`, CLI flags `--proxy-headers` / `--forwarded-allow-ips`, and `Multiprocess` vs. single-process dispatch.
- `uvicorn/config.py` (lines 24, 225, 361–365, 439–546): `STARTUP_FAILURE = 3`, default `proxy_headers=True`, fallback `FORWARDED_ALLOW_IPS="127.0.0.1,::1"`, and `Config.load()` execution order (factory call at line 514 before `ProxyHeadersMiddleware` wrapping at lines 543–544).
- `uvicorn/middleware/proxy_headers.py` (lines 24–27, 105–187): `ProxyHeadersMiddleware.app` and `_TrustedHosts` attributes (`always_trust`, `trusted_literals`, `trusted_hosts`, `trusted_networks`).
- `uvicorn/lifespan/on.py` (lines 47–101) & `uvicorn/server.py` (lines 92–119): `LifespanOn.startup()` failure handling and `Server.startup()` `sys.exit(STARTUP_FAILURE)`.
- `uvicorn/_subprocess.py` (lines 18–81) & `uvicorn/supervisors/multiprocess.py` (lines 26–232): `spawn` pickling of `Config` to worker processes and parent shutdown on child `STARTUP_FAILURE`.

### 6. Regression Tests Added
Added the 14 mandatory regression tests in §20.4 covering raw CLI `--factory` wildcard bypass (Test 1), raw CLI conflicting `--proxy-headers` (Test 2), raw programmatic `uvicorn.Config` wildcard bypass (Test 3), raw programmatic conflicting `proxy_headers` (Test 4), safe `Settings` + unsafe launcher override (Test 5), factory inability to self-certify (Test 6), production lifespan rejection of unverified app (Test 7), production lifespan rejection of mutated/mismatched verification record (Test 8), controlled launcher direct mode (Test 9), controlled launcher trusted-proxy mode (Test 10), multi-worker per-worker verification (Test 11), multi-worker mismatched worker failure aborting startup (Test 12), single-hop/multi-hop IP resolution (Test 13), and full Stage 1/2 81-test regression compatibility (Test 14).

### 7. Remaining Security Concerns, Assumptions & Preservation Confirmation
- **Unresolved Security Concerns:** **None.**
- **Q1–Q11 & Approved Architecture Preservation:** Confirmed that all Q1–Q11 decisions, Stage 3A/3B/3C migration boundaries (`0002`, `0003`, `0004`), API contracts, and Rev1–Rev4 security requirements remain 100% intact.
- **Read-Only Confirmation:** Confirmed that no repository files, source code, migrations, Docker state, or Git state were modified during this Rev5 specification turn.

### Recommendation
**READY FOR INDEPENDENT REVIEW** (awaiting project-owner review and explicit approval before any Stage 3A implementation work begins).
