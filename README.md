# Folio360 / Student360 Backend

**Folio360: A User-Centred Unified Profile for Academic, Professional, and Lifelong Learning Records.**

Folio360 is a digital identity and portfolio platform for academic qualifications, semester records, skills, certifications, internships, projects, and work experience.

This repository houses the core Phase 0 backend API service (Stages 1, 2, 3A, 3B, and 3C.1–3C.7 completed and formally accepted).

---

## Authoritative Specifications

- **Phase 0 Stage 3A & 3B (Core Auth, Email Verification, Password Reset & Change):**
  - [`F360-P0-AUTH-SPEC-REV10.md`](F360-P0-AUTH-SPEC-REV10.md) ([review report](F360-P0-AUTH-SPEC-REV10-REVIEW-REPORT.md))
- **Phase 0 Stage 3C (Google OIDC & GitHub OAuth 2.0, Stages 3C.1–3C.7):**
  - Authoritative specification: `F360-S3C-SPEC-REV12` (`Supersedes: REV1–REV11`, verified SHA-256: `f83ef10096caf9b3d7d264cd10b9ff3a3822b594a4de9ff9d5e90a1834643f83`)
- **Historical Archive:** Superseded drafts (`REV3`–`REV9`) are retained for audit traceability in [`docs/archive/superseded_specs/`](docs/archive/superseded_specs/README.md) and must not be used as implementation authority.
- **Future Phases:** Profile Creation (Phase 1 / next phase) and subsequent academic/portfolio stages remain unstarted pending separate specification approval.

---

## Architecture & Technology Stack (Phase 0 Stages 1–3C)

- **Language & Container Runtime:** Python 3.13 (`python:3.13-slim` via Docker; host dev `.venv` Python 3.12+)
- **Framework:** FastAPI (`Folio360FastAPI` ASGI3 subclass enforcing `VerifiedUvicornConfig` in production)
- **Validation & Settings:** Pydantic v2 & `pydantic-settings`
- **Server Runtime:** Uvicorn with `uvloop` (`python -m app.server`)
- **Database & ORM:** PostgreSQL 17, synchronous SQLAlchemy 2.0, `psycopg` v3 (`postgresql+psycopg://...`)
- **Migrations:** Alembic linear chain:
  1. `0001_create_users` (Stage 2 baseline)
  2. `0002_add_core_auth_tables` (Stage 3A users extension, `email_verification_tokens`, `refresh_sessions`)
  3. `0003_add_password_reset_tokens` (Stage 3B `password_reset_tokens`)
  4. `0004_add_oauth_tables` (Stage 3C `oauth_accounts`, `oauth_states`, `oauth_exchange_codes`)
- **Cryptography & Integrations:** `argon2-cffi` (Argon2id), `PyJWT[crypto]` (`HS256` session JWTs + `RS256` Google ID token verification via `HttpxJWKClient`), `cryptography` (AES-256-GCM PKCE verifier encryption with key-rotation grace window), `httpx` (bounded streaming transport), `resend` (verification and password-reset emails).

### Module Layout

```text
Folio360_backend/
├── .env.example                            # Environment variable template (placeholders only)
├── Dockerfile                              # Non-root python:3.13-slim image
├── docker-compose.yml                      # db, db_test, api, migrator, and py313 test services
├── pytest.ini                              # Pytest markers (db, migration) and testpaths
├── requirements.in / requirements.txt      # Direct & pinned dependencies
├── docs/archive/superseded_specs/          # Archived superseded spec drafts
├── alembic/
│   ├── env.py                              # Synchronous NullPool Alembic env (MIGRATION_DATABASE_URL)
│   └── versions/
│       ├── 0001_create_users.py
│       ├── 0002_add_core_auth_tables.py
│       ├── 0003_add_password_reset_tokens.py
│       └── 0004_add_oauth_tables.py
├── app/
│   ├── main.py                             # Folio360FastAPI, lifespan, ASGI middleware & router wiring
│   ├── server.py                           # VerifiedUvicornConfig & proxy trust boundary
│   ├── api/
│   │   ├── deps/auth.py                    # Bearer JWT auth, X-Client-Type, Origin CSRF, rate limits
│   │   └── routes/
│   │       ├── health.py                   # /api/v1/health & /api/v1/health/ready
│   │       ├── auth.py                     # Stage 3A/3B routes + /auth/me (with oauth_providers)
│   │       └── oauth.py                    # Stage 3C /auth/oauth/* routes
│   ├── core/
│   │   ├── config.py                       # Immutable Settings + strict startup validation
│   │   ├── crypto_keys.py                  # Stdlib-only canonical 32-byte base64url key decoder
│   │   ├── exceptions.py                   # Safe AppException + 422 input stripping
│   │   ├── logging.py                      # SecurityFilter, UvicornAccessSanitizingFilter & redaction
│   │   ├── oauth_middleware.py             # OAuthSecurityResponseMiddleware + cookie clear helpers
│   │   ├── rate_limit.py                   # Bounded sliding-window IP rate limiter
│   │   ├── security.py                     # Argon2id, opaque SHA-256 tokens, HS256 JWT, PKCE, AES-GCM
│   │   └── uri_policy.py                   # Auth/email & OAuth redirect URI validation policy
│   ├── db/
│   │   ├── base.py                         # Naming convention, declarative Base, TimestampMixin
│   │   └── session.py                      # Pooled engine, sessionmaker, readiness probe, get_db
│   ├── models/
│   │   ├── user.py                         # User
│   │   ├── email_verification_token.py     # EmailVerificationToken
│   │   ├── password_reset_token.py         # PasswordResetToken
│   │   ├── refresh_session.py              # RefreshSession
│   │   └── oauth.py                        # OAuthAccount, OAuthState, OAuthExchangeCode
│   ├── schemas/
│   │   └── auth.py                         # Stage 3A/3B & OAuthExchangeRequest / MeResponse schemas
│   └── services/
│       ├── auth_service.py                 # Core auth, verification, password reset/change, session minting
│       ├── email_service.py                # Resend email client (verification & password reset)
│       ├── oauth_providers.py              # Bounded Google OIDC/JWKS & GitHub provider clients
│       └── oauth_service.py                # OAuth start, callback state machine, SAVEPOINT recovery & /exchange
├── docker/postgres/init-least-privilege.sh # Split migrator (DDL) vs. app (DML-only) DB roles
└── tests/                                  # Unit, security, route, DB & migration regression tests
```

---

## Python 3.13 Docker Setup & Test Workflow

Automated verification runs in the Python 3.13 Docker profile (`folio360-backend:py313`) against the isolated disposable `db_test` service (`folio360_test`), or on the local host `.venv` when explicitly targeting `folio360_db_test` on `127.0.0.1:5434`.

```bash
# Build/refresh images (when dependencies or Dockerfile change)
docker compose build

# Start development and test PostgreSQL 17 services
docker compose up -d --wait db db_test

# Upgrade development database to head (uses MIGRATION_DATABASE_URL) and check for zero drift
docker compose --profile tools run --rm migrator
docker compose --profile tools run --rm migrator python -m alembic check

# Run full suite inside Python 3.13 Docker profile against disposable db_test
docker compose --profile test run --rm test

# Run non-DB unit/security tests only (no DB required)
docker compose --profile test run --rm --no-deps test \
  python -m pytest -o cache_dir=/tmp/pytest_cache -m "not db and not migration" -q

# Safe stop (preserves folio360_pg_dev_data volume; never run `down -v` unintentionally)
docker compose down
```

---

## PostgreSQL Split-Role Security Model

Both `db` (`folio360_dev` on `127.0.0.1:5433`) and `db_test` (`folio360_test` on `127.0.0.1:5434`, `tmpfs`) use `scram-sha-256` authentication and provision three roles in `docker/postgres/init-least-privilege.sh`:

| Environment | Bootstrap Admin | Migrator Role (DDL & Schema Owner) | Application Role (DML-Only, Non-Owner) |
| :--- | :--- | :--- | :--- |
| **Development (`db`, `127.0.0.1:5433`)** | `folio360_dev_admin` | `folio360_dev_migrator` | `folio360_dev_app` |
| **Test (`db_test`, `127.0.0.1:5434`)** | `folio360_test_admin` | `folio360_test_migrator` | `folio360_test_app` |

---

## Implemented API Contract (`/api/v1`)

| Method & Path | Auth & Headers | Success | Behavior |
| :--- | :--- | :--- | :--- |
| `GET /api/v1/health` | Public | `200 OK` | Service liveness check |
| `GET /api/v1/health/ready` | Public | `200` / `503` | Bounded synchronous `SELECT 1` DB readiness probe |
| `POST /api/v1/auth/register` | Public | `201 Created` | Normalizes email, Argon2id-hashes password, sends Resend verification outside DB tx (`5/15m/IP`) |
| `POST /api/v1/auth/verify-email` | Public | `200 OK` | Consumes single-use token, returns JSON only (`10/15m/IP`) |
| `POST /api/v1/auth/resend-verification` | Public | `202 Accepted` | Enumeration-safe resend with cooldown & retry backoff (`5/15m/IP`) |
| `POST /api/v1/auth/login` | `X-Client-Type: web \| mobile` (+ `Origin` for `web`) | `200 OK` | Argon2id verification; OAuth-only users (`password_hash=None`) return `401` (`10/15m/IP`) |
| `POST /api/v1/auth/refresh` | `X-Client-Type` (+ `Origin` for `web`) + refresh token | `200 OK` | Single-use rotation with family replay revocation (`30/15m/IP`) |
| `POST /api/v1/auth/logout` | `X-Client-Type` (+ `Origin` for `web`) + refresh token | `200 OK` | Idempotently revokes refresh session and clears web cookie |
| `POST /api/v1/auth/logout-all` | Bearer Access JWT (+ `Origin` if `web`) | `200 OK` | Locks `users`, increments `auth_version`, revokes all active refresh sessions |
| `GET /api/v1/auth/me` | Bearer Access JWT | `200 OK` | Returns user profile plus sorted `oauth_providers: list[str]` (`REV12 D15`) |
| `POST /api/v1/auth/forgot-password` | Public | `202 Accepted` | Enumeration-safe reset initiation; no-op for OAuth-only users (`5/15m/IP`) |
| `POST /api/v1/auth/reset-password` | Public | `200 OK` | Consumes single-use reset token, increments `auth_version`, returns zero tokens (`10/15m/IP`) |
| `POST /api/v1/auth/change-password` | Bearer JWT + `X-Client-Type` (+ `Origin` if `web`) | `200 OK` | Verifies current password (`400 PASSWORD_NOT_SET` if OAuth-only), rotates sessions (`30/15m/IP`) |
| `GET /api/v1/auth/oauth/{provider}/start` | Public (`provider`: `google` \| `github`) | `302 Found` | Validates `client_type`, `redirect_uri`, `S256` challenge; persists state; sets `web` `folio360_oauth_binding` cookie (`20/15m/IP`) |
| `GET /api/v1/auth/oauth/{provider}/callback` | Public (+ `web` binding cookie) | `302 Found` | Enforces Orders `0–12`, PKCE/OIDC/JWKS/pagination HTTP outside open DB tx, SAVEPOINT recovery, short-lived `60s` exchange code (`20/15m/IP`) |
| `POST /api/v1/auth/oauth/exchange` | `X-Client-Type` (+ `Origin` if `web`) + `web` exchange cookie | `200 OK` | `users`-first locking, RFC 7636 verifier check, `web` refresh cookie vs. `mobile` JSON tokens (`10/15m/IP`) |

---

## Environment Configuration Summary

See [`.env.example`](.env.example) for local placeholder variable names and defaults (never commit `.env` or real secrets):
- **Core / DB / Auth / Email:** `ENVIRONMENT`, `DATABASE_URL`, `MIGRATION_DATABASE_URL`, `JWT_SECRET_KEY`, `COOKIE_DEPLOYMENT_MODE` (`same_site` | `cross_site`), `REFRESH_COOKIE_*`, `FRONTEND_BASE_URL`, `RESEND_API_KEY`, `RATE_LIMIT_ENABLED`, `PROXY_HEADERS_ENABLED`, `TRUSTED_PROXY_IPS`.
- **Stage 3C OAuth:** `BACKEND_BASE_URL`, `OAUTH_BINDING_COOKIE_NAME`, `OAUTH_EXCHANGE_COOKIE_NAME`, `OAUTH_PKCE_ENCRYPTION_KEY`, `OAUTH_PKCE_ENCRYPTION_KEY_PREVIOUS`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `OAUTH_ALLOWED_WEB_REDIRECT_URIS`, `OAUTH_ALLOWED_MOBILE_REDIRECT_URIS`, `OAUTH_STATE_EXPIRE_MINUTES`, `OAUTH_HTTP_TIMEOUT_SECONDS`, `GITHUB_EMAILS_PER_PAGE`, `GITHUB_EMAILS_MAX_PAGES`.

---

## Known SDK Note & Scope Boundaries

- **Resend SDK (`resend==2.53.2`):** `resend.Emails.send()` reads module-global `resend.api_key` and `resend.default_http_client`, assuming a single active `Settings` configuration per worker process.
- **Next Phase:** Phase 1 (Profile Creation) and downstream academic/portfolio modules are not implemented and require separate specification approval before work begins.
