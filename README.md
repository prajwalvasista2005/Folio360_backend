# Folio360 Backend

**Folio360: A User-Centred Unified Profile for Academic, Professional, and Lifelong Learning Records.**

Folio360 is a centralized digital identity platform designed to consolidate and verify academic qualifications, semester records, skills, certifications, internships, projects, and work experience.

This repository houses the core backend API service powering the Folio360 platform.

---

## Architecture & Technology Stack (Stage 3A — Core Authentication Foundation)

Stage 3A implements core email/password authentication, Resend email verification, HS256 JWT access tokens with `auth_version` invalidation, rotating PostgreSQL-backed refresh sessions, split PostgreSQL migrator/application roles, Python 3.13 Docker workflows, and the hardened `VerifiedUvicornConfig` ASGI3 production entrypoint on top of the Stage 1 + Stage 2 foundation:

- **Language:** Python 3.13 (`python:3.13-slim` via Docker)
- **Framework:** FastAPI `0.163.1` (`Folio360FastAPI` ASGI3 subclass)
- **Data Validation & Settings:** Pydantic `2.14.3` & `pydantic-settings 2.16.3`
- **Server Runtime:** Uvicorn `0.54.0` with `uvloop 0.23.0` (`python -m app.server`)
- **Database & ORM:** PostgreSQL `17` (`postgres:17`), SQLAlchemy `2.0.38` (synchronous), `psycopg` v3 (`3.3.9` / `psycopg-binary==3.3.9`)
- **Migrations:** Alembic `1.20.1` (`0001_create_users` -> `0002_add_core_auth_tables`)
- **Cryptography & Email:** `argon2-cffi 25.1.0` (Argon2id), `PyJWT 2.15.1` (`HS256`), `cryptography 50.0.2`, `resend 2.53.2`
- **Testing:** Pytest `9.2.0`, `pytest-mock 3.17.0`, HTTPX `0.28.1`
- **Container Runtime:** Docker / Docker Compose (`folio360_net` bridge network)

### Module Layout

```text
Folio360_backend/
├── .dockerignore                            # Docker build exclusions
├── .env.example                             # Environment template (placeholders only)
├── .gitignore                               # Git exclusions
├── Dockerfile                               # Non-root python:3.13-slim runtime image
├── README.md                                # Operational guide (Stage 3A)
├── alembic.ini                              # Alembic configuration (blank sqlalchemy.url)
├── docker-compose.yml                       # db, db_test, api, migrator, and test services
├── pytest.ini                               # Pytest markers (db, migration) and testpaths
├── requirements.in                          # Direct high-level Python dependencies
├── requirements.txt                         # Pinned UTF-8 LF lockfile
├── alembic/
│   ├── env.py                               # Synchronous NullPool Alembic env (MIGRATION_DATABASE_URL)
│   └── versions/
│       ├── 0001_create_users.py             # Stage 2 baseline migration (immutable)
│       └── 0002_add_core_auth_tables.py     # Stage 3A users extension + verification/refresh tables
├── app/
│   ├── main.py                              # Folio360FastAPI ASGI3 gates, create_app(), lifespan
│   ├── server.py                            # VerifiedUvicornConfig, 3-layer proxy/ASGI3 verification, CLI
│   ├── api/
│   │   ├── deps/auth.py                     # Bearer JWT auth, X-Client-Type, Origin, client IP, rate limits
│   │   └── routes/
│   │       ├── auth.py                      # 8 synchronous Stage 3A /api/v1/auth/* endpoints
│   │       └── health.py                    # Liveness (/api/v1/health) & readiness (/api/v1/health/ready)
│   ├── core/
│   │   ├── config.py                        # Pydantic Settings + production startup validation
│   │   ├── exceptions.py                    # Safe AppException + 422 RequestValidationError input stripper
│   │   ├── logging.py                       # SecurityFilter/SecurityFormatter + secret/cookie/JWT redaction
│   │   ├── rate_limit.py                    # Thread-safe process-local sliding-window IP rate limiter
│   │   ├── security.py                      # Argon2id, SHA-256 opaque tokens, HS256 JWTs
│   │   └── uri_policy.py                    # Rev10 §10.2.C environment & mobile-login URI/parity validator
│   ├── db/
│   │   ├── base.py                          # POSTGRES_NAMING_CONVENTION, Base, TimestampMixin
│   │   └── session.py                       # Pooled engine, sessionmaker, readiness probe, get_db
│   ├── models/
│   │   ├── user.py                          # Extended User ORM model
│   │   ├── email_verification_token.py      # EmailVerificationToken ORM model
│   │   └── refresh_session.py               # RefreshSession ORM model
│   ├── schemas/
│   │   └── auth.py                          # Pydantic v2 Stage 3A request/response schemas
│   └── services/
│       ├── auth_service.py                  # Atomic registration, verification, Resend, login, refresh, logout
│       └── email_service.py                 # Resend verification email client + URL builder
├── docker/postgres/init-least-privilege.sh  # LF-only PostgreSQL 3-role initialization script
└── tests/                                   # Stage 1/2 regression + Stage 3A unit, Uvicorn, URI, DB & migration tests
```

---

## Python 3.13 Docker Setup & Linux Development Workflow

Host virtual environments are not required or modified; development, migrations, and automated tests execute inside `python:3.13-slim` containers attached to `folio360_net`.

### 1. Build the Python 3.13 Image & Start PostgreSQL 17 Services

```bash
# Build the application/test image (python:3.13-slim)
docker compose build

# Start development and test PostgreSQL 17 databases and wait for health checks
docker compose up -d --wait db db_test
```

### 2. Run Migrations & Verify Schema Drift (Migrator Role)

```bash
# Upgrade development database to head using MIGRATION_DATABASE_URL
docker compose --profile tools run --rm migrator

# Verify zero schema drift between SQLAlchemy ORM metadata and live DB
docker compose --profile tools run --rm migrator python -m alembic check
```

### 3. Start the API Server (`python -m app.server`)

```bash
# Start the API service on http://127.0.0.1:8000 (uses DML-only DATABASE_URL)
docker compose up -d api

# Verify liveness and database readiness
curl -fsS http://127.0.0.1:8000/api/v1/health
curl -fsS http://127.0.0.1:8000/api/v1/health/ready
```

### 4. Run Automated Tests (Python 3.13 + Isolated `db_test`)

```bash
# Run full suite inside Python 3.13 against disposable db_test
docker compose --profile test run --rm test

# Run unit tests only (no database required)
docker compose --profile test run --rm --no-deps test \
  python -m pytest -o cache_dir=/tmp/pytest_cache -m "not db and not migration" -v

# Run migration & split-role privilege tests only
docker compose --profile test run --rm test \
  python -m pytest -o cache_dir=/tmp/pytest_cache -m migration -v
```

### 5. Safe Stop vs. Volume Warning

```bash
# Safe stop: preserves folio360_pg_dev_data development volume
docker compose down
```

> **Never run `docker compose down -v`** unless you intentionally want to destroy the `folio360_pg_dev_data` volume. `/docker-entrypoint-initdb.d/init-least-privilege.sh` runs only when a PostgreSQL volume is first initialized empty.

---

## PostgreSQL Split-Role Security Model

Both `db` (`folio360_dev`) and `db_test` (`folio360_test`) enforce `scram-sha-256` authentication and provision **three** separate roles via `docker/postgres/init-least-privilege.sh`:

| Environment | Bootstrap Admin (Superuser) | Migrator Role (DDL & Schema Owner) | Application Role (DML-Only, Non-Owner) |
| :--- | :--- | :--- | :--- |
| **Development (`db`, `127.0.0.1:5433`)** | `folio360_dev_admin` | `folio360_dev_migrator` | `folio360_dev_app` |
| **Test (`db_test`, `127.0.0.1:5434`)** | `folio360_test_admin` | `folio360_test_migrator` | `folio360_test_app` |

- **Migrator role (`MIGRATION_DATABASE_URL`):** Non-superuser role owning the target database and `public` schema, holding `USAGE, CREATE` on `public`. Only Alembic migrations (`alembic/env.py`) consume `MIGRATION_DATABASE_URL`; it is never passed to the runtime `api` service.
- **Application role (`DATABASE_URL`):** Non-superuser, non-owner role granted `CONNECT, TEMPORARY` on the database, `USAGE` only (no `CREATE`) on `public`, and `SELECT, INSERT, UPDATE, DELETE` on tables (plus `USAGE, SELECT` on sequences) via explicit grants and `ALTER DEFAULT PRIVILEGES FOR ROLE <migrator>`. DDL (`CREATE`, `ALTER`, `DROP`) and `TRUNCATE` are denied by PostgreSQL.

---

## Environment Variables (Stage 3A)

See [`.env.example`](.env.example) for local placeholder defaults (copy to `.env` for local overrides; never commit `.env` or real secrets).

### Core, Database & Readiness
- `ENVIRONMENT` (`development` | `testing` | `production`), `DEBUG`, `LOG_LEVEL`, `API_V1_PREFIX`, `CORS_ORIGINS`
- `DATABASE_URL` (runtime DML-only `postgresql+psycopg://...`), `MIGRATION_DATABASE_URL` (Alembic DDL `postgresql+psycopg://...`)
- `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `DB_POOL_TIMEOUT`, `DB_CONNECT_TIMEOUT`, `DB_ECHO` (must be `false` in `production`)
- `DB_READINESS_MAX_CONCURRENCY`, `DB_READINESS_CONNECT_TIMEOUT`, `DB_READINESS_QUERY_TIMEOUT_MS`

### Authentication, Resend & Proxy Security (Stage 3A)
- `JWT_SECRET_KEY` (required `>= 32` chars in `production`), `JWT_ISSUER` (`folio360`), `JWT_AUDIENCE` (`folio360-api`), `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` (`15`)
- `REFRESH_TOKEN_EXPIRE_DAYS` (`14`), `REFRESH_TOKEN_ABSOLUTE_EXPIRE_DAYS` (`30`)
- `COOKIE_DEPLOYMENT_MODE` (`same_site` | `cross_site`), `REFRESH_COOKIE_NAME` (`folio360_refresh_token`), `REFRESH_COOKIE_SECURE`, `REFRESH_COOKIE_SAMESITE` (`lax` | `strict` | `none`), `REFRESH_COOKIE_DOMAIN`
- `FRONTEND_BASE_URL` (must be exact `https://` origin without trailing `/` in `production`)
- `EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` (validated under `ENVIRONMENT` via §10.2.C rules; backend CI/release parity reference)
- `RESEND_API_KEY` (required in `production`; when unset in local dev/test, registration commits the unverified account with `verification_email_sent: false`), `EMAIL_FROM_ADDRESS`
- `EMAIL_VERIFICATION_EXPIRE_HOURS` (`24`), `EMAIL_COOLDOWN_SECONDS` (`60`), `EMAIL_MAX_PER_HOUR` (`3`), `EMAIL_FAILED_RETRY_BACKOFF_SECONDS` (`10`), `EMAIL_PENDING_STALE_SECONDS` (`30`), `EMAIL_SEND_TIMEOUT_SECONDS` (`5.0`)
- `RATE_LIMIT_ENABLED` (must be `true` in `production`)
- `PROXY_HEADERS_ENABLED`, `TRUSTED_PROXY_IPS` (explicit IP/CIDR allowlist; `"*"` and hostnames rejected)

---

## Stage 3A API Contract (`/api/v1`)

| Method & Path | Auth & Headers | Success Status | Behavior |
| :--- | :--- | :--- | :--- |
| `GET /api/v1/health` | Public | `200 OK` | Service liveness check |
| `GET /api/v1/health/ready` | Public | `200` / `503` | Bounded synchronous `SELECT 1` DB readiness probe |
| `POST /api/v1/auth/register` | Public | `201 Created` | Normalizes email, Argon2id-hashes password, creates unverified user + pending token, sends Resend verification outside DB Tx (`5 / 15m / IP`) |
| `POST /api/v1/auth/verify-email` | Public | `200 OK` | Validates single-use token, verifies email, returns JSON only with **zero tokens, zero cookies, zero sessions, and no redirect URL** (`10 / 15m / IP`) |
| `POST /api/v1/auth/resend-verification` | Public | `202 Accepted` | Enumeration-safe resend enforcing 30s pending guard, 60s/3-per-hr caps, 0s first retry after initial failure, 10s subsequent failure backoff (`5 / 15m / IP`) |
| `POST /api/v1/auth/login` | `X-Client-Type: web \| mobile` (+ exact `Origin` for `web`) | `200 OK` | Timing-safe Argon2id check before `EMAIL_NOT_VERIFIED` (`403`); issues 15m access JWT + rotating refresh session (`10 / 15m / IP`) |
| `POST /api/v1/auth/refresh` | `X-Client-Type` (+ `Origin` for `web`) + refresh token | `200 OK` | Serializes on `FOR UPDATE`, rotates single-use token, revokes entire family on replay (`401 REFRESH_TOKEN_REUSE_DETECTED`) (`30 / 15m / IP`) |
| `POST /api/v1/auth/logout` | `X-Client-Type` (+ `Origin` for `web`) + refresh token | `200 OK` | Idempotently revokes active refresh session and clears web cookie |
| `POST /api/v1/auth/logout-all` | Bearer Access JWT (+ `Origin` if `X-Client-Type: web`) | `200 OK` | Locks `users`, increments `auth_version` (immediate JWT invalidation), revokes all active refresh sessions |
| `GET /api/v1/auth/me` | Bearer Access JWT | `200 OK` | Returns authenticated user profile (`id`, `email`, `is_active`, `is_email_verified`, `has_password`, `created_at`, `updated_at`) |

### Web vs. Mobile Token Delivery & Security Behavior

- **Web (`X-Client-Type: web`):** Refresh token is delivered solely via `HttpOnly` cookie (`Path=/api/v1/auth`) governed by `COOKIE_DEPLOYMENT_MODE` (`same_site` vs. `cross_site`). Cookie-issuing and cookie-bearing routes (`/login`, `/refresh`, `/logout`, `/logout-all`) require an exact `Origin` match in `CORS_ORIGINS` (`403 CSRF_ORIGIN_MISMATCH` otherwise).
- **Mobile (`X-Client-Type: mobile`):** Zero cookies set; `access_token` and `refresh_token` are returned in JSON. Clients must implement single-flight refresh deduplication so concurrent refresh calls do not trigger single-use replay revocation.
- **Error & Log Safety:** `RequestValidationError` responses strip Pydantic `input` and raw `ctx`; `IntegrityError` inspects only `constraint_name` (never PostgreSQL `DETAIL:`); `SecurityFilter` / `SecurityFormatter` redact passwords, JWTs, Resend `re_...` keys, cookies, tokens, DB connection strings, and SQL.
- **Production Uvicorn Entrypoint:** Production must run via `python -m app.server` (`VerifiedUvicornConfig` enforcing `lifespan="on"`, `interface="asgi3"`, and 3-layer proxy/ASGI3 verification). Raw `uvicorn` CLI invocations fail closed in `ENVIRONMENT=production`.

---

## Scope Boundaries

- **Not Implemented in Stage 3A (Deferred to Stage 3B & 3C):** Password reset (`/forgot-password`, `/reset-password`, `/change-password`, `password_reset_tokens`) belongs to **Stage 3B**; Google OIDC and GitHub OAuth 2.0 (`/oauth/*`, `oauth_*` tables, `oauth_providers` on `/me`) belong to **Stage 3C**.
- **Client Repositories:** Frontend React/Vite UI, Vite build parity checks, React Native/Expo UI, `SecureStore`, and iOS AASA / Android `assetlinks.json` domain associations live in their respective client repositories.
