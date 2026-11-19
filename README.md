# Folio360 Backend

**Folio360: A User-Centred Unified Profile for Academic, Professional, and Lifelong Learning Records.**

Folio360 is a centralized digital identity platform designed to consolidate and verify academic qualifications, semester records, skills, certifications, internships, projects, and work experience.

This repository houses the core backend API service powering the Folio360 platform.

---

## Architecture & Technology Stack (Stage 2 — Database Foundation)

Stage 2 (`F360-S2-SPEC-REV6`) builds upon the Stage 1 FastAPI foundation with a synchronous PostgreSQL 17 persistence layer, Alembic migrations, a minimal `users` table, a synchronous database readiness probe, and isolated Docker Compose development and test databases with least-privilege roles:

- **Language:** Python 3.13 (`python:3.13-slim`)
- **Framework:** FastAPI `0.163.1`
- **Data Validation & Settings:** Pydantic `2.14.3` & `pydantic-settings 2.16.3`
- **Server Runtime:** Uvicorn `0.54.0` with `uvloop 0.23.0`
- **Database & ORM:** PostgreSQL `17` (`postgres:17`), SQLAlchemy `2.0.38` (synchronous), `psycopg` v3 (`3.3.9` / `psycopg-binary==3.3.9`)
- **Migrations:** Alembic `1.20.1`
- **Testing:** Pytest `9.2.0`, `pytest-mock 3.17.0`, HTTPX `0.28.1`
- **Container Runtime:** Docker Desktop / Docker Compose (`folio360_net` bridge network)

### Acyclic Module Layering

- **Layer 0 (`app/core/*`):** `logging.py`, `config.py`, `exceptions.py` — imports nothing from `app/db/*`, `app/models/*`, or `app/api/*`.
- **Layer 1 (`app/db/base.py`):** Imports only SQLAlchemy and Python stdlib; defines `POSTGRES_NAMING_CONVENTION`, `Base`, and `TimestampMixin`.
- **Layer 2 (`app/models/*`):** `user.py`, `__init__.py` — imports `Base` and `TimestampMixin` from `app.db.base`.
- **Layer 3 (`app/db/session.py`, `app/db/__init__.py`):** Engine/sessionmaker/readiness engine/semaphore builders, `check_database_readiness`, `get_db`, and `DatabaseUnavailableError`.
- **Layer 4 (`app/api/routes/health.py`, `app/main.py`):** Health/readiness routes and exception-safe `lifespan(app)` management.
- **Layer 5 (`alembic/*`):** Migration environment importing `get_settings` (`app.core.config`) and `Base` (`app.models`).

---

## Directory Structure

```text
folio360_backend/
├── .env.example                             # Environment configuration template (Stage 1 + Stage 2)
├── .gitignore                               # Git exclusions (venv, caches, .env files, etc.)
├── FOLIO360_COMPLETE_PROJECT_HANDOVER.md    # Historical Stage 1 handover document
├── README.md                                # Project documentation and Stage 2 operational guide
├── alembic.ini                              # Alembic configuration (blank sqlalchemy.url)
├── docker-compose.yml                       # Isolated postgres:17 dev (5433) and test (5434) services
├── pytest.ini                               # Pytest markers (db, migration) and testpaths
├── requirements.in                          # Direct, high-level project dependencies
├── requirements.txt                         # Fully pinned, reproducible Linux lockfile
├── alembic/
│   ├── env.py                               # Synchronous NullPool Alembic environment
│   ├── script.py.mako                       # Alembic migration template
│   └── versions/
│       └── 0001_create_users.py             # Initial migration creating the users table
├── app/
│   ├── __init__.py                          # Package marker
│   ├── main.py                              # FastAPI application factory and exception-safe lifespan
│   ├── api/
│   │   ├── __init__.py                      # API package marker
│   │   └── routes/
│   │       ├── __init__.py                  # Routes package marker
│   │       └── health.py                    # Liveness (/api/v1/health) & readiness (/api/v1/health/ready)
│   ├── core/
│   │   ├── __init__.py                      # Core package marker
│   │   ├── config.py                        # Pydantic Settings with 4-phase import-safe DB validation
│   │   ├── exceptions.py                    # Custom exceptions and centralized error handlers
│   │   └── logging.py                       # Centralized structured logging with +driver URL redaction
│   ├── db/
│   │   ├── __init__.py                      # Public DB exports
│   │   ├── base.py                          # POSTGRES_NAMING_CONVENTION, Base, TimestampMixin
│   │   └── session.py                       # Engine, sessionmaker, readiness probe, get_db
│   └── models/
│       ├── __init__.py                      # Model exports (Base, User) for Alembic
│       └── user.py                          # Minimal User model (users table)
├── docker/
│   └── postgres/
│       └── init-least-privilege.sh          # LF-only PostgreSQL first-init least-privilege role script
└── tests/
    ├── __init__.py                          # Tests package marker
    ├── conftest.py                          # Two-stage _test DB guard and session fixtures
    ├── test_config.py                       # Settings, CORS_ORIGINS, and LOG_LEVEL validation tests
    ├── test_db_session.py                   # DB config, lifecycle, get_db, and partial-startup cleanup tests
    ├── test_exceptions.py                   # Exception handling and safe error-response tests
    ├── test_health.py                       # Liveness endpoint, OpenAPI/docs, and CORS tests
    ├── test_health_ready.py                 # Readiness endpoint, semaphore, timeout, and pool-event tests
    ├── test_logging.py                      # Logging sanitization and +driver URL redaction tests
    ├── test_migrations.py                   # Destructive Alembic round-trip test (db_test only)
    └── test_user_model.py                   # User model UUID, UTC timestamps, and constraint tests
```

---

## Environment Configuration

Configuration is managed via environment variables and loaded through Pydantic Settings (`app.core.config.Settings`, `extra="ignore"`, `case_sensitive=True`).

Copy `.env.example` to `.env` for local development:

```bash
# Linux / macOS
cp .env.example .env
```

```powershell
# Windows PowerShell
Copy-Item .env.example .env
```

### Application, Database & Readiness Variables

| Variable | Default Value | Description & Constraints |
|---|---|---|
| `APP_NAME` | `Folio360` | Application identifier |
| `APP_VERSION` | `1.0.0` | Semantic version string |
| `APP_DESCRIPTION` | `Folio360: A User-Centred...` | OpenAPI application description |
| `ENVIRONMENT` | `development` | `development`, `testing`, or `production` |
| `DEBUG` | `false` | Enable or disable debug mode (`.env.example` sets `true` for local dev) |
| `API_V1_PREFIX` | `/api/v1` | Prefix for version 1 API endpoints |
| `LOG_LEVEL` | `INFO` | `CRITICAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG`, `NOTSET` |
| `CORS_ORIGINS` | `["http://localhost:3000", ...]` | Allowed CORS origins (JSON array or comma-separated string) |
| `DOCS_URL` | `/docs` | Swagger UI documentation route (or `null` to disable) |
| `OPENAPI_URL` | `/openapi.json` | OpenAPI 3.1 JSON schema route (or `null` to disable) |
| `DATABASE_URL` | `None` | Optional in non-prod; required in `production`. Must use `postgresql+psycopg://` with non-empty host & database |
| `DB_POOL_SIZE` | `5` | Primary SQLAlchemy connection pool size (`1 <= n <= 50`) |
| `DB_MAX_OVERFLOW` | `10` | Overflow connections above `DB_POOL_SIZE` (`0 <= n <= 100`) |
| `DB_POOL_TIMEOUT` | `30` | Pool checkout timeout in seconds (`1 <= n <= 120`) |
| `DB_CONNECT_TIMEOUT` | `5` | `psycopg` TCP connect timeout in seconds (`1 <= n <= 30`) |
| `DB_ECHO` | `false` | SQLAlchemy SQL statement logging; **must be `false` in `production`** |
| `DB_READINESS_MAX_CONCURRENCY` | `2` | Per-process `BoundedSemaphore` permits for `/api/v1/health/ready` (`1 <= n <= 10`) |
| `DB_READINESS_CONNECT_TIMEOUT` | `3` | Readiness `NullPool` connect timeout in seconds (`1 <= n <= 4`) |
| `DB_READINESS_QUERY_TIMEOUT_MS` | `1000` | Readiness `SET LOCAL statement_timeout` in milliseconds (`100 <= n <= 3000`) |
| `TEST_DATABASE_URL` | *(unset)* | Pytest-only URL targeting `_test` DB (`127.0.0.1:5434` on host, `db_test:5432` in `folio360_net`) |

> **Readiness Timeout Budget Rule:** `Settings` enforces `DB_READINESS_CONNECT_TIMEOUT + (DB_READINESS_QUERY_TIMEOUT_MS / 1000.0) <= 5.0` at validation time.
>
> **Production Startup Rule:** `Settings.validate_runtime_requirements()` raises `RuntimeError` when `ENVIRONMENT == "production"` if `DATABASE_URL is None` or `DB_ECHO is True`.

### Docker Compose Service Variables (`docker-compose.yml` & `.env.example`)

| Variable | Default Value | Service |
|---|---|---|
| `POSTGRES_DEV_ADMIN_USER` | `folio360_dev_admin` | `db` (`folio360_db_dev`) |
| `POSTGRES_DEV_ADMIN_PASSWORD` | `folio360_dev_admin_pass` | `db` (`folio360_db_dev`) |
| `POSTGRES_DEV_DB` | `folio360_dev` | `db` (`folio360_db_dev`) |
| `POSTGRES_DEV_APP_USER` | `folio360_dev_user` | `db` (`folio360_db_dev`) |
| `POSTGRES_DEV_APP_PASSWORD` | `folio360_dev_pass` | `db` (`folio360_db_dev`) |
| `POSTGRES_TEST_ADMIN_USER` | `folio360_test_admin` | `db_test` (`folio360_db_test`) |
| `POSTGRES_TEST_ADMIN_PASSWORD` | `folio360_test_admin_pass` | `db_test` (`folio360_db_test`) |
| `POSTGRES_TEST_DB` | `folio360_test` | `db_test` (`folio360_db_test`) |
| `POSTGRES_TEST_APP_USER` | `folio360_test_user` | `db_test` (`folio360_db_test`) |
| `POSTGRES_TEST_APP_PASSWORD` | `folio360_test_pass` | `db_test` (`folio360_db_test`) |

---

## Docker Compose Lifecycle & Least-Privilege PostgreSQL Roles

`docker-compose.yml` provisions two isolated `postgres:17` containers on the dedicated `folio360_net` bridge network:

- **`db` (`folio360_db_dev`):** Bound to `127.0.0.1:5433:5432` (avoiding host port `5432`), backed by the persistent named volume `folio360_pg_dev_data`.
- **`db_test` (`folio360_db_test`):** Bound to `127.0.0.1:5434:5432`, backed by ephemeral `tmpfs` (`/var/lib/postgresql/data`) for clean, disposable test runs.

Both services enforce `scram-sha-256` authentication (`password_encryption=scram-sha-256`, `POSTGRES_INITDB_ARGS="--auth-host=scram-sha-256 --auth-local=scram-sha-256 --encoding=UTF8"`, `POSTGRES_HOST_AUTH_METHOD=scram-sha-256`) and execute `docker/postgres/init-least-privilege.sh` (strict Unix LF) on first-time initialization:

1. Creates the application role (`folio360_dev_user` / `folio360_test_user`) with `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION`.
2. Revokes `ALL` privileges from `PUBLIC` on the target database and `public` schema.
3. Transfers ownership of the target database and `public` schema to the application role.
4. Grants `CONNECT, TEMPORARY` on the target database and `USAGE, CREATE` on the `public` schema to the application role.

### Common Lifecycle Commands

```bash
# Start development database only and wait until healthy
docker compose up -d --wait db

# Start both development and test databases and wait until healthy
docker compose up -d --wait db db_test

# Inspect status and logs
docker compose ps
docker compose logs -f db
```

---

## Safe vs. Destructive Resets & Volume Credential Behavior

> **Safe Stop (`docker compose down`):**
> Stops and removes containers and the `folio360_net` bridge network while **preserving** the `folio360_pg_dev_data` volume (your development data and roles remain intact). `db_test` uses `tmpfs`, so test database state always clears on stop.
>
> **Destructive Reset (`docker compose down -v`):**
> **Permanently deletes** the `folio360_pg_dev_data` volume and all local development database data. Never pass `-v` unless you intend a complete wipe.
>
> **Persistent Volume Credential Behavior:**
> PostgreSQL's `/docker-entrypoint-initdb.d/` scripts (and initial `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB`) run **only once** when `folio360_pg_dev_data` is created empty. Editing `POSTGRES_DEV_*` values in `.env` afterward will **not** update roles or passwords in an already-initialized volume. To change credentials on an existing volume, connect as `folio360_dev_admin` and run `ALTER ROLE folio360_dev_user WITH PASSWORD '...';`, or perform an explicit destructive reset (`docker compose down -v && docker compose up -d --wait db`).

---

## Database Migrations (Alembic)

`alembic.ini` leaves `sqlalchemy.url` intentionally blank so `alembic/env.py` reads `DATABASE_URL` dynamically from `get_settings()`, fails clearly without leaking credentials when unconfigured, and runs synchronous migrations using `NullPool` with `compare_type=True` and `compare_server_default=True`.

### Applying Migrations to `db` (`folio360_dev`)

Ensure `.env` has `DATABASE_URL` pointing to `127.0.0.1:5433/folio360_dev` and `db` is healthy:

```powershell
# Apply all migrations up to head
.\venv\Scripts\python.exe -m alembic upgrade head

# Verify ORM metadata matches live PostgreSQL schema
.\venv\Scripts\python.exe -m alembic check
```

> **Migration Safety Warning:** Never run destructive `alembic downgrade` round-trips against `db` (`folio360_dev`), as downgrading `0001_create_users` drops the `users` table. Destructive `upgrade -> downgrade -> upgrade -> check` verification is executed exclusively against the isolated `db_test` service via `pytest -m migration`.

---

## Running the Application, Endpoints & Readiness Sizing

### Starting the API Server

Locally with the project virtual environment:

```powershell
.\venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Or inside an isolated `python:3.13-slim` container attached to `folio360_net` (targeting `db:5432`):

```bash
docker run --rm --name folio360_api --network folio360_net -p 8000:8000 \
  -v "${PWD}:/app" -w /app \
  -e DATABASE_URL="postgresql+psycopg://folio360_dev_user:folio360_dev_pass@db:5432/folio360_dev" \
  python:3.13-slim sh -c "pip install --no-cache-dir -r requirements.txt && uvicorn app.main:app --host 0.0.0.0 --port 8000"
```

### Verification Endpoints

- **Liveness Check (`GET /api/v1/health`):** `200 OK`
  ```json
  {
    "status": "healthy",
    "application": "Folio360",
    "version": "1.0.0"
  }
  ```
- **Readiness Check (`GET /api/v1/health/ready`):** Synchronous handler (`def readiness_check`) returning `200 {"status": "ready"}` when PostgreSQL responds within budget, or `503 {"status": "unavailable"}` when unconfigured, unreachable, timed out, or saturated.
- **Interactive API Documentation (Swagger UI):** `http://127.0.0.1:8000/docs`
- **OpenAPI 3.1 Specification:** `http://127.0.0.1:8000/openapi.json`

### Readiness Semantics & Concurrency Sizing

`GET /api/v1/health/ready` uses a dedicated `NullPool` engine (`db_readiness_engine`) isolated from the application's pooled `db_engine`, guarded by a per-process non-blocking `threading.BoundedSemaphore(DB_READINESS_MAX_CONCURRENCY)`. Each probe executes `SET LOCAL statement_timeout = <DB_READINESS_QUERY_TIMEOUT_MS>` and `SELECT 1`, closing its connection immediately afterward. If all semaphore permits are busy, the endpoint fails fast with `503` without queuing behind application pool exhaustion.

Because `DB_READINESS_MAX_CONCURRENCY` is enforced **per process**, total concurrent readiness probes across a deployment scale linearly:

```text
C_total = C_per_process * N_workers * N_replicas
```

Combined worst-case database connections across both the application pool and readiness probes are:

```text
Total_connections = (DB_POOL_SIZE + DB_MAX_OVERFLOW + DB_READINESS_MAX_CONCURRENCY) * N_workers * N_replicas
```

Compare against PostgreSQL's default `max_connections = 100` (~95 usable after reserving ~5 superuser/admin slots):

| Deployment Topology | `N_workers` | `N_replicas` | Readiness `C_total` | Worst-Case Connections (`5 + 10 + 2` defaults) | Fit vs `max_connections = 100` |
|---|---|---|---|---|---|
| Local dev | `1` | `1` | `2 * 1 * 1 = 2` | `17 * 1 * 1 = 17` | Safe (`17 <= 95`) |
| Single instance, multi-worker | `4` | `1` | `2 * 4 * 1 = 8` | `17 * 4 * 1 = 68` | Safe (`68 <= 95`) |
| Multi-replica scaling | `4` | `2` | `2 * 4 * 2 = 16` | `17 * 4 * 2 = 136` | **Exceeds 100** — tune down (e.g. `(3 + 5 + 1) * 4 * 2 = 72`) or increase DB capacity / pooling |

---

## Running Automated Tests

`tests/conftest.py` enforces two-stage database identity checks before executing any `db` or `migration` tests: `TEST_DATABASE_URL` must end with `_test`, must reject `postgres`, `folio360_dev*`, and `*_admin` roles, and must verify `is_superuser == 'off'` via a live query.

### 1. Host Execution (Windows Virtual Environment)

```powershell
# Run unit tests only (no database required)
.\venv\Scripts\python.exe -m pytest -m "not db and not migration" -v

# Start disposable test database and run full suite (Stage 1 + Stage 2)
docker compose up -d --wait db_test
$env:TEST_DATABASE_URL = "postgresql+psycopg://folio360_test_user:folio360_test_pass@127.0.0.1:5434/folio360_test"
.\venv\Scripts\python.exe -m pytest -v
```

### 2. Isolated `python:3.13-slim` Container over `folio360_net`

Inside an isolated container attached to `folio360_net`, `127.0.0.1:5434` refers to the test runner container itself rather than `db_test`. Containerized test runs must target the Docker service hostname and internal PostgreSQL port `db_test:5432`:

```bash
docker compose up -d --wait db_test
docker run --rm --network folio360_net \
  -v "${PWD}:/app" -w /app \
  -e TEST_DATABASE_URL="postgresql+psycopg://folio360_test_user:folio360_test_pass@db_test:5432/folio360_test" \
  python:3.13-slim sh -c "pip install --no-cache-dir -r requirements.txt && pytest -v"
```

---

## Current Scope & Boundaries (Stage 2)

This repository reflects **Stage 1 (FastAPI Foundation)** + **Stage 2 (Database Foundation)**:

- **Implemented:** Application factory, exception-safe lifespan management, Pydantic Settings with 4-phase DB validation, structured logging with `+driver` URL redaction, centralized exception handlers, liveness (`/api/v1/health`) and synchronous readiness (`/api/v1/health/ready`) endpoints, synchronous SQLAlchemy 2.0 `Base`/`TimestampMixin`/`User` model, Alembic configuration and initial `0001_create_users` migration, isolated PostgreSQL 17 Docker Compose services with least-privilege roles, and full Pytest unit/integration/migration suite.
- **NOT Implemented in Stage 2 (Deferred to Stage 3+):**
  - User registration, login, password hashing/storage, JWT issuance/verification, OAuth providers, or email verification.
  - Profile CRUD routes or domain tables (academic records, skills, certificates, internships, projects, work experience).
  - Mutating endpoints (`POST`/`PUT`/`PATCH`/`DELETE`) or custom `RequestValidationError`/`StarletteHTTPException` 422 handlers.
  - Async SQLAlchemy, Redis, Celery, microservices, production `Dockerfile`, or CI/CD pipelines.
