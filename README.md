# Folio360 Backend

**Folio360: A User-Centred Unified Profile for Academic, Professional, and Lifelong Learning Records.**

Folio360 is a centralized digital identity platform designed to consolidate and verify academic qualifications, semester records, skills, certifications, internships, projects, and work experience.

This repository houses the core backend API service powering the Folio360 platform.

---

## Architecture & Technology Stack (Stage 1)

Stage 1 establishes the production-grade application foundation using asynchronous Python and FastAPI:

- **Language:** Python 3.13
- **Framework:** FastAPI
- **Data Validation & Settings:** Pydantic v2 & Pydantic Settings
- **Async Runtime / Server:** Uvicorn with `uvloop`
- **Testing:** Pytest & FastAPI TestClient (HTTPX)
- **Container Runtime:** Docker Desktop (Linux containers, `python:3.13-slim`)

---

## Directory Structure

```text
folio360_backend/
├── .env.example              # Sample environment configuration template
├── .gitignore                # Git exclusions (venv, caches, env files, etc.)
├── requirements.in           # Direct, high-level project dependencies
├── requirements.txt          # Fully pinned, reproducible Linux lockfile
├── README.md                 # Project documentation and developer guide
├── app/
│   ├── __init__.py           # Package marker
│   ├── main.py               # FastAPI application factory and lifespan handler
│   ├── api/
│   │   ├── __init__.py       # API package marker
│   │   └── routes/
│   │       ├── __init__.py   # Routes package marker
│   │       └── health.py     # Health check route (/api/v1/health)
│   └── core/
│       ├── __init__.py       # Core package marker
│       ├── config.py         # Pydantic Settings configuration singleton
│       ├── exceptions.py     # Custom exceptions and centralized error handlers
│       └── logging.py        # Centralized structured logging with security filters
└── tests/
    ├── __init__.py           # Tests package marker
    ├── test_health.py        # Health endpoint, OpenAPI/docs, and CORS tests
    ├── test_config.py        # Settings, CORS_ORIGINS, and LOG_LEVEL validation tests
    ├── test_exceptions.py    # Exception handling and safe error-response tests
    └── test_logging.py       # Logging sanitization and security filter tests
```

---

## Environment Configuration

Configuration is managed via environment variables and loaded through Pydantic Settings (`app.core.config.Settings`).

To configure the environment locally:

```bash
cp .env.example .env
```

Key environment variables:
| Variable | Default Value | Description |
|---|---|---|
| `APP_NAME` | `Folio360` | Application identifier |
| `APP_VERSION` | `1.0.0` | Semantic version string |
| `ENVIRONMENT` | `development` | Deployment environment (`development`, `testing`, `production`) |
| `DEBUG` | `false` | Enable or disable debug mode |
| `API_V1_PREFIX` | `/api/v1` | Prefix for version 1 API endpoints |
| `LOG_LEVEL` | `INFO` | Logging threshold (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) |
| `CORS_ORIGINS` | `["http://localhost:3000", ...]` | Allowed CORS origins (JSON array or comma-separated string) |
| `DOCS_URL` | `/docs` | Swagger UI documentation route |
| `OPENAPI_URL` | `/openapi.json` | OpenAPI 3.1 JSON schema route |

---

## Running the Application

### 1. Running with Docker (Recommended)

To run the application inside an isolated Python 3.13 Linux container:

```bash
# Build/Run container interactively or in detached mode:
docker run -d --name folio360_api -p 8000:8000 -v "${PWD}:/app" -w /app python:3.13-slim sh -c "pip install -r requirements.txt && uvicorn app.main:app --host 0.0.0.0 --port 8000"
```

### 2. Running Locally with Python Virtual Environment

```bash
# Activate virtual environment
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

# Start Uvicorn development server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

---

## Verification Endpoints

Once the application is running, the following endpoints are available:

- **Health Check:** `http://127.0.0.1:8000/api/v1/health`
  ```json
  {
    "status": "healthy",
    "application": "Folio360",
    "version": "1.0.0"
  }
  ```
- **Interactive API Documentation (Swagger UI):** `http://127.0.0.1:8000/docs`
- **OpenAPI 3.1 Specification:** `http://127.0.0.1:8000/openapi.json`

---

## Running Automated Tests

Run the test suite using `pytest`:

```bash
# Inside Docker:
docker exec folio360_api pytest -v

# Locally:
pytest -v
```

---

## Current Scope & Boundaries (Stage 1)

This repository currently reflects **Stage 1 (FastAPI Application Foundation)**:
- **Implemented:** FastAPI application factory, lifespan management, Pydantic Settings, centralized logging, exception handlers, health check endpoint, CORS middleware, and Pytest suite.
- **NOT Implemented in Stage 1:**
  - Database connectivity, PostgreSQL tables, SQLAlchemy ORM models, and Alembic migrations.
  - User authentication, password hashing (Argon2id), JWT token issuance/verification, OAuth providers, and session management.
  - File storage and OCR extraction pipelines.

These subsystems are intentionally scheduled for subsequent implementation stages.
