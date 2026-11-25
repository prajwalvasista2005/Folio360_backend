# FOLIO360 — COMPLETE TECHNICAL PROJECT HANDOVER

**Document ID:** F360-HANDOVER-P0S1-REV1 *(Updated at Phase 0 Closure)*  
**Project:** Folio360 (User-Centred Unified Profile for Academic, Professional, and Lifelong Learning Records)  
**Authoritative Specifications:**
- Core Auth (Stages 3A & 3B): [`F360-P0-AUTH-SPEC-REV10.md`](F360-P0-AUTH-SPEC-REV10.md)
- OAuth 2.0 / OIDC (Stages 3C.1–3C.7): `F360-S3C-SPEC-REV12` (`Supersedes: REV1–REV11`, SHA-256 `f83ef10096caf9b3d7d264cd10b9ff3a3822b594a4de9ff9d5e90a1834643f83`)
- Historical drafts (`REV3`–`REV9`): archived in [`docs/archive/superseded_specs/`](docs/archive/superseded_specs/README.md)

**Current Phase Gate:** **Phase 0 Authentication COMPLETE & ACCEPTED** (Stages 1, 2, 3A, 3B, and 3C.1–3C.7); Alembic at head `0004_add_oauth_tables`; **Phase 1 — Profile Creation** is the next pending phase (awaiting separate specification approval).

> **Historical Note:** Sections 1–10 below preserve the original Phase 0 Stage 1 architecture handover for historical baseline reference, while the Roadmap Matrix below reflects the current accepted state.

---

## 1. Project Identity

### 1.1 Project Name & Purpose
**Folio360** is a secure, user-centred platform designed to serve as a unified digital identity and living portfolio for academic qualifications, professional achievements, and lifelong learning records.

### 1.2 Problem Statement & Target Audience
- **Problem Statement:** Academic and professional credentials today are heavily fragmented across university semester grade cards, physical degree certificates, separate training portals, coding platforms, internship letters, and disconnected resumes. Verifying a student's semester progression, GPA calculations, and project authenticity is tedious, error-prone, and manual for universities, recruiters, and background verification agencies.
- **Target Audience:**
  1. **Higher Education Students:** Specifically tailored initially for Visvesvaraya Technological University (VTU) engineering students across Karnataka, India, managing 8 semesters of credits, SGPA/CGPA grading schemes, scheme revisions (2018/2021/2022 schemes), and backlog tracking.
  2. **Academic Institutions & Evaluators:** Department heads, placement officers, and university administrators needing authoritative, tamper-evident student records.
  3. **Recruiters & Hiring Managers:** Companies seeking verified academic transcripts, project repositories, and technical skill validations.
  4. **Lifelong Learners & Alumni:** Continuous repository for upskilling certifications, licenses, and professional milestones.

### 1.3 Product Objectives & Major Features
- **Dynamic Unified Profile:** Single authoritative digital profile showcasing academic, co-curricular, and professional achievements.
- **VTU Academic Tracker:** Automated semester record management, credit-weighted SGPA/CGPA calculation engine, and backlog reconciliation.
- **Project Showcase:** Detailed project cards with technology stack badges, architecture diagrams, GitHub repository integration, and live demonstration links.
- **Skills & Certification Vault:** Centralized vault for accredited certifications, licenses, and verified skill badges.
- **Export & Verification Engine:** Generation of cryptographically signed or verifiable digital transcripts and professional PDF resumes.

### 1.4 System Architecture Overview
- **Backend API:** Python 3.13 / FastAPI high-performance RESTful API with asynchronous ASGI concurrency, strict Pydantic v2 settings validation, fail-safe logging sanitization, and standardized public exception envelopes.
- **Database & Persistence (Planned Phase 0 Stage 2):** PostgreSQL accessed via synchronous SQLAlchemy 2.0 ORM with Alembic schema migrations.
- **Frontend Web Client (Planned):** Next.js / React single-page application with server-side rendering and responsive Tailwind CSS interface.
- **Mobile Client (Planned):** Cross-platform Flutter / Dart application for student grade entry and instant profile access.

### 1.5 Team & Operational Roles
- **Project Owner & Principal Architect:** Prajwal Vasista (`prajwalvasista8@gmail.com`). Holds final decision-making authority on architecture, code modifications, Git staging/commit operations, and stage gate progressions.
- **Antigravity AI Assistant:** Technical implementation partner and code author. Operates strictly under human-in-the-loop authorization. Must not modify code or advance stages without explicit approval from Prajwal.

---

## 2. Technical Architecture

### 2.1 Backend Tech Stack & Runtime
The backend service is engineered using modern, type-safe Python technologies running on Python 3.13:

| Component | Technology | Version | Purpose |
| :--- | :--- | :--- | :--- |
| **Language Runtime** | Python (CPython) | `3.13.x` | Modern Python runtime; containerized with `python:3.13-slim` for Linux parity. |
| **Web Framework** | FastAPI | `0.163.1` | Asynchronous web framework for high-throughput HTTP REST APIs. |
| **ASGI Server** | Uvicorn | `0.54.0` | High-performance ASGI server; paired with `uvloop 0.23.0` for event-loop acceleration. |
| **Data Validation** | Pydantic / Pydantic Settings | `2.10.6` / `2.8.0` | Strict environment variable parsing, type enforcement, and settings validation. |
| **HTTP Testing Client**| HTTPX | `0.28.1` | Synchronous and asynchronous HTTP client for integration test execution. |
| **Test Runner** | Pytest | `9.2.0` | Test suite execution, assertion reporting, and test fixture management. |
| **Database ORM (Planned Stage 2)** | SQLAlchemy | `2.0.x` | Synchronous SQL toolkit and Object-Relational Mapper. |
| **Database Driver (Planned Stage 2)** | psycopg (psycopg3) | `3.2.x` | Modern, high-performance PostgreSQL database adapter. |
| **Migrations (Planned Stage 2)** | Alembic | `1.15.x` | Database schema version control and migration management. |
| **Authentication (Planned Stage 3)** | Passlib (Argon2) / PyJWT | Latest | Secure password hashing (Argon2id) and RFC 7519 JWT generation. |

### 2.2 Directory Structure & Module Layout
The repository is structured following clean architectural boundaries:

```
folio360_backend/
├── .env.example                     # Reference environment variables template (untracked)
├── .gitignore                       # Git ignore patterns for Python, venv, IDEs, tests (tracked)
├── requirements.in                  # Top-level direct project dependencies (tracked)
├── requirements.txt                 # Fully pinned, reproducible dependency lockfile (tracked)
├── README.md                        # Project documentation and local quickstart guide (untracked)
├── FOLIO360_COMPLETE_PROJECT_HANDOVER.md # Complete technical handover documentation (this document)
├── app/                             # Core application package (untracked)
│   ├── __init__.py                  # Application package marker
│   ├── main.py                      # FastAPI application factory and lifespan manager
│   ├── api/                         # API routing layer
│   │   ├── __init__.py              # API package marker
│   │   └── routes/                  # Route handlers
│   │       ├── __init__.py          # Routes package marker
│   │       └── health.py            # Health check endpoint (/api/v1/health)
│   └── core/                        # Cross-cutting foundational modules
│       ├── __init__.py              # Core package marker
│       ├── config.py                # Pydantic Settings and CORS origin parsing
│       ├── exceptions.py            # Custom exception hierarchy and public error handlers
│       └── logging.py               # Central logging setup, security filter, and redaction
└── tests/                           # Complete test suite (untracked)
    ├── __init__.py                  # Tests package marker
    ├── test_config.py               # 10 tests for environment settings and CORS validation
    ├── test_exceptions.py           # 14 tests for exception hierarchy and credential protection
    ├── test_health.py               # 5 tests for health endpoints and OpenAPI documentation
    └── test_logging.py              # 14 tests for log sanitization, regex redaction, and fail-safe policy
```

### 2.3 Application Lifespan & Initialization
In [app/main.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/main.py), the FastAPI application lifecycle is managed using the modern `@asynccontextmanager` lifespan protocol:
1. **Startup:** `setup_logging()` is executed immediately, configuring root and application loggers with the security filtering pipeline. Startup diagnostics and application metadata (`app_name`, `env`, `version`) are logged safely.
2. **Lifespan Yield:** The application serves incoming HTTP traffic.
3. **Shutdown:** Clean shutdown logging executes before process termination.

### 2.4 Configuration & Environment Management
In [app/core/config.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/core/config.py), the `Settings` class inherits from `pydantic_settings.BaseSettings`:
- Configuration is loaded from environment variables and `.env` files (`SettingsConfigDict(env_file=".env", extra="ignore")`).
- **CORS Origin Parsing:** Implemented via `@field_validator("CORS_ORIGINS", mode="before")`. The validator supports:
  - Native Python `list[str]` or `set[str]`.
  - JSON-formatted arrays: `["http://localhost:3000", "https://folio360.app"]`.
  - Comma-separated strings: `http://localhost:3000, https://folio360.app`.
  - Rejects: JSON objects (`{"origin": "..."}`), numbers, booleans, single unbracketed JSON string primitives, strings with unclosed quotes, strings with trailing commas or empty tokens, and malformed JSON arrays.

### 2.5 Logging Security & Fail-Safe Redaction
In [app/core/logging.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/core/logging.py), logging security is enforced by `SecurityFilter(logging.Filter)` and helper utilities:
- **Comprehensive Redaction Regexes:**
  - `KEY_VALUE_PATTERN`: Redacts values for `password`, `secret`, `access_token`, `refresh_token`, `token_hash`, and `token`.
  - `AUTH_HEADER_PATTERN`: Redacts credentials in `Authorization: Bearer <token>` or `Authorization: Basic <token>` while preserving the auth scheme: `Authorization: Bearer [REDACTED]`.
  - `DATABASE_URI_PATTERN`: Matches database connection URIs (`postgres://`, `postgresql://`, `mysql://`, `sqlite://`) and replaces them entirely with `[REDACTED_CONNECTION_STRING]`.
  - `SQL_PATTERN`: Matches raw SQL statements (`SELECT ... FROM ...`, `INSERT INTO ... VALUES (...)`, `UPDATE ... SET ...`, `DELETE FROM ...`) and replaces them with `[REDACTED_SQL]`.
  - `BEARER_PATTERN`: Replaces standalone `Bearer eyJ...` with `Bearer [REDACTED]`.
- **Complete LogRecord Sanitization:** Sanitizes `record.msg` (string or non-string converted via `str(record.msg)`), `record.args`, `record.exc_info`, `record.exc_text`, and `record.stack_info`.
- **Child Handler Protection:** `protect_handler(handler)` attaches `SecurityFilter` directly to any application-controlled handler, preventing child loggers with `propagate = False` from bypassing security filters.
- **Fail-Safe Suppression:** If any unexpected exception occurs during formatting or sanitization, `record.msg` is replaced with `[LOG_SANITIZATION_FAILED: Record content suppressed for security]`, and `record.args`, `record.exc_info`, `record.exc_text`, and `record.stack_info` are cleared to `None`.

### 2.6 Exception Safety & Public Message Policy
In [app/core/exceptions.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/core/exceptions.py), error responses adhere to a strict public API contract:
- **Response Format:** Standard JSON envelope:
  ```json
  {
    "error": {
      "message": "String safe message",
      "status_code": 400,
      "details": null
    }
  }
  ```
- **4xx Client Errors:** Internal `exc.message` is **NEVER** returned directly to the client. Only an explicitly authorized `exc.public_message` is returned. If `public_message` is omitted, the handler falls back to safe generic status text (e.g. `"Bad request"`, `"Resource not found"`, `"Validation failed"`).
- **Client Details Sanitization:** If client error `details` contain dictionary payloads, sensitive keys (`password`, `token`, `secret`, etc.) and credential strings are redacted before serializing into the HTTP response.
- **5xx Server Errors & Unhandled Exceptions:** Always return generic `"Internal server error"` with HTTP status 500. The `details` field is forced to `None`. Internal exception stack traces and SQL error diagnostics are logged securely through the redacted logging pipeline and never leaked over the wire.

### 2.7 API Routing & Health Checks
- [app/api/routes/health.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/api/routes/health.py) mounts `GET /api/v1/health` returning:
  ```json
  {
    "status": "healthy",
    "application": "Folio360",
    "version": "1.0.0"
  }
  ```
- Interactive API documentation is available at `/docs` (Swagger UI) and `/openapi.json` (OpenAPI 3.1.0 specification).

### 2.8 Database Architecture & Current Database Status
- **Planned Architecture:** PostgreSQL 16+ accessed via synchronous SQLAlchemy 2.0 ORM using `psycopg` (psycopg3) as the binary driver. Schema versions managed by Alembic.
- **CURRENT STATUS:** **NOT STARTED**. No database models, engine sessions, or Alembic migrations exist. Database implementation is strictly gated under Phase 0 Stage 2.

---

## 3. Development Roadmap

The Folio360 backend is developed through phased, gated stages. Below is the authoritative status matrix across all phases:

| Phase | Stage | Description | Status | Verification & Deliverables |
| :--- | :--- | :--- | :--- | :--- |
| **Phase 0** | **Stage 1** | **Core Scaffolding & Foundation**<br>Python 3.13 setup, FastAPI factory, Pydantic settings, secure logging, exception framework, health endpoint. | **ACCEPTED** | Stage 1 verified & accepted. |
| **Phase 0** | **Stage 2** | **Database & ORM Foundations**<br>SQLAlchemy 2.0 synchronous engine, declarative Base, Alembic (`0001_create_users`), split DB roles, `/health/ready`. | **ACCEPTED** | Live PostgreSQL 17 & migration verified. |
| **Phase 0** | **Stage 3A** | **Core Authentication**<br>Argon2id, Resend email verification (`0002_add_core_auth_tables`), HS256 JWTs (`auth_version`), rotating refresh families, `Origin` CSRF, IP rate limits, ASGI3 Uvicorn entrypoint. | **ACCEPTED** | Per [`F360-P0-AUTH-SPEC-REV10.md`](F360-P0-AUTH-SPEC-REV10.md). |
| **Phase 0** | **Stage 3B** | **Password Reset & Change**<br>`/forgot-password`, `/reset-password`, `/change-password`, `0003_add_password_reset_tokens`. | **ACCEPTED** | Per [`F360-P0-AUTH-SPEC-REV10.md`](F360-P0-AUTH-SPEC-REV10.md). |
| **Phase 0** | **Stage 3C (3C.1–3C.7)** | **Google OIDC & GitHub OAuth 2.0**<br>Config/keys/logging, PKCE/AES-256-GCM, `0004_add_oauth_tables`, providers & `HttpxJWKClient`, orchestration & SAVEPOINT recovery, HTTP routes & ASGI middleware, security/e2e verification. | **ACCEPTED** | Per `F360-S3C-SPEC-REV12` (`629` total repository tests passing). |
| **Phase 0 / Phase 1** | **Profile Creation** | **User Profile Core / Academic Records**<br>Student profile schemas, CRUD endpoints, and domain models. | **NOT STARTED** | Next phase; requires separate specification & owner approval. |
| **Phase 1** | **Stage 1** | **VTU Semester Records**<br>Semester models (1-8), course codes, credits, grades, marks schemas, CRUD endpoints. | **NOT STARTED** | Planned. |
| **Phase 1** | **Stage 2** | **VTU GPA Calculation Engine**<br>Automated SGPA/CGPA algorithm adhering to VTU credit-weighting rules, backlogs, grade points. | **NOT STARTED** | Planned. |
| **Phase 1** | **Stage 3** | **Academic Verification**<br>Transcript reconciliation and institutional grade verification flags. | **NOT STARTED** | Planned. |
| **Phase 2** | **Stage 1** | **Skills & Endorsements**<br>Technical skills matrix, categorization, proficiency levels. | **NOT STARTED** | Planned. |
| **Phase 2** | **Stage 2** | **Certifications Vault**<br>Certification records, verification URLs, issuing authority tracking, expiration dates. | **NOT STARTED** | Planned. |
| **Phase 3** | **Stage 1** | **Project Portfolio**<br>Project showcase models, tech stack tagging, GitHub link integration, live preview links. | **NOT STARTED** | Planned. |
| **Phase 3** | **Stage 2** | **Media Storage Integration**<br>Cloudflare R2 / AWS S3 presigned URLs for project screenshots and documents. | **NOT STARTED** | Planned. |
| **Phase 4** | **Stage 1** | **Resume & PDF Generation**<br>Dynamic curriculum vitae generation from structured profile records. | **NOT STARTED** | Planned. |
| **Phase 4** | **Stage 2** | **Public Shareable Profiles**<br>Scoped public profile links with vanity slugs and configurable privacy controls. | **NOT STARTED** | Planned. |
| **Phase 5** | **Stage 1** | **Recruiter & Institutional Portal**<br>Candidate search, bulk transcript verification, institutional audit logs. | **NOT STARTED** | Planned. |

> [!NOTE]
> **Historical Archive Boundary:** The deep-dive file tree in Sections 5–10 below records the original Phase 0 Stage 1 snapshot (`F360-HANDOVER-P0S1-REV1`). Current Phase 0 Stages 1–3C modules, APIs, and Docker test commands are documented in [`README.md`](README.md). No Phase 1 (Profile Creation) code or specification exists yet.

---

## 4. Implementation History

Phase 0 Stage 1 was developed and hardened through an initial implementation and five iterative, authorized correction rounds:

### 4.1 Initial Stage 1 Implementation
- **Scope:** Initial FastAPI scaffolding, dependency management (`requirements.in` and pinned `requirements.txt`), basic environment settings, health route, and initial logging setup.
- **Findings:** Initial test suite highlighted edge cases in CORS origin parsing (JSON objects falling through to CSV) and logging sanitization edge cases.

### 4.2 Correction Round 1 (CORS & Auth Header Redaction)
- **Scope:** Authorized targeted fixes in `app/core/config.py` and `app/core/logging.py`.
- **Fixes Applied:**
  1. *CORS Parsing:* Explicitly rejected JSON objects from falling into CSV comma parsing.
  2. *Auth Header Redaction:* Fixed regex replacement to preserve the authorization scheme (`Authorization: Bearer [REDACTED]` instead of replacing the scheme word).
- **Result:** 25 unit tests passing.

### 4.3 Correction Round 2 (Independent Review Preparation)
- **Scope:** Read-only source collection and review preparation for independent architectural evaluation.
- **Analysis:** Documented why initial pytest runs exited with code 1 before passing (missing dependencies in initial host run before switching to containerized execution) and verified zero git drift.

### 4.4 Correction Round 3 (Exception Safety & Logger State Isolation)
- **Scope:** Four security areas authorized by the project owner:
  1. *Exception Response Safety:* Prevented raw `exc.message` from reaching clients on 500 errors; introduced `public_message` contract.
  2. *Handler Protection:* Added `protect_handler(handler)` to prevent child loggers with `propagate = False` from bypassing root security filters.
  3. *Details Sanitization:* Sanitized sensitive dictionary keys in 4xx error detail payloads.
  4. *Test Logger Isolation:* Wrapped test logger manipulations in strict `try/finally` blocks to prevent handler leaks across tests.
- **Result:** Test suite expanded to 37 passing tests.

### 4.5 Correction Round 4 (Public Message Policy & Database Redaction)
- **Scope:** Six targeted corrections:
  1. *Explicit 4xx Public Message Policy:* Enforced that internal `exc.message` is never exposed, even on 4xx errors, falling back to safe generic status descriptions.
  2. *SQL Statement Redaction:* Fixed catastrophic backtracking in SQL regex by removing a trailing word boundary `\b` that caused `VALUES (...)` closing parentheses to miss redaction.
  3. *Database Connection String Redaction:* Added `DATABASE_URI_PATTERN` replacing sensitive URIs with `[REDACTED_CONNECTION_STRING]`.
  4. *Bare Token Redaction:* Updated `KEY_VALUE_PATTERN` to match standalone `token=` keys without being shadowed by longer prefixes.
  5. *Test Suite Hardening:* Added comprehensive regression tests for SQL statements and database URIs.
- **Result:** 37 passing tests with zero test regressions.

### 4.6 Correction Round 5 (Logging Hardening: Stack Info & Non-String Messages)
- **Scope:** Final logging sanitization hardening:
  1. *`record.stack_info` Sanitization:* Enforced that `stack_info` is sanitized before emission and wiped to `None` if sanitization fails.
  2. *Non-String Log Messages:* Explicitly handled non-string `record.msg` types (e.g. integers, custom objects, dicts) by converting to string representation for regex scanning.
  3. *Fail-Safe Suppression:* Ensured that any formatting or filtering failure completely suppresses the log record content and clears all arguments, stack traces, and exception info.
  4. *Expanded Test Suite:* Added 6 new regression tests in `tests/test_logging.py`.
- **Result:** Test suite expanded to **43 passing tests** in Docker Linux container (5.57s execution time). Live HTTP endpoints verified.

---

## 5. Current Repository State

### 5.1 Git Details & Authoritative HEAD
- **Active Branch:** `main`
- **Authoritative HEAD Commit:** `f3dc5d3c0f85ea03570281a0483f968187ff0d9e`
- **HEAD Commit Message:** `chore: initialize Folio360 backend environment`
- **Author:** Prajwal Vasista (`prajwalvasista8@gmail.com`)
- **Date:** Tue Nov 17 17:08:06 2026 +0530
- **Remote Origin:** `https://github.com/prajwalvasista2005/Folio360_backend.git`
- **Remote Tracking Status:** Local branch `main` is ahead of remote; tracking branch `origin/main` is marked `[gone]` because only the initial commit exists locally.

### 5.2 Working Tree Status
- **Staged Changes:** None (`git diff --cached` is empty).
- **Tracked Modified Files:** None (`git diff` is empty).
- **Tracked Whitespace Errors:** None (`git diff --check` is clean).
- **Tracked Files in Git Index (3 files):**
  1. `.gitignore`
  2. `requirements.in`
  3. `requirements.txt`
- **Untracked Project Files on Disk:**
  - `.env.example`
  - `README.md`
  - `app/` (all 9 source files)
  - `tests/` (all 5 test suite files)
  - `FOLIO360_COMPLETE_PROJECT_HANDOVER.md` (this handover document)

### 5.3 Complete File Inventory

| Relative Path | Lines | Size (Bytes) | Git Status | Description |
| :--- | :---: | :---: | :---: | :--- |
| [`.gitignore`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/.gitignore) | 67 | 781 | Tracked | Ignores `.venv/`, `__pycache__/`, `.pytest_cache/`, `.env`, IDE files. |
| [`requirements.in`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/requirements.in) | 19 | 472 | Tracked | Top-level direct project dependencies. |
| [`requirements.txt`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/requirements.txt) | 49 | 1,762 | Tracked | Pinned lockfile with all 49 transitive dependencies. |
| [`.env.example`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/.env.example) | 21 | 880 | Untracked | Template defining default environment variables. |
| [`README.md`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/README.md) | 107 | 5,189 | Untracked | Overview of project setup, running instructions, and architecture. |
| [`FOLIO360_COMPLETE_PROJECT_HANDOVER.md`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/FOLIO360_COMPLETE_PROJECT_HANDOVER.md) | ~500 | ~25,000 | Untracked | Authoritative handover document for incoming sessions. |
| [`app/__init__.py`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/__init__.py) | 1 | 44 | Untracked | Application package initialization. |
| [`app/main.py`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/main.py) | 55 | 2,099 | Untracked | FastAPI app instance, lifespan context, route and exception registration. |
| [`app/api/__init__.py`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/api/__init__.py) | 1 | 60 | Untracked | API package initialization. |
| [`app/api/routes/__init__.py`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/api/routes/__init__.py) | 1 | 26 | Untracked | Routes package initialization. |
| [`app/api/routes/health.py`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/api/routes/health.py) | 42 | 1,491 | Untracked | `GET /api/v1/health` endpoint returning application health status. |
| [`app/core/__init__.py`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/core/__init__.py) | 1 | 70 | Untracked | Core package initialization. |
| [`app/core/config.py`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/core/config.py) | 180 | 8,780 | Untracked | Pydantic Settings class and robust CORS origin parsing. |
| [`app/core/exceptions.py`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/core/exceptions.py) | 182 | 7,414 | Untracked | Custom exception hierarchy, public message policy, safe handlers. |
| [`app/core/logging.py`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/core/logging.py) | 205 | 10,882 | Untracked | Central logging configuration, `SecurityFilter`, credential & SQL redaction. |
| [`tests/__init__.py`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/tests/__init__.py) | 1 | 47 | Untracked | Tests package initialization. |
| [`tests/test_config.py`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/tests/test_config.py) | 123 | 7,588 | Untracked | 10 tests covering configuration and CORS origin validation. |
| [`tests/test_exceptions.py`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/tests/test_exceptions.py) | 248 | 12,721 | Untracked | 14 tests covering exception safety and public message policy. |
| [`tests/test_health.py`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/tests/test_health.py) | 56 | 2,661 | Untracked | 5 tests covering health check responses and OpenAPI documentation. |
| [`tests/test_logging.py`](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/tests/test_logging.py) | 426 | 18,888 | Untracked | 14 tests covering log sanitization, regex redaction, and fail-safe suppression. |

---

## 6. Current Implementation Deep Dive

### 6.1 `app/main.py`
- **Class / Function:** `create_application() -> FastAPI`
- **Lifespan Manager:** `@asynccontextmanager async def lifespan(app: FastAPI)`
- **Key Responsibilities:**
  1. Instantiates the FastAPI application using configured settings (`settings.APP_NAME`, `settings.DEBUG`, `settings.VERSION`).
  2. Attaches the CORS middleware (`CORSMiddleware`) configured with `settings.CORS_ORIGINS`.
  3. Registers centralized exception handlers for `Folio360Exception` and unhandled `Exception`.
  4. Includes API routers under the configured prefix (`settings.API_V1_PREFIX`).
- **Known Limitations:** Database connection pools and authentication middlewares are not yet hooked up (reserved for Stages 2 and 3).

### 6.2 `app/core/config.py`
- **Class:** `Settings(BaseSettings)`
- **Fields:**
  - `APP_NAME: str = "Folio360"`
  - `ENV: str = "development"`
  - `API_V1_PREFIX: str = "/api/v1"`
  - `DEBUG: bool = False`
  - `LOG_LEVEL: str = "INFO"`
  - `CORS_ORIGINS: list[str] = ["http://localhost:3000"]`
- **Key Validator:** `assemble_cors_origins(cls, v: Any) -> list[str]`
  - Validates and parses multiple input shapes (list, JSON array, comma-separated string).
  - Explicitly detects and rejects JSON objects (`v_str.startswith("{")`).
  - Detects unclosed quotes and trailing commas.
  - Strips leading/trailing whitespace and quotes from each origin token.
- **Singleton Factory:** `get_settings() -> Settings` with `@lru_cache` to avoid repeated disk reads.

### 6.3 `app/core/exceptions.py`
- **Exception Hierarchy:**
  ```
  Exception
  └── Folio360Exception (status_code, message, public_message, details)
      ├── ValidationException (422 / 400)
      ├── NotFoundException (404)
      ├── UnauthorizedException (401)
      ├── ForbiddenException (403)
      └── InternalServerException (500)
  ```
- **Public Message Policy:** `get_safe_public_message(exc: Folio360Exception) -> str`
  - For `status_code >= 500`: Always returns `"Internal server error"`.
  - For `400 <= status_code < 500`: Returns `exc.public_message` if explicitly set; otherwise returns safe default status text. Internal `exc.message` is **never** leaked.
- **Details Redaction:** `sanitize_error_details(details: Any) -> Any`
  - Recursively inspects dicts and lists, masking keys matching sensitive substrings with `"[REDACTED]"`.
- **Exception Handlers:**
  - `folio360_exception_handler(request: Request, exc: Folio360Exception) -> JSONResponse`
  - `unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse`

### 6.4 `app/core/logging.py`
- **Class:** `SecurityFilter(logging.Filter)`
- **Method:** `filter(self, record: logging.LogRecord) -> bool`
  - In-place redaction across `record.msg`, `record.args`, `record.exc_info`, `record.exc_text`, and `record.stack_info`.
  - If `record.msg` is not a string, converts via `str(record.msg)` before running regex redaction.
  - Handles `record.args` as both `tuple` and `dict` parameter mappings.
  - Wraps processing in a comprehensive `try/except Exception` block. On failure, triggers fail-safe suppression: replaces message with safe constant and wipes arguments and stack traces.
- **Handler Protection:** `protect_handler(handler: logging.Handler) -> logging.Handler` ensures all handlers carry `SecurityFilter`.
- **Setup Function:** `setup_logging() -> None` initializes the root logger and `folio360` app logger with standard formats and levels.

### 6.5 `app/api/routes/health.py`
- **Route:** `GET /api/v1/health`
- **Response Model:** `HealthResponse(BaseModel)`
  - `status: str = "healthy"`
  - `application: str`
  - `version: str`
- **Behavior:** Lightweight, synchronous endpoint returning HTTP 200 without blocking operations or external dependencies.

---

## 7. Testing & Verification

### 7.1 Pytest Test Suite Breakdown
The test suite consists of **43 comprehensive unit tests** across 4 modules:

```
tests/test_config.py . . . . . . . . . .                                 [ 23%] (10 tests)
tests/test_exceptions.py . . . . . . . . . . . . . .                     [ 55%] (14 tests)
tests/test_health.py . . . . .                                           [ 67%] ( 5 tests)
tests/test_logging.py . . . . . . . . . . . . . .                        [100%] (14 tests)

======================== 43 passed, 1 warning in 5.57s =========================
```

- **`test_config.py` (10 tests):**
  - `test_default_settings`: Verifies default application name, environment, and version.
  - `test_cors_origins_from_json_string`: Validates JSON array parsing.
  - `test_cors_origins_from_csv_string`: Validates comma-separated parsing.
  - `test_cors_rejects_non_list_json`: Confirms JSON objects are rejected.
  - `test_cors_rejects_unclosed_quotes`: Rejects malformed quotes in CSV input.
  - `test_cors_rejects_trailing_delimiter`: Rejects trailing commas.
  - `test_cors_origins_native_list`: Validates native list passthrough.
  - `test_env_override`: Verifies environment variable override precedence.
  - `test_debug_flag_parsing`: Tests boolean debug conversion.
  - `test_get_settings_caching`: Verifies settings caching via `@lru_cache`.

- **`test_exceptions.py` (14 tests):**
  - `test_folio360_exception_defaults`: Checks base exception properties.
  - `test_specific_exceptions`: Validates subclasses (Validation, NotFound, etc.).
  - `test_public_message_policy_4xx`: Confirms explicit public message is returned.
  - `test_public_message_fallback_4xx`: Ensures missing public message falls back to generic text.
  - `test_public_message_policy_5xx`: Verifies 500 errors never leak internal messages.
  - `test_details_sanitization_in_exceptions`: Confirms sensitive keys in details are redacted.
  - `test_unhandled_exception_handler`: Verifies standard unhandled 500 error envelope.
  - `test_folio360_exception_handler_client_error`: End-to-end HTTP test for 400 exceptions.
  - `test_folio360_exception_handler_server_error`: End-to-end HTTP test for 500 exceptions.
  - `test_details_as_nested_dict`: Tests recursive dict credential redaction.
  - `test_details_as_list`: Tests list-of-dict credential redaction.
  - `test_sql_in_exception_logged_safely`: Verifies SQL errors are sanitized before logging.
  - `test_internal_message_not_leaked`: Confirms database constraint names are hidden.
  - `test_exception_status_code_preservation`: Validates status code integrity.

- **`test_health.py` (5 tests):**
  - `test_health_check_status_code`: Confirms HTTP 200 response on `/api/v1/health`.
  - `test_health_check_body`: Validates JSON payload attributes.
  - `test_health_check_content_type`: Verifies `application/json` header.
  - `test_openapi_json`: Validates OpenAPI specification endpoint.
  - `test_swagger_docs`: Validates Swagger UI documentation endpoint.

- **`test_logging.py` (14 tests):**
  - `test_sanitize_log_text_credentials`: Tests redaction of passwords, secrets, tokens.
  - `test_sanitize_log_text_auth_header`: Tests `Authorization: Bearer [REDACTED]`.
  - `test_sanitize_log_text_db_uri`: Tests `[REDACTED_CONNECTION_STRING]`.
  - `test_sanitize_log_text_sql`: Tests `[REDACTED_SQL]` on SELECT, INSERT, UPDATE, DELETE.
  - `test_security_filter_record_msg`: Confirms in-place redaction of `record.msg`.
  - `test_security_filter_record_args_tuple`: Confirms redaction in tuple args.
  - `test_security_filter_record_args_dict`: Confirms redaction in dict args.
  - `test_security_filter_exc_text`: Confirms redaction in formatted exception traces.
  - `test_security_filter_stack_info`: Confirms redaction in stack information.
  - `test_security_filter_non_string_msg`: Confirms handling of integer and object messages.
  - `test_security_filter_fail_safe_suppression`: Tests fail-safe suppression when filter raises.
  - `test_protect_handler_attaches_filter`: Verifies handler protection utility.
  - `test_child_logger_handler_protection`: Confirms child loggers cannot bypass security filter.
  - `test_setup_logging_idempotence`: Verifies logging setup does not duplicate handlers.

### 7.2 Docker Linux Verification Workflow
To guarantee strict Linux environment parity (matching production deployment targets), testing is performed inside a Python 3.13 Linux container:
1. **Container Image:** `python:3.13-slim`
2. **Mount Strategy:** Volume mount host repository directory to `/app`:
   ```bash
   docker run -d --name folio360_stage1_verify -v "C:\Users\vasista0305\OneDrive\Desktop\folio360_backend:/app" -w /app python:3.13-slim tail -f /dev/null
   ```
3. **Execution Pattern:**
   ```bash
   docker exec folio360_stage1_verify pip install -r requirements.txt
   docker exec folio360_stage1_verify pytest -v
   ```
4. **Cleanup:** Once verification completes, cleanly terminate and remove the verification container:
   ```bash
   docker rm -f folio360_stage1_verify
   ```

### 7.3 Starlette Deprecation Warning Investigation
During test execution, 1 warning is emitted:
```
StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated; install httpx2 instead.
```
- **Root Cause Investigation:** In Starlette `0.45.3`, `starlette.testclient.TestClient` inspects whether `httpx` is used and emits a forward-looking deprecation notice regarding potential future separation into `httpx2`.
- **Finding:** This is an upstream Starlette framework notice. It does not indicate any defect in Folio360 application code and does not affect runtime execution or API test assertions.

### 7.4 Live HTTP Endpoint Verification
Live HTTP verification was conducted inside the container using Uvicorn:
- **`GET /api/v1/health`:** HTTP 200 OK
  ```json
  {"status":"healthy","application":"Folio360","version":"1.0.0"}
  ```
- **`GET /docs`:** HTTP 200 OK (Swagger UI HTML)
- **`GET /openapi.json`:** HTTP 200 OK (Valid OpenAPI 3.1.0 schema)

---

## 8. Development Rules & Approval Protocol

All development on Folio360 is governed by a strict **5-Step Human-in-the-Loop Protocol**. Every incoming Antigravity agent must adhere to these rules without exception:

### 8.1 The Mandatory 5-Step Protocol

```
+-------------------------------------------------------------+
| Step 1: Read-Only Inspection & Diagnosis                    |
| - Inspect repository, git status -sb, and logs              |
| - Zero file modifications, zero commits, zero side effects  |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| Step 2: Formal Authorization Request                        |
| - Present proposed diffs, rationale, and exact scope        |
| - Await explicit approval from Prajwal before editing       |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| Step 3: Targeted Implementation                             |
| - Modify ONLY authorized files                              |
| - Zero scope creep; do not start future stages              |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| Step 4: Containerized Verification                          |
| - Execute pytest in python:3.13-slim Linux container        |
| - Verify 100% pass rate; check live endpoints with curl     |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| Step 5: Read-Only Independent Review Preparation            |
| - Present complete git diffs and full source listings       |
| - Await owner instructions before staging or committing     |
+-------------------------------------------------------------+
```

### 8.2 Strict Operational Boundaries
1. **Never Modify Files Without Prior Authorization:** Even if an obvious typo or improvement is spotted, report it and request approval. Do not perform unapproved edits.
2. **Never Stage, Commit, or Push Without Explicit Direction:** Keep all working-tree edits unstaged until Prajwal explicitly instructs to commit. Never execute `git push` without permission.
3. **Never Start Future Stages Prematurely:** Do not create database models, write Alembic scripts, or install auth packages until Stage 1 has received formal gate approval.
4. **Avoid Background Polling Loops:** Do not set polling timers or shell sleep loops waiting for tasks. Use event-driven notifications (`schedule` with clear conditions or finish commands synchronously).
5. **Preserve Container Efficiency:** Never recreate Docker containers or reinstall dependencies blindly when an existing verification container or environment is already active.
6. **Code Quality Standards:**
   - Adhere strictly to PEP 8 formatting and type hints.
   - Every public API exception must enforce safe public messaging.
   - All logging handlers must be wrapped in `protect_handler()`.
   - Test files must never leak handlers or modify shared global state without `try/finally` cleanup.

---

## 9. Immediate Next Task

### 9.1 Exact Current State
- **Phase 0, Stage 1 Implementation:** **COMPLETE.**
- **Correction Round 5:** **COMPLETE.**
- **Test Suite:** **43 passing tests** (100% pass rate in Python 3.13 Linux container).
- **Git State:** 3 tracked files in index; clean working tree on tracked files; all Stage 1 code resides in untracked files (`app/`, `tests/`, `.env.example`, `README.md`, `FOLIO360_COMPLETE_PROJECT_HANDOVER.md`).

### 9.2 Immediate Next Steps (Stage 1 Review Gate)
1. **Owner Review of Correction Round 5:** Prajwal will perform an independent review of the hardened logging sanitization source code (`app/core/logging.py` and `tests/test_logging.py`).
2. **Stage 1 Completion Sign-Off:** Once satisfied, Prajwal will provide formal gate sign-off for Phase 0 Stage 1.
3. **Initial Stage 1 Git Commit:** Upon Prajwal's explicit instruction, stage and commit the untracked Stage 1 files:
   - Suggested commit message: `feat(stage1): implement core app scaffolding, configuration, logging, exceptions, and health routes`
4. **Stage 2 Scoping & Authorization:** Following commit, Prajwal will define the explicit scope and authorization requirements for **Phase 0 Stage 2 (Database Layer & ORM Foundations)**.

### 9.3 Proposed Stage 2 Scope (Pending Approval)
When authorized by Prajwal, Phase 0 Stage 2 will include:
- Establishing PostgreSQL containerized service (`docker-compose.yml` or local container).
- Implementing database engine and session factory in `app/core/database.py` using synchronous SQLAlchemy 2.0.
- Defining declarative `Base` model with UUID primary keys and timestamp mixins (`created_at`, `updated_at`).
- Initializing Alembic migration environment (`alembic/` and `alembic.ini`).
- Creating initial User model schema.
- Writing unit and integration tests verifying database connection and migration generation.

---

## 10. Instructions for the Receiving Antigravity Account

If you are a new Antigravity session taking over this repository, follow this step-by-step onboarding procedure:

### 10.1 Step 1 — Verify Environment in Read-Only Mode
1. Inspect the Git status:
   ```powershell
   git status -sb
   ```
   *Expected output:* `## main...origin/main [gone]` with untracked `.env.example`, `README.md`, `app/`, `tests/`, and `FOLIO360_COMPLETE_PROJECT_HANDOVER.md`.
2. Verify authoritative HEAD commit:
   ```powershell
   git log -n 1 --oneline
   ```
   *Expected output:* `f3dc5d3 chore: initialize Folio360 backend environment`.
3. Confirm that no files are staged (`git diff --cached` is empty).

### 10.2 Step 2 — Run Verification Suite (Docker Linux Container)
1. Check if a container is running:
   ```powershell
   docker ps -a
   ```
2. If no container is running, start a lightweight Python 3.13 verification container:
   ```powershell
   docker run -d --name folio360_stage1_verify -v "${PWD}:/app" -w /app python:3.13-slim tail -f /dev/null
   ```
3. Install dependencies and run pytest:
   ```powershell
   docker exec folio360_stage1_verify pip install -r requirements.txt
   docker exec folio360_stage1_verify pytest -v
   ```
   *Expected result:* **43 passed, 1 warning** in ~5 seconds.
4. Clean up the container when verification is complete:
   ```powershell
   docker rm -f folio360_stage1_verify
   ```

### 10.3 Step 3 — Interacting with Project Owner (Prajwal)
- Greet Prajwal concisely.
- Acknowledge that you have thoroughly ingested `FOLIO360_COMPLETE_PROJECT_HANDOVER.md`.
- State clearly that you are in **Read-Only Mode** and that Phase 0 Stage 1 is fully tested with 43 passing tests.
- Ask Prajwal if he would like to:
  - Conduct an independent source review of Correction Round 5 files.
  - Approve the Stage 1 completion gate and commit the Stage 1 files.
  - Provide instructions for scoping Phase 0 Stage 2.

### 10.4 Communication Style Guidelines
- **Be Concise and Transparent:** Avoid fluffy summaries or sycophantic greetings.
- **Link Files Directly:** Always create clickable links for files referenced in chat using markdown links (e.g. `[config.py](file:///c:/Users/vasista0305/OneDrive/Desktop/folio360_backend/app/core/config.py)`).
- **Strict Human-in-the-Loop:** Never make assumptions about architecture or proceed without explicit authorization.

---
*End of Handover Document.*
