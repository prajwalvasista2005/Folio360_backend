# Folio360 Phase 0 Authentication Specification — Rev7 Review Report

- **Target Document:** [F360-P0-AUTH-SPEC-REV7.md](F360-P0-AUTH-SPEC-REV7.md) (`F360-P0-AUTH-SPEC-REV7`)
- **Base Revision Preserved Untouched:** [F360-P0-AUTH-SPEC-REV6.md](F360-P0-AUTH-SPEC-REV6.md)
- **Repository:** `/home/prajwal/projects/Folio360_backend` (`main` at `54c155bd0ba74f3cc54473fd7b3fb0d0e52b8936`; Stage 2 baseline `206970f5923bd19d445cce905e6bbaf0b5c697ff`)
- **Status:** Specification preparation complete — **awaiting independent review and explicit owner approval before any Stage 3A implementation**.
- **Authorization Confirmation:** Strictly documentation-only. Zero application source files, tests, Alembic migrations, dependencies, environment configs, `F360-P0-AUTH-SPEC-REV6.md`, or Git state were modified; no tests, migrations, or Docker commands were executed.

---

## 1. Corrections Made (Rev6 -> Rev7)

1. **Correction A — Explicit Uvicorn ASGI3 Interface Enforcement & Coroutine-Marked `__call__`:**
   - Enforced `interface="asgi3"` (`config.asgi_version == "3.0"`) in `VerifiedUvicornConfig` (via `_UNSET` sentinel keyword parameter, rejecting `"auto"`, `"asgi2"`, `"wsgi"`, `--interface`, ambient `UVICORN_INTERFACE`, and pre/post-load mutation).
   - Specified `@inspect.markcoroutinefunction` on `Folio360FastAPI.__call__` delegating 3-arg ASGI3 calls to `async def _dispatch_asgi(self, scope, receive, send)` while handling 0-arg `Config.load()` probes synchronously (`RuntimeError` in unverified production `Config.load()`, `TypeError` otherwise) and rejecting invalid arity synchronously (`TypeError`).
   - Extended `verify_loaded_asgi_middleware` and `verify_production_asgi_trust_boundary` to confirm `isinstance(fastapi_app, Folio360FastAPI)`, `uvicorn._compat.iscoroutinefunction(fastapi_app.__call__) is True`, and absence of `ASGI2Middleware`, `WSGIMiddleware`, and `MessageLoggerMiddleware` (both outer and intermediate).
   - Added 8 proposed ASGI3 security tests (Tests 28–35 in §20.3 Part D).

2. **Correction B — Post-Verification Email Return & Navigation Contract:**
   - Explicitly preserved the 7-step non-authenticating flow (`POST /api/v1/auth/verify-email` sets zero cookies, returns zero tokens, creates zero sessions, accepts no arbitrary redirect target).
   - Added **§10.2 Web Return Contract**: navigate/redirect strictly to configured `{FRONTEND_BASE_URL}/login`, rejecting/ignoring arbitrary URL redirect parameters.
   - Added **§10.2 Mobile (Expo) Return Contract**: primary Universal Links (iOS) / App Links (Android) handling `{FRONTEND_BASE_URL}/verify-email` directly to in-app Login screen (`/(auth)/login`); fallback mobile-browser flow validating deep-link return destinations strictly against configured `EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` (default `["folio360://auth/login"]`) with fallback to `{FRONTEND_BASE_URL}/login` and zero auto-authentication.

3. **Correction C — Strict Web Login `Origin` Validation:**
   - Updated §9.1 Endpoint Matrix, §9.2 `CSRF_ORIGIN_MISMATCH`, §9.3 #4, §12.3, §17.3, and §18.1 so `POST /api/v1/auth/login` with `X-Client-Type: web` explicitly enforces `verify_web_origin` against the exact `CORS_ORIGINS` allowlist (`403 CSRF_ORIGIN_MISMATCH` on missing/empty/`"null"`/untrusted `Origin`, zero cookies/sessions created).
   - Preserved generic credential error behavior (`401 INVALID_CREDENTIALS`), `403 EMAIL_NOT_VERIFIED`, `403 ACCOUNT_INACTIVE`, HttpOnly refresh cookie handling on valid web login, and cookie-free / `Origin`-exempt `POST /login` for `X-Client-Type: mobile`.

4. **Hygiene & Cross-Reference Fixes:**
   - Normalized §18 into `§18.1`, `§18.2`, and `§18.3` (resolving Rev6's broken forward reference to `§18.3` in §12.2).
   - Converted Rev6's legacy Windows `file:///c:/Users/...` markdown links to portable repository-relative links and Linux Mint path metadata.

---

## 2. Exact Section References in `F360-P0-AUTH-SPEC-REV7.md`

| Topic / Correction | Modified / Affected Sections in `F360-P0-AUTH-SPEC-REV7.md` |
| :--- | :--- |
| Document metadata, Rev7 summary & baseline status | **§1** (Header & Revision History) |
| **Correction A:** Uvicorn ASGI3 & Starlette `TestClient` analysis | **§2** (Existing Findings), **§5** (Architecture & Invariant #1), **§6** (Module Layout), **§16.3** (Standards & Pinned Source Table), **§17.3** (Threat Matrix), **§19.1–§19.5** (Verification Concepts, `Folio360FastAPI`, `VerifiedUvicornConfig`, Bypass Table, Launch Contract), **§20.3** (Tests 9, 10, 12, 22, 25, 26 & Part D Tests 28–35), **§22** (Stage 3A Gate), **§23** (Risk #3 & Checklist), **Final Rev7 Revision Report** |
| **Correction B:** Email verification return/navigation contract | **§3** (#3), **§9.3** (#2 `/verify-email`), **§10** (Sequence Diagram & **§10.2** Web/Mobile Return Contract), **§17.3** (Threat Matrix), **§18.1–§18.2** (Client Contracts), **§20.4** (Proposed Tests), **§21** (`EMAIL_VERIFICATION_MOBILE_LOGIN_URIS`), **§22** (Stage 3A Scope & Gate), **§23** (Risk #7 & Checklist) |
| **Correction C:** Web login `Origin` validation | **§9.1** (Endpoint Matrix `/login`), **§9.2** (`CSRF_ORIGIN_MISMATCH`), **§9.3** (#4 `/login`), **§10** (Sequence Diagram), **§12.3** (Cookie & CSRF Policy), **§17.3** (Threat Matrix), **§18.1–§18.2** (Client Contracts), **§20.4** (Proposed Tests), **§22** (Stage 3A Scope & Gate), **§23** (Checklist) |

---

## 3. Uvicorn `0.54.0` (and Starlette `1.10.0` / FastAPI `0.163.1`) Source Files & Functions Inspected

All files below were directly inspected inside `/home/prajwal/projects/Folio360_backend/.venv/lib/python3.12/site-packages/`:

| Package & File | Inspected Symbols & Exact Line Numbers | Key Behavior Observed |
| :--- | :--- | :--- |
| `uvicorn/config.py` | `InterfaceType` (42), `LIFESPAN` (65–69), `STARTUP_FAILURE` (81), `Config.__init__` (196–369; `lifespan="auto"` at 212, `interface="auto"` at 218, `proxy_headers=True` at 225), `Config.asgi_version` (370–377), `Config.load` (439–546; `self.loaded_app()` at 513–518, `interface == "auto"` at 525–533, `WSGIMiddleware`/`ASGI2Middleware` at 535–539, `MessageLoggerMiddleware` at 541–542, `ProxyHeadersMiddleware` at 543–544) | `Config.load()` probes `self.loaded_app()` catching only `TypeError`; under `interface="auto"` it detects ASGI3 via `uvicorn._compat.iscoroutinefunction(app.__call__)`, otherwise wrapping in `ASGI2Middleware`; `asgi_version` raises `KeyError` on `"auto"` pre-load but returns `"3.0"` when `interface="asgi3"`. |
| `uvicorn/_compat.py` | `iscoroutinefunction` (10–13) | Uses `inspect.iscoroutinefunction` on Python `>= 3.14` and `asyncio.iscoroutinefunction` on Python `< 3.14`. |
| `uvicorn/middleware/asgi2.py` | `ASGI2Middleware.__init__`, `ASGI2Middleware.__call__` (9–15) | Dispatches ASGI2 by calling `instance = self.app(scope); await instance(receive, send)`. |
| `uvicorn/middleware/proxy_headers.py` | `ProxyHeadersMiddleware.__init__`, `__call__` (9–63), `_TrustedHosts` (105–187) | Direct ASGI3 wrapper storing `self.app` and `self.trusted_hosts`. |
| `uvicorn/lifespan/off.py` & `on.py` | `LifespanOff` (`off.py:8–17`), `LifespanOn.startup` / `main` (`on.py:47–101`) | `LifespanOff.startup()` is a no-op (`pass`). `LifespanOn.main()` invokes `loaded_app` with `"type": "lifespan"` and `asgi.version = config.asgi_version`. |
| `uvicorn/server.py` | `Server._serve` (92–114), `Server.startup` (115–206) | Calls `config.load()` before `lifespan.startup()`, exits `STARTUP_FAILURE` (`3`) on failure before socket creation. |
| `uvicorn/main.py` | `main` CLI options (`--lifespan` 185–190, `--interface` 191–197, `--proxy-headers` 232–236, `--forwarded-allow-ips` 250–257), `run` (503–641) | Click `auto_envvar_prefix="UVICORN"` binds `UVICORN_INTERFACE`, `UVICORN_LIFESPAN`, `UVICORN_PROXY_HEADERS`, `UVICORN_FORWARDED_ALLOW_IPS`. |
| `uvicorn/protocols/http/*` & `websockets/*` | `h11_impl.py:411,422`, `httptools_impl.py:422,433`, `websockets_impl.py:257,272`, `websockets_sansio_impl.py:409`, `wsproto_impl.py:362` | Calls `result = await app(scope, receive, send)` and enforces `result is None` for ASGI3. |
| `starlette/testclient.py` & `starlette/_utils.py` | `_is_asgi3` (`testclient.py:56–59`), `TestClient.__init__` (`459–463`), `is_async_callable` (`_utils.py:61–65`) | `TestClient` uses `is_async_callable(app)` (`iscoroutinefunction(app.__call__)`) and wraps non-coroutine callables in `_WrapASGI2`. |
| `fastapi/applications.py` & `starlette/applications.py` | `FastAPI.__call__`, `Starlette.__call__` | Standard `FastAPI.__call__` is `async def __call__(self, scope, receive, send) -> None`. |

---

## 4. Why Explicit ASGI3 Enforcement + `@inspect.markcoroutinefunction` Resolves the Ambiguity

1. **Why Rev6's bare `def __call__(self, *args, **kwargs)` was ambiguous:**
   - Uvicorn `Config.load()` lines 513–518 synchronously invoke `self.loaded_app()` with 0 arguments, catching **only `TypeError`**. An `async def __call__` would return an unawaited coroutine object instead of raising `RuntimeError` synchronously, defeating Guard 2.
   - However, a plain synchronous `def __call__` returns `False` for `asyncio.iscoroutinefunction` and `inspect.iscoroutinefunction` (verified directly on `.venv` Python 3.12.3). Consequently:
     - Under Uvicorn's default `interface="auto"` (`uvicorn/config.py:525–539`), Uvicorn would misclassify `Folio360FastAPI` as `"asgi2"` and wrap it in `ASGI2Middleware`, breaking ASGI3 (`self.app(scope)` 1-arg call) and breaking `ProxyHeadersMiddleware.app is fastapi_app`.
     - Under `starlette.testclient.TestClient` (`starlette/testclient.py:56–59, 459–463`), `_is_asgi3(app)` would also return `False`, wrapping the app in `_WrapASGI2` and breaking dev/test execution of the 81 Stage 1/2 tests.
2. **Why combining explicit `interface="asgi3"` + `@inspect.markcoroutinefunction` resolves every path completely:**
   - **Explicit `interface="asgi3"`** in `VerifiedUvicornConfig` bypasses Uvicorn's `if self.interface == "auto"` heuristic completely (`uvicorn/config.py:525`), keeps `config.asgi_version == "3.0"` valid both pre-load and post-load, and blocks any `"auto"` / `"asgi2"` / `"wsgi"` override via `validate_proxy_policy` (`UVICORN_INTERFACE`), `VerifiedUvicornConfig.__init__` (`_UNSET` sentinel), `VerifiedUvicornConfig.load()` (pre- and post-`super().load()`), `verify_loaded_asgi_middleware` (rejecting `ASGI2Middleware`/`WSGIMiddleware`/`MessageLoggerMiddleware`), and `lifespan(app)`.
   - **`@inspect.markcoroutinefunction`** on synchronous `def __call__(self, *args, **kwargs)` makes **all four checks** (`inspect.iscoroutinefunction`, `asyncio.iscoroutinefunction`, `uvicorn._compat.iscoroutinefunction`, and `starlette.testclient._is_asgi3`) return `True` (verified directly on `.venv` Python 3.12.3), while executing synchronously on 0-arg probes (`RuntimeError`/`TypeError`) and returning `self._dispatch_asgi(scope, receive, send)` (an `async def` coroutine yielding `None` after checking the production lifespan gate) on valid 3-arg ASGI3 scopes.

---

## 5. New and Revised Proposed Test Cases (Not Executed)

All tests below are **proposed implementation acceptance tests** defined in `F360-P0-AUTH-SPEC-REV7.md` and have **not** been executed:

- **Revised in §20.3 Parts A & C:**
  - **Tests 9, 10, 22, 25, 26:** Updated to also assert `config.interface == "asgi3"` (and `config.asgi_version == "3.0"` in Test 26, explicit `interface="asgi3"` pass-through without duplicate-keyword `TypeError` in Tests 22 & 25).
  - **Test 12:** Added worker `interface="asgi2"` drift assertion alongside `forwarded_allow_ips` and `lifespan` drift.
  - **Tests 15 & 19:** Updated ASGI request gate assertion reference to `Folio360FastAPI._dispatch_asgi`.
- **New in §20.3 Part D (Tests 28–35 — Correction A):**
  - **Test 28:** Verified config explicitly sets `interface="asgi3"` and `asgi_version == "3.0"`.
  - **Test 29:** Invalid or overridden `interface` (`"auto"`, `"asgi2"`, `"wsgi"`) rejected across `VerifiedUvicornConfig`, `build_uvicorn_config`, `app.server` CLI, `UVICORN_INTERFACE`, and post-init mutation.
  - **Test 30:** Zero-arg `Folio360FastAPI.__call__()` probe (`RuntimeError` vs `TypeError` synchronously), 1-arg ASGI2 `TypeError`, and `True` across `inspect`/`asyncio`/`uvicorn._compat`/`_is_asgi3`.
  - **Test 31:** Loaded app never wrapped in `ASGI2Middleware`/`WSGIMiddleware`/`MessageLoggerMiddleware`, and injected wrappers rejected by `verify_loaded_asgi_middleware`.
  - **Test 32:** Proxy-enabled configuration retains direct `ProxyHeadersMiddleware -> Folio360FastAPI` ASGI3 chain.
  - **Test 33:** Proxy-disabled configuration retains direct `Folio360FastAPI` ASGI3 instance.
  - **Test 34:** Real HTTP and WebSocket ASGI3 dispatch succeeds returning `None`, and unverified production `"websocket"` scope fails closed with `RuntimeError`.
  - **Test 35:** Raw Uvicorn startup in production remains rejected across all `interface` and `lifespan` combinations.
- **New in §20.4 (Other Stage 3A Authentication Tests — Corrections B & C):**
  - **Web Login `Origin` Validation (5 proposed checks):** Valid web `Origin` succeeds (`200` + HttpOnly cookie); missing `Origin` rejected (`403 CSRF_ORIGIN_MISMATCH`); untrusted/`"null"`/trailing-slash `Origin` rejected (`403 CSRF_ORIGIN_MISMATCH`); mobile `POST /login` succeeds without `Origin` (`200` + JSON token pair, zero cookies); invalid password with valid web `Origin` returns generic `401 INVALID_CREDENTIALS`.
  - **Email Verification No-Auto-Login & Return-Destination Validation (4 proposed checks):** `POST /verify-email` sets zero cookies/tokens/sessions; `POST /login` works only post-verification; verification email link builder uses strictly `FRONTEND_BASE_URL`; return-destination validator accepts only configured destinations (`{FRONTEND_BASE_URL}/login`, `EMAIL_VERIFICATION_MOBILE_LOGIN_URIS`) and rejects arbitrary redirect parameters.

---

## 6. Updated Test Counts Summary

| Category | Rev6 Count | Rev7 Count | Execution Status |
| :--- | :---: | :---: | :--- |
| **§20.1 Baseline Stage 1 & Stage 2 Regression Tests** (`43` Stage 1 + `38` Stage 2) | `81` | **`81`** | Existing codebase tests (unchanged; not re-run in this doc turn) |
| **§20.3 Uvicorn Security Tests — Part A (Proxy & Startup)** (Tests 1–13) | `13` | **`13`** | Proposed (Stage 3A — not implemented/executed) |
| **§20.3 Uvicorn Security Tests — Part B (Lifespan Bypass)** (Tests 14–19) | `6` | **`6`** | Proposed (Stage 3A — not implemented/executed) |
| **§20.3 Uvicorn Security Tests — Part C (Constructor Kwargs)** (Tests 20–27) | `8` | **`8`** | Proposed (Stage 3A — not implemented/executed) |
| **§20.3 Uvicorn Security Tests — Part D (ASGI3 Interface & Dispatch)** (Tests 28–35) | `—` | **`8`** | Proposed (Stage 3A — not implemented/executed) |
| **§20.3 Total Uvicorn Security Verification Tests** | `27` | **`35`** | **Proposed (Stage 3A gate — not executed)** |
| **§20.2 Per-Stage Migration Checks** (`0002`, `0003`, `0004`) | 5 checks/stage | **5 checks/stage** | Proposed (not executed) |
| **§20.4–§20.6 Other Stage 3A, 3B & 3C Tests** | Plus Corrections B & C tests | **Updated (+9 explicit proposed cases in §20.4)** | Proposed (not executed) |

---

## 7. Confirmation of Preserved Architecture, Q1–Q11, and Boundaries

- **Approved Q1–Q11 Decisions (§4):** All 11 binding decisions are preserved unchanged.
- **Database Schema & Migrations (§§7–8):** `users` extensions, `email_verification_tokens`, `refresh_sessions`, `password_reset_tokens`, `oauth_accounts`, `oauth_states`, `oauth_exchange_codes`, and the `0002` (3A) -> `0003` (3B) -> `0004` (3C) migration chain are untouched.
- **Tech Stack & Constraints:** Synchronous SQLAlchemy 2.x + `psycopg` v3, threadpool sync routes, process-local rate limiting + PostgreSQL email cooldowns, Resend retry state machine, AES-256-GCM PKCE encryption, Google OIDC `GOOGLE_TRUSTED_ADDITIONAL_AUDIENCES`, GitHub bounded pagination, and zero new Python dependencies remain completely intact.
- **Stage Boundaries & Governance (§22):** Stage 3A/3B/3C implementation boundaries and strict Git operation governance remain unchanged. `F360-P0-AUTH-SPEC-REV6.md` was preserved untouched.

---

## 8. Remaining Unresolved Concerns, Assumptions & Verification Gates

1. **Python `>= 3.12` Runtime Assumption for `inspect.markcoroutinefunction`:** `inspect.markcoroutinefunction` was introduced in Python 3.12. Both the Linux Mint host (`Python 3.12.3`) and the project target runtime (`Python 3.13`) support it, so this holds for all Folio360 environments; Python `<= 3.11` would not be compatible without a fallback.
2. **Pinned `uvicorn==0.54.0` Internals:** Protected by exact lockfile pinning in [requirements.txt](requirements.txt) plus the 35 proposed Uvicorn security tests (§20.3). Note also that if an outer ASGI wrapper (such as `ProxyHeadersMiddleware`) itself does not carry an `interface` check, Uvicorn `0.54.0` skips `ASGI2Middleware` whenever `config.interface == "asgi3"`.
3. **Google Confidential Web-Server PKCE Gate (§16.4):** Unverified live assumption retained from Rev3–Rev6 — controlled live integration test against a real Google Cloud Web Application OAuth client remains mandatory prior to Stage 3C production release.
4. **Universal Links / App Links Infrastructure (Correction B):** Native iOS/Android interception of `{FRONTEND_BASE_URL}/verify-email` requires publishing Apple AASA and Android `assetlinks.json` on the production frontend host; browser fallback handles environments without verified Universal/App Links via `EMAIL_VERIFICATION_MOBILE_LOGIN_URIS`.
