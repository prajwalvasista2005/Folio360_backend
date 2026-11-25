# Folio360 Phase 0 Authentication Specification — Rev8 Review Report

- **Target Document:** [F360-P0-AUTH-SPEC-REV8.md](F360-P0-AUTH-SPEC-REV8.md) (`F360-P0-AUTH-SPEC-REV8`)
- **Base Revision Preserved Untouched:** [F360-P0-AUTH-SPEC-REV7.md](F360-P0-AUTH-SPEC-REV7.md)
- **Repository:** `/home/prajwal/projects/Folio360_backend` (`main` at `54c155bd0ba74f3cc54473fd7b3fb0d0e52b8936`; Stage 2 baseline `206970f5923bd19d445cce905e6bbaf0b5c697ff`)
- **Status:** Specification preparation complete — **awaiting independent review and explicit owner approval before any Stage 3A implementation**.
- **Authorization Confirmation:** Strictly documentation-only. Zero application source files, tests, Alembic migrations, dependencies, environment configs, `F360-P0-AUTH-SPEC-REV7.md`, or Git state were modified; no tests, migrations, or Docker commands were executed.

---

## 1. Exact Sections Changed (`F360-P0-AUTH-SPEC-REV7.md` -> `F360-P0-AUTH-SPEC-REV8.md`)

| Section | Narrowly Scoped Change Made |
| :--- | :--- |
| **§1 (Header & Revision History)** | Updated Document ID to `F360-P0-AUTH-SPEC-REV8` and appended the Rev 8 revision bullet summarizing the mobile email-verification fallback configuration clarification. Kept Rev 0–Rev 7 history intact. |
| **§6 (Module Responsibilities)** | Clarified `app/core/config.py` summary note to identify `EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` as the backend parity anchor. |
| **§9.3 (#2 `POST /api/v1/auth/verify-email`)** | Preserved the exact API contract (`{"token"}` -> `200 OK`, zero tokens, zero `Set-Cookie`, zero sessions, zero redirect URL field) and clarified that post-verification navigation is executed solely by the frontend from trusted local build-time config (§10.2). |
| **§10 (Sequence Diagram) & §10.2 (Post-Verification Navigation)** | Updated §10.2.B and added **§10.2.C** defining frontend build-time `VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` (public non-secret config), backend `EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` deployment parity validation, explicit approval policy for `folio360://auth/login`, strict parsed-component URI validation & canonicalization rules, prohibition on untrusted destination inputs/concatenation, and fail-safe fallback to `{FRONTEND_BASE_URL}/login`. |
| **§17.3 (Threat-Mitigation Summary)** | Updated the "Open redirect / session confusion after email verification" row to reference `VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS`, canonical parity with `EMAIL_VERIFICATION_MOBILE_LOGIN_URIS`, parsed-component validation, and `{FRONTEND_BASE_URL}/login` fallback. |
| **§18.1–§18.2 (Client Contracts)** | Clarified Web (`/verify-email` browser fallback using `VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS`) and Mobile Expo navigation/fallback alignment with §10.2.C. |
| **§20.4 (Other Stage 3A Auth Tests)** | Expanded the email verification navigation/no-auto-login bullet into **9 explicit proposed acceptance tests (Not Executed)** per specification requirements. |
| **§21 (Configuration & Env Variables)** | Clarified backend `EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` role as deployment reference & CI parity anchor in §21.1, and added §21.2 documenting public build-time `VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` (explicitly marked non-secret). |
| **§22 (Stage 3A Gate), §23 (Risks & Checklist) & Final Rev8 Report** | Updated Stage 3A scope/gate notes for parity validation and the 9 proposed tests in §20.4, updated Risk #7, and updated the Rev8 consistency checklist and closing report. |

All unaffected sections — including §2, §3, §4 (Q1–Q11), §5, §7, §8, §9.1–§9.2, §11–§16, §17.1–§17.2, §18.3, §19 (Uvicorn ASGI3 + `@inspect.markcoroutinefunction`), §20.1–§20.3 (`81` baseline + `35` Uvicorn tests), §20.5–§20.6, and §22 Git governance — remain preserved intact.

---

## 2. Frontend / Backend Configuration Relationship & Deployment Parity

1. **Frontend Ownership (`VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS`):**
   - Public, **non-secret** build-time configuration compiled into the React/Vite frontend bundle.
   - Enforced locally by the `/verify-email` page after `POST /api/v1/auth/verify-email` succeeds (`200 OK`) when executing mobile-browser fallback navigation.
   - The frontend **must never** read, derive, or override redirect targets from URL query parameters, fragments, `POST /verify-email` response fields, email-link parameters, `document.referrer`, or other user-controlled inputs, and **must never** concatenate untrusted strings into deep links.
2. **Backend Role (`EMAIL_VERIFICATION_MOBILE_LOGIN_URIS`) & API Preservation:**
   - `POST /api/v1/auth/verify-email` is **not** redesigned: it performs no HTTP redirects, returns no redirect target, sets no cookies, issues no tokens, and creates no authenticated session.
   - Backend `EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` in `Settings` serves as the backend startup-validated deployment reference and parity anchor for the same environment.
3. **Deployment Parity Validation Process:**
   - Both `VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` and `EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` must contain the exact same canonical set of approved mobile login destinations for a given deployment.
   - CI / release pipelines parse both variables through the identical §10.2.C validator/canonicalizer and **fail the deployment/build** if either contains invalid entries or if `canonical_set(VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS) != canonical_set(EMAIL_VERIFICATION_MOBILE_LOGIN_URIS)`.
4. **Default `folio360://auth/login` Policy:**
   - Permitted **only** where explicitly configured and approved in both variables for that deployment (e.g., dev/testing or production builds registered for `folio360://`), never hardcoded as an unconfigurable bypass.

---

## 3. Exact Parsed-Component URI Validation, Canonicalization & Fallback Behavior

Rather than naive string matching or prefix checks, validation uses **pre-parse raw rejection + structured URL component parsing (`urllib.parse.urlsplit` / WHATWG `new URL(...)`) + canonicalization + exact set equality**:

1. **Pre-Parse Raw Rejection:** Reject non-strings, empty values, leading/trailing/embedded whitespace, control chars (`0x00–0x1F`, `0x7F`), backslashes (`\`), wildcards (`*`), `@` userinfo, `?` query, `#` fragment, dot-segments (`..`, `/./`), consecutive path slashes (`//`), and encoded traversal (`%2f`, `%5c`, `%2e`, `%00`).
2. **Scheme Validation:** Lowercase scheme; unconditionally reject `javascript`, `data`, `vbscript`, `file`, `blob`, `about`, `intent`, `mailto`, `tel`, `ftp`, and `http` in `ENVIRONMENT="production"`. Allow only `https` or an explicitly approved RFC 3986 custom app scheme (`^[a-z][a-z0-9+.-]*$`).
3. **Authority Validation:** Forbid `username`/`password`; require non-empty lowercase `host`; forbid ports on custom schemes; reject redundant explicit `:443` on `https`.
4. **Path, Query & Fragment Validation:** Require non-empty absolute path starting with `/` (no trailing `/` on routes like `/login`, no `//`, exact case-sensitive match); require empty `query` and empty `fragment`.
5. **Canonical Form & Exact Match:** Canonicalize to `(scheme, host, port, path)` / `scheme://host[:port]/path` and accept **only** exact membership in the allowlist.
6. **Fail-Safe Web Fallback:** If `VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` is unset, empty, invalid after validation, or the native app cannot be opened, fall back safely to the configured web login URL (`{FRONTEND_BASE_URL}/login`). Web-only verification continues to navigate strictly to `{FRONTEND_BASE_URL}/login`.

---

## 4. New & Revised Proposed Acceptance Tests (§20.4 — Not Executed)

All 9 proposed tests in §20.4 are **proposed implementation acceptance tests** and have **not** been executed:

1. **Configured mobile URI accepted** after §10.2.C parsed-component canonicalization.
2. **Unconfigured URI rejected** (syntactically valid URI absent from the allowlist).
3. **Malicious scheme rejected** (`javascript:`, `data:`, `vbscript:`, `file:`, `intent:`, `http:` in production).
4. **Unapproved host or path rejected** (wrong host, extra segment, trailing slash, query/fragment attached).
5. **Malformed and ambiguous URI values rejected** (empty, whitespace, control chars, userinfo `@`, `\`, `..`, `%2f`/`%5c`/`%2e`, `*`, redundant `:443`, custom-scheme port).
6. **Invalid, empty, or unavailable mobile configuration falls back safely** to configured web login (`{FRONTEND_BASE_URL}/login`).
7. **Backend/frontend allowlist parity mismatch detected** by deployment parity validation (`EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` vs. `VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS`).
8. **Arbitrary verification-link redirect parameters ignored** (`?next=`, `?redirect=`, `?redirect_uri=`, `?return_to=`, `#...` cannot influence destination; `email_service.py` pins links strictly to `FRONTEND_BASE_URL`).
9. **Successful verification creates no session, token, or authentication cookie** (`POST /api/v1/auth/verify-email` sets zero `Set-Cookie`, returns zero tokens, creates zero `refresh_sessions` rows; login works only post-verification).

Existing test counts remain unchanged: **81 Baseline Stage 1 & Stage 2 Regression Tests** (§20.1) and **35 Proposed Uvicorn Security Verification Tests** (§20.3).

---

## 5. Confirmation of Preserved Architecture & Q1–Q11

- **Q1–Q11 (§4):** 100% unchanged and preserved verbatim.
- **Database Schema & Migrations (§§7–8):** All 7 tables and `0002` (3A) -> `0003` (3B) -> `0004` (3C) migration chain untouched.
- **Uvicorn ASGI3 & Security Controls (§§12–19):** Explicit `interface="asgi3"`, `@inspect.markcoroutinefunction` on `Folio360FastAPI.__call__`, 3-layer proxy/lifespan checks, web login `Origin` validation (`403 CSRF_ORIGIN_MISMATCH`), Google OIDC / GitHub OAuth architecture, Resend retry state machine, and process-local rate limiting remain unchanged.
- **Stage Boundaries & Governance (§22):** Stage 3A/3B/3C boundaries and strict Git authorization governance remain unchanged.

---

## 6. Remaining Unresolved Assumptions

1. **Deployment CI Integration Hook:** The exact CI/CD script location that enforces `canonical_set(EMAIL_VERIFICATION_MOBILE_LOGIN_URIS) == canonical_set(VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS)` belongs to deployment/pipeline setup (explicitly outside Stage 2/3A application repository scope).
2. **Retained Upstream Gates from Rev6/Rev7:** Python `>= 3.12` for `inspect.markcoroutinefunction`, exact `uvicorn==0.54.0` lockfile pinning, Google confidential web-server PKCE pre-release live verification (§16.4), and Apple AASA / Android `assetlinks.json` hosting on the production frontend domain for Universal/App Links.
