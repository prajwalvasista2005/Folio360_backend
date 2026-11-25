# Folio360 Phase 0 Authentication Specification — Rev9 Review Report

- **Target Document:** [F360-P0-AUTH-SPEC-REV9.md](F360-P0-AUTH-SPEC-REV9.md) (`F360-P0-AUTH-SPEC-REV9`)
- **Base Revision Preserved Untouched:** [F360-P0-AUTH-SPEC-REV8.md](F360-P0-AUTH-SPEC-REV8.md)
- **Repository:** `/home/prajwal/projects/Folio360_backend` (`main` at `54c155bd0ba74f3cc54473fd7b3fb0d0e52b8936`; Stage 2 baseline `206970f5923bd19d445cce905e6bbaf0b5c697ff`)
- **Status:** Specification preparation complete — **awaiting independent review and explicit owner approval before any Stage 3A implementation**.
- **Authorization Confirmation:** Strictly documentation-only. Zero application source files, tests, Alembic migrations, dependencies, environment configs, `F360-P0-AUTH-SPEC-REV8.md` (or earlier revisions), or Git state were modified; no tests, migrations, or runtime commands were executed.

---

## 1. Exact Sections Changed (`F360-P0-AUTH-SPEC-REV8.md` -> `F360-P0-AUTH-SPEC-REV9.md`)

| Section | Narrowly Scoped Change Made |
| :--- | :--- |
| **Title & §1 (Document Status & Revision History)** | Updated title and Document ID to `F360-P0-AUTH-SPEC-REV9`, shifted Rev 8 bullet from `This Document` to historical history, and appended the Rev 9 bullet summarizing Corrections A & B and the expanded **13** proposed verification tests. |
| **§6 (Module Responsibilities)** | Updated the `app/core/config.py` annotation to note environment-specific URI validation on backend parity anchor `EMAIL_VERIFICATION_MOBILE_LOGIN_URIS`. |
| **§9.3 (#2 `POST /api/v1/auth/verify-email`)** | Preserved the exact JSON-based non-authenticating contract (`200 OK`, zero tokens, zero `Set-Cookie`, zero `refresh_sessions`, zero redirect URL) and clarified that browser UX (**“Open in Folio360 app”** + **“Continue to web login”**) uses validated local build-time `VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` with no browser-time config discovery endpoint. |
| **§10 (Sequence Diagram) & §10.2 (Navigation, Reliable Mobile Fallback UX & Environment URI Policy)** | Aligned §10.2.A with the confirmation UI; rewrote §10.2.B to specify Universal/App Links preference, explicit **“Open in Folio360 app”** + always-visible **“Continue to web login”**, zero tokens/sensitive params in app URIs, explicit browser launch-detection limitation, no blank/loading stranding, native Login landing, web fallback when unconfigured, and a 5-scenario UX table; updated §10.2.C to state CI/build-only parity validation (no runtime discovery), explicit **Production** vs. **Development/Testing** URI rules, and cross-parser `[::1]` and raw `:443`/`:80` canonicalization checks. |
| **§17.3 (Threat-Mitigation Summary)** | Updated the email-verification mitigation row for Rev9's non-blocking fallback UX, CI/build-only parity, and explicit production/development URI policy. |
| **§18.1–§18.2 (Client Contracts)** | Updated Web and Mobile post-verification integration rules to require **“Open in Folio360 app”** + always-visible **“Continue to web login”**, zero tokens/sensitive params, zero unreliable browser launch-detection assumptions, zero runtime backend discovery queries, and environment-specific §10.2.C validation. |
| **§20 (Intro) & §20.4 (Stage 3A Proposed Auth Tests)** | Expanded the §20.4 email verification test suite from `9` to **13 explicit proposed acceptance tests (Proposed — Not Executed)** covering all Rev9 UX, environment URI, parity, untrusted-input, and no-auto-login cases; updated startup validation test note for production rejection of dev `http://`. |
| **§21.1–§21.2 (Environment Configuration)** | Updated `EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` (§21.1) and `VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` (§21.2) to reflect explicit dev/test vs. production URI rules, no dev carry-over into production, fallback UX behavior, and CI/build-only parity. |
| **§22 (Stage 3A Gate), §23 (Risks, Rev9 Checklist & Final Rev9 Report)** | Synchronized Stage 3A scope/gate (`13` proposed §20.4 verification tests), updated Risk #7 for browser launch-detection limits and fallback resilience, replaced the Rev8 checklist/closing report with Rev9 equivalents, and explicitly distinguished proposed vs. executed tests. |

All unaffected sections — including §2, §3, §4 (Q1–Q11), §5, §7, §8, §9.1–§9.2, §9.3 (#1, #3–#14), §10.1, §11–§16, §17.1–§17.2, §18.3, §19 (`VerifiedUvicornConfig` `interface="asgi3"` + `@inspect.markcoroutinefunction`), §20.1–§20.3 (`81` baseline + `35` Uvicorn tests), §20.5–§20.6, unchanged §21.1 variables, §22 Stage 3B/3C & Git governance, and §23 Risks #1–#6 & #8 — remain preserved verbatim from Rev8.

---

## 2. How Correction A Resolved the App-Launch UX Ambiguity

1. **Browser Detection Honesty & No Stranding (§10.2.B):** Web browsers cannot reliably determine whether a native app is installed or whether a custom-scheme (`folio360://...`) launch succeeded, and timer/`visibilitychange` timeouts are unreliable proof of absence. Rev9 therefore prohibits blank-screen redirects and indefinite loading/spinner states waiting for an app launch.
2. **Preferred Native Routing & Non-Authenticating Endpoint (§9.3, §10.2):** iOS Universal Links / Android App Links remain the preferred route for opening `{FRONTEND_BASE_URL}/verify-email` directly inside the Expo app. `POST /api/v1/auth/verify-email` stays purely JSON-based and never sets auth cookies, issues tokens, creates `refresh_sessions`, or returns a redirect URL.
3. **Explicit Two-Action Fallback UI When Configured (§10.2.B):** Upon `200 OK`, if `VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` contains a valid destination under §10.2.C, the browser confirmation screen shows an explicit **“Open in Folio360 app”** action (strictly targeting the validated build-time allowlist URI with zero verification/access/refresh tokens, arbitrary redirect values, or sensitive parameters) alongside an **always-visible “Continue to web login”** fallback (`{FRONTEND_BASE_URL}/login`). Opening the app always lands on the native Login screen (`/(auth)/login`) with zero auto-login.
4. **All Five UX Outcomes Specified (§10.2.B Table):**
   - *App opens:* Hands off to native Login (`/(auth)/login`); browser tab retains intact confirmation UI with **“Continue to web login”**.
   - *App not installed:* Browser/OS no-op or dismissed prompt without false install-detection claims; user clicks always-visible **“Continue to web login”**.
   - *App launch blocked/fails:* Confirmation screen stays interactive (no stuck spinner); user can retry **“Open in Folio360 app”** or choose **“Continue to web login”**.
   - *User chooses web login:* Navigates strictly to `{FRONTEND_BASE_URL}/login` to sign in explicitly.
   - *No valid destination configured:* Unset/empty/invalid `VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` omits the app-launch button and uses `{FRONTEND_BASE_URL}/login`.

---

## 3. Explicit Development vs. Production URI Policy & CI/Build Parity (§10.2.C, §21)

| URI Category | Production (`ENVIRONMENT="production"` / Prod Build) | Development / Testing (`ENVIRONMENT in {"development", "testing"}` / Dev Build) |
| :--- | :--- | :--- |
| **`https://` Universal / App Links** | **Allowed** (exact canonical host & path allowlist; `:443` rejected). | **Allowed** (exact canonical allowlist; `:443` rejected). |
| **Approved Custom App Schemes** (`folio360://auth/login`) | **Allowed only** if explicitly configured/approved in canonical allowlist (`port` forbidden). | **Allowed only** if explicitly configured/approved in canonical allowlist (`port` forbidden). |
| **`http://` Local Loopback** (`localhost`, `127.0.0.1`, `[::1]`) | **Unconditionally REJECTED.** Zero dev carry-over to production. | **Allowed only** for explicitly configured loopback host/path/port (`:80` rejected). |
| **Arbitrary External `http://`** | **Unconditionally REJECTED.** | **Unconditionally REJECTED.** |
| **Dangerous Schemes, Credentials, Query, Fragment, Traversal, Non-Canonical URIs** | **Unconditionally REJECTED.** | **Unconditionally REJECTED.** |

- **Identical Frontend & Backend Parsing (§10.2.C.4):** Python (`urllib.parse.urlsplit`) and JS/TS (WHATWG `new URL(...)`) enforce identical pre-parse raw checks (including explicit raw `:443`/`:80` rejection before `new URL()` strips default ports) and normalize IPv6 `[::1]` consistently (`"[::1]"` canonical host).
- **CI / Build Parity Clarification (§10.2.C.2):** Matching `canonical_set(VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS) == canonical_set(EMAIL_VERIFICATION_MOBILE_LOGIN_URIS)` is strictly a **CI / build / release validation gate**, never a browser-time runtime discovery mechanism.

---

## 4. Updated Proposed Test Cases & Counts (Proposed vs. Executed)

**All Stage 3 tests in §§20.2–20.6 are explicitly labeled Proposed — Not Executed.** No tests were executed during this documentation-only revision. The `81` Stage 1 & Stage 2 regression tests (§20.1) represent an existing historical code baseline count and were not re-executed here.

| Test Category (Spec Section) | Classification / Execution Status | Count | Change in Rev9 |
| :--- | :--- | :--- | :--- |
| **§20.1 Stage 1 & Stage 2 Regression Baseline** | Historical Baseline Count (**Not executed in this revision**) | **81** | Unchanged (43 Stage 1 + 38 Stage 2) |
| **§20.3 Uvicorn Proxy, Lifespan, Constructor & ASGI3 Security Tests** | **Proposed — Not Executed** | **35** | Unchanged (13 Part A + 6 Part B + 8 Part C + 8 Part D) |
| **§20.4 Web Login `Origin` Validation Tests** | **Proposed — Not Executed** | **5** | Unchanged |
| **§20.4 Email Verification Fallback UX, Env URI Policy, CI Parity & No-Auto-Login Tests** | **Proposed — Not Executed** | **13** | Expanded from `9` to **`13`** per Rev9 requirements |
| **§20.4 Resend Delivery/Retry State Machine Tests** | **Proposed — Not Executed** | **8** | Unchanged |
| **§20.6 Google `aud`/`azp` & GitHub Pagination Tests** | **Proposed — Not Executed** | **10 + 9** | Unchanged |

### The 13 Proposed Verification & Redirect Acceptance Tests in §20.4 (Not Executed)
1. Valid configured Universal / App Link destination accepted (`https://app.folio360.com/login`).
2. Valid configured custom-scheme destination accepted (`folio360://auth/login` when configured; unconfigured custom schemes rejected).
3. Missing or invalid mobile destination omits app-launch action and uses web login fallback (`{FRONTEND_BASE_URL}/login`).
4. Unapproved / malicious schemes rejected (`javascript:`, `data:`, `vbscript:`, `file:`, `blob:`, `about:`, `intent:`, `mailto:`, `ftp:`, unconfigured schemes).
5. Production `http://` destinations unconditionally rejected (including loopback and external hosts; zero dev carry-over).
6. Development `http://` accepted only for explicitly permitted local loopback hosts (`localhost`, `127.0.0.1`, `[::1]`; redundant `:80` and unconfigured targets rejected).
7. Arbitrary external `http://` rejected in both development and production.
8. Invalid host, path, port, query, fragment, credentials (`@`), whitespace, control characters (`0x00–0x1F`, `0x7F`), traversal (`/..`, `%2f`, `%5c`, `%2e`), and malformed/non-canonical URIs rejected across both parsers.
9. Frontend / backend canonical allowlist parity success and failure (CI/build validator detects mismatches, `[::1]` parity, invalid entries, and dev `http://` in prod; zero browser-time discovery).
10. Browser UI provides both **“Open in Folio360 app”** (validated URI only, zero tokens/sensitive params) and always-visible **“Continue to web login”** when configured, without blank/loading stranding.
11. No unreliable browser app-launch detection claims and resilient fallback UX across app-open, app-not-installed, and blocked/failed launch outcomes.
12. `POST /api/v1/auth/verify-email` creates zero sessions, issues zero tokens, sets zero cookies, and never auto-logs the user in.
13. Untrusted redirect inputs (`?next=`, `?redirect=`, `?redirect_uri=`, `?return_to=`, `?mobile_uri=`, `#...`, `document.referrer`) are ignored; `email_service.py` pins links strictly to `FRONTEND_BASE_URL`.

---

## 5. Confirmation of Preserved Architecture, Q1–Q11, and Untouched Rev8

- **Q1–Q11 Decisions (§4):** 100% preserved verbatim without reopening or weakening.
- **Prior Architecture Unchanged:** Stage 3A / 3B / 3C boundaries (§22), DB schema & `0002 -> 0003 -> 0004` migration sequence (§§7–8), Resend integration & retry state machine (§11), Google OIDC & GitHub OAuth design (§§14–16), refresh-token rotation & replay detection (§12.2), web cookie & mobile `SecureStore` transport (§12.3, §18), CSRF & strict web login `Origin` validation (§12.3, Rev7), `VerifiedUvicornConfig` ASGI3 enforcement (`interface="asgi3"` + `@inspect.markcoroutinefunction`, §19), dependencies, and Git authorization governance (§22) remain completely intact.
- **Untouched Prior Revisions & Code:** [F360-P0-AUTH-SPEC-REV8.md](F360-P0-AUTH-SPEC-REV8.md) (and earlier spec revisions), source files, tests, migrations, dependencies, `.env`/runtime configuration files, and Git repository state were not modified.

---

## 6. Remaining Ambiguities or Blockers

- **Architectural / Specification Blockers:** None remaining. Both Rev9 ambiguities (mobile fallback UX & environment-specific URI policy) are resolved cleanly.
- **Non-Blocking Operational & Implementation Gates Retained:**
  1. Wiring the CI/CD pipeline script to run the §10.2.C canonical parity check on `EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` and `VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` at build/release time (deployment repo/pipeline scope).
  2. Sharing canonical test vectors between the Python backend validator and TypeScript/React frontend validator during implementation to verify identical parser output (including `[::1]` and raw `:443`/`:80`).
  3. Upstream Stage 3 operational gates retained from Rev6/Rev7: Python `>= 3.12` (`inspect.markcoroutinefunction`), exact `uvicorn==0.54.0` lockfile pinning, Apple AASA / Android `assetlinks.json` hosting for Universal/App Links, and controlled live Stage 3C verification of Google confidential web-server PKCE (§16.4).
