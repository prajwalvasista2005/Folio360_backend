# Folio360 Phase 0 Authentication Specification — Rev10 Change Summary & Independent Review Report

- **Review Target Document:** [F360-P0-AUTH-SPEC-REV10.md](F360-P0-AUTH-SPEC-REV10.md) (`F360-P0-AUTH-SPEC-REV10`, `1,413` lines)
- **Baseline Document Compared Against:** [F360-P0-AUTH-SPEC-REV9.md](F360-P0-AUTH-SPEC-REV9.md) (`F360-P0-AUTH-SPEC-REV9`, `1,359` lines — preserved untouched)
- **Repository:** `/home/prajwal/projects/Folio360_backend` (`main` at `54c155bd0ba74f3cc54473fd7b3fb0d0e52b8936`; Stage 2 baseline `206970f5923bd19d445cce905e6bbaf0b5c697ff`)
- **Authorization & Scope Constraint:** Strictly documentation-only. Zero application source code, tests, Alembic migrations, dependencies, environment/deployment configuration files, `F360-P0-AUTH-SPEC-REV10.md`, `F360-P0-AUTH-SPEC-REV9.md`, or Git state were modified; zero tests or runtime commands were executed.

> **Document Structure Notice:** **Part I** records the descriptive authoring delta applied from Rev9 to Rev10. **Part II** records the verification audit of Rev10 against Rev9, separates verified textual findings from unverified implementation/runtime claims, and issues the formal final verdict.

---

# PART I — REVISION / CHANGE SUMMARY (AUTHORING DELTA: REV9 -> REV10)

## 1. Sections Modified (`F360-P0-AUTH-SPEC-REV9.md` -> `F360-P0-AUTH-SPEC-REV10.md`)

| Rev10 Section | Line Range (Rev10) | Summary of Descriptive Changes Applied |
| :--- | :--- | :--- |
| **Title & §1 (Status & Revision History)** | `L1–L40` | Updated Document ID to `F360-P0-AUTH-SPEC-REV10`, moved Rev 9 from current to historical history, and added Rev 10 bullet summarizing Corrections A & B and expanded `20` proposed tests. |
| **§9.3 (#2 `POST /api/v1/auth/verify-email`)** | `L431` | Updated frontend validation reference to cite build-target `VITE_APP_ENVIRONMENT` while retaining JSON-only, non-authenticating behavior. |
| **§10 (Diagram Note) & §10.2.A–C** | `L480`, `L492–L626` | Updated diagram note for dual-route Universal/App Links; updated §10.2.A normal browser `/login` fallback note; rewrote §10.2.B.1 to cover both `/verify-email` and `/login` on iOS (AASA + `associatedDomains`) and Android (`assetlinks.json` + `autoVerify="true"` intent filters) with a 6-case table; added §10.2.C.2–3 defining `VITE_APP_ENVIRONMENT`, 1-to-1 backend mapping, standalone prod build loopback guard, and 4-gate CI/release check. |
| **§17.3 (Threat-Mitigation Summary)** | `L862` | Updated email-verification mitigation row for dual-route association scoping, `VITE_APP_ENVIRONMENT == ENVIRONMENT` parity, and standalone prod loopback rejection. |
| **§18.1–§18.2 (Client Integration Contracts)** | `L871–L890` | Added `VITE_APP_ENVIRONMENT` build-time validation & standalone prod guard to §18.1; extended §18.2 mobile Universal/App Link requirements to cover both `/verify-email` and `/login` with zero credentials in `/login` deep links. |
| **§20 (Intro) & §20.4 (Stage 3A Tests)** | `L1192`, `L1267–L1287` | Expanded §20.4 email-verification suite from `13` to **`20` explicit proposed tests (Proposed — Not Executed)** (updated `#1, #2, #5–#7, #9`; preserved `#3, #4, #8, #10–#13`; added `#14–#20`). |
| **§21.1–§21.2 (Config & Env Variables)** | `L1307`, `L1323`, `L1357–L1358` | Added §21.1 note linking backend `ENVIRONMENT` to `VITE_APP_ENVIRONMENT`; updated `EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` parity row; added **`VITE_APP_ENVIRONMENT`** as the first §21.2 variable and updated `VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS`. |
| **§22 (Stage 3A Gate) & §23 (Risks, Checklist, Report)** | `L1365–L1367`, `L1394–L1413` | Synchronized Stage 3A scope/gate (`20` proposed tests in §20.4), Risk #7, Rev10 consistency checklist, and closing Rev10 revision report. |

## 2. Concise Delta Overview

1. **Correction A (Dual-Route Platform Links):** Added iOS (`apple-app-site-association` + `associatedDomains` `applinks:<frontend-host>`) and Android (`assetlinks.json` + verified `android:autoVerify="true"` intent filters) coverage for both `/verify-email` and `/login`, strict path scoping (forbidding unrestricted `/*`), and a 6-case installed vs. app-not-installed behavior table keeping zero credentials in `/login` URIs and preserving Rev9 browser fallback UX.
2. **Correction B (Explicit Environment Parity):** Added non-secret build-time selector `VITE_APP_ENVIRONMENT` (`"development" | "testing" | "production"`, fail-closed), mapped 1-to-1 to backend `ENVIRONMENT` under one unified §10.2.C URI policy, added a standalone Vite production build check rejecting dev loopback `http://`, and formalized a 4-gate CI/release check failing on environment or allowlist mismatch (strictly CI/build-time, never browser-time discovery).
3. **Proposed Test Delta:** Expanded §20.4 email-verification/platform-link/env-parity acceptance tests from `13` to **`20` proposed tests (Not Executed)**, leaving historical `81` baseline tests (§20.1) and `35` proposed Uvicorn tests (§20.3) unchanged.

---

# PART II — INDEPENDENT REVIEW ASSESSMENT (AUDIT OF REV10 AGAINST REV9)

## 1. Review Scope, Method, and Exact Documents Compared

- **Exact Documents Compared:**
  - Baseline: `/home/prajwal/projects/Folio360_backend/F360-P0-AUTH-SPEC-REV9.md` (`1,359` lines)
  - Revised Target: `/home/prajwal/projects/Folio360_backend/F360-P0-AUTH-SPEC-REV10.md` (`1,413` lines)
- **Review Scope & Procedure:** Complete line-by-line read-only inspection of `F360-P0-AUTH-SPEC-REV9.md` and `F360-P0-AUTH-SPEC-REV10.md` across all 23 sections, cross-reference reconciliation across API contracts (§9.3), verification/fallback specs (§10.2), threat mitigations (§17.3), client contracts (§18), proposed test matrices (§20), environment tables (§21), stage gates (§22), risks/checklists (§23), and read-only inspection of `.git/HEAD` and `.git/logs/HEAD`.
- **Reviewer Context Disclosure:** This review assessment was conducted as a structured verification audit within the same AI assistant session that authored Rev10, comparing the literal on-disk Rev9 and Rev10 specification files; no separate uninvolved third-party reviewer or human owner has reviewed Rev10 yet.

---

## 2. How Both Rev9 Issues Were Checked Against Actual `F360-P0-AUTH-SPEC-REV10.md` Text

### 2.1 Issue A Check — Universal Links & Android App Links Coverage for `/login`

| Review Question Checked | Evidence Verified in `F360-P0-AUTH-SPEC-REV10.md` | Check Result |
| :--- | :--- | :--- |
| Are both `/verify-email` and `/login` covered on iOS? | `§10.2.B.1` (`L518–L520`) requires `com.apple.developer.associated-domains` (`applinks:<frontend-host>`) plus redirect-free HTTPS `/.well-known/apple-app-site-association` explicitly associating both `"/verify-email"` and `"/login"` with `<TEAM_ID>.<BUNDLE_ID>`; echoed in `§18.2` (`L887`) and `§23` Risk #7 (`L1394`). | **PASS** |
| Are both `/verify-email` and `/login` covered on Android? | `§10.2.B.1` (`L521–L523`) requires HTTPS `/.well-known/assetlinks.json` (`delegate_permission/common.handle_all_urls`, `package_name`, `sha256_cert_fingerprints`) and verified `<intent-filter android:autoVerify="true">` rules covering both `android:path="/verify-email"` and `android:path="/login"`; echoed in `§18.2` (`L887`). | **PASS** |
| Are unrelated routes protected against accidental app capture? | `§10.2.B.1` (`L517`) requires explicit `/verify-email` and `/login` enumeration (or strictly auth-scoped, explicitly documented patterns) and explicitly forbids unrestricted `/*` wildcards. | **PASS** |
| Are all 6 installed / not-installed & credential rules specified? | `§10.2.B.1` table (`L526–L533`) covers all 6 required cases: (1) installed `/verify-email` -> native verify -> `/(auth)/login` (zero auto-login); (2) installed **“Open in Folio360 app”** on `/login` -> native Login (`/(auth)/login`); (3) uninstalled `/verify-email` -> browser verify + safe fallback UI; (4) uninstalled `/login` -> `{FRONTEND_BASE_URL}/login` normal web login page (`§10.2.A` `L507`, `§18.1` `L880`); (5) zero tokens/credentials in `/login` deep link (`L532`); (6) Rev9 browser fallback UX preserved (`L533`, `L535–L554`). | **PASS** |
| Do proposed acceptance tests cover iOS, Android, installed, uninstalled & security boundaries? | `§20.4` Tests `#14` (iOS AASA `/verify-email` & `/login`), `#15` (Android `assetlinks.json`/intent filters), `#16` (installed-app handling + zero credentials in `/login` URI), and `#17` (app-not-installed browser usability for both routes) (`L1281–L1284`), all labeled **Proposed — Not Executed**. | **PASS** |

### 2.2 Issue B Check — Explicit Frontend / Backend Environment-Policy Parity

| Review Question Checked | Evidence Verified in `F360-P0-AUTH-SPEC-REV10.md` | Check Result |
| :--- | :--- | :--- |
| Is the frontend build-target selector explicit, deterministic & fail-closed? | `§10.2.C.2` (`L563–L567`) and `§21.2` (`L1357`) define non-secret build-time **`VITE_APP_ENVIRONMENT`** with strict closed enum **`"development" | "testing" | "production"`**, banning heuristic hostname/`DEV`/`--mode` inference and requiring missing, empty, whitespace-padded, differently cased, or unknown values (`"staging"`, `"preview"`, `"local"`) to fail closed (zero silent fallback). | **PASS** |
| Does it map 1-to-1 to backend `ENVIRONMENT` without creating a second policy? | `§10.2.C.2` table (`L570–L574`) and `§21.1` (`L1307`) establish an exact 1-to-1 mapping (`development<->development`, `testing<->testing`, `production<->production`) driving the single unified §10.2.C.4 policy matrix (`L593–L599`) and shared §10.2.C.5 6-step parser (`L603–L626`). | **PASS** |
| Are standalone production frontend builds blocked from accepting dev loopback `http://`? | `§10.2.C.2` (`L577`), `§18.1` (`L878`), and `§21.2` (`L1358`) mandate pre-emit build validation failing whenever `VITE_APP_ENVIRONMENT == "production"` sees any `http://` entry (including `localhost`, `127.0.0.1`, `[::1]`) or any external `http://`. | **PASS** |
| Does CI/release validation fail on env mismatches without runtime discovery? | `§10.2.C.3` (`L582–L587`) defines 4 deterministic CI/release gates: (1) closed-enum check on both vars; (2) **`VITE_APP_ENVIRONMENT == ENVIRONMENT`**; (3) env-policy validation on both URI lists; (4) canonical set equality. `L587` and `§18.1` (`L877`) explicitly bar browser-time config discovery. | **PASS** |
| Do proposed acceptance tests cover matching envs, mismatch failure, loopback/external HTTP & standalone prod build? | `§20.4` Tests `#1, #2, #5–#7, #9` (`L1268–L1276`) plus new Tests `#18` (all 3 matching env pairs), `#19` (env mismatches & invalid `VITE_APP_ENVIRONMENT`), and `#20` (standalone prod build rejecting loopback `http://`) (`L1285–L1287`), all labeled **Proposed — Not Executed**. | **PASS** |

---

## 3. Consistency & Non-Regression Checks (`Rev9` vs. `Rev10`)

| Preserved Governance / Technical Area | Exact Lines Compared (`Rev9` -> `Rev10`) | Audit Finding |
| :--- | :--- | :--- |
| **Approved Q1–Q11 Decisions (§4)** | `Rev9 L69–L84` -> `Rev10 L73–L88` | **PASS — Verbatim match.** Zero Q1–Q11 decisions reopened or altered. |
| **Stage 3A / 3B / 3C Boundaries & Git Governance (§22)** | `Rev9 L1305–L1325` -> `Rev10 L1362–L1382` | **PASS — Preserved.** Stage 3A/3B/3C scopes and 5-gate Git authorization rules unchanged; Stage 3A gate updated only for Rev10 links, `VITE_APP_ENVIRONMENT` parity & `20` proposed tests. |
| **Database Schema & Migration Sequence (§§7–8)** | `Rev9 L182–L360` -> `Rev10 L186–L364` | **PASS — Verbatim match.** All 7 tables, `0001 -> 0002 (3A) -> 0003 (3B) -> 0004 (3C)`, and 5 migration verification rules unchanged. |
| **Core Auth, API Error Codes, Resend, Locking, OAuth/OIDC (§§9.1–9.2, §9.3 #1/#3–#14, §§11–16, §17.1–17.2, §18.3)** | `Rev9 L365–L442, L586–L808, L843–L844` -> `Rev10 L369–L446, L630–L852, L892–L893` | **PASS — Verbatim match.** Verification remains JSON-only (`§9.3 #2`), non-auto-authenticating, single-use opaque hashed tokens, `users`-first locking, Google OIDC `aud`/`azp`, GitHub bounded pagination, AEAD PKCE. |
| **Rev7 Uvicorn ASGI3 & Login `Origin` Controls (§9.3 #4, §12.3, §16.3, §19, §20.3, §20.4)** | `Rev9 L425–L428, L641–L653, L848–L1217` -> `Rev10 L433–L436, L685–L697, L897–L1266` | **PASS — Verbatim match.** `interface="asgi3"`, `@inspect.markcoroutinefunction`, 3-layer verifier, `35` proposed Uvicorn tests (§20.3), and `5` web login `Origin` tests (§20.4) untouched. |
| **Rev8 Allowlist Ownership & Canonical Parity (§10.2.C.1, §10.2.C.3, §21)** | `Rev9 L534–L544, L1267, L1301` -> `Rev10 L558–L561, L579–L588, L1323, L1358` | **PASS — Preserved.** Non-secret `VITE_EMAIL_VERIFICATION_MOBILE_LOGIN_URIS`, backend `EMAIL_VERIFICATION_MOBILE_LOGIN_URIS` anchor, and explicit `folio360://auth/login` approval policy intact. |
| **Rev9 Browser Fallback UX & 6-Step URI Parser (§10.2.B.2–3, §10.2.C.4–5)** | `Rev9 L512–L582` -> `Rev10 L535–L626` | **PASS — Preserved.** 5-outcome UX table, browser launch-detection honesty, no blank/loading stranding, explicit prod vs. dev/test URI table, and shared 6-step parser (`[::1]`, raw `:443`/`:80`) intact. |
| **Cross-References & Test Counts (§§1, 20, 22, 23)** | `Rev10 L39, L1189–L1192, L1196–L1287, L1367, L1401, L1409` | **PASS — Synchronized.** `81` historical baseline (`§20.1`), `35` proposed Uvicorn (`§20.3`), and `20` proposed verification/link/parity tests (`§20.4`) match across all sections, with zero `Rev 9 — This Document` or stale `13`-test gate claims. |

---

## 4. Verified Findings vs. Claims NOT Independently Verified

### 4.1 Verified Findings (Directly Observed Textually in On-Disk Documents)
- Confirmed exact textual diffs and section synchronization between `F360-P0-AUTH-SPEC-REV9.md` (`1,359` lines) and `F360-P0-AUTH-SPEC-REV10.md` (`1,413` lines).
- Confirmed both Rev9 gaps (Correction A `/login` Universal/App Links and Correction B deterministic `VITE_APP_ENVIRONMENT` <-> `ENVIRONMENT` parity) are explicitly specified, cross-referenced across `§§1, 9.3, 10, 10.2, 17.3, 18.1–18.2, 20, 20.4, 21.1–21.2, 22, 23`, and covered by proposed tests `#1–#20`.
- Confirmed zero regressions to Q1–Q11, Stage 3A/3B/3C boundaries, `0002 -> 0003 -> 0004` migrations, and Rev1–Rev9 controls.
- Confirmed via `read_file` that `F360-P0-AUTH-SPEC-REV9.md` (`L1–L15`), `.git/HEAD` (`ref: refs/heads/main`), and `.git/logs/HEAD` (`54c155bd0ba74f3cc54473fd7b3fb0d0e52b8936`) were not altered during Rev10 authoring or this report revision.

### 4.2 Claims & Items NOT Independently Verified (Explicit Boundaries)
1. **No Separate Third-Party / Human Reviewer:** Verification was performed as a structured self-audit inside the same AI assistant session that drafted Rev10; independent human/owner review remains pending.
2. **Zero Tests Implemented or Executed:** All Stage 3 acceptance tests (`35` Uvicorn in `§20.3`, `5` login `Origin` + `20` verification/link/env-parity + `8` Resend in `§20.4`, `0002`–`0004` migrations in `§20.2`, Stage 3B in `§20.5`, Stage 3C `10` Google + `9` GitHub + PKCE in `§20.6`) are **Proposed — Not Executed**. The `81` Stage 1/2 tests (`§20.1`) are a historical baseline count not re-executed here.
3. **No Runtime Verification of Platform Manifests, Vite Build Guard, or CI Parity Script:** Actual hosting/validation of iOS AASA (`<TEAM_ID>.<BUNDLE_ID>`), Android `assetlinks.json` (`package_name`, release `sha256_cert_fingerprints`), Vite `vite.config.ts` build-time rejection of loopback `http://`, and the 4-gate CI/release script + shared Python/JS canonical test vectors cannot be verified until Stage 3A frontend/mobile/CI implementation.
4. **No Shell `git status` / `git diff` Verification:** Shell commands were not executed because the fixed shell working directory (`/home/prajwal/Documents/PRAJWAL DOCUMENTS/projects/AI_JOB_SCAM_DETECTOR`) does not exist on disk; repository file-tree cleanliness outside `F360-P0-AUTH-SPEC-REV9.md` (`L1–L15`), `.git/HEAD`, and `.git/logs/HEAD` was not scanned via `git status`.
5. **Retained Upstream & Operational Assumptions:** Live Stage 3C verification of Google confidential web-server PKCE + `client_secret` (`§16.4`), target `Python >= 3.12` / pinned `uvicorn==0.54.0` deployment verification, and the policy assumption that internet-facing staging/pre-production deployments must use `"production"` on both `ENVIRONMENT` and `VITE_APP_ENVIRONMENT` unless a 4th tier is formally specified later remain pre-implementation/deployment assumptions.

---

## 5. Formal Final Verdict

**Verdict: `ACCEPTABLE — ready for owner approval.`**

### Verdict Rationale
Every textual specification requirement for Rev10 Correction A (`/verify-email` and `/login` Universal Links & Android App Links coverage across all 6 behaviors with strict path scoping) and Correction B (`VITE_APP_ENVIRONMENT` strict closed enum, 1-to-1 mapping to backend `ENVIRONMENT`, standalone production build guard against loopback `http://`, 4-gate deterministic CI/release check with zero runtime discovery, and unified §10.2.C URI semantics) is completely and consistently documented in [F360-P0-AUTH-SPEC-REV10.md](F360-P0-AUTH-SPEC-REV10.md), with full preservation of Q1–Q11, Stage 3A/3B/3C boundaries, `0002 -> 0003 -> 0004` migrations, and Rev1–Rev9 security controls. All unverified items in Section 4.2 are implementation, deployment, and test-execution gates rather than specification blockers. Stage 3A implementation remains paused pending explicit project-owner approval.
