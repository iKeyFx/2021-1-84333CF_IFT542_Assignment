# IFT 542 — Task 1: STRIDE Threat Model & Risk Assessment (14 marks)

**Application:** Student Registration Web Application (Next.js 14 + PostgreSQL, localhost prototype)
**Scope:** login, profile update, course registration, document upload, admin course management, admin enrolment management.
**Note:** every threat below is tied to an actual planted vulnerability with its file path, so the model reflects the real code, not textbook generics.

---

## 1. Data-Flow Diagram with Trust Boundaries (Evidence item 6)

The Mermaid source is below; a rendered copy is committed at `evidence/task1/dfd.png` (regenerated locally with `@mermaid-js/mermaid-cli`) and embedded immediately beneath it.

```mermaid
flowchart TB
    subgraph CLIENT["🔴 Untrusted Zone — Browser / Internet"]
        STU["Student<br/>(external entity)"]
        ADM["Admin<br/>(external entity)"]
        ATK["Attacker<br/>(external entity)"]
    end

    subgraph APP["🟡 Application Trust Boundary — Next.js Server (localhost:3000)"]
        AUTH["P1: Login / Auth<br/>api/login/route.ts"]
        PROF["P2: Profile Update<br/>api/profile/route.ts"]
        ENR["P3: Course Registration<br/>api/enrol/route.ts"]
        UPL["P4: Document Upload<br/>upload handler"]
        subgraph ADMZONE["🟠 Privileged Sub-boundary — Admin"]
            ACRS["P5: Manage Courses"]
            AENR["P6: Manage Enrolments"]
            URLP["P7: URL Preview / Import<br/>api/admin/url-preview/route.ts"]
        end
        SESS["Session store<br/>lib/session.ts"]
    end

    subgraph DATA["🟢 Data Trust Boundary — PostgreSQL (127.0.0.1)"]
        DBP[("profiles")]
        DBC[("courses")]
        DBE[("enrolments")]
        DBU[("uploads")]
    end

    subgraph EXT["🟣 External / Internal Network — reached by P7"]
        FS[["Local filesystem<br/>uploaded docs"]]
        NET(["Arbitrary URL /<br/>loopback / metadata"])
    end

    STU -->|"credentials, profile, enrol reqs"| AUTH
    ADM -->|"admin actions, preview URLs"| ACRS
    ATK -.->|"malicious input, forged reqs"| AUTH

    AUTH <-->|"SQL (concatenated!)"| DBP
    AUTH <--> SESS
    PROF <--> DBP
    ENR <--> DBE
    ENR --> DBC
    ACRS <--> DBC
    AENR <--> DBE
    UPL --> FS
    UPL --> DBU
    URLP -.->|"unrestricted fetch"| NET
    PROF -->|"unescaped display name"| STU
```

![Data-flow diagram with trust boundaries for the Student Registration app](../evidence/task1/dfd.png)

**Trust boundaries marked:** (1) browser ↔ server, (2) server ↔ database, (3) server ↔ external/internal network via URL-preview, (4) server ↔ local filesystem, and (5) a privilege sub-boundary between ordinary and admin functions. The red dotted flows are the attacker's entry points.

---

## 2. STRIDE Worksheet (Evidence item 7 — ≥6 threats, ≥1 per category)

> **All `file:line` references in §2, §3, §4 and Appendix A describe the tagged `v0-vulnerable`
> baseline** (commit `b42df0a`) and are left unchanged as the historical record of the threat model.
> Task 2 has since remediated T1, T5, T7, T8 and the T9 fixation component; the line numbers in the
> current working tree therefore differ. See **Appendix B** for the remediation status, the controls
> implemented, and their new locations.

| # | STRIDE | Application-specific threat | Planted vulnerability (file : line) |
|---|--------|------------------------------|--------------------------------------|
| T1 | **S**poofing | Authenticate as any user (incl. admin) with no valid password by injecting into the login query | SQLi — `src/app/api/login/route.ts:46–54` |
| T2 | **T**ampering | Force a logged-in victim's browser to submit profile updates / course enrolments via a forged cross-site request | No CSRF + no SameSite — `api/profile/route.ts:27`, `api/enrol/route.ts:23`, `lib/session.ts:60` |
| T3 | **T**ampering / EoP | Stored script in the display name executes in any viewer's (incl. admin's) session, hijacking it or forging privileged actions | Stored XSS — source `api/profile/route.ts:32`, sinks `dashboard/page.tsx:23`, `profile/page.tsx:25` |
| T4 | **R**epudiation | An admin (or attacker acting as admin) removes an enrolment or changes records; no tamper-evident audit log exists, so the action cannot be attributed or disproven | No security logging in baseline (added only in Task 3) |
| T5 | **I**nformation Disclosure | Whole-database password compromise, since credentials are stored and compared in cleartext and are exfiltratable through T1 | Plaintext passwords — `db/migrations/001_init.sql:29`, `db/seed.sql:26–34`, compared `api/login/route.ts:50` |
| T6 | **I**nformation Disclosure | Server-side request forgery reaches loopback / private / cloud-metadata addresses and returns internal responses | SSRF — `src/app/api/admin/url-preview/route.ts:27` |
| T7 | **I**nformation Disclosure | Verbose SQL/stack errors and distinct "no account" vs "wrong password" responses leak schema and valid accounts | Verbose errors `api/login/route.ts:56`; enumeration `api/login/route.ts:86` |
| T8 | **D**enial of Service | Unthrottled login and unbounded document upload allow request/large-file flooding and unlimited brute force | No rate limiting `api/login/route.ts:28`; upload handler (no size cap) |
| T9 | **E**levation of Privilege | Ordinary user becomes admin by using the default admin credentials or forging a session with the committed hardcoded secret | Default admin `lib/config.ts:26`, `db/seed.sql:8`; hardcoded secret `lib/config.ts:16`; session fixation `lib/session.ts:35` |

All six STRIDE categories are covered (S:T1 · T:T2,T3 · R:T4 · I:T5,T6,T7 · D:T8 · E:T9).

---

## 3. Risk Register (Evidence item 8)

Likelihood (L) and Impact (I) on 1–5; **Risk = L × I**; ranked; control type in brackets; residual after the planned Task 2/3 fixes.

| Rank | # | STRIDE | Threat | L | I | Risk | Priority | Control (P=preventive, D=detective, C=corrective) | Residual (L×I) |
|------|----|--------|--------|---|---|------|----------|--------|----------|
| 1 | T1 | S | SQLi auth bypass | 5 | 5 | **25** | Critical | Parameterized queries **(P)**; input validation **(P)**; log rejected/anomalous queries **(D)**; session revocation + runbook **(C)** | 1×5 = **5** |
| 2 | T9 | E | Default admin creds + hardcoded secret → privilege escalation | 4 | 5 | **20** | Critical | Remove default account, force strong seeded password, secret to env + rotate **(P)**; MFA for admin **(P)**; log denied-authorization **(D)**; invalidate sessions on leak **(C)** | 1×5 = **5** |
| 3 | T5 | I | Plaintext password disclosure (via DB read / T1) | 4 | 5 | **20** | Critical | Argon2id hashing, never return plaintext **(P)**; monitor bulk DB reads **(D)**; forced reset on suspected breach **(C)** | 2×3 = **6** |
| 4 | T3 | T/E | Stored XSS in display name | 4 | 4 | **16** | High | Contextual output encoding + restrictive CSP **(P)**; CSP report-uri **(D)** | 1×4 = **4** |
| 5 | T2 | T | CSRF on profile / enrolment | 4 | 3 | **12** | High | Anti-CSRF token + SameSite cookie **(P)** | 1×3 = **3** |
| 6 | T8 | D | Login/upload flooding & brute force | 4 | 3 | **12** | High | Rate limiting + temporary lockout + upload size cap **(P)**; alert on repeated failures **(D)** | 2×3 = **6** |
| 7 | T4 | R | Unattributable admin/user actions | 4 | 3 | **12** | High | Structured who/what/when audit logs **(D)**; append-only retention **(C)** | 2×2 = **4** |
| 8 | T6 | I | SSRF via admin URL preview | 3 | 4 | **12** | High | Destination allowlist; reject loopback/private/metadata; re-check after DNS **(P)** | 1×3 = **3** |
| 9 | T7 | I | Verbose errors + user enumeration | 5 | 2 | **10** | Medium | Generic errors, debug off **(P)**; monitor error rates **(D)** | 1×2 = **2** |

---

## 4. Justification for the Top-Three Risks (Evidence item 9)

**#1 — T1, SQLi authentication bypass (25).** This is the single highest risk because it is unauthenticated, trivially exploitable (already demonstrated logging in as `ada.learner` with no valid password), and grants complete account takeover including the admin account — collapsing every other control. Likelihood is maximal (the concatenated query at `login/route.ts:46–54` accepts attacker-controlled SQL directly) and impact is maximal (full data and privilege compromise). **Residual 5:** after parameterized binding, user input can no longer alter query structure, so likelihood drops to 1; the residual reflects only the possibility of an unrelated future injection elsewhere, which is monitored and accepted as low.

**#2 — T9, privilege escalation via default admin + hardcoded secret (20).** Any user who knows the shipped default (`admin@campus.local / admin123`) or the committed session secret (`lib/config.ts:16`) can reach admin course/enrolment management, which is a full trust-boundary crossing. Likelihood is high because both values are discoverable in source or documentation; impact is maximal (administrative control). **Residual 5:** removing the default account, forcing a strong per-deployment password, moving the secret to an environment variable and rotating it makes guessing or forgery infeasible, so likelihood drops to 1. The remaining residual is generic credential-theft risk, further reduced by admin MFA, and is accepted as low.

**#3 — T5, plaintext password disclosure (20).** Credentials are stored and compared in cleartext (`001_init.sql:29`, `seed.sql:26–34`, `login/route.ts:50`) and are exfiltratable through T1, meaning one read compromises every account and any password reused elsewhere. Likelihood is high given T1; impact is maximal (mass credential compromise with downstream reuse). **Residual 6:** Argon2id hashing means that even a full database read yields only expensive-to-crack hashes; the residual reflects offline cracking of weak passwords, mitigated by a password policy and accepted as low.

---

## Appendix A — OWASP Top 10 (2021) mapping

This appendix folds in the OWASP Top-10 (2021) view (originally drafted in `report/threat-model.md`)
so the two documents agree. **STRIDE (§2) and the risk register (§3) remain the primary model;** this
is a cross-reference that ties every *planted* vulnerability to its STRIDE threat ID and risk-register
rank. File:line references match §2 exactly.

| Planted vulnerability | File : line | STRIDE | Risk # | OWASP 2021 |
|---|---|---|---|---|
| SQL injection in login (concatenated `sql.unsafe`) | `api/login/route.ts:46–54` | T1 | 1 | A03 Injection |
| Plaintext password storage & compare | `001_init.sql:29`, `seed.sql:26–34`, `login/route.ts:50` | T5 | 3 | A02 Cryptographic Failures |
| Verbose DB/stack errors to client | `api/login/route.ts:56` (also :92) | T7 | 9 | A05 Security Misconfiguration |
| User enumeration / field disclosure | `api/login/route.ts:86` | T7 | 9 | A07 Identification & Auth Failures |
| No rate limiting on login | `api/login/route.ts:28` | T8 | 6 | A07 Identification & Auth Failures |
| No session-id regeneration (fixation) | `lib/session.ts:35`; used `login/route.ts:70` | T9 | 2 | A07 Identification & Auth Failures |
| Stored XSS (display name) | source `api/profile/route.ts:32`; sinks `dashboard/page.tsx:23`, `profile/page.tsx:25` | T3 | 4 | A03 Injection (XSS) |
| No CSRF on state-changing POSTs | `api/profile/route.ts:27`, `api/enrol/route.ts:23` | T2 | 5 | A01 Broken Access Control |
| No SameSite on session cookie (enables CSRF) | `lib/session.ts:60` | T2 | 5 | A05 Security Misconfiguration |
| SSRF in admin URL preview | `api/admin/url-preview/route.ts:27` | T6 | 8 | A10 Server-Side Request Forgery |
| Debug mode on (drives verbose errors) | `lib/config.ts:11` | T7 | 9 | A05 Security Misconfiguration |
| Hardcoded session secret (committed fallback) | `lib/config.ts:16` | T9 | 2 | A05 / A02 |
| Default admin with well-known password | `lib/config.ts:26`, `seed.sql:8` | T9 | 2 | A07 Identification & Auth Failures |

**OWASP categories represented:** A01, A02, A03, A05, A07, A10 (2021).

**Note on T4:** the repudiation threat (no tamper-evident audit log) is an *absence of control*, not a
planted code sink, so it has no `file:line` row above; it corresponds to OWASP **A09 Security Logging &
Monitoring Failures**.

---

## Appendix B — Task 2 remediation status

Task 2 hardened authentication and database access. The six Task 2 findings from Appendix A are
closed; the seven Task 3 findings are untouched by design. Baseline for comparison is tag
`v0-vulnerable`:

```
git diff v0-vulnerable -- src/app/api/login/route.ts
```

| Planted vulnerability (Appendix A) | STRIDE | Risk # | Status | Control implemented | New location | Evidence |
|---|---|---|---|---|---|---|
| SQL injection in login (concatenated `sql.unsafe`) | T1 | 1 | **Closed** | postgres.js tagged template — `WHERE p.email = ${input.email}` sent as an extended query with a `$1` placeholder, so input binds as data. `sql.unsafe` and the second injectable email-only lookup removed. | `api/login/route.ts:84–92` | `tests/sqli-parameterized.test.ts`; `evidence/task2/run-output-after.txt` §1 |
| Plaintext password storage & compare | T5 | 3 | **Closed** | Argon2id, m=19456 KiB, t=2, p=1, 32-byte digest, per-row random salt (OWASP minimum). Login fetches by email then calls `argon2.verify()`. Plaintext column dropped; `CHECK (password_hash LIKE '$argon2id$%')` enforces the format in the database. | `lib/password.ts`, `db/hash-passwords.mjs`, `db/migrations/002_argon2id_password_hash.sql` | `tests/password-storage.test.ts`; `evidence/task2/run-output-after.txt` §2, §2b |
| Verbose DB/stack errors to client | T7 | 9 | **Closed** | Driver message, stack and query logged server-side only; client gets a fixed string. The login page no longer renders `stack`/`query`. | `api/login/route.ts:93–97`, `app/login/page.tsx` | `tests/auth-login.test.ts`; `evidence/task2/run-output-after.txt` §3 |
| User enumeration / field disclosure | T7 | 9 | **Closed** | One generic `401 {"error":"Invalid email or password"}` for every failure mode; unknown-email and wrong-password replies are byte-identical. Timing equalised via a decoy Argon2id verification. | `api/login/route.ts:44`, `107–112`; `lib/password.ts` | `tests/auth-login.test.ts` (`toEqual(wrongPwBody)`) |
| No rate limiting on login | T8 | 6 | **Closed** (login half) | Per-IP fixed window: 5 failures / 60 s, then `429` + `Retry-After`, checked before any DB or hashing work. Failures only; success clears the bucket. | `lib/rate-limit.ts`, `api/login/route.ts:57–66` | `tests/rate-limit.test.ts`; `evidence/task2/run-output-after.txt` §5 |
| No session-id regeneration (fixation) | T9 | 2 | **Closed** | Fresh `randomUUID()` on every successful login; the presented id is deleted, not re-pointed. | `lib/session.ts:43–63` | `tests/session-regeneration.test.ts`; `evidence/task2/run-output-after.txt` §6 |
| Stored XSS (display name) | T3 | 4 | Open (Task 3) | — | unchanged | — |
| No CSRF on state-changing POSTs | T2 | 5 | Open (Task 3) | — | unchanged | — |
| No SameSite on session cookie | T2 | 5 | Open (Task 3) | — | unchanged | — |
| SSRF in admin URL preview | T6 | 8 | Open (Task 3) | — | unchanged | `node tests/ssrf-demo.mjs` still confirms |
| Debug mode on | T7 | 9 | Open (Task 3) | Login route no longer reads `DEBUG`, but the flag still defaults to `true` and still drives the URL-preview handler. | unchanged | — |
| Hardcoded session secret | T9 | 2 | Open (Task 3) | — | unchanged | — |
| Default admin with well-known password | T9 | 2 | Open (Task 3) | — | unchanged | asserted still working in `tests/auth-login.test.ts` |

**Supporting control added:** input validation (`lib/validate.ts`) — email format plus 3–254 length
bounds, password 8–128 length bounds, and rejection of non-string values rather than `String()`
coercion. `PASSWORD_MIN` is capped at 8 precisely so the Task 3 default admin (`admin123`, exactly
8 characters) keeps working; a test asserts this so the finding cannot be removed by accident.

**Residual risk after Task 2.** The §3 residual scores anticipated these fixes and still stand
(T1 → 5, T5 → 6, T7 → 2, T8 → 6). Qualifications worth recording:

- T8's residual assumed rate limiting *and* an upload size cap. Only the login half is delivered;
  the upload handler still has no size cap, so T8's residual is not yet fully realised.
- The limiter is a **fixed** window, so ~2× the limit can be burst across a boundary; its state is
  in-process and lost on restart; and it trusts `X-Forwarded-For`, which is safe only because this
  artefact is localhost-only.
- Timing is *equalised*, not constant — the decoy hash removes the ~30 ms Argon2 step function, but
  a sub-millisecond database round-trip difference remains.
- T9's residual of 5 depends on **all three** of its components. Only session fixation is closed;
  the default admin and the hardcoded secret remain, so T9 is still live at its original score.

---

### Coverage & consistency checklist for this task
- [x] DFD exported to `evidence/task1/dfd.png` and referenced in the report
- [x] All six STRIDE categories present (they are: S,T,R,I,D,E)
- [x] ≥6 threats in worksheet (9 here) — every one tied to a real file path
- [x] Risk register shows L, I, Score, Priority, Control, Residual for every row
- [x] Risk = L × I arithmetic correct in every row
- [x] Residual < initial for every mitigated threat, with reasoning
- [x] Top-3 justification written (above)
- [x] Reconcile with Claude Code's `report/threat-model.md` (merge the OWASP mapping in as an appendix so the two documents agree)
