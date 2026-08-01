# Incident Record — INC-2026-001

> ## ⚠️ THIS IS AN AUTHORISED SIMULATED EXERCISE — NOT A REAL BREACH
>
> Every event below was produced **deliberately, by the author, against their own
> localhost-only teaching artefact**, as the offensive half of IFT542 coursework. The
> "attacker" and the "responder" are the same student. No third-party system was touched, no
> real person's data exists in this application, and nothing was ever exposed to a network.
> All accounts are fictitious (`@campus.local`), all names are invented, and no PII is
> present. See [`ETHICS.md`](../ETHICS.md).
>
> This document is written in incident-report form because **producing one is the
> deliverable** (evidence item 26). If it is ever read outside that context, read it as a
> worked example, not as a report of a real compromise.

| Field | Value |
|---|---|
| **Incident ID** | `INC-2026-001` |
| **Title** | Chained SQL-injection → full credential disclosure → SSRF as admin |
| **Classification** | Simulated / authorised security exercise |
| **Severity** | **Critical** (would be P1 in a real deployment) |
| **Status** | **Closed — remediated and verified** |
| **Detected** | *Not detected.* Reconstructed after the fact — see §2.1 |
| **Environment** | `http://127.0.0.1:3000`, local docker-compose Postgres. Localhost only. |
| **Affected build** | tag `v0-vulnerable` (commit `b42df0a`) |
| **Remediated in** | `v1-hardened-task2` (`d8b532f`), `v2-hardened-task3` (`9d91d0c`) |
| **Data involved** | 7 fictitious accounts (6 students + 1 admin). No real PII. |

> **Companion document.** This is the detailed incident *record* (evidence item 26). The
> six-stage summary of the response process — Preparation, Identification, Containment,
> Eradication, Recovery, Lessons Learned — is the one-page runbook at
> [`report/incident-runbook.md`](incident-runbook.md), in which every step is a command rather
> than a paragraph.

---

## 1. Preparation

What existed before the incident, honestly stated:

| Capability | State at `v0-vulnerable` |
|---|---|
| Threat model | **Yes** — STRIDE worksheet + risk register, now §1.2–§1.3 and Appendix A of [`report/2021-1-84333CF_IFT542_report.md`](2021-1-84333CF_IFT542_report.md) |
| Security logging | **None.** Six ad-hoc `console.log` calls, unparseable, one printing a raw email |
| Audit retention | **None** |
| Alerting | **None** |
| Session revocation | **None** — no way to invalidate a session short of a manual `DELETE` |
| Forced credential reset | **None** |
| Incident runbook | **None** — the phrase "session revocation + runbook" appeared in the risk register as a promise |

The threat model had **correctly predicted this exact chain** before it was executed: T1
(SQLi auth bypass, risk 25, rank 1), T5 (plaintext disclosure via T1, risk 20, rank 3) and T6
(SSRF, risk 12, rank 8). Prediction without detection or response capability is the finding
this incident really illustrates: knowing about a risk is not a control.

---

## 2. Detection and Analysis

### 2.1 How it was found — and the detection gap

**It was not detected. There was nothing to detect it with.**

The application emitted no security events, so no failed login, no privilege check and no
outbound fetch left any record. The timeline in §2.3 is **reconstructed from the exploit
transcripts** in `evidence/task2/run-output.txt` and `evidence/task3/run-output.txt`, not from
logs — because there were no logs.

That absence is itself finding **T4** in the risk register ("unattributable actions", rank 7),
and it is the reason this exercise ends by building an append-only audit sink rather than only
patching the injection.

> **Note on the timestamps.** The exploit transcripts are stamped **12:17**, which is *earlier*
> than the `v0-vulnerable` tag commit at **13:27**. That is not an inconsistency in the record:
> the exploits were run against the working tree before it was committed and tagged. The code
> under test at 12:17 is byte-identical to what `b42df0a` later committed.

### 2.2 Entry point

`POST /api/login`, at `src/app/api/login/route.ts:46-54` in the baseline, built its
authentication query by string concatenation and executed it through `sql.unsafe()`:

```js
const authQuery =
  "SELECT p.id, p.email, p.role, p.display_name " +
  "FROM profiles p " +
  "JOIN credentials c ON c.profile_id = p.id " +
  "WHERE p.email = '" + email + "' AND c.password = '" + password + "'";
rows = await sql.unsafe(authQuery);
```

The email field was concatenated directly into the statement, so input was parsed as **code**.

### 2.3 Timeline (times are WCAST, the recording machine's local zone)

| Time | Event | Evidence |
|---|---|---|
| **12:17:31** | **Initial access.** `email = ' OR '1'='1' -- ` submitted to `/api/login`. Server replies `200 {"ok":true,...}` and issues session `a74f9d57-…` as `ada.learner` with **no valid password**. Cookie lifetime 24 h, `HttpOnly` only — no `SameSite`, no `Secure`. | `evidence/task2/run-output.txt` §1 |
| 12:17:3x | **Discovery.** Unknown vs known email return *different* messages (`"No account exists…"` vs `"Incorrect password…"`), confirming account enumeration. A malformed payload returns **HTTP 500 with `stack` and `query` fields**, disclosing the schema and the literal SQL. | ibid. §2 |
| 12:17:3x | **Credential access.** All 7 credentials read in **cleartext** — the `credentials.password` column stored raw passwords, including `admin@campus.local / admin123`. | ibid. §3 |
| 12:17:3x | **Privilege escalation.** The disclosed admin password grants the admin role directly; the hardcoded `SESSION_SECRET` in `src/lib/config.ts:16` (committed to the repository) would have allowed session forgery as a second path. | `report/2021-1-84333CF_IFT542_report.md` Appendix A, T9 |
| **12:17:44** | **Lateral movement / SSRF.** As admin, the URL-preview endpoint is asked to fetch `http://127.0.0.1:3000/login`. The server follows it and returns the body — no scheme, host or IP restriction. Any internal service reachable from the server was readable. | `evidence/task3/run-output.txt` §1 |
| 12:17:4x | **Persistence / impact.** Stored XSS via the profile display name: `<img src=x onerror=…>` saved verbatim and rendered through `dangerouslySetInnerHTML` on `/dashboard`, executing in **any viewer's session including an admin's**. | ibid. §2 |
| **16:05** | **Baseline completed.** Forged cross-site POST to `/api/profile` with `Origin: null` and no token is **accepted** (`303`, state changed). All six security headers confirmed **absent**. | `evidence/task3/run-output.txt` §4-6 |

### 2.4 Impact assessment

| Dimension | Assessment |
|---|---|
| **Confidentiality** | **Total.** Every credential disclosed in cleartext; arbitrary internal HTTP reachable via SSRF. |
| **Integrity** | **Total.** Admin access permits any record change; stored XSS and CSRF allow changes attributable to the victim rather than the attacker. |
| **Availability** | Not targeted. Unthrottled login (T8) would have permitted brute force, but no DoS was attempted. |
| **Attribution** | **Impossible.** With no logging, nothing could have been proven about who did what — the repudiation threat (T4) realised. |
| **Real-world impact** | **None.** Fictitious data, localhost only, single operator. |

### 2.5 Root causes

Not "a bug" — four independent failures that happened to compose:

1. **Data and code were not separated.** String concatenation into SQL. Every other failure
   downstream is reachable because of this one.
2. **Credentials were stored in a recoverable form.** Plaintext meant that one read was total
   compromise; hashed storage would have made the same read far less useful.
3. **Failures were verbose and distinguishable.** Different messages per failure mode, plus
   stack and query in the response body, turned the login endpoint into a reconnaissance tool.
4. **There was no way to see or to respond.** No logs, no revocation, no forced reset. Even
   after detection, there was nothing to *do*.

---

## 3. Containment, Eradication and Recovery

### 3.1 What was actually done (the real remediation)

| Phase | Action | Commit / tag | Verified by |
|---|---|---|---|
| Eradication | Parameterized the login query; `sql.unsafe()` removed | `d8b532f` `v1-hardened-task2` | `tests/sqli-parameterized.test.ts` (11) |
| Eradication | Argon2id hashing (m=19456, t=2, p=1); plaintext column **dropped**; `CHECK` constraint added | `d8b532f` | `tests/password-storage.test.ts` (13) |
| Eradication | One generic `401 {"error":"Invalid email or password"}` for every failure mode; timing equalised with a decoy digest | `d8b532f` | `tests/auth-login.test.ts` (19) |
| Hardening | Per-IP rate limiting; session-ID regeneration on login | `d8b532f` | `rate-limit.test.ts` (7), `session-regeneration.test.ts` (5) |
| Eradication | Output encoding + strict CSP with per-request nonce | `9d91d0c` `v2-hardened-task3` | `tests/xss-encoding.test.ts` (9) |
| Eradication | Signed double-submit CSRF tokens; `HttpOnly; SameSite=Lax; Secure` | `9d91d0c` | `tests/csrf.test.ts` (18) |
| Eradication | SSRF allowlist + DNS re-check + per-hop redirect validation | `9d91d0c` | `tests/ssrf-guard.test.ts` (50) |
| Eradication | Admin credential rotated off `admin123`; secret moved to env; `DEBUG` fail-closed | `9d91d0c` | `tests/security-headers.test.ts` (14) |
| **Detection** | Structured JSON-Lines security logging with enforced redaction | `9d91d0c` | `tests/logging.test.ts` (13) |
| **Response** | Session revocation, secret rotation, forced reset, append-only retention | `0552968` `v3-incident-response` | `tests/incident-response.test.ts` (25) |

### 3.2 The response, replayed with the tooling that now exists

The four corrective controls promised in the risk register but never built are now real
commands. Replaying this incident against the hardened build:

```bash
# 1. Assess
npm run ir:status

# 2. CONTAIN — the injected session a74f9d57-… stays valid for 24 h even after
#    the query is patched. Patching stops new bypasses; only revocation ends
#    the access the attacker already has.
npm run ir:revoke-sessions -- --all --incident INC-2026-001 --yes

# 3. CONTAIN — all 7 passwords were disclosed in cleartext, so every account is
#    compromised regardless of how it is stored today.
npm run ir:force-reset -- --require --all --incident INC-2026-001 --yes

# 4. ERADICATE — the admin password and SESSION_SECRET are in public git history
#    at v0-vulnerable and cannot be un-published. Rotation is the only remedy.
npm run ir:rotate-secrets -- --role admin --incident INC-2026-001 --yes

# 5. VERIFY
npm run ir:audit-log -- --verify
npm run ir:status
```

Step-by-step form, with the expected result at each stage, is in
[`report/incident-runbook.md`](incident-runbook.md). The real output of this cycle is
`evidence/task3/run-output-after.txt` §7–§9.

### 3.3 Recovery verification

- `npx vitest run tests/sqli-parameterized.test.ts` → injection bound as data; generic `401`,
  no session, zero rows matched
- `npx vitest run tests/auth-login.test.ts` → identical replies for unknown email and wrong
  password, body keys `['error']`
- `npx vitest run tests/ssrf-guard.test.ts` → every internal destination refused, bodies identical
- `npx vitest run tests/csrf.test.ts` → forged cross-site POST `403`, profile unchanged
- `npm test` → **`183 passed | 1 skipped (184)` across 11 files**

---

## 4. Post-Incident Activity

### 4.1 Findings register

Every issue found during the incident, with the threat-model ID it maps to and the tag that
closed it. This is the compact register; the full analysis is in the threat model.

| ID | Finding | STRIDE | Risk | Closed in | Control |
|---|---|---|---|---|---|
| **T1** | SQL-injection authentication bypass | Spoofing | 25 | `v1` | Parameterized query |
| **T9** | Default admin `admin123` + hardcoded `SESSION_SECRET` | EoP | 20 | `v1`/`v2` | Rotation, secret to env, fixation closed |
| **T5** | Plaintext password storage | Info. disclosure | 20 | `v1` | Argon2id + `CHECK` constraint |
| **T3** | Stored XSS in display name | Tampering/EoP | 16 | `v2` | Output encoding + nonce CSP |
| **T2** | CSRF on profile and enrolment | Tampering | 12 | `v2` | Signed double-submit token + `SameSite` |
| **T8** | Unthrottled login (brute force) | DoS | 12 | `v1` | Per-IP rate limit |
| **T4** | No audit log — actions unattributable | Repudiation | 12 | `v2`/`v3` | Structured logging + append-only sink |
| **T6** | SSRF via admin URL preview | Info. disclosure | 12 | `v2` | Allowlist + IP/DNS rejection |
| **T7** | Verbose errors + user enumeration | Info. disclosure | 10 | `v1` | Single generic error |

### 4.2 Lessons learned

1. **The threat model was right and it did not help.** T1, T5 and T6 were all documented as
   critical *before* they were exploited. Documentation is not a control; only code is.
2. **Detection was the real gap.** Every preventive control was missing, but the compounding
   failure was that nothing recorded anything. An attack you cannot see is one you cannot
   scope, contain or prove.
3. **Patching is not containment.** Parameterizing the query does nothing to the session
   already issued. The two are separate actions and the second was not possible until
   `v3-incident-response`.
4. **A leaked secret stays leaked.** `admin123` and the hardcoded `SESSION_SECRET` are in the
   git history permanently. Rotation is the only remedy, which is why it is a script and not
   a paragraph.
5. **The response needs its own audit trail.** Every `ir:*` mutation writes to
   `security_events`, so "who locked this account and under which incident" is answerable —
   and the table refuses to let the responder edit their own tracks.

### 4.3 Actions arising

| # | Action | Status |
|---|---|---|
| 1 | Build session revocation (T1 corrective) | **Done** — `ir/revoke-sessions.mjs` |
| 2 | Build secret rotation (T9 corrective) | **Done** — `ir/rotate-secrets.mjs` |
| 3 | Build forced credential reset (T5 corrective) | **Done** — `ir/force-reset.mjs` |
| 4 | Build append-only audit retention (T4 corrective) | **Done** — `ir/audit-log.mjs`, migration 003 |
| 5 | Write the response runbook | **Done** — `report/incident-runbook.md` (one page, six stages) |
| 6 | Regression-test every control | **Done** — `183 passed \| 1 skipped (184)` across 11 files |
| 7 | Log aggregation, alert thresholds, on-call rotation | **Not done** — out of scope for a localhost artefact; carried as a residual in runbook §6 |
| 8 | Self-service password reset over a verified channel | **Not done** — no mail path exists; `--complete` is a documented stand-in, not a reset flow |
| 9 | Upload size cap (other half of T8) | **Not done** — carried as a residual in Appendix A of `report/2021-1-84333CF_IFT542_report.md` |

### 4.4 Residual risk accepted

Carried forward deliberately and documented rather than hidden:

- **SSRF TOCTOU.** A DNS-rebinding window remains between our resolution and undici's connect.
- **Missing `Origin` is allowed**, so a non-browser client bypasses that layer; the CSRF token
  is the primary control and is not bypassable this way.
- **HSTS is inert** over plain HTTP on localhost.
- **One `next` advisory has no fix inside the 14.2 line.**
- **`--complete` is not a real password-reset flow** — see action 8.

---

*Prepared as coursework evidence for IFT542, Task 3 item 26. Declaration in
[`ETHICS.md`](../ETHICS.md).*
