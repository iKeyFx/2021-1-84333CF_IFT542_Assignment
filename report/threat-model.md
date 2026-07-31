# IFT542 — Threat Model (companion notes)

> **Primary document:** [`report/task1-threat-model.md`](task1-threat-model.md) is the authoritative
> threat model for Task 1 — it holds the data-flow diagram, the **STRIDE worksheet**, the **risk
> register**, and the top-three justification. This file is a companion only.
>
> The **OWASP Top-10 (2021) mapping** that used to live here has been folded into that document as
> **Appendix A**, cross-referenced to the STRIDE threat IDs (T1–T9) and risk ranks, so the two
> documents agree and there is a single source of truth for each view.

**Artefact:** Student Registration web app (Next.js 14 App Router + TypeScript + Postgres).
**Status:** *Fully hardened (Tasks 2 and 3).* All planted findings are remediated. Tag
`v0-vulnerable` is the untouched "before" build; `v1-hardened-task2` is the authentication pass;
`v2-hardened-task3` is the application/configuration pass.
**Scope:** Isolated localhost, fictitious data. See `ETHICS.md`.

Remediated sinks are tagged in source with `// [FIXED — Task N: <name>]`. For the full
vulnerability register with file:line, STRIDE ID, risk rank, and OWASP category, see **Appendix A**
of the primary document; for what Task 2 changed see **Appendix B**, and for Task 3 **Appendix C**.

## Delivered — Task 2

| Threat | Control implemented | Where |
| --- | --- | --- |
| **T1 / SQL injection** | Parameterized postgres.js tagged template — `WHERE p.email = ${input.email}` sent as an extended query with a `$1` placeholder. `sql.unsafe` and string concatenation removed from the handler, along with the second injectable email-only lookup. | `src/app/api/login/route.ts` |
| **T5 / plaintext passwords** | Argon2id (m=19456 KiB, t=2, p=1, 32-byte digest, per-row random salt), OWASP Password Storage minimum. Login fetches the account by email, then verifies with `argon2.verify()`. Plaintext column dropped; a CHECK constraint enforces the `$argon2id$` format at the database level. | `src/lib/password.ts`, `db/hash-passwords.mjs`, `db/migrations/002_argon2id_password_hash.sql` |
| **T7 / verbose errors** | Driver messages, stack traces and the raw query are logged server-side only. The client receives a fixed string; the login page no longer renders `stack`/`query`. | `src/app/api/login/route.ts`, `src/app/login/page.tsx` |
| **T7 / user enumeration** | One generic `401 {"error":"Invalid email or password"}` for every failure mode. Unknown-email and wrong-password replies are byte-identical, and both perform one Argon2id verification (against a memoised decoy digest when the account does not exist) so **timing** is not an oracle either. | `src/app/api/login/route.ts`, `src/lib/password.ts` |
| **T8 / rate limiting** | Per-IP fixed window: 5 failed attempts / 60 s, then `429` with `Retry-After`. Checked before any DB or hashing work. Failures only are counted and success clears the bucket. | `src/lib/rate-limit.ts` |
| **T9 / session fixation** | A fresh `randomUUID()` session id is minted on every successful login and the presented id is **deleted**, so a fixed session cannot cross the authentication boundary. | `src/lib/session.ts` |
| *(supporting)* | Input validation — email format and length bounds (3–254), password length bounds (8–128, a pre-hash DoS cap), and rejection of non-string values rather than `String()` coercion. | `src/lib/validate.ts` |

Verified by the automated suite (`npm test`, see `tests/README.md`) and captured in
`evidence/task2/run-output-after.txt`.

### Residual weaknesses, stated honestly

- **Fixed window, not sliding** — an attacker can burst up to 2× the limit across a window
  boundary. A sliding log or token bucket removes this.
- **In-memory limiter state** — per-process and lost on restart; a real deployment needs a shared
  store (e.g. Redis) so the limit survives restarts and holds across instances.
- **`X-Forwarded-For` is trusted** for the client IP because `next dev` sits behind no proxy. This
  is acceptable only for a localhost artefact; behind a real proxy the header must be taken solely
  from a known trusted hop.
- **Per-IP only, not per-account.** Per-account bucketing was deliberately not added: it is itself
  a lockout-denial-of-service vector against a known user. OWASP recommends both, with care.
- **Timing is equalised, not constant.** The decoy hash removes the ~30 ms Argon2 step function;
  a sub-millisecond difference in the database round trip (0 rows vs 1 row) remains.

## Delivered — Task 3

| Threat | Control implemented | Where |
| --- | --- | --- |
| **T3 / stored XSS** | Contextual output encoding: both `dangerouslySetInnerHTML` sinks now render `{user.display_name}` as a text node, so a stored payload is displayed literally. The payload is deliberately still stored VERBATIM — encoding at output is the control; input filtering would be the weaker half and would hide that the value survives intact. Backed by a nonce-based CSP. | `src/app/dashboard/page.tsx`, `src/app/profile/page.tsx`, `src/lib/security-headers.ts` |
| **T2 / CSRF** | Signed double-submit token: `<id>.HMAC-SHA256(SESSION_SECRET, id)` bound to the **session id**, so it rotates at the authentication boundary and cannot be forged by an attacker who can write but not read cookies (the sid is `HttpOnly`). Enforced on all seven authenticated POSTs. `/api/login` gets the Origin check only, being pre-session. | `src/lib/csrf.ts`, `src/app/_components/CsrfField.tsx`, all `src/app/api/*` handlers |
| **T2 / cookie flags** | Session cookie now `HttpOnly; SameSite=Lax; Secure`. Lax rather than Strict so inbound links do not appear logged-out; Lax already blocks the cross-site POST that CSRF needs. | `src/lib/session.ts` |
| **T6 / SSRF** | Scheme allowlist (http/https), destination **host allowlist**, DNS resolution with rejection of loopback / RFC1918 / link-local (incl. `169.254.169.254`) / reserved / IPv4-mapped-IPv6 addresses, manual redirect handling that re-validates **every hop**, 5 s timeout, 64 KB body cap. Blocked responses are byte-identical so the reason is not an internal-network oracle. | `src/lib/url-guard.ts`, `src/app/api/admin/url-preview/route.ts` |
| **T7 / T9 misconfiguration** | `DEBUG` fail-closed (`=== "true"`, was fail-open); `SESSION_SECRET` required in production and now genuinely load-bearing as the CSRF HMAC key; dead `DEFAULT_ADMIN` deleted; default admin password rotated off `admin123` to `ADMIN_PASSWORD` env with a strong fallback; `productionBrowserSourceMaps: false`; full security-header set. | `src/lib/config.ts`, `next.config.js`, `src/middleware.ts`, `db/hash-passwords.mjs` |
| **T4 / repudiation** | Structured JSON-lines security logging answering who/what/when, with three required event types: `auth.login.failed`, `authz.denied`, `validation.rejected` (plus `csrf.rejected` and `ssrf.blocked`). Redaction is enforced **inside** the logger — emails masked, and a deny-list drops password/hash/token/session/secret fields even if a caller passes them. | `src/lib/logger.ts`, `src/lib/auth.ts` |

The `authz.denied` seam is worth noting: `currentAdmin()` previously returned `null` for both
"anonymous" and "authenticated but not an admin", collapsing exactly the case worth alerting on. It
now distinguishes them.

### Residual weaknesses, stated honestly

- **SSRF TOCTOU / DNS rebinding.** A name can re-resolve between our `lookup()` and undici's
  `connect()`. Closing it needs a custom undici `Agent` whose connect hook pins the validated IP.
  Not implemented; disclosed.
- **Origin check allows a MISSING Origin.** Non-browser clients send none, and the Task 2 PoC
  scripts depend on that. Browsers always send one cross-site, so the check still works where it
  matters — but it is a secondary control behind the token, not a primary one.
- **HSTS is inert on localhost.** Browsers ignore it over plain HTTP. Emitted in production for
  completeness; it would only take effect behind TLS.
- **The development CSP is not the production CSP.** `next dev` needs `'unsafe-eval'` (webpack HMR)
  and inline styles. The strict policy applies to `next build && next start`, which is where the
  evidence was captured.
- **One `next` advisory remains** with no fix inside the 14.2 line (`npm audit fix --force` would
  install Next 16, a breaking major). Recorded rather than hidden.
- **`X-Forwarded-For` is trusted** for the client IP in rate limiting and log lines. Acceptable
  only because this is a localhost artefact; behind a real proxy it must come from a trusted hop.
- **Upload size cap still absent** — the other half of T8. Out of scope for Task 3's five
  deliverables, so T8's residual is not yet fully realised.

## Delivered — Task 3, item 26 (corrective controls)

The register in the primary document marks four controls **(C) corrective**. Tasks 2 and 3
delivered the preventive and detective controls; these four were promised and never built. A
corrective control is the one you need *after* prevention has already failed — as it had.

| Threat | Promised | Delivered | Enforced at |
|---|---|---|---|
| **T1** | `session revocation + runbook (C)` | `ir/revoke-sessions.mjs`, `report/response-runbook.md` | `DELETE FROM sessions`; `src/lib/auth.ts` re-checks every request, so removal is immediate |
| **T9** | `invalidate sessions on leak (C)` | `ir/rotate-secrets.mjs` | Argon2id re-hash + a new `SESSION_SECRET`, which also invalidates every outstanding CSRF token |
| **T5** | `forced reset on suspected breach (C)` | `ir/force-reset.mjs`, `credential_resets` | `src/app/api/login/route.ts` — `LEFT JOIN`, folded into the existing failure branch |
| **T4** | `append-only retention (C)` | `security_events`, `ir/audit-log.mjs` | `db/migrations/003_incident_response.sql` — statement-level triggers raising `42501` |

Two design points carry the weight:

- **The lock is checked after `verifyPassword()`, not before.** One Argon2id operation has already
  run on every path, and the response is byte-identical to a wrong password and to an unknown
  account. Checking earlier would be faster for locked accounts and would hand back the
  enumeration oracle T7 was closed to remove.
- **The triggers are `FOR EACH STATEMENT`.** A row-level `BEFORE DELETE` never fires on zero
  matching rows, so `DELETE ... WHERE id = -1` would succeed silently and any test asserting
  "DELETE is refused" against an empty table would pass vacuously.

Full detail, including honest limitations, is in **Appendix D** of the primary document and in
`report/incident-record.md`.

### Residual after item 26

- **`--complete` is not a password-reset flow.** It restores the demo password so the exercise
  repeats. A real system issues a single-use, time-limited, signed token over a verified channel.
- **`--ingest` is a stand-in log shipper.** The app emits JSON Lines to stdout and never writes to
  the database — `src/lib/logger.ts` must stay edge-safe because middleware imports it.
- **Append-only is enforced inside the database it protects.** A full database compromise could
  drop the trigger; real tamper-evidence needs an independent off-host sink.
- **No alerting.** Events are emitted and can be ingested, but nothing watches them.

## Reproduction

See `tests/README.md` and `evidence/task{1,2,3}/README.md`. Response procedures are in
`report/response-runbook.md`; every command there has been executed and its real output pasted.
