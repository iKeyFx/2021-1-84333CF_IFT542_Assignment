# IFT542 — Threat Model (companion notes)

> **Primary document:** [`report/task1-threat-model.md`](task1-threat-model.md) is the authoritative
> threat model for Task 1 — it holds the data-flow diagram, the **STRIDE worksheet**, the **risk
> register**, and the top-three justification. This file is a companion only.
>
> The **OWASP Top-10 (2021) mapping** that used to live here has been folded into that document as
> **Appendix A**, cross-referenced to the STRIDE threat IDs (T1–T9) and risk ranks, so the two
> documents agree and there is a single source of truth for each view.

**Artefact:** Student Registration web app (Next.js 14 App Router + TypeScript + Postgres).
**Status:** *Task 2 hardened.* Authentication and database access are remediated; the Task 3
findings remain planted. Tag `v0-vulnerable` is the untouched "before" build.
**Scope:** Isolated localhost, fictitious data. See `ETHICS.md`.

Remaining sinks are tagged in source with `// [VULN: <name> — <Task>]`; remediated ones with
`// [FIXED — Task 2: <name>]`. For the full vulnerability register with file:line, STRIDE ID, risk
rank, and OWASP category, see **Appendix A** of the primary document; for what Task 2 changed, see
**Appendix B**.

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

Verified by 54 automated tests (`npm test`, see `tests/README.md`) and captured in
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

## Planned hardening (Task 3 — not done)

- **T3 / stored XSS:** render `display_name` as text (`{value}`) / sanitise on input; add a CSP.
- **T2 / CSRF:** per-session CSRF token on forms + verify; set `SameSite=Lax` (and `Secure` over HTTPS).
- **T6 / SSRF:** allowlist schemes/hosts; resolve and block loopback/link-local/private IPs; disable
  redirects; re-check after DNS resolution.
- **T9 / config:** load the session secret from env and fail closed if absent; remove/rotate the
  default admin account; turn `DEBUG` off outside development.

> The session cookie's missing `SameSite`/`Secure` and the `admin@campus.local` / `admin123`
> account were left **intentionally untouched** by the Task 2 work — they belong to Task 3 and its
> CSRF proof-of-concept depends on them.

## Reproduction

See `tests/README.md` and `evidence/task{1,2,3}/README.md`.
