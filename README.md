# IFT542 — Student Registration (Hardened Build)

> ⚠️ **ISOLATED LOCALHOST TEACHING ARTEFACT.** This app began as a deliberately-vulnerable
> build for a before/after coursework demonstration. **Do not deploy it, do not expose it to a
> network, and do not put real data in it.** All seeded data is fictitious. See `ETHICS.md`.

A prototype university Student Registration portal built with **Next.js 14 (App Router) +
TypeScript + Tailwind**, backed by **local PostgreSQL** (docker-compose) and **postgres.js**, with
**custom cookie-session auth** (no third-party provider).

**Build status:** **all planted defects are remediated.** Task 2 fixed the authentication and
database findings; Task 3 fixed the application and configuration findings and added security
logging. Tags: `v0-vulnerable` (untouched baseline) → `v1-hardened-task2` → `v2-hardened-task3`.

## Features

1. Student login (email + password)
2. Student profile update (display name, bio)
3. Course registration (enrol in a course)
4. Document upload (stored to local disk under `./uploads`)
5. Admin: manage courses (create / edit / delete)
6. Admin: manage enrolments (view / remove)

## Prerequisites

- Node.js 18+ (developed on Node 24)
- Docker + Docker Compose (for local Postgres)

`psql` is **not** required — migrations and seeding run through a Node script (`db/migrate.mjs`)
using postgres.js.

## Quick start

```bash
# 1. Install dependencies
npm install

# 2. (optional) create your local env file
cp .env.example .env            # Windows PowerShell: Copy-Item .env.example .env

# 3. Start Postgres (bound to 127.0.0.1 only), then migrate + seed.
#    db:reset does: docker compose up -d  ->  wait for DB  ->  migrate + seed
npm run db:reset

# 4. Start the dev server (bound to 127.0.0.1 only)
npm run dev
# App: http://127.0.0.1:3000

# 5. Run the Task 2 hardening tests (starts a server itself if one isn't up)
npm test
```

Individual DB commands if you prefer:

```bash
npm run db:up            # start the Postgres container
npm run db:migrate       # run migrations + seed against a running DB
npm run db:down          # stop the container
npm run db:reset:legacy  # stage v0 PLAINTEXT credentials, then re-hash them
                         # to Argon2id — demonstrates the migration end to end
```

## Dummy test accounts (fictitious)

| Role    | Email                        | Password       |
|---------|------------------------------|----------------|
| Student | `ada.learner@campus.local`   | `ada-pw-2025`  |
| Student | `grace.coder@campus.local`   | `grace-pw-2025`|
| Student | `nova.trainee@campus.local`  | `nova-pw-2025` |
| Admin   | `admin@campus.local`         | see note below |

(Other students: `linus.pupil`, `mira.scholar`, `otto.student` — all `@campus.local`, password
`<first-name>-pw-2025`.)

The student passwords are unchanged, but they are **no longer stored as plaintext** — the database
holds Argon2id digests (`$argon2id$v=19$m=19456,p=1,t=2$…`). The plaintext values live only in
`db/hash-passwords.mjs` (`demoPasswords()`), which hashes them at seed time.

**The admin password was rotated in Task 3.** It is no longer `admin123`; it comes from the
`ADMIN_PASSWORD` environment variable, falling back to `Adm1n-Str0ng-Dummy-2026-x7QF`.

## Hardened — Task 2

The six planted authentication defects are fixed. Diff the login handler against the baseline with
`git diff v0-vulnerable -- src/app/api/login/route.ts`.

| Control | Where |
| --- | --- |
| **Parameterized query** — postgres.js tagged template; `sql.unsafe` and string concatenation removed, so input binds as `$1` data | `src/app/api/login/route.ts` |
| **Argon2id hashing** — OWASP minimum (m=19 MiB, t=2, p=1), per-row random salt; login fetches by email then calls `argon2.verify()` | `src/lib/password.ts`, `db/hash-passwords.mjs`, `db/migrations/002_argon2id_password_hash.sql` |
| **Input validation** — email format + length bounds, password length bounds, no type coercion | `src/lib/validate.ts` |
| **Single generic error** — every failure returns `401 {"error":"Invalid email or password"}`; driver messages, stack traces and raw SQL are logged server-side only | `src/app/api/login/route.ts`, `src/app/login/page.tsx` |
| **Rate limiting** — 5 failed attempts per IP per 60 s, then `429` + `Retry-After`; failures only, cleared on success, checked before any DB or hashing work | `src/lib/rate-limit.ts` |
| **Session-id regeneration** — a fresh UUID on every login; the presented id is deleted, closing session fixation | `src/lib/session.ts` |

Timing was equalised as well: an unknown email still costs one Argon2id verification against a
decoy digest, so response time is not an enumeration oracle either.

`credentials` now enforces the fix at the database level:

```sql
password_hash TEXT NOT NULL
CONSTRAINT credentials_password_hash_argon2id CHECK (password_hash LIKE '$argon2id$%')
```

New dependencies: `argon2` (runtime), `vitest` (dev). Evidence:
[`evidence/task2/run-output-after.txt`](evidence/task2/run-output-after.txt).

## Hardened — Task 3

The remaining application and configuration findings. Diff with
`git diff v1-hardened-task2 v2-hardened-task3`.

| Control | Where |
| --- | --- |
| **Contextual output encoding** — both `dangerouslySetInnerHTML` sinks render `{user.display_name}` as a text node. The payload is still stored verbatim and rendered inert; input filtering is deliberately not used. | `src/app/dashboard/page.tsx`, `src/app/profile/page.tsx` |
| **Content-Security-Policy** with a per-request nonce — strict in production (no `unsafe-inline`, no `unsafe-eval`), relaxed in dev only for webpack HMR. Plus HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`. | `src/lib/security-headers.ts`, `src/middleware.ts`, `next.config.js` |
| **Anti-CSRF tokens** — signed double-submit, `<id>.HMAC-SHA256(SESSION_SECRET, id)` bound to the session id, on all 7 authenticated POSTs. Plus an Origin/Referer check. | `src/lib/csrf.ts`, `src/app/_components/CsrfField.tsx` |
| **Session cookie** — `HttpOnly; SameSite=Lax; Secure`. | `src/lib/session.ts` |
| **SSRF guard** — scheme + host allowlist, DNS resolution with loopback/private/link-local/metadata rejection, per-hop redirect re-validation, 5 s timeout, 64 KB cap. | `src/lib/url-guard.ts` |
| **Fail-closed config** — `DEBUG` opt-in, `SESSION_SECRET` required in production (and now load-bearing as the CSRF key), `DEFAULT_ADMIN` deleted, `productionBrowserSourceMaps: false`. | `src/lib/config.ts`, `next.config.js` |
| **Default admin rotated** off `admin123` to `ADMIN_PASSWORD` with a strong fallback. | `db/hash-passwords.mjs` |
| **Structured security logging** — JSON lines with who/what/when; emails masked and secret-shaped fields dropped inside the logger. | `src/lib/logger.ts`, `src/lib/auth.ts` |

Evidence: [`evidence/task3/run-output-after.txt`](evidence/task3/run-output-after.txt).

### Known residuals (documented, not hidden)

- SSRF TOCTOU: a DNS-rebinding window remains between our lookup and undici's connect.
- The Origin check allows a *missing* Origin, so non-browser clients bypass that layer — the token
  is the primary control.
- HSTS is inert over plain HTTP on localhost.
- One `next` advisory has no fix inside the 14.2 line (`npm audit fix --force` would install Next 16).
- The upload size cap (the other half of T8) is not implemented.

## Project layout

```
src/app/            App Router pages + /api route handlers
src/lib/            db, config, session, auth, password, validate, rate-limit helpers
db/                 migrations/ + seed.sql + hash-passwords.mjs + migrate.mjs runner
tests/              Vitest suite (*.test.ts) + the v0 PoC scripts (*.mjs)
evidence/task1..3/  what to capture per task (+ csrf-poc.html)
report/             threat model, risk register, OWASP mapping, remediation status
uploads/            runtime file storage (gitignored)
```

## Vulnerability register

Remaining issues are tagged in source with `// [VULN: <name> — <Task>]`; remediated ones with
`// [FIXED — Task 2: <name>]`. The full register (with file:line and OWASP mapping) is in
[`report/task1-threat-model.md`](report/task1-threat-model.md) — Appendix A for the OWASP mapping,
Appendix B for Task 2 remediation status. Reproduction steps are in
[`tests/README.md`](tests/README.md) and `evidence/task{1,2,3}/README.md`.

## Reset / teardown

```bash
npm run db:reset     # wipe + re-migrate + re-seed
npm run db:down      # stop Postgres
```
