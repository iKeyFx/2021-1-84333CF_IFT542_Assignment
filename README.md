# IFT542 — Student Registration (Hardened Build)

> ⚠️ **ISOLATED LOCALHOST TEACHING ARTEFACT.** This app began as a deliberately-vulnerable build
> for a before/after coursework demonstration. It is not deployed, not exposed to any network, and
> holds no real data. All seeded data is fictitious. See `ETHICS.md`.

A prototype university Student Registration portal — **Next.js 14 (App Router) + TypeScript +
Tailwind**, backed by **local PostgreSQL** (docker-compose) and **postgres.js**, with **custom
cookie-session auth**. Six features: student login, profile update, course registration, document
upload, admin course management, admin enrolment management.

Thirteen vulnerabilities were planted in the baseline, modelled with STRIDE in Task 1, and closed
across Tasks 2 and 3. **All thirteen are remediated.** The submitted build is tag
`v4-browser-fixes`; every earlier tag is broken in a real browser, because `Referrer-Policy:
no-referrer` made browsers send `Origin: null` on plain form POSTs, which the CSRF Origin check
correctly rejected.

| Artefact | Location |
|---|---|
| Consolidated report | `report/2021-1-84333CF_IFT542_report.md` — Tasks 1–3 plus Appendices A–D |
| Exported report | `2021-1-84333CF_IFT542.pdf` |
| Screenshots and transcripts | `evidence/task1/`, `evidence/task2/`, `evidence/task3/` |
| Incident record and runbook | `report/incident-record.md`, `report/incident-runbook.md` |
| Ethics declaration | `ETHICS.md` |

## Prerequisites

- Node.js 18+ (developed on Node 24)
- Docker + Docker Compose, for the local Postgres container

`psql` is not needed — migrations and seeding run through `db/migrate.mjs` using postgres.js.

## Setup and run

```bash
npm install
cp .env.example .env      # Windows PowerShell: Copy-Item .env.example .env
npm run db:reset          # docker compose up -d -> wait for DB -> migrate + seed
npm run dev               # http://127.0.0.1:3000
```

Other commands:

```bash
npm run build && npm start   # production build (the strict CSP applies only here)
npm run db:up                # start the Postgres container
npm run db:migrate           # migrate + seed against a running DB
npm run db:reset:legacy      # stage the v0 plaintext credentials, then re-hash to Argon2id
npm run db:down              # stop the container
npm run ir:status            # read-only: live sessions, locked accounts, audit health
```

The five `ir:*` incident-response commands (`ir:status`, `ir:revoke-sessions`, `ir:force-reset`,
`ir:rotate-secrets`, `ir:audit-log`) default to a dry run; `--yes` plus `--incident <id>` and
exactly one scope are required before any of them changes anything.
`report/incident-runbook.md` is the six-stage procedure they serve.

## Test accounts (fictitious)

Every account is invented and uses the non-routable `@campus.local` domain.

| Role | Email | Password |
|---|---|---|
| Student | `ada.learner@campus.local` | `ada-pw-2025` |
| Student | `grace.coder@campus.local` | `grace-pw-2025` |
| Student | `nova.trainee@campus.local` | `nova-pw-2025` |
| Admin | `admin@campus.local` | `ADMIN_PASSWORD`, falling back to `Adm1n-Str0ng-Dummy-2026-x7QF` |

Other students follow the same pattern: `linus.pupil`, `mira.scholar` and `otto.student`, all
`@campus.local` with the password `<first-name>-pw-2025`.

These passwords are dummy values. The database stores only Argon2id digests
(`$argon2id$v=19$m=19456,p=1,t=2$…`); the plaintext exists solely in `db/hash-passwords.mjs`,
which hashes it at seed time. The admin password was rotated off `admin123` in Task 3 —
`admin123` now returns `401`.

## Tests

```bash
npm run db:reset     # the suite needs a migrated database
npm test             # 183 passed | 1 skipped (184) across 11 files
```

`npm test` reuses a dev server already listening on `127.0.0.1:3000` and otherwise starts and tears
one down itself, so it runs from cold as a single command. The one skip is the live-network SSRF
success path, gated behind `ALLOW_NETWORK_TESTS=1` so the suite stays green offline. Individual
files run with `npx vitest run tests/<file>.test.ts`; the full inventory is Appendix B of the
report.

## Export the report to PDF

```bash
npm run report:pdf
```

That renders `report/2021-1-84333CF_IFT542_report.md` and places the result at the repository root
as `2021-1-84333CF_IFT542.pdf`.

## Build the submission archive

```bash
git archive --format=zip -o 2021-1-84333CF_IFT542.zip HEAD
```

Tracked files only — no `node_modules`, `.next`, logs or `.env`.

## Project layout

```
src/app/            App Router pages + /api route handlers
src/lib/            db, config, session, auth, password, validate, rate-limit,
                    csrf, url-guard, security-headers, logger
db/                 migrations/ + seed.sql + hash-passwords.mjs + migrate.mjs runner
ir/                 incident-response commands (npm run ir:*)
tests/              Vitest suite (*.test.ts) — defensive regression tests only
evidence/task1..3/  screenshots and recorded transcripts, one README per task
report/             consolidated report, incident record, incident runbook
uploads/            runtime file storage (gitignored)
```

Remediated defects are tagged in source with `// [FIXED — Task 2: <name>]` or
`// [FIXED — Task 3: <name>]`. The full register, OWASP mapping, per-finding remediation status and
accepted residual risks are in Appendix A of `report/2021-1-84333CF_IFT542_report.md`.
