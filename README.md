# IFT542 — Student Registration (Deliberately-Vulnerable Build)

> ⚠️ **ISOLATED LOCALHOST TEACHING ARTEFACT.** This app *intentionally* contains common web
> vulnerabilities for a before/after coursework demonstration. **Do not deploy it, do not expose it
> to a network, and do not put real data in it.** All seeded data is fictitious. See `ETHICS.md`.

A prototype university Student Registration portal built with **Next.js 14 (App Router) +
TypeScript + Tailwind**, backed by **local PostgreSQL** (docker-compose) and **postgres.js**, with
**custom cookie-session auth** (no third-party provider). This is the *vulnerable* build; a hardened
build follows in a later session.

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

# 4. Start the dev server
npm run dev
# App: http://127.0.0.1:3000
```

Individual DB commands if you prefer:

```bash
npm run db:up        # start the Postgres container
npm run db:migrate   # run migrations + seed against a running DB
npm run db:down      # stop the container
```

## Dummy test accounts (fictitious)

| Role    | Email                        | Password       |
|---------|------------------------------|----------------|
| Student | `ada.learner@campus.local`   | `ada-pw-2025`  |
| Student | `grace.coder@campus.local`   | `grace-pw-2025`|
| Student | `nova.trainee@campus.local`  | `nova-pw-2025` |
| Admin   | `admin@campus.local`         | `admin123`     |

(Other students: `linus.pupil`, `mira.scholar`, `otto.student` — all `@campus.local`, password
`<first-name>-pw-2025`.)

## Project layout

```
src/app/            App Router pages + /api route handlers
src/lib/            db, config, session, auth helpers
db/                 migrations/ + seed.sql + migrate.mjs runner
tests/              local, app-only PoC scripts (SQLi, enum/verbose, SSRF, XSS payloads)
evidence/task1..3/  what to capture per task (+ csrf-poc.html)
report/             threat-model.md (vuln register + OWASP mapping)
uploads/            runtime file storage (gitignored)
```

## Planted vulnerabilities

Each is tagged in source with `// [VULN: <name> — <Task>]`. The full register (with file:line and
OWASP mapping) is in [`report/threat-model.md`](report/threat-model.md). Reproduction steps are in
[`tests/README.md`](tests/README.md) and `evidence/task{1,2,3}/README.md`.

## Reset / teardown

```bash
npm run db:reset     # wipe + re-migrate + re-seed
npm run db:down      # stop Postgres
```
