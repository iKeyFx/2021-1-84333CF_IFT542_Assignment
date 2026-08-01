# Incident-Response Runbook — Student Registration Portal

> **Scope.** The IFT542 Student Registration teaching artefact on `http://127.0.0.1:3000`, backed
> by a local docker-compose PostgreSQL instance. Localhost only, fictitious data only — see
> [`ETHICS.md`](../ETHICS.md).
>
> One page, six stages. The worked example against a simulated intrusion is
> [`incident-record.md`](incident-record.md); the real output of every command below is
> `evidence/task3/run-output-after.txt` §7–§9.

## 1. Preparation

Five response commands are installed and tested ahead of time — `ir:status`, `ir:revoke-sessions`,
`ir:force-reset`, `ir:rotate-secrets` and `ir:audit-log` — each defaulting to a dry run and
refusing to mutate anything without both `--yes` and `--incident <id>`. The application emits
structured JSON Lines to stdout from `src/lib/logger.ts`, with emails masked and secret-shaped
fields dropped at source, and `security_events` in Postgres is append-only under statement-level
triggers that refuse UPDATE, DELETE and TRUNCATE with SQLSTATE `42501`. Demo credentials, the
`SESSION_SECRET` handling and the database connection string are documented in `README.md` and
`.env.example` so a responder does not have to reverse-engineer them mid-incident. Verify the
whole chain is healthy with `npm run ir:audit-log -- --verify` before you need it.

## 2. Identification

Watch the server's stdout for the eight event names the app actually emits; `auth.login.blocked`
(a correct password presented to a locked account), `ssrf.blocked` and `csrf.rejected` each
warrant investigation on a single occurrence, while `auth.login.failed` and `auth.login.throttled`
matter in volume — many for one IP, or one IP across many accounts, indicates credential stuffing.
Run `npm run ir:status` first: it is read-only, takes no scope and needs no confirmation, so you
can see live sessions, locked accounts and audit health without committing to any change. Classify
severity 1–4 (authentication bypass or admin compromise is severity 1) and record the incident id
now, because every subsequent command requires it. Record the `ir:status` output *before* touching
anything — `npm run db:reset` would destroy sessions and application state, and only
`security_events` survives it.

## 3. Containment

Revoke sessions first: `npm run ir:revoke-sessions -- --all --incident <id> --yes`. This is the
step that actually ends the attacker's access, because patching the vulnerability does nothing to
a session already issued — in `INC-2026-001` the injected session stayed valid for a further 24
hours after the query was parameterised. If credentials were disclosed, lock the accounts with
`npm run ir:force-reset -- --require --all --incident <id> --yes`, which also revokes those
accounts' sessions; a lock that leaves live sessions authenticated is theatre. Scope down to
`--email` or `--role` once the blast radius is known, and confirm containment by replaying a
revoked `sid` cookie against `/dashboard` — it must return `307 → /login`, not `200`.

## 4. Eradication

Rotate every exposed secret with `npm run ir:rotate-secrets -- --all --incident <id> --yes`, which
issues new passwords and a new `SESSION_SECRET`. Rotation is the only remedy for anything already
in the git history — `admin123` and the hardcoded secret are permanently present at
`v0-vulnerable` and cannot be un-published. Because a CSRF token is
`<sid>.HMAC-SHA256(SESSION_SECRET, sid)`, rotating the secret invalidates every outstanding CSRF
token at the same time. Place the new `SESSION_SECRET` in `.env` by hand and restart the server:
the script deliberately does not write the file, since the process reads the key once at start and
would otherwise keep running on the old one while every CSRF check silently failed.

## 5. Recovery

Restore service with `npm run ir:force-reset -- --complete --all --incident <id> --yes`, then
confirm the old credential is refused (`401`) and the new one succeeds (`200`). Re-run the full
regression suite — `npm test` must report `183 passed | 1 skipped (184)` across 11 files — and
`npm run ir:audit-log -- --verify` to confirm all 7 append-only checks still pass. Then run
`npm run ir:status` a final time and confirm live sessions are `TOTAL: 0` and no account remains
unintentionally locked. Note honestly that `--complete` is **not** a real password-reset flow: it
restores the documented demo password so the exercise repeats, where a real deployment would issue
a single-use signed token over a verified channel.

## 6. Lessons Learned

Write the incident up in [`incident-record.md`](incident-record.md) with a timeline, the findings
register mapped to threat-model IDs, and the tag that closed each one. `INC-2026-001` produced the
central lesson recorded there: containment and remediation are different actions, and the risk
register's four *corrective* controls existed only on paper until this exercise turned them into
runnable commands. Feed residual gaps back into the register rather than hiding them — this
artefact still has no alerting, no off-host log sink, no multi-person authorisation, and its
append-only trigger lives inside the database it protects. Review this runbook after every
incident and re-execute each command against the current build, because a runbook containing an
untested command is worse than no runbook.
