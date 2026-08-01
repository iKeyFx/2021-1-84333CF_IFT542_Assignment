# Local test cases (app-only)

Everything here is **hard-wired to `http://127.0.0.1:3000`** and only exercises
*this* application. Nothing in this directory is a reusable attack tool.

## Automated suite (Vitest) — Tasks 2 and 3

```
npm run db:reset      # Postgres up + migrate + seed (Argon2id hashes)
npm test              # 183 passed | 1 skipped; starts a dev server itself if one isn't up
```

`npm test` reuses a dev server already listening on `127.0.0.1:3000`, and
otherwise spawns and tears one down itself — so it is a single command from
cold. It fails early with an actionable message if the database is not migrated.

### The four required proofs

| # | Required proof | Test file | Key assertion |
| --- | --- | --- | --- |
| 1 | **Valid login works** | `auth-login.test.ts` | `200`, `body.ok === true`, a `sid=<uuid>` cookie is issued (student *and* admin) |
| 2 | **Invalid credentials rejected** | `auth-login.test.ts` | `401` + `{"error":"Invalid email or password"}`, no cookie issued |
| 3 | **Injection string treated as DATA** | `sqli-parameterized.test.ts` | generic `401` *and* `` sql`… WHERE email = ${payload}` `` returns **0 rows**, no session created, tables intact |
| 4 | **Stored passwords are Argon2id, never plaintext** | `password-storage.test.ts` | every value `.startsWith("$argon2id$")`; no stored value equals or contains a known plaintext |

The two extra controls get a file each:

| Control | Test file | Key assertion |
| --- | --- | --- |
| Rate limiting | `rate-limit.test.ts` | 5 failures per IP per 60 s, then `429` + `Retry-After`; per-IP not global; even a *correct* password is refused once throttled |
| Session regeneration | `session-regeneration.test.ts` | a presented `sid` is replaced **and deleted** on login; malformed cookies do not 500 |

### Task 3 — the five deliverables

| # | Deliverable | Test file | Key assertion |
| --- | --- | --- | --- |
| 1 | **XSS neutralised by output encoding** | `xss-encoding.test.ts` | the payload is stored **verbatim in the DB** *and* served **escaped** on both pages — asserting only the escaped output would also pass if the app silently stripped input |
| 2 | **CSRF rejected** | `csrf.test.ts` | missing / tampered / other-session tokens and `Origin: null` all 403, each paired with a DB read proving the state did not change |
| 3 | **SSRF blocked** | `ssrf-guard.test.ts` | loopback, RFC1918, `169.254.169.254`, IPv4-mapped IPv6, `file://` and non-allowlisted hosts refused; blocked responses are **indistinguishable** from one another |
| 4 | **Security headers / config** | `security-headers.test.ts` | CSP with a per-request nonce that reaches Next's bootstrap scripts; no `unsafe-*` in the production policy; cookie has `HttpOnly; SameSite=Lax; Secure` |
| 5 | **Structured logging** | `logging.test.ts` | who/what/when on every event; deny-listed fields dropped even when passed explicitly |

### Full coverage per file

| File | Tests | Task | Proves |
| --- | --- | --- | --- |
| `auth-login.test.ts` | 19 | 2 | Valid student and admin logins work; wrong password, unknown email and every validation failure return one byte-identical generic 401; the retired `admin123` is rejected |
| `sqli-parameterized.test.ts` | 11 | 2 | Injection strings in the email field are bound as **data** — generic 401, no session issued, zero rows matched, database untouched, no `sql.unsafe` left in the handler |
| `password-storage.test.ts` | 13 | 2 | Stored passwords are `$argon2id$` PHC strings with per-row salts and the documented work factor; the plaintext column is gone; the CHECK constraint rejects plaintext |
| `rate-limit.test.ts` | 7 | 2 | 5 failures per IP per 60 s, then `429` + `Retry-After`; per-IP not global; success clears the bucket |
| `session-regeneration.test.ts` | 5 | 2 | A presented `sid` is destroyed and replaced on login (fixation closed); malformed cookies do not 500 |
| `xss-encoding.test.ts` | 9 | 3 | Five payloads stored verbatim and rendered inert on `/dashboard` and `/profile`; no executable attribute survives; input bounds are a resource limit, not a filter |
| `csrf.test.ts` | 18 | 3 | Token issuance and session binding; every protected POST rejects missing/tampered/foreign tokens and hostile Origins; `/api/login` is origin-checked but token-exempt |
| `security-headers.test.ts` | 14 | 3 | CSP, nonce propagation and per-request uniqueness; static headers on pages and `/api/*`; the session cookie's `HttpOnly; SameSite=Lax; Secure`; `buildCsp()` unit-tested for both dev and production |
| `ssrf-guard.test.ts` | 50 | 3 | The full IP-range matrix offline via an injected resolver, plus the live endpoint; includes the 172.16/12 boundary and IPv4-mapped IPv6 |
| `logging.test.ts` | 13 | 3 | Event shape, level mapping, email masking, and that secrets are dropped by the logger itself |
| `incident-response.test.ts` | 25 | 3 (item 26) | The four corrective controls, by running the actual `ir/` scripts: CLI safety contract, revocation (incl. the live 307 probe on a revoked cookie), forced reset proven not to be an oracle, and the append-only matrix |

**Total: 184 across 11 files — `183 passed | 1 skipped`.**

One test is skipped by default: the live-network SSRF success path, gated behind
`ALLOW_NETWORK_TESTS=1` so the suite stays green offline.

### Task 3, item 26 — the incident-response controls

`incident-response.test.ts` runs the real `ir/*.mjs` scripts with `spawnSync`
and asserts on exit code, stdout and database state. Re-implementing their logic
in the test would only prove the test agrees with itself; `npm run ir:*` is what
a responder types, so it is what has to work.

Two assertions carry most of the weight:

- **The forced reset is not an oracle.** A locked account presenting the
  *correct* password must return a reply byte-identical to a wrong password and
  to an account that does not exist — same status, same body, no `Set-Cookie`.
  Otherwise an attacker learns which stolen credentials are still live.
- **`DELETE` matching ZERO rows is still refused.** This is what distinguishes a
  statement-level trigger from a row-level one. A row-level `BEFORE DELETE`
  never fires when nothing matches, so without it the whole append-only control
  is bypassable with `WHERE id = -1` — and a test against an empty table would
  pass vacuously.

The file uses `nova.trainee@campus.local`, which no other file touches, and its
`--all` revocation runs **last** because it clears every session in the database.

### Source-address allocation

Test source IPs are spoofed via `X-Forwarded-For` from the IANA benchmarking
range `198.18.0.0/15`, so the rate limiter never makes the suite flaky and no
test-only backdoor endpoint is needed — adding a state-clearing route to a
security deliverable would itself be a vulnerability.

The allocator gives each **file** its own block and each **run** one of 256
address slices. The per-run entropy is load-bearing: it previously had only two
possible values, so two runs inside the limiter's 60 s window collided half the
time and `rate-limit.test.ts` — the one file that deliberately exhausts a
bucket — failed on roughly every other back-to-back `npm test`. See the comment
block in `helpers.ts`.

## Reproducing a specific vulnerability

The standalone v0 proof-of-concept scripts (`sqli-login.mjs`,
`enum-and-verbose.mjs`, `ssrf-demo.mjs`, `xss-payload.txt`, and
`evidence/task3/csrf-poc.html`) were **removed before submission**: the
coursework forbids submitting reusable attack payloads. Nothing was lost —
every assertion they made is covered by the Vitest suite, which additionally
checks database state after each rejection, something the scripts never did.

```
npm run db:reset      # Postgres up + migrate + seed
```

| Finding | Reproduce with | Asserts |
| --- | --- | --- |
| SQL-injection auth bypass on `/api/login` | `npx vitest run tests/sqli-parameterized.test.ts` | generic `401`, no session issued, the payload matches **0 rows**, tables intact |
| User enumeration + verbose DB/stack errors | `npx vitest run tests/auth-login.test.ts` | unknown-email and wrong-password bodies are byte-identical; body keys are `['error']` only |
| Stored XSS in the profile display name | `npx vitest run tests/xss-encoding.test.ts` | five payloads stored verbatim in the DB and served escaped on `/dashboard` and `/profile` |
| CSRF on the authenticated POSTs | `npx vitest run tests/csrf.test.ts` | missing / tampered / foreign tokens and `Origin: null` all `403`, each paired with a DB read |
| SSRF via the admin URL-preview | `npx vitest run tests/ssrf-guard.test.ts` | loopback, RFC1918, `169.254.169.254`, `file://` and non-allowlisted hosts refused, indistinguishably |

The incident-response commands are **not** PoCs — they are the response side.
See [`report/incident-runbook.md`](../report/incident-runbook.md):

```
npm run ir:status                 # read-only; safe at any time
npm run ir:audit-log -- --verify  # proves security_events is append-only
```

Before/after captures: `evidence/task2/run-output{,-after}.txt` (Tasks 1-2) and
`evidence/task3/run-output{,-after}.txt` (Task 3).
