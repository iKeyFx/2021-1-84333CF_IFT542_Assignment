# Local test cases (app-only)

Everything here is **hard-wired to `http://127.0.0.1:3000`** and only exercises
*this* application. Nothing in this directory is a reusable attack tool.

## Automated suite (Vitest) — Tasks 2 and 3

```
npm run db:reset      # Postgres up + migrate + seed (Argon2id hashes)
npm test              # 158 tests; starts a dev server itself if one isn't up
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
| `security-headers.test.ts` | 13 | 3 | CSP, nonce propagation and per-request uniqueness; static headers on pages and `/api/*`; `buildCsp()` unit-tested for both dev and production |
| `ssrf-guard.test.ts` | 50 | 3 | The full IP-range matrix offline via an injected resolver, plus the live endpoint; includes the 172.16/12 boundary and IPv4-mapped IPv6 |
| `logging.test.ts` | 13 | 3 | Event shape, level mapping, email masking, and that secrets are dropped by the logger itself |

One test is skipped by default: the live-network SSRF success path, gated behind
`ALLOW_NETWORK_TESTS=1` so the suite stays green offline.

Test source IPs are spoofed via `X-Forwarded-For` from the IANA benchmarking
range `198.18.0.0/15`, randomised per run, so the rate limiter never makes the
suite flaky and no test-only backdoor endpoint is needed.

## Manual proof-of-concept scripts

These are the original PoCs, kept as the "before" artefacts. Against the
hardened build they now demonstrate the *fix* — but `sqli-login.mjs` and
`enum-and-verbose.mjs` still print their v0 narration claiming the app is
vulnerable, so read the data they print, not their prose.

Two were edited in Task 3, and both edits are load-bearing:
`ssrf-demo.mjs` now fetches a CSRF token first (without it the request was
refused by the CSRF check *before* reaching the SSRF guard, so the script proved
the wrong thing) and reports `[SSRF BLOCKED]`; all of them set
`process.exitCode` instead of calling `process.exit()`, because on Windows
exiting while an undici socket is closing trips a libuv assertion and aborts
with 127, corrupting the captured output.

```
npm run db:reset      # Postgres up + migrate + seed
npm run dev           # app on http://127.0.0.1:3000
```

Then, in another terminal:

| Script | Demonstrates | Task | Against the hardened build |
| --- | --- | --- | --- |
| `node tests/sqli-login.mjs` | SQL-injection auth bypass on `/api/login` | 2 | exits 1 with `[NO BYPASS]` — the fix |
| `node tests/enum-and-verbose.mjs` | User enumeration + verbose DB/stack errors | 2 | identical replies, body keys `[ 'error' ]` — the fix |
| `node tests/ssrf-demo.mjs` | SSRF via admin URL-preview (server fetches loopback) | 3 | `[SSRF BLOCKED]` (exit 1) — the fix |
| `tests/xss-payload.txt` | Stored-XSS payloads for the profile display name (manual) | 3 | payloads render as literal text — the fix |

CSRF is demonstrated with `evidence/task3/csrf-poc.html` — open it in a browser
while logged in (see that file's comments). It now **fails** with a 403 and the
profile is unchanged, on three independent grounds: no token, `Origin: null`,
and `SameSite=Lax` on the session cookie.

Before/after captures: `evidence/task2/run-output{,-after}.txt` (Tasks 1-2) and
`evidence/task3/run-output{,-after}.txt` (Task 3).
