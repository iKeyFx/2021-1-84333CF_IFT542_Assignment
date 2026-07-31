# Local test cases (app-only)

Everything here is **hard-wired to `http://127.0.0.1:3000`** and only exercises
*this* application. Nothing in this directory is a reusable attack tool.

## Automated suite (Vitest) — Task 2 hardening

```
npm run db:reset      # Postgres up + migrate + seed (Argon2id hashes)
npm test              # 54 tests; starts a dev server itself if one isn't up
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

### Full coverage per file

| File | Tests | Proves |
| --- | --- | --- |
| `auth-login.test.ts` | 16 | Valid student and admin logins work; wrong password, unknown email and every validation failure return one byte-identical generic 401; no stack/query/hash ever reaches the client |
| `sqli-parameterized.test.ts` | 11 | Injection strings in the email field are bound as **data** — generic 401, no session issued, zero rows matched, database untouched, no `sql.unsafe` left in the handler |
| `password-storage.test.ts` | 13 | Stored passwords are `$argon2id$` PHC strings with per-row salts and the documented work factor; the plaintext column is gone; the CHECK constraint rejects plaintext |
| `rate-limit.test.ts` | 7 | 5 failures per IP per 60 s, then `429` + `Retry-After`; per-IP not global; success clears the bucket |
| `session-regeneration.test.ts` | 5 | A presented `sid` is destroyed and replaced on login (fixation closed); malformed cookies do not 500 |

Test source IPs are spoofed via `X-Forwarded-For` from the IANA benchmarking
range `198.18.0.0/15`, randomised per run, so the rate limiter never makes the
suite flaky and no test-only backdoor endpoint is needed.

## Manual proof-of-concept scripts

These are the **unchanged `v0-vulnerable` PoCs**, kept verbatim as the "before"
artefacts. Against the hardened build they now demonstrate the *fix* — but their
printed narration still claims the app is vulnerable, so read the data they
print, not their prose.

```
npm run db:reset      # Postgres up + migrate + seed
npm run dev           # app on http://127.0.0.1:3000
```

Then, in another terminal:

| Script | Demonstrates | Task | Against the hardened build |
| --- | --- | --- | --- |
| `node tests/sqli-login.mjs` | SQL-injection auth bypass on `/api/login` | 2 | exits 1 with `[NO BYPASS]` — the fix |
| `node tests/enum-and-verbose.mjs` | User enumeration + verbose DB/stack errors | 2 | identical replies, body keys `[ 'error' ]` — the fix |
| `node tests/ssrf-demo.mjs` | SSRF via admin URL-preview (server fetches loopback) | 3 | still `[SSRF CONFIRMED]` — Task 3 is out of scope |
| `tests/xss-payload.txt` | Stored-XSS payloads for the profile display name (manual) | 3 | still vulnerable |

CSRF is demonstrated with `evidence/task3/csrf-poc.html` — open it in a browser
while logged in (see that file's comments). It still fires: the session cookie
deliberately keeps its Task 3 flags.

Before/after captures are in `evidence/task2/run-output.txt` and
`evidence/task2/run-output-after.txt`.
