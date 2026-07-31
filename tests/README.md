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

| File | Proves |
| --- | --- |
| `auth-login.test.ts` | Valid student and admin logins work; wrong password, unknown email and every validation failure return one byte-identical generic 401; no stack/query/hash ever reaches the client |
| `sqli-parameterized.test.ts` | Injection strings in the email field are bound as **data** — generic 401, no session issued, zero rows matched, database untouched, no `sql.unsafe` left in the handler |
| `password-storage.test.ts` | Stored passwords are `$argon2id$` PHC strings with per-row salts and the documented work factor; the plaintext column is gone; the CHECK constraint rejects plaintext |
| `rate-limit.test.ts` | 5 failures per IP per 60 s, then `429` + `Retry-After`; per-IP not global; success clears the bucket |
| `session-regeneration.test.ts` | A presented `sid` is destroyed and replaced on login (fixation closed); malformed cookies do not 500 |

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
