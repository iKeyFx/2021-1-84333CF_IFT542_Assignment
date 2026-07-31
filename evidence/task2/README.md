# Evidence — Task 2 (authentication)

Planted in `src/app/api/login/route.ts` + `src/lib/`. Start the stack
(`npm run db:reset` then `npm run dev`) before running the scripts.

**Before / after.** The vulnerable baseline is tag `v0-vulnerable`; its capture is
`run-output.txt`. The hardened capture is `run-output-after.txt`. The code diff is:

```
git diff v0-vulnerable -- src/app/api/login/route.ts
```

> The `.mjs` scripts below are the **unchanged v0 proof-of-concepts**. Their narration still
> asserts that the app is vulnerable — read the data they print, not their prose. Their new
> failure output *is* the after-evidence.

## 1. SQL injection — auth bypass
- Run: `node tests/sqli-login.mjs`
- Or in the UI: log in with email `' OR '1'='1' -- ` and any password.
- **Before:** authenticated as the first account with no valid password.
- **After:** `401 {"error":"Invalid email or password"}`, no `Set-Cookie`, script exits 1 with
  `[NO BYPASS]`. The query is a postgres.js tagged template, so the payload binds as `$1` and is
  compared as a literal email address.
- Automated: `tests/sqli-parameterized.test.ts` — asserts both the 401 *and* that the payload
  matched zero rows and left the database untouched.

## 2. Password storage
- **Before:** the `credentials.password` column stored raw passwords.
- **After:** `credentials.password_hash` stores an Argon2id PHC string; the plaintext column is
  dropped and a CHECK constraint enforces the format.
  ```
  docker compose exec postgres psql -U ift542 -d ift542 \
    -c "SELECT p.email, left(c.password_hash,46) FROM credentials c JOIN profiles p ON p.id=c.profile_id;"
  docker compose exec postgres psql -U ift542 -d ift542 -c "\d credentials"
  ```
- Capture: every row prefixed `$argon2id$v=19$m=19456,p=1,t=2$`, distinct salts, and a
  `credentials` table with no `password` column.
- **The migration itself:** `npm run db:reset:legacy` stages the exact v0 plaintext credentials and
  then re-hashes them, printing before/after in one command. The default `npm run db:reset` never
  writes plaintext at any instant. Both end in the same schema — see `db/hash-passwords.mjs`.
- Automated: `tests/password-storage.test.ts`.

## 3. Verbose DB/stack errors + 4. User enumeration
- Run: `node tests/enum-and-verbose.mjs`
- **Before:** different messages for unknown vs known email, and a response carrying the raw SQL
  `query` + `stack` on a forced DB error.
- **After:** both replies are byte-identical `401 {"error":"Invalid email or password"}`, and the
  error body has keys `[ 'error' ]` only. The forced-error payload is now rejected by input
  validation before it reaches the database.
- Timing was equalised too — an unknown email still costs one full Argon2id verification against a
  decoy digest (`src/lib/password.ts`), so response time is not an enumeration oracle either.
- Automated: `tests/auth-login.test.ts` (`expect(unknownBody).toEqual(wrongPwBody)`).

## 5. Rate limiting
- **Before:** no lockout, delay, or CAPTCHA — attempts could be repeated freely.
- **After:** 5 failed attempts per IP per 60 s, then `429` with a `Retry-After` header. Only
  failures count and a success clears the bucket, so mistyping twice then succeeding is never
  punished. The check runs before any DB or hashing work.
- Capture: a burst of 8 attempts showing `401 ×5` then `429 ×3`.
- Automated: `tests/rate-limit.test.ts`.

## 6. Session-id regeneration / session fixation
- **Before:** `establishSession()` reused a presented `sid` cookie instead of minting a new one.
- **After:** a fresh UUID is minted on every successful login and the presented id is **deleted**,
  so an attacker-fixed session cannot survive the authentication boundary.
- Demo: set a `sid` cookie to a known UUID in devtools, log in, and confirm the cookie value
  changed and the old id is gone from the `sessions` table.
- Automated: `tests/session-regeneration.test.ts`.

## Regression check — Task 3 must stay reproducible

Task 2 hardening is deliberately scoped. After the change, confirm these still hold:

- `admin@campus.local` / `admin123` still logs in (default admin).
- The session cookie still has **no** `SameSite` and **no** `Secure` (`evidence/task3/csrf-poc.html`).
- `DEBUG` still defaults to `true` in `src/lib/config.ts`.
- `node tests/ssrf-demo.mjs` still reports `[SSRF CONFIRMED]`.
