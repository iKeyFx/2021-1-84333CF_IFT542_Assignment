# Evidence — Task 2 (authentication)

Planted in `src/app/api/login/route.ts` + `src/lib/`. Start the stack
(`npm run db:reset` then `npm run dev`) before running the scripts.

**Before / after.** The vulnerable baseline is tag `v0-vulnerable`; its capture is
`run-output.txt`. The hardened capture is `run-output-after.txt`.

The side-by-side code excerpt for the login query — the centrepiece of Task 2 — is in
[`login-query-before-after.md`](login-query-before-after.md). Regenerate the full diff with:

```
git diff v0-vulnerable v1-hardened-task2 -- src/app/api/login/route.ts
```

> **Plaintext handling.** `run-output.txt` (the v0 capture) deliberately shows cleartext
> passwords — that *is* the vulnerability evidence. In `run-output-after.txt` the plaintext is
> redacted, since the point of that file is that plaintext no longer exists. The fictitious demo
> passwords remain documented in the root `README.md` for reproduction.

> The `.mjs` scripts below are the **unchanged v0 proof-of-concepts**. Their narration still
> asserts that the app is vulnerable — read the data they print, not their prose. Their new
> failure output *is* the after-evidence.

---

# Screenshots to capture

Naming follows the `evidence/task1/` convention (`NN-name.png`). Task 1 used `01`–`06`, so the
Task 2 captures continue from `07`. Every command below is also captured as text in
`run-output-after.txt`, so the screenshots are corroboration, not the only record.

**Setup once, then run the commands in order:**

```bash
npm run db:reset      # Postgres up + migrate + seed (Argon2id)
npm run dev           # app on http://127.0.0.1:3000, in its own terminal
```

| # | File | Command / action | What must be visible in the frame |
|---|------|------------------|-----------------------------------|
| 07 | `07-argon2id-hashes.png` | <code>docker compose exec postgres psql -U ift542 -d ift542 -c "SELECT p.email, left(c.password_hash,46) FROM credentials c JOIN profiles p ON p.id=c.profile_id ORDER BY p.id;" -c "\d credentials"</code> | All 7 rows prefixed `$argon2id$v=19$m=19456,p=1,t=2$` with **different** salts; and the `credentials` table showing only `profile_id` + `password_hash` (**no** `password` column) plus the `CHECK (password_hash ~~ '$argon2id$%')` constraint |
| 08 | `08-sqli-no-bypass.png` | `node tests/sqli-login.mjs` | `HTTP status: 401`, body `{"error":"Invalid email or password"}`, `Set-Cookie: []`, and the final `[NO BYPASS]` line |
| 09 | `09-generic-error-ui.png` | In the browser at `/login`, submit a **wrong password** for `ada.learner@campus.local`; then submit a **non-existent** email. Two shots, or one split frame. | The identical red banner `Invalid email or password` in both cases — and **no** `<pre>` stack-trace block, which v0 rendered |
| 10 | `10-enum-and-verbose.png` | `node tests/enum-and-verbose.mjs` | Section 1: the unknown-email and known-email lines carrying the **same** message. Section 2: `body keys: [ 'error' ]` — no `stack`, no `query` |
| 11 | `11-rate-limit.png` | `node evidence/task2/capture-rate-limit.mjs` | Attempts 1–5 → `401`, attempt 6+ → `429` with `Retry-After`, and the "correct password while throttled → 429" line |
| 12 | `12-session-regeneration.png` | `node evidence/task2/capture-session-regen.mjs` | Planted sid ≠ issued sid, and `planted sid in DB: 0 rows` |
| 13 | `13-tests-green.png` | `npm test` | `Test Files 5 passed (5)` and `Tests 54 passed (54)` |
| 14 | `14-migration-rehash.png` | `npm run db:reset:legacy` | The `before:` pane (plaintext), then `re-hashed 7`, then the `after:` pane (`$argon2id$…`), then `Credentials: 7 rows, all Argon2id, no plaintext column.` |

**Redaction note for 14.** That capture necessarily shows the fictitious plaintext demo passwords
in its `before:` pane — that is the migration's input. Either blur those three values before
submitting, or cite `run-output-after.txt` §2b (already redacted) instead. Do **not** redact
`run-output.txt`: there the cleartext is the v0 vulnerability evidence.

Screenshot 09 is the only one needing a browser; the rest are terminal captures.

---

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
- **Screenshot to take** (`07-argon2id-hashes.png`, matching the `evidence/task1/` convention):
  run the two commands above in one terminal and screenshot the combined output. `left(...,46)`
  truncates each digest so the screenshot shows the `$argon2id$` prefix and parameters without
  publishing full hashes. The text capture of the same output is in `run-output-after.txt` §2.
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
