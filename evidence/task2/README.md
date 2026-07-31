# Evidence — Task 2 (authentication vulnerabilities)

Planted in `src/app/api/login/route.ts` + `src/lib/`. Start the stack
(`npm run db:reset` then `npm run dev`) before running the scripts.

## 1. SQL injection — auth bypass
- Run: `node tests/sqli-login.mjs`
- Or in the UI: log in with email `' OR '1'='1' -- ` and any password.
- Expected: authenticated as the first account with no valid password.
- Capture: script output / logged-in screenshot.

## 2. Plaintext passwords (by inspection)
- The `credentials.password` column stores raw passwords (see
  `db/migrations/001_init.sql` and `db/seed.sql`).
- Verify against the running DB:
  ```
  docker compose exec postgres psql -U ift542 -d ift542 \
    -c "SELECT p.email, c.password FROM credentials c JOIN profiles p ON p.id=c.profile_id;"
  ```
- Capture: the query output showing cleartext passwords.

## 3. Verbose DB/stack errors + 4. User enumeration
- Run: `node tests/enum-and-verbose.mjs`
- Expected: different messages for unknown vs known email (enumeration), and a
  response containing the raw SQL `query` / `stack` on a forced DB error.
- Capture: the script output.

## 5. No rate limiting (by observation)
- Re-run `tests/enum-and-verbose.mjs` or the login form many times in a row —
  there is no lockout, delay, or CAPTCHA. Capture a burst of attempts succeeding
  without throttling.

## 6. No session-id regeneration / session fixation (by inspection + observation)
- `src/lib/session.ts` → `establishSession()` reuses a presented `sid` cookie
  instead of minting a new one on login.
- Demo: set a `sid` cookie to a known UUID in the browser devtools, log in, and
  confirm the same UUID is still your session afterwards (it was not rotated
  across the auth boundary).
