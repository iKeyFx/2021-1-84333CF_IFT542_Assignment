# Evidence — Task 2

Records the authentication and database hardening: the parameterized login query, Argon2id password storage, and the four supporting controls.

| File | What it shows | Assignment item |
|---|---|---|
| `login-query-before-after.md` | The login query side by side — the concatenated `sql.unsafe` form at `v0-vulnerable` and the postgres.js tagged template at `v1-hardened-task2` — with file paths and line numbers | Item 16 — before/after code excerpts with file paths |
| `07-argon2id-hashes.png` | All 7 credential rows prefixed `$argon2id$v=19$m=19456,p=1,t=2$` with visibly different salts, beside `\d credentials` showing no `password` column and the `CHECK (password_hash LIKE '$argon2id$%')` constraint. Digests are truncated by `left(…,46)`, so only the prefix and work factor are visible | Item 17 — database evidence of hashed passwords without exposing credentials |
| `13-tests-green.png` | The suite as Task 2 closed at tag `v1-hardened-task2`: `Test Files 5 passed (5)`, `Tests 54 passed (54)` across the five Task 2 files | Item 18 — authentication-control test results |
| `08-sqli-no-bypass.png` | The payload `' OR '1'='1' -- ` submitted to `/api/login` and answered `HTTP status: 401`, `{"error":"Invalid email or password"}`, `Set-Cookie: []`, `[NO BYPASS]` | Item 19 — empirical backing for the parameterization explanation |
| `run-output.txt` | The baseline transcript at `v0-vulnerable`: the injection authenticating with no valid password, distinct enumeration messages, the `stack`/`query` disclosure, and all 7 passwords readable in cleartext | Items 16–19 — the "before" record |
| `run-output-after.txt` | The hardened transcript: §1 injection bound as data, §2/§2b Argon2id storage and the migration, §3 one generic 401, §5 rate limiting, §6 session-id regeneration | Items 17–19 — the "after" record |

## Reproduce

```bash
npm run db:reset                                    # Postgres up + migrate + seed (Argon2id)
npm test                                            # 183 passed | 1 skipped (184) across 11 files
npx vitest run tests/sqli-parameterized.test.ts     # injection binds as data, 0 rows matched
npx vitest run tests/password-storage.test.ts       # every digest is an Argon2id PHC string
npx vitest run tests/auth-login.test.ts             # unknown email and wrong password reply identically
npx vitest run tests/rate-limit.test.ts             # 5 failures per IP per 60 s, then 429
npx vitest run tests/session-regeneration.test.ts   # the presented sid is replaced and deleted
git diff v0-vulnerable v1-hardened-task2 -- src/app/api/login/route.ts
docker compose exec postgres psql -U ift542 -d ift542 \
  -c "SELECT p.email, left(c.password_hash,46) FROM credentials c JOIN profiles p ON p.id=c.profile_id ORDER BY p.id;" \
  -c "\d credentials"
npm run db:reset:legacy                             # stages the v0 plaintext, then re-hashes it
```

> **Note.** All data is fictitious — invented names, the non-routable `@campus.local` domain, no PII (see `ETHICS.md`). `run-output.txt` shows cleartext passwords deliberately, because that *is* the v0 vulnerability evidence; `run-output-after.txt` redacts them, because its point is that plaintext no longer exists. Both transcripts also name the standalone proof-of-concept scripts that were deleted before submission — the coursework forbids submitting reusable attack payloads — and the transcripts are left unedited as genuine records of commands actually run, with every assertion they made now covered by the Vitest files above.
