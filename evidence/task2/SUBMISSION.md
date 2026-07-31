# Task 2 — Evidence to submit (items 16–19)

Maps each required evidence item to its artefact. Baseline for every "before" is tag
`v0-vulnerable` (`b42df0a`); the hardened build is `v1-hardened-task2`.

| Item | Artefact | Screenshot needed? |
|---|---|---|
| 16. Before-and-after code excerpts with file paths | [`login-query-before-after.md`](login-query-before-after.md) | No — it is a document |
| 17. Database evidence showing hashed passwords without exposing real credentials | `07-argon2id-hashes.png` + [`run-output-after.txt`](run-output-after.txt) §2 | **Yes — 07** |
| 18. Authentication-control configuration and test results | §1 below (configuration) + `13-tests-green.png` | **Yes — 13** |
| 19. Concise explanation of how parameterization separates data from code | §2 below | No — it is prose |

**You need two screenshots: 07 and 13.** Optionally add `08-sqli-no-bypass.png` as empirical
backing for item 19. Captures 09–12 and 14 in [`README.md`](README.md) exist for reproducibility
and are **not** required for this submission.

---

## 1. Authentication-control configuration (item 18)

All four controls are configured in code, not environment variables, so the settings are auditable
in the diff and cannot drift between environments.

### Password hashing — `src/lib/password.ts:24-30`

```ts
export const ARGON2_OPTIONS = {
  type: argon2id,
  memoryCost: 19456, // KiB => 19 MiB
  timeCost: 2,       // iterations
  parallelism: 1,    // lanes
  hashLength: 32,    // bytes of output
} as const;
```

Argon2id at the OWASP Password Storage Cheat Sheet minimum (19 MiB, t=2, p=1). Parameters are
passed explicitly rather than taking the library defaults (64 MiB, t=3, **p=4**) so the work factor
is auditable directly from the stored digest: `$argon2id$v=19$m=19456,p=1,t=2$…`. A fresh 16-byte
random salt is generated per hash.

### Rate limiting — `src/lib/rate-limit.ts:39-40`

```ts
export const LOGIN_MAX_ATTEMPTS = 5;
export const LOGIN_WINDOW_MS = 60_000;
```

Per-IP fixed window, checked at the top of the handler **before** any database or hashing work.
Only failures are counted and a success clears the bucket, so a user who mistypes twice and then
succeeds is never throttled. Exceeding the limit returns `429` with a `Retry-After` header.

### Input validation — `src/lib/validate.ts:14-34`

```ts
export const EMAIL_MIN = 3;
export const EMAIL_MAX = 254;   // RFC 5321 reverse-path limit
export const PASSWORD_MIN = 8;
export const PASSWORD_MAX = 128;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{1,63}$/;
```

`PASSWORD_MAX` is a denial-of-service control, not a password policy — it caps input length
*before* the server spends 19 MiB of Argon2 work on it. The regex is linear-time with no nested
quantifiers, so it carries no ReDoS risk.

### Session regeneration — `src/lib/session.ts:43-63`

A fresh `randomUUID()` is minted on every successful login and any session id the caller presented
is deleted, so a fixed session cannot cross the authentication boundary.

### Error handling — `src/app/api/login/route.ts:44`

```ts
const GENERIC_ERROR = { error: "Invalid email or password" } as const;
```

Returned for every authentication failure — bad format, unknown account, wrong password. Driver
messages, stack traces and the raw query go to the server log only.

---

## 2. Test results (item 18)

```
$ npm test

 ✓ tests/auth-login.test.ts            (16 tests)
 ✓ tests/sqli-parameterized.test.ts    (11 tests)
 ✓ tests/password-storage.test.ts      (13 tests)
 ✓ tests/rate-limit.test.ts             (7 tests)
 ✓ tests/session-regeneration.test.ts   (5 tests)

 Test Files  5 passed (5)
      Tests  54 passed (54)
```

The four required proofs map as follows:

| Proof | Test file | Key assertion |
|---|---|---|
| Valid login works | `auth-login.test.ts` | `200`, `body.ok`, a `sid=<uuid>` cookie (student **and** admin) |
| Invalid credentials rejected | `auth-login.test.ts` | `401` + generic body, no cookie issued |
| Injection treated as data | `sqli-parameterized.test.ts` | generic `401` **and** the bound payload matches 0 rows |
| Passwords are Argon2id | `password-storage.test.ts` | every value `.startsWith("$argon2id$")`; none equals a plaintext |

Reproducible from cold with `npm run db:reset && npm test` — the suite starts its own dev server if
one is not already running.

---

## 3. How parameterization separates data from code (item 19)

**The vulnerability.** A concatenated query hands the database a single finished string, so the
driver cannot tell which characters came from the developer and which came from the user. The
parser sees one blob and interprets *all* of it as SQL. In the baseline
(`src/app/api/login/route.ts:46-54`) the email was spliced in directly:

```ts
"WHERE p.email = '" + email + "' AND c.password = '" + password + "'"
```

Submitting `' OR '1'='1' -- ` produces:

```sql
WHERE p.email = '' OR '1'='1' -- ' AND c.password = '...'
```

The user's quote **closed the string literal early**, `OR '1'='1'` became a new always-true
condition, and `--` commented out the password check. The input stopped being a value and became
*grammar* — that is the entire vulnerability class.

**The fix.** A parameterized query never concatenates. The SQL text and the values travel to the
server as **separate fields of the wire protocol**. In the hardened handler
(`src/app/api/login/route.ts:84-92`):

```ts
rows = await sql<AuthRow[]>`
  SELECT p.id, p.email, p.role, p.display_name, c.password_hash
  FROM profiles p
  JOIN credentials c ON c.profile_id = p.id
  WHERE p.email = ${input.email}
  LIMIT 1
`;
```

This is a postgres.js *tagged template*, not string interpolation. The driver sends the statement
as `… WHERE p.email = $1 …` via PostgreSQL's extended query protocol, and ships `input.email`
separately as the value for `$1`.

**Why that is decisive.** The server **parses and plans the statement before it ever sees the
parameter**. By the time the value arrives, the query's structure is already fixed — the parser has
finished. A bound parameter is therefore only ever compared as a value; it cannot introduce a quote,
an operator, a comment marker, or a second statement, because no re-parsing happens. The payload
`' OR '1'='1' -- ` is treated as a literal 16-character email address, matches zero rows, and the
login fails. It is data, and it stays data.

Note this is a property of the *protocol*, not of escaping: nothing is being sanitised or filtered.
That is why it holds against payloads nobody anticipated, whereas a blocklist only stops the
payloads its author thought of.

**Demonstrated, not just asserted.** `tests/sqli-parameterized.test.ts` runs the same clause through
the driver and asserts the row count directly:

```ts
const payload = "' OR '1'='1' -- ";
const rows = await sql`SELECT id FROM profiles WHERE email = ${payload}`;
expect(rows.length).toBe(0);   // the concatenated v0 form matched all 7
```

Testing only the HTTP status would prove that *validation* rejected the payload; asserting the row
count proves the *query itself* is safe. The same file also confirms that an injection burst creates
no session rows, and that a stacked `'; DROP TABLE sessions; --` leaves the `sessions` table and all
7 profiles intact.

**Defence in depth.** Input validation rejects these payloads before the database is reached anyway
(`' OR '1'='1' -- ` is not a valid email address). Parameterization is what makes the query correct;
validation is a second, independent layer.
