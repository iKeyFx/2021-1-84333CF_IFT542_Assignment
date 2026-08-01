# Before / after — the login query

**File (path unchanged across both builds):** `src/app/api/login/route.ts`

Regenerate this comparison at any time with:

```bash
git diff v0-vulnerable v1-hardened-task2 -- src/app/api/login/route.ts
```

---

## BEFORE — tag `v0-vulnerable`, lines 46–54

```ts
  const authQuery =
    "SELECT p.id, p.email, p.role, p.display_name " +
    "FROM profiles p " +
    "JOIN credentials c ON c.profile_id = p.id " +
    "WHERE p.email = '" + email + "' AND c.password = '" + password + "'";

  let rows: any[];
  try {
    rows = await sql.unsafe(authQuery);
```

Two defects in five lines:

- **`email` and `password` are concatenated into the SQL string** and executed with
  `sql.unsafe()`, so attacker input is parsed as **code**. Submitting
  `email = ' OR '1'='1' -- ` produces:

  ```sql
  WHERE p.email = '' OR '1'='1' -- ' AND c.password = '...'
  ```

  The `--` comments out the password check and the statement returns the first row —
  authentication bypassed with no valid password.

- **The password is compared in cleartext** (`c.password = '<password>'`) because
  `credentials.password` stored the raw value.

---

## AFTER — tag `v1-hardened-task2`, lines 84–92

```ts
  let rows: AuthRow[];
  try {
    rows = await sql<AuthRow[]>`
      SELECT p.id, p.email, p.role, p.display_name, c.password_hash
      FROM profiles p
      JOIN credentials c ON c.profile_id = p.id
      WHERE p.email = ${input.email}
      LIMIT 1
    `;
```

followed by, at lines 100–112:

```ts
  const account = rows[0] ?? null;

  // verifyPassword always performs exactly one Argon2id verification, even when
  // `account` is null, so an unknown email costs the same time as a known email
  // with the wrong password.
  const ok = await verifyPassword(account?.password_hash ?? null, input.password);

  if (!account || !ok) {
    console.warn(`[login] failed ip=${ip} email=${input.email} account_exists=${Boolean(account)}`);
    recordFailure(rateKey);
    // Identical response for "no such account" and "wrong password".
    return NextResponse.json(GENERIC_ERROR, { status: 401 });
  }
```

What changed:

- **Parameterized.** This is a postgres.js *tagged template*, not a string. The driver sends it
  as an extended query with a `$1` placeholder and ships `input.email` separately as a bound
  parameter. `' OR '1'='1' -- ` is therefore compared as a **literal email address**, matches
  zero rows, and cannot alter the statement's structure. `sql.unsafe` is gone from the handler.
- **The password left the SQL entirely.** The query selects `c.password_hash` and the comparison
  happens in application code via `argon2.verify()` against an Argon2id digest.
- **`LIMIT 1`** — the lookup is by unique email, so at most one row is ever of interest.
- **The second injectable query is deleted.** `v0` ran a further concatenated lookup
  (`"SELECT id FROM profiles WHERE email = '" + email + "'"`, lines 91–113) purely to report
  *which* field was wrong. That user-enumeration oracle no longer exists.

---

## Proof that the payload is bound as data

Not merely that the request 401s — validation would also produce that — but that the **query
itself** is safe. From `tests/sqli-parameterized.test.ts`:

```ts
const payload = "' OR '1'='1' -- ";
const rows = await sql`SELECT id FROM profiles WHERE email = ${payload}`;
expect(rows.length).toBe(0);            // the v0 concatenated form matched all 7
```

The same test file also asserts that an injection burst creates **no** session rows, that a
stacked `'; DROP TABLE sessions; --` leaves `to_regclass('sessions')` non-null and all 7 profiles
intact, and — statically, with comments stripped — that no `sql.unsafe` call or concatenated SQL
fragment remains in the handler.

Live confirmation against the running app:

```
$ npx vitest run tests/sqli-parameterized.test.ts
 ✓ tests/sqli-parameterized.test.ts (11 tests)
 Test Files  1 passed (1)
      Tests  11 passed (11)
```

The transcript below was produced by the standalone `sqli-login.mjs` script
that was removed before submission (the coursework forbids shipping reusable payloads). It is
reproduced verbatim because it is a record of a command actually run:

```
HTTP status: 401
Response body: {"error":"Invalid email or password"}
Set-Cookie: []
[NO BYPASS] The injection did not authenticate.
```
