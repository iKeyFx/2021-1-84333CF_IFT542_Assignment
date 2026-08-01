# Incident Response Runbook — long form (appendix)

> **Superseded as the primary runbook.** The one-page, six-stage runbook submitted for item 25 is
> [`report/incident-runbook.md`](../incident-runbook.md). This document is retained as an
> appendix: it is the long-form operational detail — every command with its real captured output,
> the full detection-trigger table, and the scenario walkthroughs.
>
> **Scope.** The IFT542 Student Registration teaching artefact running on
> `http://127.0.0.1:3000` against a local docker-compose Postgres. **Localhost only, fictitious
> data only.** See [`ETHICS.md`](../../ETHICS.md).
>
> **Every command in this document has been executed and its real output pasted.** A runbook
> containing an untested command is worse than no runbook: it fails during the one hour you
> cannot afford to debug it.

Worked example of these steps against a real (simulated) intrusion:
[`report/incident-record.md`](../incident-record.md).

---

## 1. The four commands

| Command | Purpose | Threat |
|---|---|---|
| `npm run ir:status` | Read-only. What is live, what is locked, is the audit log healthy | — |
| `npm run ir:revoke-sessions` | Containment. End authenticated access | T1, T9 |
| `npm run ir:force-reset` | Containment. Lock accounts pending credential reset | T5 |
| `npm run ir:rotate-secrets` | Eradication. New passwords + new `SESSION_SECRET` | T9 |
| `npm run ir:audit-log` | Retention. Verify, ingest and read the audit trail | T4 |

### Safety contract — the same for every script

- **`--dry-run` is the DEFAULT.** Nothing changes without `--yes`. Run any command without it
  first, always; the dry run prints exactly what would happen.
- **`--incident <id>` is mandatory for any mutation.** There are no anonymous response actions.
- **Exactly one scope is required** — `--all`, `--email <address>` or `--role <student|admin>`.
  There is no implicit "everything".
- **Exit codes:** `0` success · `1` runtime failure · `2` usage error.
- Every mutation appends an `ir.*` record to `security_events`, so the response is audited by
  the same append-only control it administers.

`--help` works on all five.

---

## 2. Detection triggers

The application emits JSON Lines to stdout (`src/lib/logger.ts`). These are the **real event
names** — grep for them exactly.

| Event | Meaning | Act when |
|---|---|---|
| `auth.login.failed` | Bad password or unknown account | Many for one `ip`, or one `ip` across many accounts → credential stuffing |
| `auth.login.throttled` | Rate limiter engaged (5/60 s per IP) | Sustained, or from many IPs at once → distributed brute force |
| **`auth.login.blocked`** | **Correct password presented to a LOCKED account** | **Always investigate.** Either the real user, or an attacker with stolen credentials |
| `authz.denied` | Non-admin hit an admin endpoint | Repeated, from an authenticated session → probing after account takeover |
| `validation.rejected` | Input failed validation | Bursts with odd `reason` values → automated probing |
| `csrf.rejected` | Anti-CSRF check failed | Any, from a real browser session → active CSRF attempt |
| `ssrf.blocked` | Outbound URL refused by the guard | Any → someone is probing internal addresses |
| `auth.login.db_error` | Driver fault in the login path | Any → possible injection attempt or DB problem |

Watch a live server:

```bash
npm run dev 2>&1 | grep --line-buffered '"event":"auth.login.blocked"'
```

### Severity

| Sev | Definition | Response | Sections |
|---|---|---|---|
| **1 — Critical** | Authentication bypassed, credentials disclosed, or admin compromised | Immediate. Contain first, investigate second | §4 → §5 → §6 |
| **2 — High** | Single account compromised, or a working exploit against one control | Contain the account, then assess blast radius | §4 (scoped) → §6 |
| **3 — Medium** | Repeated probing, no confirmed compromise | Monitor, capture evidence, no containment | §3, §7 |
| **4 — Low** | Isolated anomalies | Note and move on | §3 |

---

## 3. Step 0 — Assess (always first, always safe)

```bash
npm run ir:status
```

Read-only. Takes no scope, needs no `--yes`, mutates nothing — during an incident you must be
able to look at the system without first committing to change it.

```
=== LIVE SESSIONS ===
  none — no authenticated session exists
  TOTAL: 0

=== PENDING CREDENTIAL RESETS ===
  none — every account may log in normally

=== AUDIT LOG (security_events) ===
  rows: 105
  append-only triggers: BOTH PRESENT
  (prove enforcement with: npm run ir:audit-log -- --verify)
```

Filter to one incident, and widen the event list:

```bash
npm run ir:status -- --incident INC-2026-001 --events 20
```

> **Note on masked identities.** `ir:status` masks addresses (`a***@campus.local`) using the
> same rule as the logger, so two accounts can display identically — `ada.learner` and `admin`
> both render as `a***@campus.local`. The `role` column disambiguates them. Exact identity is
> always available by joining `credential_resets.profile_id`.

---

## 4. Scenario A — Compromised session (T1: injection, token theft, XSS)

**Trigger:** evidence of authentication bypass, or a session you believe an attacker holds.

**The point of this step:** patching the vulnerability does **nothing** to a session already
issued. In `INC-2026-001` the injected session was valid for a further 24 hours after the query
was parameterized. Revocation is a separate action and it is the one that ends the access.

### A1. Dry run first

```bash
npm run ir:revoke-sessions -- --all
```

```
=== SESSION REVOCATION — scope: all profiles ===
  a***@campus.local        student  1 session(s)
  1 session(s) across 1 account(s)

  would DELETE the above from `sessions`

[DRY RUN] Nothing was changed. Re-run with --yes --incident <id> to apply.
```

### A2. Apply

```bash
npm run ir:revoke-sessions -- --all --incident INC-2026-001 --yes
```

```
=== SESSION REVOCATION — scope: all profiles ===
  a***@campus.local        student  1 session(s)
  1 session(s) across 1 account(s)

  REVOKED 1 session(s).
  Affected users are logged out on their next request (307 -> /login).
  Verify with: npm run ir:status
```

Scope it down when you know the blast radius:

```bash
npm run ir:revoke-sessions -- --email ada.learner@campus.local --incident INC-2026-001 --yes
npm run ir:revoke-sessions -- --role admin --incident INC-2026-001 --yes
```

### A3. Verify

The revoked cookie must stop working. `src/middleware.ts` only redirects when the `sid` cookie
is **absent**, so a revoked-but-present cookie falls through to `currentUser()` and is
redirected there instead — **307**, not 200:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -H "Cookie: sid=$SID" http://127.0.0.1:3000/dashboard
```

```
before revocation -> HTTP 200
after  revocation -> HTTP 307   Location: /login
```

Then `npm run ir:status` → `TOTAL: 0`.

---

## 5. Scenario B — Disclosed credentials (T5)

**Trigger:** the credential store was read, or passwords were disclosed by any path.

**Applies even if passwords are hashed.** In `INC-2026-001` all seven were dumped in
*cleartext*; Argon2id protects the store going forward but does nothing about passwords already
in an attacker's hands.

### B1. Lock the accounts

```bash
npm run ir:force-reset -- --require --all --incident INC-2026-001 --yes
```

```
=== FORCED RESET — LOCK — scope: all profiles ===
  a***@campus.local        student
  g***@campus.local        student
  l***@campus.local        student
  m***@campus.local        student
  o***@campus.local        student
  n***@campus.local        student
  a***@campus.local        admin
  7 account(s) to lock  (reason: suspected-credential-compromise)
  sessions for these accounts will also be revoked

  LOCKED 7 account(s); revoked 0 session(s).
  Login is now refused for these accounts EVEN WITH THE CORRECT PASSWORD,
  with the same generic 401 as any other failure.
```

`--require` **also revokes those accounts' sessions**. A lock that leaves live sessions
authenticated is theatre — the attacker holding a stolen `sid` never visits the login page.

Record why, if it is not the default:

```bash
npm run ir:force-reset -- --require --role admin --reason "credentials in public git history" \
  --incident INC-2026-001 --yes
```

### B2. Verify the lock is not an oracle

A locked account must be **indistinguishable** from a wrong password and from an account that
does not exist. Anything else tells an attacker which of their stolen credentials are still
worth trying:

```
correct password, locked account -> {"error":"Invalid email or password"} HTTP 401
wrong password, same account     -> {"error":"Invalid email or password"} HTTP 401
unknown account                  -> {"error":"Invalid email or password"} HTTP 401
```

Identical status, identical body, no `Set-Cookie`, and one Argon2id verification on every path
so the timing matches too. The distinction exists **only in the server log**, as
`auth.login.blocked`. Asserted by `tests/incident-response.test.ts`.

### B3. Restore service

```bash
npm run ir:force-reset -- --complete --all --incident INC-2026-001 --yes
```

```
  UNLOCKED 7 account(s).
```

> ### ⚠️ `--complete` IS NOT A PASSWORD-RESET FLOW
>
> It re-hashes each account back to its documented demo password from
> `db/hash-passwords.mjs` and clears the lock, so the exercise is repeatable. **That is all it
> is.** A real deployment issues a single-use, time-limited, signed token over an
> independently-verified channel and lets the *user* choose a new password — the operator never
> learns it. This artefact has no mail path and no reset UI, so that flow does not exist here.
> See §7.

---

## 6. Scenario C — Leaked secret (T9)

**Trigger:** `SESSION_SECRET`, an admin password, or any credential has been exposed —
committed to git, pasted into a ticket, or disclosed by Scenario B.

In `INC-2026-001` both `admin123` and the hardcoded `SESSION_SECRET` are in the repository
history at `v0-vulnerable`, permanently. **They cannot be un-published. Rotation is the only
remedy.**

### C1. Dry run, then rotate

```bash
npm run ir:rotate-secrets -- --role admin
npm run ir:rotate-secrets -- --role admin --incident INC-2026-001 --yes
```

```
  ROTATED 1 password(s); revoked 3 session(s).

=== NEW CREDENTIALS — transcribe now, they are not stored anywhere ===
  admin@campus.local           XXXXX-XXXXX-XXXXX-XXXXX      <- redacted in this document

=== NEW SESSION_SECRET — put this in .env, then restart the server ===
  SESSION_SECRET=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX   <- redacted in this document
```

> The real command prints these **unmasked**, because you need to use them. That output is a
> live secret: do not paste it into evidence, a ticket, or a screenshot. The values above are
> redacted for exactly that reason.

### C2. Place the new secret — a manual step, on purpose

```bash
# put SESSION_SECRET=<value> in .env, then restart:
npm run dev
```

The script does **not** write `.env` itself. The server reads `SESSION_SECRET` once at process
start, so editing the file would leave the running process on the old key and silently break
every CSRF check until someone noticed.

**Free win:** CSRF tokens are `<sid>.HMAC-SHA256(SESSION_SECRET, sid)` (`src/lib/csrf.ts`), so
rotating `SESSION_SECRET` invalidates every outstanding CSRF token at the same time.

### C3. Verify

```bash
curl -s -w " HTTP %{http_code}\n" -X POST http://127.0.0.1:3000/api/login \
  -H "content-type: application/json" -H "origin: http://127.0.0.1:3000" \
  -d '{"email":"admin@campus.local","password":"<OLD password>"}'
```

```
old password -> {"error":"Invalid email or password"} HTTP 401
new password -> {"ok":true,"user":{...,"role":"admin"}} HTTP 200
```

---

## 7. The audit trail (T4)

### Prove it is append-only

```bash
npm run ir:audit-log -- --verify
```

```
=== APPEND-ONLY VERIFICATION — security_events ===
  [PASS] trigger security_events_no_change defined present
  [PASS] trigger security_events_no_truncate defined present
  [PASS] INSERT is permitted                    allowed (rolled back)
  [PASS] UPDATE is refused                      42501
  [PASS] DELETE is refused                      42501
  [PASS] DELETE matching ZERO rows is refused   42501
  [PASS] TRUNCATE is refused                    42501

  ALL 7 CHECKS PASSED — security_events is append-only.
  Records may be added but never altered or removed, by anyone,
  including the table owner the application connects as.
```

This does not merely check that the triggers are *defined* — it **attempts** each mutation
inside a transaction that is always rolled back, and asserts SQLSTATE `42501`. Safe to run at
any time, including mid-incident.

The zero-row `DELETE` is the check that matters most: a row-level `BEFORE DELETE` trigger never
fires when nothing matches, so without a **statement-level** trigger the whole control would be
bypassable with `DELETE FROM security_events WHERE id = -1`.

Enforcement is a trigger rather than `REVOKE` because the application connects as the table
**owner**, and an owner can always grant privileges back to themselves.

### Read it

```bash
npm run ir:audit-log -- --tail 6
```

```
  2026-07-31T20:56:55.168Z  notice  ir.credentials.reset_required locked    responder@ift542-lab   - [INC-2026-001]
  2026-07-31T20:56:53.814Z  notice  ir.sessions.revoked        revoked      responder@ift542-lab   - [INC-2026-001]
  2026-07-31T20:52:22.496Z  notice  ir.sessions.revoked        no-op        vitest@ift542-lab      - [TEST-1785531135101-755361]

  6 record(s). Emails are masked at source by src/lib/logger.ts.
```

### Ingest logs

```bash
npm run ir:audit-log -- --ingest --file server.log --incident INC-2026-001
npm run dev 2>&1 | node ir/audit-log.mjs --ingest
```

```
=== AUDIT INGEST — server.log ===
  read 4 line(s), appended 3 record(s)
       1  auth.login.failed
       1  authz.denied
       1  auth.login.blocked
```

Lines without an `event` field are ignored, so ordinary Next.js stdout noise passes through
without polluting the table.

> **What `--ingest` honestly is.** The application does **not** write to `security_events`.
> `src/lib/logger.ts` emits JSON Lines to stdout and knows nothing about a database — it has to
> stay edge-safe because `src/middleware.ts` imports it. `--ingest` is a **log shipper standing
> in for the real one**. In production you replace it with Vector / Fluent Bit / your platform's
> pipeline, writing to WORM or object storage with a retention lock. The shape is identical —
> read JSON Lines, map fields, append — which is why demonstrating it this way is worth
> anything at all.

### Retention survives a wipe

`security_events` has **no foreign key** and is never dropped, so it survives `npm run db:reset`
— which is what "retention" means. Verified: 105 rows before a full drop-and-reseed, 105 after.

The absence of an FK on `actor_profile_id` is deliberate. `ON DELETE CASCADE` would mean that
deleting a profile erases that profile's audit trail — the exact repudiation threat (T4) rebuilt
inside the control meant to close it.

---

## 8. Do NOT do these

| Don't | Why |
|---|---|
| **Delete or edit log records** to "clean up" | The trigger refuses anyway (`42501`), but attempting it during an incident destroys the chain of custody you are trying to establish |
| **`npm run db:reset` before capturing state** | Wipes sessions, locks and application data. Run `ir:status` and capture output first. `security_events` survives; nothing else does |
| **Skip the dry run** | It costs two seconds and shows you the blast radius before you commit to it |
| **Paste `rotate-secrets` output into evidence** | It contains live secrets, unmasked, on purpose |
| **Use `--all` when `--email` will do** | `--all` revokes every session in the system, including uninvolved users' |
| **Tell the user their account is locked** | That is an enumeration oracle. The generic 401 is the control; the log is where the truth lives |
| **Edit `.env` and assume it took effect** | The server reads secrets at process start. Restart it |
| **Run any `ir:*` command against anything but localhost** | Out of scope, and out of the ethics declaration |

---

## 9. What a real deployment adds

This artefact is a single-operator localhost teaching build. Everything below is genuinely
missing, and its absence is a limitation of the exercise, not of the design:

| Missing | What it would be |
|---|---|
| **Log aggregation** | Logs go to stdout. Production ships them off-host immediately, so an attacker with host access cannot suppress them |
| **Alerting** | Nothing watches the events. Production alerts on thresholds — N `auth.login.failed` per minute, any `ssrf.blocked`, any `auth.login.blocked` |
| **On-call rotation** | There is one person, who is also the attacker |
| **Self-service password reset** | No mail path, no reset UI. `--complete` is a stand-in (§5) |
| **Immutable/WORM storage** | Append-only is enforced by a trigger inside the same database. Production writes to storage with an independent retention lock, so a database compromise cannot reach the log |
| **Backups and restore testing** | None |
| **Multi-person authorisation** | Any single operator can run any `ir:*` command. Production requires a second approver for destructive actions |
| **Legal / disclosure process** | Not applicable: no real data, no real users, no regulator |

---

## 10. Quick reference

```bash
npm run ir:status                                                            # assess (safe)
npm run ir:revoke-sessions -- --all                                          # dry run
npm run ir:revoke-sessions -- --all --incident INC-2026-001 --yes            # contain
npm run ir:force-reset     -- --require  --all --incident INC-2026-001 --yes # lock
npm run ir:force-reset     -- --complete --all --incident INC-2026-001 --yes # restore
npm run ir:rotate-secrets  -- --role admin --incident INC-2026-001 --yes     # eradicate
npm run ir:audit-log       -- --verify                                       # prove
npm run ir:audit-log       -- --tail 20                                      # read
```

Full regression check after any response:

```bash
npm test          # 183 passed | 1 skipped (184) across 11 files
```
