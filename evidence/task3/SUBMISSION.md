# Task 3 — Evidence to submit

Maps each deliverable to its artefact. Baseline for every "before" is tag `v1-hardened-task2`;
the hardened build is `v2-hardened-task3`.

| # | Deliverable | Artefact | Screenshot? |
|---|---|---|---|
| 1 | XSS — output encoding + CSP, payload neutralised | `run-output-after.txt` §1, `tests/xss-encoding.test.ts` | **Yes — 15** |
| 2 | CSRF — token + `SameSite`/`HttpOnly`/`Secure`, forged POST rejected | `run-output-after.txt` §2, `tests/csrf.test.ts` | **Yes — 16, 17** |
| 3 | SSRF — allowlist + IP/DNS rejection | `run-output-after.txt` §3, `tests/ssrf-guard.test.ts` | **Yes — 18** |
| 4 | Misconfiguration — headers, debug off, secrets, admin, `npm audit` | `run-output-after.txt` §4 | **Yes — 19, 20** |
| 5 | Logging — three event types, redacted | `run-output-after.txt` §5, `tests/logging.test.ts` | **Yes — 21** |
| — | Defensive test results | `run-output-after.txt` §6 | **Yes — 22** |

Numbering continues from Task 2 (which used 07, 08, 13).

---

## Evidence item 26

> *"Submit defensive tests and code/configuration evidence, redacted logs, an incident record,
> the response runbook and a signed ethics."*

Five components. Three already existed from the hardening work; two were new.

| # | Component | Artefact | Screenshot? |
|---|---|---|---|
| 1 | **Defensive tests** | `npm test` → **182 passed, 1 skipped, 11 files**. `run-output-after.txt` §6. The four corrective controls are covered by `tests/incident-response.test.ts` (25) | **Yes — 22** |
| 2 | **Code / configuration evidence** | `evidence/task2/login-query-before-after.md`; `run-output-after.txt` §1–§4; `db/migrations/003_incident_response.sql`; `ir/*.mjs`; `git diff v2-hardened-task3 v3-incident-response` | **Yes — 15–20** |
| 3 | **Redacted logs** | `run-output-after.txt` §5 (five masked application events) and §9b (the persisted audit records). Emails masked at source by `src/lib/logger.ts`; secret-shaped fields dropped by the logger itself | **Yes — 21, 25** |
| 4 | **Incident record** | [`report/incident-record.md`](../../report/incident-record.md) — `INC-2026-001`, NIST SP 800-61 lifecycle, findings register | — |
| 5 | **Response runbook** | [`report/response-runbook.md`](../../report/response-runbook.md) — every command executed once and its real output pasted | **Yes — 23, 24** |
| 6 | **Signed ethics** | [`ETHICS.md`](../../ETHICS.md) → *Declaration* — 8 clauses + signature block | **Yes — 26** |

The four corrective controls the risk register promised and had never delivered are now
runnable commands. `report/task1-threat-model.md` **Appendix D** records them as delivered.

| Threat | Promised (§3) | Delivered |
|---|---|---|
| T1 | `session revocation + runbook (C)` | `npm run ir:revoke-sessions` + the runbook |
| T9 | `invalidate sessions on leak (C)` | `npm run ir:rotate-secrets` |
| T5 | `forced reset on suspected breach (C)` | `npm run ir:force-reset` |
| T4 | `append-only retention (C)` | `npm run ir:audit-log -- --verify` |

---

## Which screenshots are actually required

**The numbering 15–26 is this project's own scheme, not the assignment's.** The assignment names
five components for item 26 (defensive tests, code/configuration evidence, redacted logs, an
incident record, the response runbook, a signed ethics). Screenshots are how those are *presented*,
not a separate requirement — so the question for each one is whether it evidences something the
text artefacts cannot.

| Priority | Screenshots | Why |
|---|---|---|
| **Essential** | 21, 22, 24, 26 | 21 = "redacted logs", named twice in the brief. 22 = "defensive tests". 24 = the append-only proof, which is a live assertion rather than a claim. 26 = the signed ethics, which only exists once signed. |
| **Strong** | 15, 16, 18, 19 | The four exploit-neutralised proofs. 19 in particular cannot be inferred from source — the production CSP is assembled at runtime. |
| **Supporting** | 17, 23, 25 | Useful confirmations. 17 is the only browser-level proof that `Secure` is accepted over loopback, which no Node test can show. |
| **Optional** | **20** | Already proven three ways: `run-output-after.txt` §4, `tests/auth-login.test.ts:54` (asserts `admin123` → 401), and `db/hash-passwords.mjs`. A screenshot adds presentation, not proof. Skip it if short on time. |

**On 21 specifically:** §5 of `run-output-after.txt` already satisfies the letter of "a redacted
sample of each log type". A live terminal capture is still worth taking, because a log appearing in
real time as you trigger it is harder to fabricate than a text file — but if you have to drop one of
21 and 20, drop 20.

## Screenshots to capture

**Set up once.** Note §4a and the CSP evidence need a **production** build — the strict policy does
not apply under `npm run dev`.

```bash
npm run db:reset
npm run dev                    # for 15-18, 21
npm run build && npm start     # for 19 (strict CSP + HSTS)
```

> ### Two traps before you capture 19
>
> **1. Stop the dev server first.** If anything is already listening on 3000, Next does **not**
> fail — it prints "Port 3000 is in use, trying 3001 instead" and starts there. `curl` to
> `:3000` then hits the *dev* server and you capture the development policy while believing you
> captured production. Check the port is free:
>
> ```bash
> curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:3000/login   # want: 000
> ```
>
> **2. `npm start` needs a `.env`.** In production `sessionSecret()` throws when `SESSION_SECRET`
> is unset — deliberately, that is the fix for the hardcoded secret. Without it the server starts
> but every request fails.
>
> ```bash
> cp .env.example .env          # Windows PowerShell: Copy-Item .env.example .env
> ```
>
> **How to tell at a glance which policy you captured:**
>
> | | development | production |
> |---|---|---|
> | `script-src` | has **`'unsafe-eval'`** | nonce only |
> | `style-src` | has **`'unsafe-inline'`** | `'self'` only |
> | `connect-src` | has **`ws: wss:`** | `'self'` only |
> | `upgrade-insecure-requests` | absent | **present** |
> | `strict-transport-security` | **absent** | present |
>
> Any `unsafe-` or `ws:` in the capture means you are on the dev server. The production header,
> verified:
>
> ```
> content-security-policy: default-src 'self'; script-src 'self' 'nonce-UzY2XexEOcNw1OcHiHU3+A==';
>   style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none';
>   base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests
> strict-transport-security: max-age=63072000; includeSubDomains
> x-content-type-options: nosniff
> x-frame-options: DENY
> referrer-policy: same-origin
> permissions-policy: camera=(), microphone=(), geolocation=(), interest-cohort=()
> ```

| # | File | Command / action | What must be visible |
|---|------|------------------|----------------------|
| 15 | `15-xss-neutralised.png` | Browser: `/profile` → set display name to `<img src=x onerror="alert('xss-on-dashboard')">` → save → load `/dashboard`. Then run the psql query below in a terminal. | The dashboard showing the payload **as literal text**, no alert dialog; **and** the psql output proving the DB still holds it verbatim. Both halves in one frame if possible. |
| 16 | `16-csrf-rejected.png` | Open `evidence/task3/csrf-poc.html` while logged in; show the Network tab. | The POST to `/api/profile` returning **303 → `/login`**, and `/dashboard` still showing the real display name. **Not a 403** — see below |
| 16b | `16b-csrf-rejected.png` | `node evidence/task3/capture-csrf-layers.mjs` | All three layers: `303` anonymous, `403` bad-origin, `403` missing-token, then the control `303 /profile?saved=1` |
| 17 | `17-cookie-flags.png` | Browser devtools → Application → Cookies → `127.0.0.1` | The `sid` cookie row with **HttpOnly ✓, Secure ✓, SameSite = Lax**. This is also the proof that `Secure` works over `http://127.0.0.1`. **Blur the Value column on BOTH `sid` and `csrf`** — see *What to redact* |
| 18 | `18-ssrf-blocked.png` | `node tests/ssrf-demo.mjs` | `HTTP status of preview call: 403`, `URL not allowed`, and the `[SSRF BLOCKED]` line |
| 19 | `19-security-headers.png` | `npm run build && npm start`, then `curl -I http://127.0.0.1:3000/login` | CSP with `'nonce-…'` and **no `unsafe-`**, plus HSTS, nosniff, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` |
| 20 | `20-admin-rotated.png` | Two login attempts as `admin@campus.local` | rotated password → `200 … "role":"admin"`; `admin123` → `401 {"error":"Invalid email or password"}` |
| 21 | `21-security-logs.png` | **Two terminals** — see *Capturing 21* below. T1: `npm run dev`. T2: `node evidence/task3/capture-security-logs.mjs`. Screenshot **T1**. | Three JSON lines: `auth.login.failed`, `validation.rejected`, `authz.denied` — with `email` shown **masked** as `a***@campus.local` |
| 22 | `22-tests-green.png` | `npm test` | `Test Files 11 passed (11)` and `Tests 182 passed \| 1 skipped (183)` |
| 23 | `23-ir-revocation.png` | `npm run ir:status`, then `npm run ir:revoke-sessions -- --all --incident INC-2026-001 --yes`, then `ir:status` again | Sessions listed → `REVOKED n session(s)` → `TOTAL: 0`. Ideally include the `307` from a revoked cookie |
| 24 | `24-append-only.png` | `npm run ir:audit-log -- --verify` | The full `[PASS]` matrix, `42501` on UPDATE / DELETE / **zero-row DELETE** / TRUNCATE, and `ALL 7 CHECKS PASSED` |
| 25 | `25-ir-locked-login.png` | Lock an account, then attempt login with the **correct** password alongside a wrong-password attempt | Both `401 {"error":"Invalid email or password"}` — identical. Plus the `auth.login.blocked` line in the server log |
| 26 | `26-signed-ethics.png` | `ETHICS.md` → *Declaration*, printed and signed | The 8 clauses and the completed signature block (name, date, signature filled in **by hand**) |

**Screenshot 22 must be re-shot** if you captured it before item 26 — the count changed from
157/10 to 182/11.

For 23–25, pin the operator identity so the capture does not carry your machine's hostname:

```bash
IR_OPERATOR="responder@ift542-lab" npm run ir:revoke-sessions -- --all --incident INC-2026-001 --yes
```

**Do not screenshot `npm run ir:rotate-secrets --yes`** — it prints a live password and a live
`SESSION_SECRET`, unmasked, because an operator has to use them. Its evidence is already in
`run-output-after.txt` §8d with both values redacted.

For 15, the paired database check:

```bash
docker compose exec postgres psql -U ift542 -d ift542 \
  -c "SELECT display_name FROM profiles WHERE email='ada.learner@campus.local';"
```

### What to redact

Most of this needs nothing: the data is fictitious (`@campus.local`, invented names, no PII — see
`ETHICS.md`) and the log samples are masked by the logger itself. **Three things are exceptions.**

**1. Screenshot 17 — the cookie VALUES.** A session id is a **bearer credential**: anyone holding it
is that user until it expires. It is the same reasoning that makes `ir/revoke-sessions.mjs` refuse to
write session ids into the audit log. The practical risk here is nil — localhost only, fictitious
account, the session is destroyed by the next `db:reset` — but a security submission should not
publish a live credential just because that credential happens to be worthless.

**The trap:** blurring the `sid` row alone does not redact it, because the `csrf` cookie *contains
the session id*:

```
sid  = 17663e3b-0b02-44f2-8a18-aee89b319f05
csrf = 17663e3b-0b02-44f2-8a18-aee89b319f05.E03fI0fltBqapLXFgfhTR_g--IinaA8idWlJAChg-WE
       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ the same value, before the dot
```

That is by design — the token is `<sid>.HMAC-SHA256(SESSION_SECRET, sid)`, which is what binds it to
the session. But it means **you must blur the Value column on both rows, or neither is redacted.**

Keep the first block (`17663e3b-…`) visible if you want it to look real; blur the rest. The
**Flags columns must stay fully readable** — `HttpOnly`, `Secure` and `SameSite=Lax` are the actual
evidence, and the value contributes nothing to it.

**2. `npm run ir:rotate-secrets --yes` output** — prints a live password and a live `SESSION_SECRET`,
unmasked, because an operator has to use them. Do not screenshot it at all; its evidence is already
in `run-output-after.txt` §8d with both values redacted.

**3. Operator identity in screenshots 23–25** — `ir:*` records `<windows-user>@<machine-name>`. Not
secret, and attribution is the point, but there is no reason to publish your hostname. Pin it:

```bash
IR_OPERATOR="responder@ift542-lab" npm run ir:status
```

Not sensitive, for the avoidance of doubt: the CSRF token's HMAC (computed with the *documented*
development secret), the rotated admin password in `README.md` (a documented dummy), and the CSP
nonce (single-use, already spent).

### Capturing 21 — the log screenshot, step by step

The log lines are printed by the **server**, not by whatever you run to trigger them. So you need
two terminals, and you screenshot the *server* one.

**Terminal 1 — the server. This is the one you screenshot.**

```bash
npm run dev
```

If Next's compile output makes the lines hard to see, filter it instead — this shows *only* the
security events, which makes a much cleaner screenshot:

```bash
npm run dev 2>&1 | grep --line-buffered '"event":'
```

**Terminal 2 — trigger one of each event.**

```bash
node evidence/task3/capture-security-logs.mjs
```

**Then screenshot Terminal 1.** Three lines, newest last:

```json
{"ts":"…","level":"warn","event":"auth.login.failed","actor":{"type":"anonymous"},
 "outcome":"denied","ip":"198.18.100.11","method":"POST","path":"/api/login",
 "email":"a***@campus.local","reason":"bad-password"}

{"ts":"…","level":"warn","event":"validation.rejected","actor":{"type":"anonymous"},
 "outcome":"denied","ip":"198.18.100.12","method":"POST","path":"/api/login",
 "reason":"email-format"}

{"ts":"…","level":"warn","event":"authz.denied","actor":{"type":"user","profile_id":1,
 "role":"student"},"outcome":"denied","ip":"127.0.0.1","method":"POST",
 "path":"/api/admin/courses","reason":"not-admin","required_role":"admin"}
```

**Why a script rather than "just trigger the three events".** The third one is not obvious.
`authz.denied` with `reason: "not-admin"` needs a **logged-in student** posting to an admin
endpoint. Posting anonymously to the same URL logs `reason: "no-session"` instead — a different
event, and the dull one. That distinction is the entire point of the log line: `currentAdmin()`
used to return `null` for both cases, collapsing the only one worth alerting on. The script logs
in first so you get `not-admin`.

**What to point out in the report:**

| | |
|---|---|
| **WHO** | `actor` (`profile_id` + `role`, or `{"type":"anonymous"}`) and `ip` |
| **WHAT** | `event` + `method` + `path` + `outcome` + `reason` |
| **WHEN** | `ts`, ISO-8601 UTC |

And what is **absent**: no password, no digest, no session id, no CSRF token. Those keys are
dropped inside `src/lib/logger.ts`, so a caller cannot leak one even by passing it explicitly —
"remember not to log the password" is not a control. The email is masked to `a***@campus.local`.

Worth noting in the write-up: steps 1 and 2 returned the **same generic 401** to the client. The
reason they differ exists only in the log. That is the anti-enumeration control and the logging
control doing their separate jobs.

### Screenshot 16 — why the browser shows 303, not 403

The earlier instruction here said to expect a **403**. In a real browser you will
never see one, and the reason is worth putting in the report rather than treating
as a failed capture.

`SameSite=Lax` stops the browser attaching the session cookie to a cross-site POST
**at all**. The forged request therefore arrives with no identity, is refused for
having no session, and is redirected to `/login`:

```json
{"event":"authz.denied","actor":{"type":"anonymous"},"outcome":"denied",
 "method":"POST","path":"/api/profile","reason":"no-session"}
```

Note `actor: anonymous`. That is the **strongest** of the three layers — the attack
never gets to use the victim's identity at all — but it means the request never
reaches the token check, so no 403 can be produced. A browser cannot demonstrate
layers 2 and 3, because a browser will not send the cookie that would let the
request get far enough to be judged by them.

`capture-csrf-layers.mjs` (screenshot 16b) forces the cookie through with a Node
client, which does not implement `SameSite`, and shows the inner two layers holding
on their own. Together the two screenshots show defence in depth:

| Layer | Control | Forged request gets |
|---|---|---|
| 1 | `SameSite=Lax` on the session cookie | cookie never sent → `303 /login`, anonymous |
| 2 | Origin/Referer check | `403` — `Origin: null` refused even with a valid cookie **and** token |
| 3 | Signed double-submit token | `403` — missing or tampered token refused |

The `303` in your Network tab **is the pass condition** for screenshot 16. Pair it
with `/dashboard` still showing the real display name.

### If a capture shows the wrong thing

- **`[SSRF CONFIRMED]` instead of `[SSRF BLOCKED]`** — you are on an old build. Check `git log`.
- **`Request rejected` instead of `URL not allowed`** in 18 — the CSRF check fired before the SSRF
  guard, so the script never reached the thing you are trying to prove. `tests/ssrf-demo.mjs`
  fetches a token first; make sure you are running the current version.
- **CSP contains `unsafe-eval`** in 19 — that is the *development* policy. You either did not run
  `npm run build && npm start`, or you did and **a dev server was still holding port 3000**, so
  `npm start` quietly moved to 3001 and your `curl` hit the old server. See *Two traps* above.
- **A `404` page** from any script — stale `.next` route manifest after a force-killed dev server.
  `rm -rf .next && npm run dev`, and confirm with
  `curl -o /dev/null -w "%{http_code}" http://127.0.0.1:3000/login` before re-shooting.
