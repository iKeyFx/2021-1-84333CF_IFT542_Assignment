# Evidence — Task 3 (application & configuration security)

Start the stack (`npm run db:reset`, then `npm run dev`) before reproducing.

**Before / after.** The vulnerable baseline is tag `v1-hardened-task2`; its capture is
`run-output.txt`. The hardened capture is `run-output-after.txt`. Code diff:

```
git diff v1-hardened-task2 v2-hardened-task3
```

> **Capture §4 against a production build.** The strict CSP (no `unsafe-inline`, no
> `unsafe-eval`) only applies in production. `npm run dev` deliberately relaxes it for webpack
> HMR. Use `npm run build && npm start` for the header screenshot.

---

## 1. Stored XSS — payload rendered inert
- Run: `npx vitest run tests/xss-encoding.test.ts` (the five payloads are declared inline in that
  file; the standalone `xss-payload.txt` was removed before submission).
- Steps: log in → `/profile` → set display name to
  `<img src=x onerror="alert('xss-on-dashboard')">` → save → load `/dashboard`.
- **Before:** the script executed; `dangerouslySetInnerHTML` injected it as raw markup.
- **After:** the payload is displayed as literal text. No alert fires.
- **Capture both halves.** The database still holds the payload verbatim:
  ```
  docker compose exec postgres psql -U ift542 -d ift542 \
    -c "SELECT display_name FROM profiles WHERE email='ada.learner@campus.local';"
  ```
  while the served HTML contains only `&lt;img …`. Showing only the escaped output would look
  identical if the app had silently stripped the input — a weaker control. Storing it intact and
  escaping on output is what contextual output encoding means.
- Automated: `tests/xss-encoding.test.ts`.

## 2. CSRF — forged cross-site POST rejected
- Run: `npx vitest run tests/csrf.test.ts`. (The hand-written `csrf-poc.html` page was removed
  before submission; the test drives the same three requests and additionally reads the database
  after each one to prove nothing changed.)
- **Before:** the display name and bio changed with no token.
- **After:** `403`, and the profile is unchanged. A forged cross-site POST fails on **three**
  independent grounds: no CSRF token, `Origin: null` (what a `file://` page sends), and
  `SameSite=Lax` on the session cookie. The test exercises each in isolation so the layering is
  visible.
- Also show the cookie in devtools (Application → Cookies): it now has `HttpOnly`, `SameSite=Lax`
  and `Secure`. **This is also the check for `Secure` over `http://127.0.0.1`** — browsers treat
  loopback as a trustworthy origin, but confirm the cookie is actually stored rather than assuming.
- Automated: `tests/csrf.test.ts` — each rejection is paired with a DB read proving the state did
  not change.

## 3. SSRF — internal destinations refused
- Run: `npx vitest run tests/ssrf-guard.test.ts` (it authenticates and fetches a CSRF token first;
  without that a request is refused by the CSRF check before ever reaching the SSRF guard, which
  would prove the wrong thing).
- Or in the UI: `/admin/url-preview` → `http://127.0.0.1:3000/login` → Preview.
- **Before:** `[SSRF CONFIRMED]` — the server fetched the internal URL and returned its body.
- **After:** `403 {"ok":false,"error":"URL not allowed"}` and `[SSRF BLOCKED]`.
- Capture the matrix in `run-output-after.txt` §3: loopback, `localhost`, `169.254.169.254`,
  10/8, 172.16/12, 192.168/16, `file://`, a non-allowlisted host and `[::1]`. **Every response body
  is identical** — a distinct reason would let an admin map the internal network.
- Automated: `tests/ssrf-guard.test.ts` (runs offline via an injected resolver).

## 4. Security misconfiguration
- **Headers** (production build):
  ```
  npm run build && npm start
  curl -I http://127.0.0.1:3000/login
  ```
  Capture CSP (with `'nonce-…'`, no `unsafe-*`), HSTS, `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`. **Before:** all absent.
- **Config** — `src/lib/config.ts`: `DEBUG` is now opt-in (`=== "true"`), `SESSION_SECRET` has no
  committed fallback and throws in production, `DEFAULT_ADMIN` is deleted,
  `productionBrowserSourceMaps` is `false`.
- **Default admin rotated** — capture both:
  ```
  admin@campus.local + rotated password -> 200
  admin@campus.local + admin123         -> 401
  ```
- **Dependencies** — `npm audit` before/after: 1 critical + 1 high → 1 high. Record the residual
  honestly; the remaining `next` advisory has no fix inside the 14.2 line.

## 5. Security logging (threat T4)
- The Task 1 worksheet lists T4 as *"no security logging in baseline (added only in Task 3)"*.
  This is that deliverable — there was **no** logging item in this file before.
- Trigger the three required event types and capture the JSON lines from the server's stdout:
  ```
  # failed-login
  curl -s -X POST http://127.0.0.1:3000/api/login -H 'Content-Type: application/json' \
    -d '{"email":"ada.learner@campus.local","password":"wrong-password"}'

  # rejected-validation
  curl -s -X POST http://127.0.0.1:3000/api/login -H 'Content-Type: application/json' \
    -d '{"email":"not-an-email","password":"whatever1"}'

  # denied-authorization — log in as a STUDENT, then POST to an admin endpoint
  ```
- Expected: one JSON object per line, each with `ts`, `level`, `event`, `actor` (`profile_id` +
  `role`, or `type:"anonymous"`), `ip`, `method`, `path`, `outcome`, `reason`.
- **Check the redaction**: emails appear masked (`a***@campus.local`), and no password, hash,
  session id or CSRF token appears anywhere. Samples are in `run-output-after.txt` §5.
- Automated: `tests/logging.test.ts`.

---

## Capture scripts

Two deliverables are awkward to capture by hand, so each has a script. Both are read-only
demonstrations against localhost; neither is attack tooling.

| Script | Captures | Why it exists |
|---|---|---|
| `node evidence/task3/capture-security-logs.mjs` | Screenshot 21 | Triggers one of each required event. The `authz.denied` case needs a **logged-in student** posting to an admin endpoint — anonymous logs `no-session` instead, which is the wrong event |

Screenshot **16b** (CSRF layers 2 and 3) is reproduced with `npx vitest run tests/csrf.test.ts`.
A Node client does not implement `SameSite`, so the session cookie goes through and the Origin
check and the signed token can each be seen failing on their own — a browser cannot show them,
because it is stopped by `SameSite` first (that is screenshot 16). The standalone
`capture-csrf-layers.mjs` script the existing capture was taken with was removed before
submission along with the other proof-of-concept payloads.

For 21 you need two terminals: `npm run dev` in one (screenshot **that** one), the script in the
other. See `SUBMISSION.md` → *Capturing 21*.

## Regression check — Task 1 and Task 2 must stay intact

- `npx vitest run tests/sqli-parameterized.test.ts` → injection strings bound as data: generic
  `401`, no session, zero rows matched.
- `npx vitest run tests/auth-login.test.ts` → identical replies for unknown email and wrong
  password, body keys `['error']`.
- `npm test` → `183 passed | 1 skipped (184)` across 11 files. The skip is the live-network SSRF
  test, gated behind `ALLOW_NETWORK_TESTS=1`.
- `db/migrations/001_init.sql` unchanged, so the Task 1 citation of `001_init.sql:29` still resolves.

---

## Item 26 — incident response

Added after the five deliverables above. See `SUBMISSION.md` → *Evidence item 26* for the full
map, and `run-output-after.txt` §8–§9 for the captures.

- `report/incident-record.md` — `INC-2026-001` (authorised **simulated** exercise; the record
  says so in a banner at the top).
- `report/incident-runbook.md` — the one-page six-stage runbook (Preparation → Lessons Learned).
  Long form, with every quoted command executed and its real output pasted:
  `report/appendix/response-runbook.md`.
- `ETHICS.md` → *Declaration* — sign by hand; ID and course are pre-filled.
- `npm run ir:status` · `ir:revoke-sessions` · `ir:force-reset` · `ir:rotate-secrets` ·
  `ir:audit-log` — the four corrective controls from the risk register, now runnable.
- `npm run ir:audit-log -- --verify` → all 7 checks pass; `security_events` refuses UPDATE,
  DELETE, zero-row DELETE and TRUNCATE with SQLSTATE `42501`.
