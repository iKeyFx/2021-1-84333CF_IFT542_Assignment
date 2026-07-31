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
- Payloads: `tests/xss-payload.txt`.
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
- PoC: `evidence/task3/csrf-poc.html`. Log in as a student, then open that file in the same browser.
- **Before:** the display name and bio changed with no token.
- **After:** `403`, and the profile is unchanged. The PoC fails on **three** independent grounds:
  no CSRF token, `Origin: null` (what a `file://` page sends), and `SameSite=Lax` on the session
  cookie. Demonstrate each in isolation so the layering is visible.
- Also show the cookie in devtools (Application → Cookies): it now has `HttpOnly`, `SameSite=Lax`
  and `Secure`. **This is also the check for `Secure` over `http://127.0.0.1`** — browsers treat
  loopback as a trustworthy origin, but confirm the cookie is actually stored rather than assuming.
- Automated: `tests/csrf.test.ts` — each rejection is paired with a DB read proving the state did
  not change.

## 3. SSRF — internal destinations refused
- Run: `node tests/ssrf-demo.mjs` (it now fetches a CSRF token first; without that it is refused by
  the CSRF check before ever reaching the SSRF guard and would prove the wrong thing).
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

## Regression check — Task 1 and Task 2 must stay intact

- `node tests/sqli-login.mjs` → `[NO BYPASS]` (exit 1).
- `node tests/enum-and-verbose.mjs` → identical replies, body keys `['error']`.
- `npm test` → 157 passing, 1 skipped (the live-network SSRF test, gated behind
  `ALLOW_NETWORK_TESTS=1`).
- `db/migrations/001_init.sql` unchanged, so the Task 1 citation of `001_init.sql:29` still resolves.
