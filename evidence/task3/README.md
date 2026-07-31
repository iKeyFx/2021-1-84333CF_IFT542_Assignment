# Evidence — Task 3 (application & configuration vulnerabilities)

Start the stack (`npm run db:reset` then `npm run dev`) before reproducing.

## 1. Stored XSS (profile display name)
- Payloads: `tests/xss-payload.txt`.
- Steps: log in → `/profile` → set display name to
  `<img src=x onerror="alert('xss-on-dashboard')">` → save → load `/dashboard`.
- Expected: the script executes because the name is rendered with
  `dangerouslySetInnerHTML` (see `src/app/dashboard/page.tsx`,
  `src/app/profile/page.tsx`).
- Capture: the alert firing.

## 2. No CSRF protection + no SameSite cookie
- PoC: `evidence/task3/csrf-poc.html` (auto-submits a cross-origin profile
  update). Log in as a student, then open that file in the same browser.
- Expected: display name/bio change with no CSRF token, because the session
  cookie has no `SameSite` attribute (`src/lib/session.ts` → `buildSessionCookie`)
  and `src/app/api/profile/route.ts` performs no token/origin check.
- Capture: the changed profile on `/dashboard`; also show the cookie in devtools
  (Application → Cookies) has no SameSite value.

## 3. SSRF (admin URL preview)
- Run: `node tests/ssrf-demo.mjs` (logs in as admin, asks the server to fetch a
  loopback URL).
- Or in the UI: `/admin/url-preview` → enter `http://127.0.0.1:3000/login` (or
  another internal address) → Preview.
- Expected: the server fetches the internal URL and returns its body — no host /
  scheme / IP restrictions (`src/app/api/admin/url-preview/route.ts`).
- Capture: the returned status + body snippet for an internal target.

## 4. Insecure configuration
- `src/lib/config.ts`: `DEBUG` on by default (drives the verbose errors above),
  a hardcoded `SESSION_SECRET` fallback, and a default admin
  (`admin@campus.local` / `admin123`) that is also seeded and documented.
- Capture: the relevant lines of `config.ts` and a successful admin login with
  the well-known password.
