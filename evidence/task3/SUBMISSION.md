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

## Screenshots to capture

**Set up once.** Note §4a and the CSP evidence need a **production** build — the strict policy does
not apply under `npm run dev`.

```bash
npm run db:reset
npm run dev                    # for 15-18, 21
npm run build && npm start     # for 19 (strict CSP + HSTS)
```

| # | File | Command / action | What must be visible |
|---|------|------------------|----------------------|
| 15 | `15-xss-neutralised.png` | Browser: `/profile` → set display name to `<img src=x onerror="alert('xss-on-dashboard')">` → save → load `/dashboard`. Then run the psql query below in a terminal. | The dashboard showing the payload **as literal text**, no alert dialog; **and** the psql output proving the DB still holds it verbatim. Both halves in one frame if possible. |
| 16 | `16-csrf-rejected.png` | Open `evidence/task3/csrf-poc.html` while logged in; show the network tab. | The POST to `/api/profile` returning **403**, and `/dashboard` still showing the real display name |
| 17 | `17-cookie-flags.png` | Browser devtools → Application → Cookies → `127.0.0.1` | The `sid` cookie row with **HttpOnly ✓, Secure ✓, SameSite = Lax**. This is also the proof that `Secure` works over `http://127.0.0.1` |
| 18 | `18-ssrf-blocked.png` | `node tests/ssrf-demo.mjs` | `HTTP status of preview call: 403`, `URL not allowed`, and the `[SSRF BLOCKED]` line |
| 19 | `19-security-headers.png` | `npm run build && npm start`, then `curl -I http://127.0.0.1:3000/login` | CSP with `'nonce-…'` and **no `unsafe-`**, plus HSTS, nosniff, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` |
| 20 | `20-admin-rotated.png` | Two login attempts as `admin@campus.local` | rotated password → `200 … "role":"admin"`; `admin123` → `401 {"error":"Invalid email or password"}` |
| 21 | `21-security-logs.png` | Trigger a failed login, a malformed email, and a student POST to an admin endpoint; screenshot the server's stdout | Three JSON lines: `auth.login.failed`, `validation.rejected`, `authz.denied` — with `email` shown **masked** as `a***@campus.local` |
| 22 | `22-tests-green.png` | `npm test` | `Test Files 10 passed (10)` and `Tests 157 passed | 1 skipped (158)` |

For 15, the paired database check:

```bash
docker compose exec postgres psql -U ift542 -d ift542 \
  -c "SELECT display_name FROM profiles WHERE email='ada.learner@campus.local';"
```

**Nothing needs redacting.** All data is fictitious (`@campus.local`, invented names, no PII — see
`ETHICS.md`). The log samples are already masked by the logger itself. The rotated admin password is
a documented dummy, not a real secret.

### If a capture shows the wrong thing

- **`[SSRF CONFIRMED]` instead of `[SSRF BLOCKED]`** — you are on an old build. Check `git log`.
- **`Request rejected` instead of `URL not allowed`** in 18 — the CSRF check fired before the SSRF
  guard, so the script never reached the thing you are trying to prove. `tests/ssrf-demo.mjs`
  fetches a token first; make sure you are running the current version.
- **CSP contains `unsafe-eval`** in 19 — that is the *development* policy. Use
  `npm run build && npm start`.
- **A `404` page** from any script — stale `.next` route manifest after a force-killed dev server.
  `rm -rf .next && npm run dev`, and confirm with
  `curl -o /dev/null -w "%{http_code}" http://127.0.0.1:3000/login` before re-shooting.
