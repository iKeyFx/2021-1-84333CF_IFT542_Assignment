# Evidence — Task 3

Records the application and configuration hardening — XSS, CSRF, SSRF, security headers and configuration, structured logging — and the incident-response controls delivered under item 26.

| File | What it shows | Assignment item |
|---|---|---|
| `01-xss-neutralised.png` | `/dashboard` rendering `<img src=x onerror="alert('xss-on-dashboard')">` as literal text with no alert firing, beside the psql query proving the row still holds the payload verbatim | Deliverable 1 — XSS neutralised by output encoding |
| `02-csrf-rejected.png` | The browser's Network tab: a cross-site POST to `/api/profile` answered `303 → /login`, with `/dashboard` still showing the real display name — `SameSite=Lax` stopping the cookie before the request can be judged by the inner layers | Deliverable 2 — CSRF layer 1 (`SameSite`) |
| `03-csrf-rejected-layers.png` | The same forged requests from a Node client, which does not implement `SameSite`: `403` with `csrf.rejected reason:"bad-origin"`, `403` with `reason:"missing-token"`, a tampered signature also `403`, the legitimate control request accepted as `303 /profile?saved=1`, and the database read proving no forged write landed | Deliverable 2 — CSRF layers 2 and 3 (Origin check, signed token) |
| `04-cookie-flags.png` | The devtools cookie row for `sid` with `HttpOnly`, `Secure` and `SameSite=Lax` set — also the only proof that `Secure` is accepted over `http://127.0.0.1`. Cookie values are blurred; the flags are not | Deliverable 2 — session-cookie attributes |
| `05-ssrf-blocked.png` | The URL-preview endpoint refusing loopback, `localhost`, `169.254.169.254`, RFC1918 ranges, `file://` and non-allowlisted hosts, every blocked body the identical `403 {"ok":false,"error":"URL not allowed"}` | Deliverable 3 — SSRF blocked |
| `06-security-headers.png` | The production response headers: CSP with a per-request `'nonce-…'` and no `unsafe-` token, plus HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` and `Permissions-Policy` — all absent in the baseline | Deliverable 4 — security headers and configuration |
| `07-security-logs.png` | The server's stdout carrying `auth.login.failed`, `validation.rejected`, `auth.login.succeeded` and `authz.denied` as JSON lines, each with `ts`, `level`, `event`, `actor`, `ip`, `method`, `path`, `outcome` and `reason`, and the email masked to `a***@campus.local` | Deliverable 5 — structured logging, redacted |
| `08-tests-green.png` | `Test Files 11 passed (11)` and `Tests 183 passed \| 1 skipped (184)` — the submitted build's full suite | Item 26 — defensive test results |
| `run-output.txt` | The baseline transcript at `v1-hardened-task2`: SSRF fetching an internal URL, the XSS payload executing, the forged POST accepted, and all six headers absent | Deliverables 1–5 — the "before" record |
| `run-output-after.txt` | The hardened transcript: §1 XSS inert, §2 CSRF rejected, §3 the SSRF matrix, §4 headers and configuration, §4e the `Referrer-Policy` browser fix, §5 redacted log samples, §6 test results, §7–§9 the incident-response cycle and the persisted `ir.*` audit records | Deliverables 1–5 and item 26 — the "after" record |

## Reproduce

```bash
npm run db:reset                                  # Postgres up + migrate + seed
npm test                                          # 183 passed | 1 skipped (184) across 11 files
npx vitest run tests/xss-encoding.test.ts         # payload stored verbatim, served escaped
npx vitest run tests/csrf.test.ts                 # missing, tampered and foreign tokens all 403
npx vitest run tests/ssrf-guard.test.ts           # the full IP-range matrix, refused identically
npx vitest run tests/security-headers.test.ts     # CSP nonce, static headers, cookie attributes
npx vitest run tests/logging.test.ts              # event shape, masking, deny-listed fields dropped
npx vitest run tests/incident-response.test.ts    # the four corrective controls, via the real ir/ scripts
npm run build && npm start                        # the production build the strict CSP applies to
curl -I http://127.0.0.1:3000/login               # the header set in 06-security-headers.png
npm run ir:status                                 # read-only: live sessions, locked accounts, audit health
npm run ir:audit-log -- --verify                  # security_events refuses UPDATE/DELETE/TRUNCATE (42501)
git diff v1-hardened-task2 v2-hardened-task3
docker compose exec postgres psql -U ift542 -d ift542 \
  -c "SELECT display_name FROM profiles WHERE email='ada.learner@campus.local';"
```

The incident record is `report/incident-record.md` (`INC-2026-001`, an authorised simulated exercise) and the six-stage response runbook is `report/incident-runbook.md`.

> **Note.** All data is fictitious — invented names, the non-routable `@campus.local` domain, no PII (see `ETHICS.md`) — and the log samples are masked by `src/lib/logger.ts` itself. The cookie values in `04-cookie-flags.png` are blurred on both the `sid` and `csrf` rows, because the CSRF token contains the session id before its dot; `npm run ir:rotate-secrets` output is never screenshotted, since it prints a live password and `SESSION_SECRET` unmasked. The standalone proof-of-concept scripts were deleted before submission — the coursework forbids submitting reusable attack payloads — so the `run-output.txt` transcripts and the terminal in `03-csrf-rejected-layers.png` name files no longer in the tree; those records are left unedited, and every assertion they made now lives in the Vitest files above.
