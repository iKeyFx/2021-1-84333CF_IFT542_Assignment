# Planted Vulnerabilities — file paths (IFT542, `v0-vulnerable`)

> Isolated localhost teaching artefact — fictitious data, do not deploy. See `ETHICS.md`.
> Every sink below is tagged in source with a `// [VULN: <name> — <Task>]` comment.
> The authoritative threat model is [`report/task1-threat-model.md`](../../report/task1-threat-model.md)
> (STRIDE + risk register + OWASP Appendix A); this file is the flat file-path index.

Regenerate the raw marker list at any time:

```bash
grep -rn "\[VULN:" src db          # every tagged sink with its line number
```

## Register (13 planted issues, grouped as the 8 required categories)

| # | Vulnerability | Task | File : line | STRIDE | OWASP 2021 |
|---|---|---|---|---|---|
| 1 | SQL injection in login (string-concatenated `sql.unsafe`) | 2 | `src/app/api/login/route.ts:33` (marker); query built `:46–50`, executed `:54` | T1 | A03 Injection |
| 2 | Plaintext password storage & compare | 2 | column `db/migrations/001_init.sql:29`; values `db/seed.sql:26–34`; compared `src/app/api/login/route.ts:50` | T5 | A02 Cryptographic Failures |
| 3 | Verbose DB/stack errors to client | 2 | `src/app/api/login/route.ts:56` (also `:92`) | T7 | A05 Security Misconfiguration |
| 4 | User enumeration / field disclosure | 2 | `src/app/api/login/route.ts:86` | T7 | A07 Identification & Auth Failures |
| 5 | No rate limiting on login | 2 | `src/app/api/login/route.ts:28` | T8 | A07 Identification & Auth Failures |
| 6 | No session-id regeneration (session fixation) | 2 | `src/lib/session.ts:35`; applied at `src/app/api/login/route.ts:70` | T9 | A07 Identification & Auth Failures |
| 7 | Stored XSS (display name rendered unescaped) | 3 | source `src/app/api/profile/route.ts:32`; sinks `src/app/dashboard/page.tsx:23`, `src/app/profile/page.tsx:25` | T3 | A03 Injection (XSS) |
| 8 | No CSRF protection on state-changing POSTs | 3 | `src/app/api/profile/route.ts:27`, `src/app/api/enrol/route.ts:23` (forms: `src/app/profile/page.tsx:38`, `src/app/courses/page.tsx:51`) | T2 | A01 Broken Access Control |
| 9 | Session cookie has no SameSite (enables CSRF) | 3 | `src/lib/session.ts:60` (`buildSessionCookie`) | T2 | A05 Security Misconfiguration |
| 10 | SSRF in admin URL-preview (no guards) | 3 | `src/app/api/admin/url-preview/route.ts:27` (marker `:4`) | T6 | A10 Server-Side Request Forgery |
| 11 | Debug mode on (drives verbose errors) | 3 | `src/lib/config.ts:11` | T7 | A05 Security Misconfiguration |
| 12 | Hardcoded session secret (committed fallback) | 3 | `src/lib/config.ts:16` | T9 | A05 / A02 |
| 13 | Default admin with well-known password (`admin@campus.local` / `admin123`) | 3 | `src/lib/config.ts:26`; seeded `db/seed.sql:8` (comment), password literal `db/seed.sql:34` | T9 | A07 Identification & Auth Failures |

**Maps to the 8 required deliberate vulnerabilities:** SQLi (#1) · plaintext passwords (#2) ·
verbose/enumeration errors (#3,#4) · no rate-limit + no session regen (#5,#6) · stored XSS (#7) ·
no CSRF + no SameSite (#8,#9) · SSRF (#10) · insecure config: debug + hardcoded secret + default
admin (#11,#12,#13).

## Reproduction

Task 2: `node tests/sqli-login.mjs`, `node tests/enum-and-verbose.mjs` (+ `evidence/task2/README.md`).
Task 3: `node tests/ssrf-demo.mjs`, `tests/xss-payload.txt`, `evidence/task3/csrf-poc.html`
(+ `evidence/task3/README.md`). Captured output: `evidence/task2/run-output.txt`,
`evidence/task3/run-output.txt`.
