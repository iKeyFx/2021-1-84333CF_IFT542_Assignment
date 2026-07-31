# IFT542 — Threat Model (companion notes)

> **Primary document:** [`report/task1-threat-model.md`](task1-threat-model.md) is the authoritative
> threat model for Task 1 — it holds the data-flow diagram, the **STRIDE worksheet**, the **risk
> register**, and the top-three justification. This file is a companion only.
>
> The **OWASP Top-10 (2021) mapping** that used to live here has been folded into that document as
> **Appendix A**, cross-referenced to the STRIDE threat IDs (T1–T9) and risk ranks, so the two
> documents agree and there is a single source of truth for each view.

**Artefact:** Student Registration web app (Next.js 14 App Router + TypeScript + Postgres).
**Status:** *Vulnerable build* (before). A hardened build (after) will follow.
**Scope:** Isolated localhost, fictitious data. See `ETHICS.md`.

All planted sinks are tagged in source with `// [VULN: <name> — <Task>]`. For the full vulnerability
register with file:line, STRIDE ID, risk rank, and OWASP category, see **Appendix A** of the primary
document.

## Planned hardening (after — not done this session)

These are the remediation details behind the risk-register controls in the primary document (§3),
kept here as an engineering to-do list for the follow-up "after" build:

- **T1 / SQLi, T5 / plaintext:** parameterized query via tagged templates (`sql\`… ${email} …\``);
  store salted password hashes (e.g. Argon2id / scrypt) and compare hashes.
- **T7 / verbose errors + enumeration:** single generic “invalid email or password” message; log
  details server-side only; `DEBUG` off outside development.
- **T8 / rate limiting, T9 / fixation:** per-account/IP rate limiting + lockout/backoff; rotate the
  session id on login.
- **T3 / stored XSS:** render `display_name` as text (`{value}`) / sanitise on input; add a CSP.
- **T2 / CSRF:** per-session CSRF token on forms + verify; set `SameSite=Lax` (and `Secure` over HTTPS).
- **T6 / SSRF:** allowlist schemes/hosts; resolve and block loopback/link-local/private IPs; disable
  redirects; re-check after DNS resolution.
- **T9 / config:** load the session secret from env and fail closed if absent; remove/rotate the
  default admin account.

## Reproduction

See `tests/README.md` and `evidence/task{1,2,3}/README.md`.
