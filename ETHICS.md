# Ethics & Safe-Use Statement

## Purpose

This repository is a **teaching artefact** for the IFT542 web-security coursework. It deliberately
contains common web vulnerabilities so they can be identified, exploited *against this app only*, and
then hardened in a follow-up session to demonstrate a before/after comparison. This mirrors
well-established educational projects such as OWASP Juice Shop, WebGoat, and DVWA.

## Authorised scope

- **Localhost only.** The app and its database bind to `127.0.0.1`. It must never be deployed,
  port-forwarded, tunnelled, or otherwise exposed to any network or other person.
- **Fictitious data only.** Every seeded name, email (`@campus.local`), password, course, and
  document is invented. No real personal data is present, and none should ever be entered.
- **You test only this app.** The scripts in `tests/` and `evidence/task3/csrf-poc.html` are
  hard-wired to `http://127.0.0.1:3000` and target *this* application. They are single, app-specific
  reproductions — **not** reusable scanners, exploit kits, or attack tooling, and contain nothing
  intended for use against any third-party system.

## What this repo intentionally does NOT contain

- No reusable/weaponised exploit tooling, payload generators, or scanners.
- No techniques aimed at third-party or production systems.
- No real secrets. The hardcoded values (e.g. `SESSION_SECRET`, the default admin password) are
  themselves *planted vulnerabilities for the lesson* and are fictitious placeholders.

## Responsible handling

- Keep the repository private to the coursework context.
- Run it in an isolated local environment; stop the container (`npm run db:down`) when finished.
- The default admin (`admin@campus.local` / `admin123`) exists **on purpose** as a demonstrated
  weakness. Do not reuse these credentials anywhere real.
- The follow-up "hardened" build will remediate every item listed in `report/threat-model.md`.

## If in doubt

If any use would take an "attack" outside this local app, or would involve real data or a real
system, **stop** — that is outside the authorised scope of this coursework artefact.
