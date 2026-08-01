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
- **You test only this app.** The tests in `tests/` are hard-wired to `http://127.0.0.1:3000` and
  target *this* application. They are defensive regression tests asserting that each control holds
  — **not** reusable scanners, exploit kits, or attack tooling, and they contain nothing intended
  for use against any third-party system. The standalone proof-of-concept scripts used during
  development were removed before submission.

## What this repo intentionally does NOT contain

- No reusable/weaponised exploit tooling, payload generators, or scanners.
- No techniques aimed at third-party or production systems.
- No real secrets. The hardcoded values (e.g. `SESSION_SECRET`, the default admin password) are
  themselves *planted vulnerabilities for the lesson* and are fictitious placeholders.

## Responsible handling

- Keep the repository private to the coursework context.
- Run it in an isolated local environment; stop the container (`npm run db:down`) when finished.
- The default admin credential `admin@campus.local` / `admin123` existed **on purpose** as a
  demonstrated weakness in the `v0-vulnerable` baseline. **It was rotated in Task 3** and is now
  rejected; the current password comes from `ADMIN_PASSWORD`, falling back to a documented dummy.
  The retired value remains in the git history at tag `v0-vulnerable` and must never be reused
  anywhere real.
- Every item listed in `report/task1-threat-model.md` **has been remediated** — Task 2 closed the
  authentication and database findings, Task 3 the application and configuration findings. See
  Appendices B, C and D of that document.

## Incident-response exercise

Task 3 adds a simulated incident-response exercise. Three things about it are worth stating
plainly:

- [`report/incident-record.md`](report/incident-record.md) documents `INC-2026-001` in the form of
  a real incident report. **It is not a real breach.** Every event in it was produced deliberately
  by the author against their own localhost artefact, and the record carries that warning at the
  top so it cannot be mistaken for one if read out of context.
- The `ir/` directory contains **operational response commands**, not attack tooling. They revoke
  sessions, lock accounts, rotate this application's own credentials and verify its audit log.
  They connect only to the local docker-compose database, require an explicit `--yes` and an
  incident id before changing anything, and default to a dry run.
- `ir/rotate-secrets.mjs` prints newly generated secrets **unmasked**, because an operator has to
  use them. That output must not be pasted into evidence, tickets or screenshots.

## If in doubt

If any use would take an "attack" outside this local app, or would involve real data or a real
system, **stop** — that is outside the authorised scope of this coursework artefact.

---

## Declaration

I declare that, in producing and submitting this coursework artefact:

1. **Authorisation.** All security testing was performed against this application only, on
   hardware I own or am authorised to use, as coursework set for IFT542. No third-party,
   institutional or production system was targeted, scanned, or accessed at any point.
2. **Containment.** The application and its database were bound to `127.0.0.1` throughout. The
   artefact was never deployed, port-forwarded, tunnelled, published, or made reachable by any
   other person or machine.
3. **Data.** All data in this repository is fictitious. Every name is invented, every address uses
   the non-routable `@campus.local` domain, and no real personal data of any person — myself
   included — was entered, processed or stored.
4. **No third-party impact.** The test suite in `tests/`, the evidence-capture scripts under
   `evidence/`, and the incident-response commands in `ir/` are hard-wired to
   `http://127.0.0.1:3000`. They are single, application-specific defensive checks, not reusable
   scanners, exploit kits or attack tooling. **No reusable attack payload is submitted:** the
   standalone proof-of-concept scripts written against the `v0-vulnerable` baseline were deleted
   from the submitted tree, and their coverage now lives in the Vitest suite.
5. **Secrets.** No real credential or secret appears in this repository. The values present in the
   `v0-vulnerable` baseline were planted placeholders forming part of the lesson, and have been
   rotated.
6. **Honesty of evidence.** The captured outputs, logs, test results and timings submitted as
   evidence are genuine records of commands actually run. Where a control is incomplete, a
   limitation is documented rather than concealed — see the "Known residuals" section of
   `README.md` and §4.4 of `report/incident-record.md`. Nothing has been fabricated or
   selectively edited to appear more favourable.
7. **Simulated incident.** `report/incident-record.md` records an authorised simulated exercise. I
   have not represented it, and will not represent it, as a real security breach.
8. **Responsible handling.** I will keep this repository within the coursework context and will not
   redistribute it, or any part of it, for use against systems I am not authorised to test.
9. **Responsible disclosure.** Had a genuine vulnerability been found in any third-party system, I
   would have followed responsible-disclosure principles and taken no exploitative action. Every
   finding recorded here concerns defects I deliberately planted in my own localhost artefact, so
   no disclosure to any external party was owed or made.
10. **Own work.** This submission — code, report and evidence — is my own work, produced for this
    assessment. Sources, standards and reference projects that informed it (OWASP Top-10 2021,
    the OWASP Password Storage and CSRF Prevention cheat sheets, and the teaching precedent of
    Juice Shop / WebGoat / DVWA) are cited where used.

| | |
|---|---|
| **Student ID** | `2021-1-84333CF` |
| **Course** | `IFT542` — Web Security |
| **Artefact** | Student Registration portal (localhost teaching build) |
| **Full name** | ................................................................ |
| **Date** | ................................................................ |
| **Signature** | ................................................................ |

> **To submit:** print or export this file, then complete the three blank fields above by hand.
> Student ID and Course are pre-filled; name, date and signature are deliberately left blank and
> must be completed by the student personally.
