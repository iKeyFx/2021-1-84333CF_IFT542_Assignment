# Evidence — Task 1

Records the six application features working in the `v0-vulnerable` baseline, the data-flow diagram behind the STRIDE model, and the file-path index of every planted defect.

| File | What it shows | Assignment item |
|---|---|---|
| `dfd.png` | The data-flow diagram with five trust boundaries — browser ↔ server, server ↔ database, server ↔ external network (P7), server ↔ filesystem, and the admin privilege sub-boundary — with the attacker's entry points as dotted flows | Task 1, item 6 — DFD with trust boundaries |
| `01-login-student.png` | A student signing in as `ada.learner@campus.local` and landing on the dashboard | Task 1 — baseline feature 1 (student login) |
| `02-login-admin.png` | The admin signing in as `admin@campus.local` and landing on the admin views | Task 1 — baseline feature 1 (admin login) |
| `03-profile-update.png` | A display name and bio saved on `/profile`, with the saved banner and the updated value | Task 1 — baseline feature 2 (profile update) |
| `04-course-register.png` | An enrolment created on `/courses`, with the "Enrolled" badge and the dashboard count increased | Task 1 — baseline feature 3 (course registration) |
| `05-upload.png` | A fictitious document uploaded on `/uploads` and listed in "Your documents", stored under `./uploads` | Task 1 — baseline feature 4 (document upload) |
| `06-admin-courses.png` | A course created, edited and deleted on `/admin/courses` | Task 1 — baseline feature 5 (admin course management) |
| `07-admin-enrolments.png` | The enrolment list on `/admin/enrolments` and an enrolment removed | Task 1 — baseline feature 6 (admin enrolment management) |
| `planted-vulns.md` | The flat index of all 13 planted defects with `file:line`, STRIDE id and OWASP 2021 category, each tagged in source with a `// [VULN: …]` marker | Task 1, items 7–8 — source data for the STRIDE worksheet and risk register |

## Reproduce

```bash
npm run db:reset                 # Postgres up + migrate + seed
npm run dev                      # http://127.0.0.1:3000
git checkout v0-vulnerable       # the baseline build these frames were taken against
grep -rn "\[VULN:" src db        # every tagged sink with its line number
```

The STRIDE worksheet, risk register and top-three justification built from this evidence are §1.2–§1.4 of `report/2021-1-84333CF_IFT542_report.md`.

> **Note.** All data is fictitious — invented names, the non-routable `@campus.local` domain, no PII (see `ETHICS.md`). The standalone proof-of-concept scripts written against this baseline were deleted before submission because the coursework forbids submitting reusable attack payloads; the `run-output.txt` transcripts in `evidence/task2/` and `evidence/task3/` still name them, being unedited records of commands actually run, and every assertion they made now lives in the Vitest suite.
