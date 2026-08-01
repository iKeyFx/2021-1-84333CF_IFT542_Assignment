# Evidence — Task 1 (baseline: the working application)

Capture proof that all six required features work before any attack analysis.
Drop screenshots / notes in this folder.

## What to capture

1. **Login** — sign in as a student (`ada.learner@campus.local` / `ada-pw-2025`)
   and as the admin (`admin@campus.local`, using the password from `ADMIN_PASSWORD`
   — it falls back to `Adm1n-Str0ng-Dummy-2026-x7QF`, see the root `README.md`).
   Screenshot each landing on their dashboard/admin views.

   > The v0 baseline seeded the admin as `admin123`. **That password was rotated in Task 3 and is
   > now rejected with a `401`** (asserted in `tests/auth-login.test.ts`), so use the value above.
   > The Task 1 captures in this folder were taken against the pre-hardening build.
2. **Profile update** — change display name + bio on `/profile`, show the saved
   banner and the updated value.
3. **Course registration** — enrol in a course on `/courses`; show the “Enrolled”
   badge and the dashboard count increasing.
4. **Document upload** — upload a small fictitious file on `/uploads`; show it in
   the “Your documents” table and note it appears on disk under `./uploads`.
5. **Admin: manage courses** — create, edit, then delete a course on
   `/admin/courses`.
6. **Admin: manage enrolments** — view the enrolment list and remove one on
   `/admin/enrolments`.

## Suggested filenames

`01-login-student.png`, `02-profile-update.png`, `03-course-register.png`,
`04-upload.png`, `05-admin-courses.png`, `06-admin-enrolments.png`.
