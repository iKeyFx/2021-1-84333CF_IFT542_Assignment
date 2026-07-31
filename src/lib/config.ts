// ============================================================================
//  Central config for the IFT542 teaching artefact.
//
//  Several planted vulnerabilities live here on purpose (Task 3):
//   - Debug mode is ON and drives verbose error output.
//   - The session secret has a HARDCODED fallback checked into the repo.
//   - A default admin account with a well-known password is documented here
//     and seeded into the DB.
// ============================================================================

// [VULN: Debug mode on — Task 3]
// DEBUG defaults to true and is used to decide whether to leak stack traces
// and raw SQL back to the client.
export const DEBUG = (process.env.DEBUG ?? "true") !== "false";

// [VULN: Hardcoded secret — Task 3]
// A real app would fail closed if SESSION_SECRET were missing. This one falls
// back to a constant committed to source control, so every deployment shares
// the same guessable signing secret.
export const SESSION_SECRET =
  process.env.SESSION_SECRET || "ift542-super-secret-do-not-change-me-123";

// Name of the session cookie set at login.
export const SESSION_COOKIE = "sid";

// [VULN: Default admin with well-known password — Task 3]
// These credentials are also seeded into the database (see db/seed.sql) and
// documented in the README, so anyone can log in as admin out of the box.
export const DEFAULT_ADMIN = {
  email: "admin@campus.local",
  password: "admin123",
};

// Where uploaded documents are written on local disk.
export const UPLOAD_DIR = process.env.UPLOAD_DIR || "./uploads";

export const DATABASE_URL =
  process.env.DATABASE_URL || "postgres://ift542:ift542_dev_pw@127.0.0.1:5432/ift542";
