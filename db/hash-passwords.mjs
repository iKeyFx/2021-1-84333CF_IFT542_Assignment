// ============================================================================
//  IFT542 — Argon2id credential migration.  [FIXED — Task 2]
//
//  Runs after db/seed.sql (see db/migrate.mjs) and handles BOTH paths:
//
//   1. LEGACY BACKFILL — if the plaintext `credentials.password` column still
//      exists and holds rows, each value is re-hashed into `password_hash`.
//      This is the real-world migration of an existing plaintext store. Stage
//      it deliberately with:  npm run db:reset:legacy
//
//   2. FRESH SEED — any profile without a password_hash gets one computed from
//      demoPasswords(). This is the default path (npm run db:reset), on which
//      plaintext NEVER touches the database at any instant.
//
//  Either way the step finishes by dropping the legacy column, making
//  password_hash NOT NULL, and adding a CHECK constraint so "no plaintext" is
//  a database invariant rather than a convention.
//
//  Usage:  imported by db/migrate.mjs — not run directly.
// ============================================================================
import { hash } from "argon2";

/**
 * MUST mirror ARGON2_OPTIONS in src/lib/password.ts. A .mjs cannot import the
 * .ts module, so the two are duplicated; tests/password-storage.test.ts parses
 * the stored digests and asserts they match src/lib/password.ts, which fails
 * the build if these ever drift apart.
 *
 * type 2 === argon2id.
 */
const ARGON2_OPTIONS = {
  type: 2,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
  hashLength: 32,
};

/**
 * [FIXED — Task 3: default admin with a well-known password]
 *
 * The admin password is no longer the notorious `admin123`. It comes from the
 * ADMIN_PASSWORD environment variable, falling back to a strong documented
 * dummy so the artefact stays reproducible for a marker without shipping a
 * guessable credential.
 *
 * MUST be read lazily, inside the function — db/migrate.mjs calls
 * process.loadEnvFile() at import time, so a module-scope read would capture
 * the value BEFORE .env is loaded and silently ignore the override.
 */
export const ADMIN_PASSWORD_FALLBACK = "Adm1n-Str0ng-Dummy-2026-x7QF";

function adminPassword() {
  const fromEnv = process.env.ADMIN_PASSWORD;
  return fromEnv && fromEnv.length > 0 ? fromEnv : ADMIN_PASSWORD_FALLBACK;
}

/**
 * Fictitious demo credentials. These lived in db/seed.sql:26-36 in the
 * v0-vulnerable baseline, where they were INSERTed as plaintext. The student
 * values are unchanged — only their storage is. The admin value was rotated
 * in Task 3 (see above).
 */
export function demoPasswords() {
  return {
    "ada.learner@campus.local": "ada-pw-2025",
    "grace.coder@campus.local": "grace-pw-2025",
    "linus.pupil@campus.local": "linus-pw-2025",
    "mira.scholar@campus.local": "mira-pw-2025",
    "otto.student@campus.local": "otto-pw-2025",
    "nova.trainee@campus.local": "nova-pw-2025",
    "admin@campus.local": adminPassword(),
  };
}

/** True if `credentials` still has the legacy plaintext column. */
async function hasLegacyColumn(sql) {
  const rows = await sql`
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'credentials' AND column_name = 'password'
  `;
  return rows.length > 0;
}

/**
 * Reproduce the exact v0-vulnerable plaintext state so the legacy backfill has
 * something to migrate. Only called via `node db/migrate.mjs --legacy-plaintext`
 * to demonstrate the migration; never on the default path.
 */
export async function seedLegacyPlaintext(sql) {
  if (!(await hasLegacyColumn(sql))) {
    throw new Error(
      "cannot stage legacy plaintext: credentials.password no longer exists"
    );
  }

  const profiles = await sql`SELECT id, email FROM profiles ORDER BY id`;
  const passwords = demoPasswords();
  let staged = 0;

  for (const { id, email } of profiles) {
    const plain = passwords[email];
    if (!plain) continue;
    await sql`
      INSERT INTO credentials (profile_id, password)
      VALUES (${id}, ${plain})
      ON CONFLICT (profile_id) DO UPDATE SET password = EXCLUDED.password
    `;
    staged++;
  }

  return staged;
}

/**
 * Migrate every credential to an Argon2id digest, then lock the schema down.
 * Idempotent: safe to run repeatedly (each run re-salts, which is correct).
 *
 * Returns { rehashed, seeded } so the caller can report which path ran.
 */
export async function migrateCredentials(sql) {
  let rehashed = 0;
  let seeded = 0;

  // ---- 1. Legacy backfill: plaintext -> Argon2id ---------------------------
  if (await hasLegacyColumn(sql)) {
    const legacy = await sql`
      SELECT profile_id, password
      FROM credentials
      WHERE password IS NOT NULL
      ORDER BY profile_id
    `;

    for (const { profile_id, password } of legacy) {
      const digest = await hash(password, ARGON2_OPTIONS);
      await sql`
        UPDATE credentials SET password_hash = ${digest} WHERE profile_id = ${profile_id}
      `;
      rehashed++;
    }
  }

  // ---- 2. Fresh seed: any profile still without a digest -------------------
  const missing = await sql`
    SELECT p.id, p.email
    FROM profiles p
    LEFT JOIN credentials c ON c.profile_id = p.id
    WHERE c.password_hash IS NULL
    ORDER BY p.id
  `;

  const passwords = demoPasswords();

  for (const { id, email } of missing) {
    const plain = passwords[email];
    if (!plain) {
      console.warn(`  ! no demo password for ${email} — skipped`);
      continue;
    }
    // Independent random salt per row: two accounts sharing a password still
    // produce different digests.
    const digest = await hash(plain, ARGON2_OPTIONS);
    await sql`
      INSERT INTO credentials (profile_id, password_hash)
      VALUES (${id}, ${digest})
      ON CONFLICT (profile_id) DO UPDATE SET password_hash = EXCLUDED.password_hash
    `;
    seeded++;
  }

  // ---- 3. Finalize: no plaintext column, and enforce the format ------------
  await sql.unsafe(`
    ALTER TABLE credentials DROP COLUMN IF EXISTS password;
    ALTER TABLE credentials ALTER COLUMN password_hash SET NOT NULL;
    ALTER TABLE credentials DROP CONSTRAINT IF EXISTS credentials_password_hash_argon2id;
    ALTER TABLE credentials ADD  CONSTRAINT credentials_password_hash_argon2id
      CHECK (password_hash LIKE '$argon2id$%');
  `);

  return { rehashed, seeded };
}
