// ============================================================================
//  Migration + seed runner for the IFT542 teaching artefact.
//  Runs every db/migrations/*.sql (in filename order), then db/seed.sql, then
//  the Argon2id credential migration in db/hash-passwords.mjs.
//  Uses postgres.js because the host has no `psql` on PATH.
//
//  Usage:  node db/migrate.mjs
//          node db/migrate.mjs --legacy-plaintext
//
//  --legacy-plaintext stages the v0-vulnerable plaintext credentials first, so
//  the Argon2id step demonstrates a real backfill-and-drop migration of an
//  existing plaintext store. Without the flag, plaintext never touches the DB.
// ============================================================================
import postgres from "postgres";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { migrateCredentials, seedLegacyPlaintext } from "./hash-passwords.mjs";

// Load .env if present (Node >= 20.6 has loadEnvFile).
try {
  process.loadEnvFile(join(process.cwd(), ".env"));
} catch {
  // no .env — fall back to the default below
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATABASE_URL =
  process.env.DATABASE_URL || "postgres://ift542:ift542_dev_pw@127.0.0.1:5432/ift542";

const sql = postgres(DATABASE_URL, { onnotice: () => {} });

const LEGACY_PLAINTEXT = process.argv.includes("--legacy-plaintext");

async function run() {
  const migrationsDir = join(__dirname, "migrations");
  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort();

  for (const file of files) {
    const content = readFileSync(join(migrationsDir, file), "utf8");
    process.stdout.write(`  → applying migration ${file} ... `);
    await sql.unsafe(content);
    console.log("done");
  }

  const seed = readFileSync(join(__dirname, "seed.sql"), "utf8");
  process.stdout.write("  → seeding fictitious data ... ");
  await sql.unsafe(seed);
  console.log("done");

  // ---- Argon2id credential migration [FIXED — Task 2] ----------------------
  if (LEGACY_PLAINTEXT) {
    process.stdout.write("  → staging v0 PLAINTEXT credentials (demo only) ... ");
    const staged = await seedLegacyPlaintext(sql);
    console.log(`done (${staged})`);

    const sample = await sql`
      SELECT p.email, c.password
      FROM credentials c JOIN profiles p ON p.id = c.profile_id
      ORDER BY p.id LIMIT 3
    `;
    console.log("    before:");
    for (const r of sample) console.log(`      ${r.email.padEnd(28)} ${r.password}`);
  }

  process.stdout.write("  → hashing credentials with Argon2id ... ");
  const { rehashed, seeded } = await migrateCredentials(sql);
  console.log(`done (re-hashed ${rehashed}, seeded ${seeded})`);

  if (LEGACY_PLAINTEXT) {
    const sample = await sql`
      SELECT p.email, left(c.password_hash, 40) AS digest
      FROM credentials c JOIN profiles p ON p.id = c.profile_id
      ORDER BY p.id LIMIT 3
    `;
    console.log("    after:");
    for (const r of sample) console.log(`      ${r.email.padEnd(28)} ${r.digest}…`);
  }

  // Fail the migration loudly if anything is not an Argon2id digest.
  const [{ bad }] = await sql`
    SELECT count(*)::int AS bad FROM credentials WHERE password_hash NOT LIKE '$argon2id$%'
  `;
  if (bad > 0) throw new Error(`${bad} credential row(s) are not Argon2id digests`);

  const [{ count: students }] = await sql`SELECT count(*)::int FROM profiles WHERE role = 'student'`;
  const [{ count: courses }] = await sql`SELECT count(*)::int FROM courses`;
  const [{ count: enrolments }] = await sql`SELECT count(*)::int FROM enrolments`;
  const [{ count: creds }] = await sql`SELECT count(*)::int FROM credentials`;
  console.log(
    `\nSeeded: ${students} students, ${courses} courses, ${enrolments} enrolments, 1 admin.`
  );
  console.log(`Credentials: ${creds} rows, all Argon2id, no plaintext column.`);
}

run()
  .then(() => sql.end())
  .then(() => {
    console.log("Migration + seed complete.");
    process.exit(0);
  })
  .catch(async (err) => {
    console.error("\nMigration failed:", err.message);
    await sql.end({ timeout: 1 }).catch(() => {});
    process.exit(1);
  });
