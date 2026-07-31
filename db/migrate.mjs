// ============================================================================
//  Migration + seed runner for the IFT542 teaching artefact.
//  Runs every db/migrations/*.sql (in filename order), then db/seed.sql.
//  Uses postgres.js because the host has no `psql` on PATH.
//
//  Usage:  node db/migrate.mjs
// ============================================================================
import postgres from "postgres";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

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

  const [{ count: students }] = await sql`SELECT count(*)::int FROM profiles WHERE role = 'student'`;
  const [{ count: courses }] = await sql`SELECT count(*)::int FROM courses`;
  const [{ count: enrolments }] = await sql`SELECT count(*)::int FROM enrolments`;
  console.log(
    `\nSeeded: ${students} students, ${courses} courses, ${enrolments} enrolments, 1 admin.`
  );
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
