// ============================================================================
//  Waits until the local Postgres container is accepting connections, so
//  `npm run db:reset` can chain `db:up` -> wait -> migrate reliably.
//
//  Usage:  node db/wait.mjs
// ============================================================================
import postgres from "postgres";
import { join } from "node:path";

try {
  process.loadEnvFile(join(process.cwd(), ".env"));
} catch {
  // no .env — use default below
}

const DATABASE_URL =
  process.env.DATABASE_URL || "postgres://ift542:ift542_dev_pw@127.0.0.1:5432/ift542";

const MAX_ATTEMPTS = 30;
const DELAY_MS = 1000;

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForDb() {
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const sql = postgres(DATABASE_URL, { max: 1, idle_timeout: 1, connect_timeout: 2 });
    try {
      await sql`SELECT 1`;
      await sql.end({ timeout: 1 });
      console.log(`Postgres is ready (attempt ${attempt}).`);
      return;
    } catch {
      await sql.end({ timeout: 1 }).catch(() => {});
      process.stdout.write(`  waiting for Postgres (${attempt}/${MAX_ATTEMPTS})...\r`);
      await delay(DELAY_MS);
    }
  }
  console.error("\nPostgres did not become ready in time. Is the container running?");
  process.exit(1);
}

waitForDb();
