// ============================================================================
//  Vitest global setup: make sure a database and an app server are available.
//
//  Strategy is "probe, then spawn":
//   1. Preflight the database and fail with an ACTIONABLE message if it is not
//      migrated, rather than a postgres.js stack trace 20 tests later.
//   2. If a dev server is already listening on 127.0.0.1:3000, reuse it (fast
//      inner loop while developing).
//   3. Otherwise spawn `next dev` ourselves and tear it down afterwards, so
//      `npm test` is a single command for a marker.
//
//  Everything is pinned to 127.0.0.1 — this artefact is localhost-only.
// ============================================================================
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import postgres from "postgres";

const require = createRequire(import.meta.url);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

export const BASE_URL = "http://127.0.0.1:3000";

const DATABASE_URL =
  process.env.DATABASE_URL || "postgres://ift542:ift542_dev_pw@127.0.0.1:5432/ift542";

async function reachable(url: string): Promise<boolean> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(2_000) });
    return res.status < 500;
  } catch {
    return false;
  }
}

async function waitFor(check: () => Promise<boolean>, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`timed out after ${timeoutMs}ms waiting for the app server`);
}

export default async function setup() {
  // ---- 1. Database preflight ----------------------------------------------
  const sql = postgres(DATABASE_URL, { max: 1, connect_timeout: 5, onnotice: () => {} });
  try {
    await sql`SELECT password_hash FROM credentials LIMIT 1`;
    // Migration 003 (incident response) must be present too, or
    // tests/incident-response.test.ts fails with a raw driver error.
    await sql`SELECT 1 FROM credential_resets LIMIT 1`;
    await sql`SELECT 1 FROM security_events LIMIT 1`;
  } catch {
    throw new Error(
      "Database is not ready or not migrated.\n" +
        "  Run:  npm run db:reset\n" +
        `  (tried ${DATABASE_URL})`
    );
  }

  // ---- 1b. No account may start the run LOCKED -----------------------------
  // A crashed incident-response test could leave a credential_resets row
  // behind. Every subsequent run would then see that account's login refused
  // and blame the login handler — a confusing failure a long way from its
  // cause. Fail here instead, with the command that fixes it.
  try {
    const locked = await sql<{ email: string }[]>`
      SELECT p.email FROM credential_resets r JOIN profiles p ON p.id = r.profile_id
      ORDER BY p.email
    `;
    if (locked.length > 0) {
      throw new Error(
        `${locked.length} account(s) are locked pending a credential reset:\n` +
          locked.map((r) => `    ${r.email}`).join("\n") +
          "\n  A previous incident-response test probably did not clean up.\n" +
          "  Clear them with:  npm run db:reset\n" +
          "  (or: npm run ir:force-reset -- --complete --all --incident CLEANUP --yes)"
      );
    }
  } finally {
    await sql.end({ timeout: 1 }).catch(() => {});
  }

  // ---- 2. Reuse an already-running dev server ------------------------------
  if (await reachable(`${BASE_URL}/login`)) {
    console.log("[setup] reusing the dev server already on 127.0.0.1:3000");
    return () => {};
  }

  // ---- 3. Spawn one --------------------------------------------------------
  // Resolve Next's JS entry rather than the `next.cmd` shim: .cmd needs a shell
  // on Windows and orphans easily.
  console.log("[setup] starting `next dev` on 127.0.0.1:3000 ...");
  const child: ChildProcess = spawn(
    process.execPath,
    [require.resolve("next/dist/bin/next"), "dev", "--hostname", "127.0.0.1", "--port", "3000"],
    { cwd: ROOT, stdio: "ignore", env: { ...process.env, NODE_ENV: "development" } }
  );

  await waitFor(() => reachable(`${BASE_URL}/login`), 90_000);

  // Warm the page so the first API test is not paying for a cold compile.
  // Deliberately NOT warming POST /api/login — that would consume rate-limit
  // budget before any test runs.
  await fetch(`${BASE_URL}/login`).catch(() => {});
  console.log("[setup] dev server ready");

  return async () => {
    if (!child.pid) return;
    if (process.platform === "win32") {
      // child.kill() does not kill the process TREE on Windows: the Next
      // compiler worker survives and keeps port 3000 bound for the next run.
      spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
    } else {
      child.kill("SIGTERM");
    }
  };
}
