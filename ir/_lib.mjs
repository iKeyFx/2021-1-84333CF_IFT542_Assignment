// ============================================================================
//  IFT542 — Incident-response toolkit: shared helpers
//  [DELIVERED — Task 3 item 26]
//
//  These are the four CORRECTIVE controls the risk register
//  (report/task1-threat-model.md §3) promised but never built:
//
//    T1  session revocation + runbook          ir/revoke-sessions.mjs
//    T9  invalidate sessions on leak           ir/rotate-secrets.mjs
//    T5  forced reset on suspected breach      ir/force-reset.mjs
//    T4  append-only retention                 ir/audit-log.mjs
//
//  report/incident-runbook.md drives every step through these commands, so a
//  responder types a command rather than interpreting a paragraph.
//
//  ---- SAFETY CONTRACT (enforced here, uniform across all scripts) ----------
//    * --dry-run is the DEFAULT. Nothing mutates without an explicit --yes.
//    * --incident <id> is MANDATORY for any mutation, so every action taken
//      during a response is attributable to a specific incident record.
//    * Exactly one scope flag (--all | --email | --role) is required. There is
//      no implicit "everything".
//    * Every mutation writes an ir.* row to security_events, so the response
//      itself is audited by the same append-only control it manages.
//
//  Exit codes: 0 success, 1 runtime failure, 2 usage error.
//
//  LOCALHOST ONLY. Operates on the local docker-compose Postgres and the
//  fictitious seed data. See ETHICS.md.
// ============================================================================
import postgres from "postgres";
import { hostname, userInfo } from "node:os";
import { join } from "node:path";

// db/migrate.mjs does this too — .env must be loaded before DATABASE_URL is read.
try {
  process.loadEnvFile(join(process.cwd(), ".env"));
} catch {
  // no .env — the default below is the docker-compose credential
}

export const DATABASE_URL =
  process.env.DATABASE_URL || "postgres://ift542:ift542_dev_pw@127.0.0.1:5432/ift542";

export function connect() {
  return postgres(DATABASE_URL, { onnotice: () => {} });
}

// ---------------------------------------------------------------------------
//  Argument parsing
// ---------------------------------------------------------------------------
/**
 * Minimal parser: `--flag`, `--key value` and `--key=value`.
 * Deliberately dependency-free — an IR tool that needs `npm install` to run
 * during an incident is not a control.
 */
export function parseArgs(argv = process.argv.slice(2)) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith("--")) {
      args._.push(token);
      continue;
    }
    const body = token.slice(2);
    const eq = body.indexOf("=");
    if (eq !== -1) {
      args[body.slice(0, eq)] = body.slice(eq + 1);
      continue;
    }
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith("--")) {
      args[body] = next;
      i++;
    } else {
      args[body] = true;
    }
  }
  return args;
}

export class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = "UsageError";
  }
}

/**
 * Postgres OID for int4. `sql.array(ids)` alone infers a TEXT array, which
 * makes `profiles.id = ANY($1)` fail with "operator does not exist:
 * integer = text". The element type has to be stated.
 */
const INT4 = 23;

/** An int4[] parameter safe to use with `= ANY(...)`, including when empty. */
export function intArray(sql, ids) {
  return sql.array(ids, INT4);
}

/**
 * Resolve the target scope. Exactly one of --all / --email / --role.
 *
 * Returns TWO phrasings of the same scope, and the split is deliberate:
 *
 *   description  RAW — printed to the operator's own terminal. The confirmation
 *                step is exactly where you want to see the full address you are
 *                about to lock, spelled out.
 *   auditScope   MASKED — the phrasing that gets PERSISTED to security_events.
 *
 * Without the split, `--email ada@…` wrote the full address into the audit
 * record's `scope` field while the sibling `accounts` field was masked — the
 * record leaked the PII that src/lib/logger.ts exists to keep out of logs. The
 * profile_id in credential_resets is enough to identify the account exactly, so
 * the stored copy of the address is unnecessary as well as inconsistent.
 */
export async function resolveScope(sql, args) {
  const given = ["all", "email", "role"].filter((k) => args[k] !== undefined);

  if (given.length === 0) {
    throw new UsageError(
      "a scope is required: --all, --email <address> or --role <student|admin>"
    );
  }
  if (given.length > 1) {
    throw new UsageError(`scope flags are mutually exclusive (got --${given.join(", --")})`);
  }

  if (args.all === true) {
    const profiles = await sql`SELECT id, email, role FROM profiles ORDER BY id`;
    return { description: "all profiles", auditScope: "all profiles", profiles };
  }

  if (args.email !== undefined) {
    if (typeof args.email !== "string") throw new UsageError("--email needs an address");
    const profiles = await sql`
      SELECT id, email, role FROM profiles WHERE email = ${args.email}
    `;
    if (profiles.length === 0) {
      // Not a UsageError: during a real response "that account does not exist"
      // is a finding, not a typo, and the operator should see it as one.
      throw new Error(`no profile with email ${args.email}`);
    }
    return {
      description: `email = ${args.email}`,
      auditScope: `email = ${maskEmail(args.email)}`,
      profiles,
    };
  }

  if (args.role !== "student" && args.role !== "admin") {
    throw new UsageError("--role must be 'student' or 'admin'");
  }
  const profiles = await sql`SELECT id, email, role FROM profiles WHERE role = ${args.role} ORDER BY id`;
  return { description: `role = ${args.role}`, auditScope: `role = ${args.role}`, profiles };
}

/**
 * The mutation gate. Returns true only when the operator has supplied BOTH
 * --yes and --incident. Everything else is a dry run.
 *
 * `--incident` being required for mutation (but not for a dry run) is the
 * point: you can always look, but you cannot act anonymously.
 */
export function confirmMutation(args) {
  const wants = args.yes === true;
  if (!wants) return false;
  if (typeof args.incident !== "string" || args.incident.trim() === "") {
    throw new UsageError(
      "--yes requires --incident <id> so the action is attributable " +
        "(e.g. --incident INC-2026-001; see report/incident-record.md)"
    );
  }
  return true;
}

/**
 * Who is running this. Recorded on every ir.* event and on every lock.
 *
 * Operator identity is the "who" of who/what/when, so it is deliberately NOT
 * masked — an unattributable response action is the T4 threat all over again.
 * IR_OPERATOR overrides the OS-derived default, which is useful when capturing
 * evidence: the real value is `<windows-user>@<machine-name>`, and a marker has
 * no need for the student's hostname.
 */
export function operator() {
  const override = process.env.IR_OPERATOR;
  if (typeof override === "string" && override.trim() !== "") return override.trim();
  try {
    return `${userInfo().username}@${hostname()}`;
  } catch {
    return "unknown-operator";
  }
}

/**
 * Append an ir.* row to security_events.
 *
 * The response is audited by the same append-only control it administers —
 * including ir/audit-log.mjs itself, which cannot erase its own tracks.
 *
 * NO SECRETS EVER GO IN `detail`. Callers pass counts and identifiers; the new
 * admin password, session ids and tokens are all excluded at the call site.
 * Emails are masked here with the same rule as src/lib/logger.ts.
 */
export async function recordIrEvent(sql, { event, outcome = "ok", incidentId, detail = {} }) {
  await sql`
    INSERT INTO security_events (event, level, outcome, actor_email, incident_id, detail)
    VALUES (
      ${event},
      'notice',
      ${outcome},
      ${operator()},
      ${incidentId ?? null},
      ${sql.json(detail)}
    )
  `;
}

/**
 * Delete every server-side session for the given profiles; returns the count.
 *
 * Lives here rather than in revoke-sessions.mjs because force-reset.mjs needs
 * it too, and importing it from a script whose module body calls main() would
 * run that script as a side effect of the import.
 */
export async function revokeFor(sql, profileIds) {
  if (profileIds.length === 0) return 0;
  const deleted = await sql`
    DELETE FROM sessions WHERE profile_id = ANY(${intArray(sql, profileIds)}) RETURNING id
  `;
  return deleted.length;
}

/** Mirrors redactEmail() in src/lib/logger.ts: a***@campus.local */
export function maskEmail(email) {
  if (typeof email !== "string" || !email.includes("@")) return "[redacted]";
  const [local, domain] = email.split("@");
  if (local.length === 0) return `***@${domain}`;
  return `${local[0]}***@${domain}`;
}

// ---------------------------------------------------------------------------
//  Output helpers — plain text, greppable, no colour codes
// ---------------------------------------------------------------------------
export function banner(title) {
  console.log(`\n=== ${title} ===`);
}

export function dryRunNotice(args) {
  if (confirmMutationSafe(args)) return;
  console.log(
    "\n[DRY RUN] Nothing was changed. Re-run with --yes --incident <id> to apply."
  );
}

function confirmMutationSafe(args) {
  try {
    return confirmMutation(args);
  } catch {
    return false;
  }
}

/**
 * Fail early and legibly if migration 003 has not been applied, rather than
 * surfacing a raw "relation does not exist" from the driver mid-incident.
 */
export async function preflight(sql) {
  const rows = await sql`
    SELECT table_name FROM information_schema.tables
    WHERE table_name IN ('credential_resets', 'security_events')
  `;
  if (rows.length < 2) {
    throw new Error(
      "incident-response schema missing — run `npm run db:reset` " +
        "(db/migrations/003_incident_response.sql)"
    );
  }
}

/**
 * Standard entry point. Handles connect, preflight, error classification and
 * teardown so each script is only its own logic.
 *
 * Uses process.exitCode rather than process.exit(): on Windows, exiting while a
 * socket is still closing trips a libuv assertion and aborts with 127, which
 * corrupts captured evidence. The same fix was applied to the tests/*.mjs PoCs.
 */
export async function main(fn, { skipPreflight = false } = {}) {
  const args = parseArgs();
  const sql = connect();
  try {
    // Validate the safety contract BEFORE touching the database, so a malformed
    // invocation exits 2 without having reported anything or done any work.
    if (!args.help) confirmMutation(args);
    if (!skipPreflight) await preflight(sql);
    await fn(sql, args);
    process.exitCode = 0;
  } catch (err) {
    if (err instanceof UsageError) {
      console.error(`\nusage error: ${err.message}`);
      process.exitCode = 2;
    } else {
      console.error(`\nfailed: ${err.message}`);
      process.exitCode = 1;
    }
  } finally {
    await sql.end({ timeout: 5 }).catch(() => {});
  }
}
