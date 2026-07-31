// ============================================================================
//  ir/audit-log.mjs — append-only audit retention
//  [DELIVERED — Task 3 item 26]  Closes the T4 corrective control
//  ("append-only retention") from report/task1-threat-model.md §3.
//
//  T4 is "unattributable actions": in the v0 build nothing was logged, so the
//  intrusion documented in report/incident-record.md could not be detected at
//  the time and had to be RECONSTRUCTED from test captures afterwards. Task 3
//  added structured logging (src/lib/logger.ts); this closes the other half —
//  a sink those records cannot be edited or deleted out of.
//
//  ---- WHAT --ingest HONESTLY IS -------------------------------------------
//  The application does NOT write to security_events. src/lib/logger.ts emits
//  JSON Lines to stdout and knows nothing about a database — it must stay
//  edge-safe, because src/middleware.ts imports it and the edge runtime has no
//  node: builtins and no DB handle.
//
//  --ingest is therefore a LOG SHIPPER, standing in for the real one. In a
//  production deployment you replace this with Vector / Fluent Bit / the
//  platform's log pipeline, writing to WORM or object storage with a retention
//  lock. The shape is the same — read JSON Lines, map fields, append — which is
//  the point of demonstrating it this way.
//
//  Usage:
//    npm run ir:audit-log -- --verify                  prove append-only
//    npm run ir:audit-log -- --tail 20                 read recent records
//    npm run ir:audit-log -- --ingest --file server.log
//    npm run dev 2>&1 | node ir/audit-log.mjs --ingest
// ============================================================================
import { createInterface } from "node:readline";
import { createReadStream } from "node:fs";
import { main, banner, UsageError } from "./_lib.mjs";

const HELP = `
ir/audit-log.mjs — append-only audit retention (T4)

  MODE (exactly one, required)
    --verify              actively attempt UPDATE / DELETE / TRUNCATE and
                          assert each is refused with SQLSTATE 42501
    --ingest              read JSON Lines and append them to security_events
    --tail [n]            print the n most recent records (default 20)

  --file <path>     with --ingest: read this file instead of stdin
  --incident <id>   with --ingest: stamp the ingested records
  --help            this text

--verify runs inside a transaction that is ALWAYS rolled back, so it is safe to
run at any time, including on a live incident.
`;

// ---------------------------------------------------------------------------
//  --verify
// ---------------------------------------------------------------------------
/**
 * Prove enforcement rather than assert configuration.
 *
 * Checking pg_trigger alone would only show the triggers are DEFINED. The
 * mutations below prove they FIRE, and the zero-row DELETE proves the trigger
 * is statement-level: a row-level BEFORE DELETE trigger does not fire when
 * nothing matches, so that case would pass vacuously and the control would be
 * bypassable with a WHERE clause that matches nothing.
 *
 * Everything runs inside a rolled-back transaction. If a mutation were ever
 * ALLOWED, the rollback is what stops this diagnostic from destroying the audit
 * trail it is checking.
 */
async function verify(sql) {
  banner("APPEND-ONLY VERIFICATION — security_events");

  const results = [];

  // 1. Definition check.
  const triggers = await sql`
    SELECT tgname FROM pg_trigger
    WHERE tgrelid = 'security_events'::regclass AND NOT tgisinternal
    ORDER BY tgname
  `;
  const present = triggers.map((t) => t.tgname);
  for (const expected of ["security_events_no_change", "security_events_no_truncate"]) {
    results.push({
      check: `trigger ${expected} defined`,
      pass: present.includes(expected),
      detail: present.includes(expected) ? "present" : "MISSING",
    });
  }

  // 2. Enforcement checks. Each in its own rolled-back transaction so one
  //    failure cannot poison the next (an aborted tx rejects further commands).
  const attempts = [
    ["INSERT is permitted", "insert", async (tx) => {
      await tx`
        INSERT INTO security_events (event, level, outcome, detail)
        VALUES ('ir.audit.verify', 'debug', 'probe', '{}'::jsonb)
      `;
    }],
    ["UPDATE is refused", "42501", async (tx) => {
      await tx`UPDATE security_events SET outcome = 'tampered'`;
    }],
    ["DELETE is refused", "42501", async (tx) => {
      await tx`DELETE FROM security_events`;
    }],
    ["DELETE matching ZERO rows is refused", "42501", async (tx) => {
      await tx`DELETE FROM security_events WHERE id = -1`;
    }],
    ["TRUNCATE is refused", "42501", async (tx) => {
      await tx.unsafe("TRUNCATE security_events");
    }],
  ];

  for (const [label, expect, run] of attempts) {
    let outcome;
    try {
      await sql.begin(async (tx) => {
        await run(tx);
        // Never keep it, not even the INSERT probe: --verify must be free of
        // side effects so it can be run repeatedly during an incident.
        throw new Error("__rollback__");
      });
      outcome = { code: "committed", pass: false };
    } catch (err) {
      if (err.message === "__rollback__") {
        outcome = { code: "allowed (rolled back)", pass: expect === "insert" };
      } else {
        outcome = { code: err.code ?? "?", pass: err.code === expect };
      }
    }
    results.push({ check: label, pass: outcome.pass, detail: outcome.code });
  }

  for (const r of results) {
    console.log(`  [${r.pass ? "PASS" : "FAIL"}] ${r.check.padEnd(38)} ${r.detail}`);
  }

  const failed = results.filter((r) => !r.pass);
  if (failed.length > 0) {
    console.log(`\n  ${failed.length} CHECK(S) FAILED — the audit log is not tamper-evident.`);
    throw new Error("append-only verification failed");
  }
  console.log(`\n  ALL ${results.length} CHECKS PASSED — security_events is append-only.`);
  console.log("  Records may be added but never altered or removed, by anyone,");
  console.log("  including the table owner the application connects as.");
}

// ---------------------------------------------------------------------------
//  --ingest
// ---------------------------------------------------------------------------
/**
 * Map one src/lib/logger.ts JSON line onto a security_events row.
 * Returns null for anything that is not one of our events, so ordinary Next.js
 * stdout noise passes through a `npm run dev | ir:audit-log --ingest` pipe
 * without polluting the table.
 */
function mapLine(line, incidentId) {
  let obj;
  try {
    obj = JSON.parse(line);
  } catch {
    return null;
  }
  if (!obj || typeof obj !== "object") return null;
  if (typeof obj.event !== "string") return null;

  return {
    occurred_at: typeof obj.ts === "string" ? obj.ts : new Date().toISOString(),
    event: obj.event,
    level: typeof obj.level === "string" ? obj.level : "info",
    outcome: typeof obj.outcome === "string" ? obj.outcome : "",
    // The logger has ALREADY masked the email (a***@campus.local) and dropped
    // every deny-listed field. Nothing is re-redacted here, because re-deriving
    // redaction at the sink would let an un-redacted path exist upstream.
    actor_profile_id: Number.isInteger(obj.profile_id) ? obj.profile_id : null,
    actor_email: typeof obj.email === "string" ? obj.email : null,
    actor_ip: typeof obj.ip === "string" ? obj.ip : null,
    incident_id: incidentId ?? null,
    detail: obj,
  };
}

async function ingest(sql, args) {
  const incidentId = typeof args.incident === "string" ? args.incident : null;

  const input =
    typeof args.file === "string"
      ? createReadStream(args.file, { encoding: "utf8" })
      : process.stdin;

  if (typeof args.file !== "string" && process.stdin.isTTY) {
    throw new UsageError(
      "--ingest reads JSON Lines from stdin; give it a pipe or use --file <path>"
    );
  }

  banner(`AUDIT INGEST — ${typeof args.file === "string" ? args.file : "stdin"}`);

  let read = 0;
  let appended = 0;
  const byEvent = new Map();

  for await (const line of createInterface({ input, crlfDelay: Infinity })) {
    if (line.trim() === "") continue;
    read++;
    const row = mapLine(line, incidentId);
    if (!row) continue;

    await sql`INSERT INTO security_events ${sql(row)}`;
    appended++;
    byEvent.set(row.event, (byEvent.get(row.event) ?? 0) + 1);
  }

  console.log(`  read ${read} line(s), appended ${appended} record(s)`);
  for (const [event, n] of [...byEvent].sort((a, b) => b[1] - a[1])) {
    console.log(`    ${String(n).padStart(4)}  ${event}`);
  }
  if (appended === 0 && read > 0) {
    console.log("  (no line carried an `event` field — was this a logger stream?)");
  }
  console.log("\n  Records are now append-only. Verify: npm run ir:audit-log -- --verify");
}

// ---------------------------------------------------------------------------
//  --tail
// ---------------------------------------------------------------------------
async function tail(sql, args) {
  const raw = args.tail === true ? "20" : String(args.tail);
  const n = Number.parseInt(raw, 10);
  const limit = Number.isFinite(n) && n > 0 ? n : 20;

  banner(`AUDIT LOG — most recent ${limit}`);
  const rows = await sql`
    SELECT occurred_at, event, level, outcome, actor_email, actor_ip, incident_id
    FROM security_events ORDER BY occurred_at DESC, id DESC LIMIT ${limit}
  `;
  if (rows.length === 0) {
    console.log("  (empty — ingest some with: npm run ir:audit-log -- --ingest --file <log>)");
    return;
  }
  for (const r of rows) {
    const inc = r.incident_id ? ` [${r.incident_id}]` : "";
    console.log(
      `  ${r.occurred_at.toISOString()}  ${r.level.padEnd(7)} ${r.event.padEnd(26)} ` +
        `${r.outcome.padEnd(12)} ${(r.actor_email ?? "-").padEnd(24)} ${r.actor_ip ?? "-"}${inc}`
    );
  }
  console.log(`\n  ${rows.length} record(s). Emails are masked at source by src/lib/logger.ts.`);
}

// ---------------------------------------------------------------------------
await main(async (sql, args) => {
  if (args.help) {
    console.log(HELP.trim());
    return;
  }

  const modes = ["verify", "ingest", "tail"].filter((m) => args[m] !== undefined);
  if (modes.length !== 1) {
    throw new UsageError("exactly one mode is required: --verify, --ingest or --tail");
  }

  if (modes[0] === "verify") return verify(sql);
  if (modes[0] === "ingest") return ingest(sql, args);
  return tail(sql, args);
});
