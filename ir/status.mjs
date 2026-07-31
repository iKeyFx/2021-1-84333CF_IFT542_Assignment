// ============================================================================
//  ir/status.mjs — read-only incident status
//  [DELIVERED — Task 3 item 26]
//
//  The command every runbook step ends with. Never mutates anything, takes no
//  scope flag, needs no --yes: during an incident you must be able to look at
//  the system without first deciding to change it.
//
//  Usage:  npm run ir:status
//          npm run ir:status -- --incident INC-2026-001   (filter the events)
//          npm run ir:status -- --events 20               (default 10)
// ============================================================================
import { main, banner, maskEmail } from "./_lib.mjs";

const HELP = `
ir/status.mjs — read-only incident status (no flags required)

  --incident <id>   only show security_events for this incident
  --events <n>      how many recent events to show (default 10)
  --help            this text

Shows: live sessions, accounts locked pending reset, audit-table health and the
most recent security events. Mutates nothing.
`;

await main(async (sql, args) => {
  if (args.help) {
    console.log(HELP.trim());
    return;
  }

  const limit = Number.parseInt(args.events ?? "10", 10);
  if (!Number.isFinite(limit) || limit < 1) {
    console.log("(--events must be a positive integer; using 10)");
  }
  const eventLimit = Number.isFinite(limit) && limit > 0 ? limit : 10;

  // ---- Live sessions (T1 / T9) --------------------------------------------
  banner("LIVE SESSIONS");
  const sessions = await sql`
    SELECT p.email, p.role, count(*)::int AS n, max(s.created_at) AS newest
    FROM sessions s JOIN profiles p ON p.id = s.profile_id
    GROUP BY p.email, p.role ORDER BY n DESC, p.email
  `;
  if (sessions.length === 0) {
    console.log("  none — no authenticated session exists");
  } else {
    for (const s of sessions) {
      console.log(
        `  ${maskEmail(s.email).padEnd(24)} ${s.role.padEnd(8)} ${String(s.n).padStart(3)} session(s)  newest ${s.newest.toISOString()}`
      );
    }
  }
  const [{ total: sessionTotal }] = await sql`SELECT count(*)::int AS total FROM sessions`;
  console.log(`  TOTAL: ${sessionTotal}`);

  // ---- Accounts locked pending reset (T5) ---------------------------------
  banner("PENDING CREDENTIAL RESETS");
  const resets = await sql`
    SELECT p.email, r.incident_id, r.reason, r.required_at, r.required_by
    FROM credential_resets r JOIN profiles p ON p.id = r.profile_id
    ORDER BY r.required_at DESC
  `;
  if (resets.length === 0) {
    console.log("  none — every account may log in normally");
  } else {
    for (const r of resets) {
      console.log(
        `  ${maskEmail(r.email).padEnd(24)} ${r.incident_id.padEnd(14)} ${r.reason}`
      );
      console.log(
        `    required ${r.required_at.toISOString()} by ${r.required_by}`
      );
    }
    console.log(
      `  TOTAL: ${resets.length} account(s) locked — login is refused even with the correct password`
    );
  }

  // ---- Audit sink health (T4) ---------------------------------------------
  banner("AUDIT LOG (security_events)");
  const [{ n: eventCount }] = await sql`SELECT count(*)::int AS n FROM security_events`;
  const triggers = await sql`
    SELECT tgname FROM pg_trigger
    WHERE tgrelid = 'security_events'::regclass AND NOT tgisinternal
    ORDER BY tgname
  `;
  const expected = ["security_events_no_change", "security_events_no_truncate"];
  const present = triggers.map((t) => t.tgname);
  const missing = expected.filter((t) => !present.includes(t));

  console.log(`  rows: ${eventCount}`);
  console.log(
    `  append-only triggers: ${missing.length === 0 ? "BOTH PRESENT" : `MISSING ${missing.join(", ")}`}`
  );
  if (missing.length > 0) {
    console.log("  !! the audit log is NOT tamper-evident — re-run `npm run db:reset`");
  } else {
    console.log("  (prove enforcement with: npm run ir:audit-log -- --verify)");
  }

  // ---- Recent events -------------------------------------------------------
  const filter = typeof args.incident === "string" ? args.incident : null;
  banner(filter ? `RECENT EVENTS — ${filter}` : "RECENT EVENTS");
  const events = filter
    ? await sql`
        SELECT occurred_at, event, level, outcome, actor_email, incident_id
        FROM security_events WHERE incident_id = ${filter}
        ORDER BY occurred_at DESC, id DESC LIMIT ${eventLimit}
      `
    : await sql`
        SELECT occurred_at, event, level, outcome, actor_email, incident_id
        FROM security_events
        ORDER BY occurred_at DESC, id DESC LIMIT ${eventLimit}
      `;

  if (events.length === 0) {
    console.log("  (no events recorded)");
  } else {
    for (const e of events) {
      const who = e.actor_email ?? "-";
      const inc = e.incident_id ? ` [${e.incident_id}]` : "";
      console.log(
        `  ${e.occurred_at.toISOString()}  ${e.level.padEnd(7)} ${e.event.padEnd(24)} ${e.outcome.padEnd(10)} ${who}${inc}`
      );
    }
  }

  console.log("");
});
