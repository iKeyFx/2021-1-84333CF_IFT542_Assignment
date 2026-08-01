// ============================================================================
//  ir/revoke-sessions.mjs — containment: kill authenticated sessions
//  [DELIVERED — Task 3 item 26]  Closes the T1 corrective control
//  ("session revocation + runbook") promised in report/2021-1-84333CF_IFT542_report.md Appendix A.
//
//  WHY THIS IS THE FIRST CONTAINMENT STEP:
//  T1 (SQL-injection auth bypass) hands the attacker a *session*, not a
//  password. Patching the query — which Task 2 did — stops new bypasses but
//  does nothing about the sid already issued at 12:17:31, which stays valid for
//  its full 24 h lifetime. Deleting the sessions row is what actually ends the
//  attacker's access, because src/lib/auth.ts resolves the cookie against this
//  table on every request.
//
//  EFFECT ON THE REVOKED CLIENT: src/middleware.ts only redirects when the sid
//  cookie is ABSENT, so a revoked-but-present cookie falls through to
//  currentUser() -> redirect("/login"), i.e. a 307. That is the live probe used
//  by tests/incident-response.test.ts.
//
//  Usage:
//    npm run ir:revoke-sessions -- --all                        (dry run)
//    npm run ir:revoke-sessions -- --all --incident INC-2026-001 --yes
//    npm run ir:revoke-sessions -- --email nova.trainee@campus.local --incident INC-2026-001 --yes
//    npm run ir:revoke-sessions -- --role admin --incident INC-2026-001 --yes
// ============================================================================
import {
  main,
  banner,
  maskEmail,
  resolveScope,
  confirmMutation,
  recordIrEvent,
  dryRunNotice,
  revokeFor,
  intArray,
} from "./_lib.mjs";

const HELP = `
ir/revoke-sessions.mjs — delete server-side sessions (containment, T1/T9)

  SCOPE (exactly one, required)
    --all                    every profile
    --email <address>        one account
    --role <student|admin>   every account with that role

  --incident <id>   required with --yes; recorded on the audit event
  --yes             actually delete. WITHOUT THIS THE SCRIPT ONLY REPORTS.
  --help            this text

Revoked users are logged out immediately: the next request finds no session row
and is redirected to /login (307).
`;

await main(async (sql, args) => {
  if (args.help) {
    console.log(HELP.trim());
    return;
  }

  const { description, auditScope, profiles } = await resolveScope(sql, args);
  const ids = profiles.map((p) => p.id);

  banner(`SESSION REVOCATION — scope: ${description}`);

  const live = await sql`
    SELECT p.id, p.email, p.role, count(s.id)::int AS n
    FROM profiles p LEFT JOIN sessions s ON s.profile_id = p.id
    WHERE p.id = ANY(${intArray(sql, ids)})
    GROUP BY p.id, p.email, p.role
    HAVING count(s.id) > 0
    ORDER BY p.id
  `;

  const totalLive = live.reduce((sum, r) => sum + r.n, 0);

  if (totalLive === 0) {
    console.log("  no live sessions in scope — nothing to revoke");
    // Still record the check when acting under an incident: "we looked and it
    // was already clean" is a finding worth having in the audit trail.
    if (confirmMutation(args)) {
      await recordIrEvent(sql, {
        event: "ir.sessions.revoked",
        outcome: "no-op",
        incidentId: args.incident,
        detail: { scope: auditScope, profiles_in_scope: ids.length, sessions_deleted: 0 },
      });
      console.log("  recorded a no-op to security_events");
    }
    dryRunNotice(args);
    return;
  }

  for (const r of live) {
    console.log(`  ${maskEmail(r.email).padEnd(24)} ${r.role.padEnd(8)} ${r.n} session(s)`);
  }
  console.log(`  ${totalLive} session(s) across ${live.length} account(s)`);

  if (!confirmMutation(args)) {
    console.log("\n  would DELETE the above from `sessions`");
    dryRunNotice(args);
    return;
  }

  const deleted = await revokeFor(sql, ids);

  await recordIrEvent(sql, {
    event: "ir.sessions.revoked",
    outcome: "revoked",
    incidentId: args.incident,
    detail: {
      scope: auditScope,
      profiles_in_scope: ids.length,
      accounts_affected: live.length,
      sessions_deleted: deleted,
      // Session ids are deliberately NOT recorded: a sid is a bearer credential,
      // and an audit log is exactly the wrong place to keep one.
    },
  });

  console.log(`\n  REVOKED ${deleted} session(s).`);
  console.log("  Affected users are logged out on their next request (307 -> /login).");
  console.log("  Verify with: npm run ir:status");
});
