// ============================================================================
//  ir/force-reset.mjs — containment: lock accounts pending a credential reset
//  [DELIVERED — Task 3 item 26]  Closes the T5 corrective control
//  ("forced reset on suspected breach") from report/task1-threat-model.md §3.
//
//  T5 is the plaintext-password disclosure: the SQLi chain dumped all seven
//  credentials in cleartext (see report/incident-record.md). Hashing them in
//  Task 2 protects the store going forward but does nothing about the seven
//  passwords already in the attacker's hands. Those accounts must be locked
//  until their passwords change.
//
//  --require DOES TWO THINGS, AND THE SECOND IS THE IMPORTANT ONE:
//    1. inserts a credential_resets row, so login is refused; and
//    2. revokes that profile's sessions.
//  A forced reset that leaves live sessions authenticated is theatre. The
//  attacker holding a stolen sid never visits the login page, so step 1 alone
//  would inconvenience only the legitimate user.
//
//  HOW THE LOCK IS ENFORCED: src/app/api/login/route.ts LEFT JOINs this table
//  and folds `must_reset` into its EXISTING failure branch — after the Argon2id
//  verification, returning the same generic 401. A locked account is therefore
//  neither a timing oracle nor a response oracle. See that file's comments.
//
//  ---- HONEST LIMITATION: --complete IS NOT A PASSWORD-RESET FLOW ------------
//  --complete re-hashes the account back to its documented demo password from
//  db/hash-passwords.mjs and clears the lock. It exists so the exercise is
//  repeatable. It is NOT how a reset works in a real system, and it is not
//  presented as one.
//
//  A real deployment issues a single-use, time-limited, signed token over an
//  independently-verified channel and lets the USER choose a new password; the
//  operator never learns it. This artefact has no mail path and no reset UI, so
//  that flow does not exist here. report/appendix/response-runbook.md §"What a real
//  deployment adds" states the same thing.
//
//  Usage:
//    npm run ir:force-reset -- --require --all                       (dry run)
//    npm run ir:force-reset -- --require --email nova.trainee@campus.local --incident INC-2026-001 --yes
//    npm run ir:force-reset -- --complete --email nova.trainee@campus.local --incident INC-2026-001 --yes
// ============================================================================
import { hash } from "argon2";
import {
  main,
  banner,
  maskEmail,
  resolveScope,
  confirmMutation,
  recordIrEvent,
  dryRunNotice,
  revokeFor,
  operator,
  intArray,
  UsageError,
} from "./_lib.mjs";
import { demoPasswords } from "../db/hash-passwords.mjs";

// MUST mirror ARGON2_OPTIONS in src/lib/password.ts and db/hash-passwords.mjs.
const ARGON2_OPTIONS = { type: 2, memoryCost: 19456, timeCost: 2, parallelism: 1, hashLength: 32 };

const HELP = `
ir/force-reset.mjs — lock / unlock accounts pending credential reset (T5)

  MODE (exactly one, required)
    --require     lock: refuse login AND revoke sessions
    --complete    unlock: restore the demo password and clear the lock

  SCOPE (exactly one, required)
    --all                    every profile
    --email <address>        one account
    --role <student|admin>   every account with that role

  --incident <id>   required with --yes
  --reason <text>   recorded on the lock (default suspected-credential-compromise)
  --yes             actually apply. WITHOUT THIS THE SCRIPT ONLY REPORTS.
  --help            this text

A locked account is refused even when the password is correct, and the reply is
byte-identical to a wrong-password reply — no enumeration oracle.

--complete is this artefact's STAND-IN for a user completing a reset; it is not
a real reset flow. See the header of this file.
`;

await main(async (sql, args) => {
  if (args.help) {
    console.log(HELP.trim());
    return;
  }

  const modes = ["require", "complete"].filter((m) => args[m] === true);
  if (modes.length !== 1) {
    throw new UsageError("exactly one mode is required: --require or --complete");
  }
  const mode = modes[0];

  const { description, auditScope, profiles } = await resolveScope(sql, args);
  const ids = profiles.map((p) => p.id);
  const reason =
    typeof args.reason === "string" && args.reason.trim() !== ""
      ? args.reason.trim()
      : "suspected-credential-compromise";

  // Current lock state, so the dry run reports the DELTA rather than the scope.
  const locked = await sql`
    SELECT profile_id FROM credential_resets WHERE profile_id = ANY(${intArray(sql, ids)})
  `;
  const lockedIds = new Set(locked.map((r) => r.profile_id));

  // -------------------------------------------------------------- --require
  if (mode === "require") {
    const toLock = profiles.filter((p) => !lockedIds.has(p.id));

    banner(`FORCED RESET — LOCK — scope: ${description}`);
    if (toLock.length === 0) {
      console.log(`  all ${profiles.length} account(s) in scope are already locked — nothing to do`);
      dryRunNotice(args);
      return;
    }
    for (const p of toLock) console.log(`  ${maskEmail(p.email).padEnd(24)} ${p.role}`);
    console.log(`  ${toLock.length} account(s) to lock  (reason: ${reason})`);
    console.log(`  sessions for these accounts will also be revoked`);

    if (!confirmMutation(args)) {
      dryRunNotice(args);
      return;
    }

    const lockIds = toLock.map((p) => p.id);
    for (const p of toLock) {
      await sql`
        INSERT INTO credential_resets (profile_id, incident_id, reason, required_by)
        VALUES (${p.id}, ${args.incident}, ${reason}, ${operator()})
        ON CONFLICT (profile_id) DO NOTHING
      `;
    }

    // The half that makes this a control rather than a gesture.
    const revoked = await revokeFor(sql, lockIds);

    await recordIrEvent(sql, {
      event: "ir.credentials.reset_required",
      outcome: "locked",
      incidentId: args.incident,
      detail: {
        scope: auditScope,
        accounts_locked: toLock.length,
        sessions_revoked: revoked,
        reason,
        accounts: toLock.map((p) => maskEmail(p.email)),
      },
    });

    console.log(`\n  LOCKED ${toLock.length} account(s); revoked ${revoked} session(s).`);
    console.log("  Login is now refused for these accounts EVEN WITH THE CORRECT PASSWORD,");
    console.log("  with the same generic 401 as any other failure.");
    console.log("  Verify with: npm run ir:status");
    return;
  }

  // ------------------------------------------------------------- --complete
  const toUnlock = profiles.filter((p) => lockedIds.has(p.id));

  banner(`FORCED RESET — COMPLETE — scope: ${description}`);
  if (toUnlock.length === 0) {
    console.log(`  no account in scope is locked — nothing to do`);
    dryRunNotice(args);
    return;
  }
  for (const p of toUnlock) console.log(`  ${maskEmail(p.email).padEnd(24)} ${p.role}`);
  console.log(`  ${toUnlock.length} account(s) to unlock`);
  console.log("  each is re-hashed to its documented demo password (db/hash-passwords.mjs)");
  console.log("  NOTE: this is the artefact's stand-in for a user completing a reset.");

  if (!confirmMutation(args)) {
    dryRunNotice(args);
    return;
  }

  const passwords = demoPasswords();
  let restored = 0;
  const skipped = [];

  for (const p of toUnlock) {
    const plain = passwords[p.email];
    if (!plain) {
      // No demo password to restore. Leave the lock in place — silently
      // unlocking an account we cannot give a known password to would be worse.
      skipped.push(p.email);
      continue;
    }
    const digest = await hash(plain, ARGON2_OPTIONS);
    await sql`UPDATE credentials SET password_hash = ${digest} WHERE profile_id = ${p.id}`;
    await sql`DELETE FROM credential_resets WHERE profile_id = ${p.id}`;
    restored++;
  }

  await recordIrEvent(sql, {
    event: "ir.credentials.reset_completed",
    outcome: "unlocked",
    incidentId: args.incident,
    detail: {
      scope: auditScope,
      accounts_unlocked: restored,
      accounts_skipped: skipped.length,
      accounts: toUnlock.map((p) => maskEmail(p.email)),
      method: "demo-password-restore (artefact stand-in, not a real reset flow)",
    },
  });

  console.log(`\n  UNLOCKED ${restored} account(s).`);
  if (skipped.length > 0) {
    console.log(`  ${skipped.length} left LOCKED — no demo password on record:`);
    for (const e of skipped) console.log(`    ${maskEmail(e)}`);
  }
  console.log("  Verify with: npm run ir:status");
});
