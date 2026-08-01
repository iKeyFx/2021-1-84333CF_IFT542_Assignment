// ============================================================================
//  ir/rotate-secrets.mjs — eradication: rotate leaked secrets
//  [DELIVERED — Task 3 item 26]  Closes the T9 corrective control
//  ("invalidate sessions on leak") from report/2021-1-84333CF_IFT542_report.md Appendix A.
//
//  T9 is the finding that the repository shipped a hardcoded SESSION_SECRET and
//  a default admin account. Both are in git history at tag v0-vulnerable and
//  cannot be un-published; the only real remedy is rotation.
//
//  THE FREE WIN WORTH KNOWING: CSRF tokens are
//      <sid>.base64url(HMAC-SHA256(SESSION_SECRET, sid))   -- src/lib/csrf.ts
//  so rotating SESSION_SECRET invalidates every outstanding CSRF token at the
//  same time, with no extra step. Sessions are revoked here anyway, which is
//  the stronger control, but the token invalidation is what stops a captured
//  token being replayed against a *new* session.
//
//  WHAT THIS SCRIPT DOES AND DOES NOT DO:
//    DOES  rotate the admin password in the database (Argon2id), revoke every
//          session, and print the new SESSION_SECRET for the operator to place.
//    DOES NOT write .env. Deliberately: this artefact reads SESSION_SECRET at
//          process start, so a script that edited .env would leave the running
//          server on the old key and silently break every CSRF check until
//          someone noticed. Placing the value and restarting is a human step,
//          and the runbook says so.
//
//  Usage:
//    npm run ir:rotate-secrets -- --all                            (dry run)
//    npm run ir:rotate-secrets -- --all --incident INC-2026-001 --yes
//    npm run ir:rotate-secrets -- --role admin --incident INC-2026-001 --yes
// ============================================================================
import { hash } from "argon2";
import { randomBytes } from "node:crypto";
import {
  main,
  banner,
  maskEmail,
  resolveScope,
  confirmMutation,
  recordIrEvent,
  dryRunNotice,
  revokeFor,
} from "./_lib.mjs";

// MUST mirror ARGON2_OPTIONS in src/lib/password.ts and db/hash-passwords.mjs.
// tests/password-storage.test.ts parses stored digests and fails if they drift.
const ARGON2_OPTIONS = { type: 2, memoryCost: 19456, timeCost: 2, parallelism: 1, hashLength: 32 };

const HELP = `
ir/rotate-secrets.mjs — rotate credentials and the session secret (eradication, T9)

  SCOPE (exactly one, required) — which accounts get a new password
    --all                    every profile
    --email <address>        one account
    --role <student|admin>   every account with that role

  --incident <id>   required with --yes
  --yes             actually rotate. WITHOUT THIS THE SCRIPT ONLY REPORTS.
  --keep-sessions   do NOT revoke sessions (you almost never want this)
  --help            this text

Prints a fresh SESSION_SECRET for you to put in .env. It does not write .env
itself — the running server would keep the old key in memory.
`;

/** URL-safe, 256-bit. Same shape src/lib/config.ts expects. */
function newSecret() {
  return randomBytes(32).toString("base64url");
}

/**
 * A rotated password an operator can actually read off a terminal and type,
 * while still being high-entropy (~62 bits). Uppercase I/O and lowercase l are
 * excluded because this WILL be transcribed from a screenshot during an
 * exercise, and a misread character reads as "the rotation failed".
 */
function newPassword() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = randomBytes(20);
  let out = "";
  for (const b of bytes) out += alphabet[b % alphabet.length];
  return `${out.slice(0, 5)}-${out.slice(5, 10)}-${out.slice(10, 15)}-${out.slice(15, 20)}`;
}

await main(async (sql, args) => {
  if (args.help) {
    console.log(HELP.trim());
    return;
  }

  const { description, auditScope, profiles } = await resolveScope(sql, args);
  const ids = profiles.map((p) => p.id);
  const revokeSessions = args["keep-sessions"] !== true;

  banner(`SECRET ROTATION — scope: ${description}`);
  for (const p of profiles) {
    console.log(`  ${maskEmail(p.email).padEnd(24)} ${p.role}`);
  }
  console.log(`  ${profiles.length} account(s) would get a new Argon2id password`);
  console.log(`  sessions: ${revokeSessions ? "WILL be revoked" : "kept (--keep-sessions)"}`);
  console.log("  SESSION_SECRET: a new value will be printed for you to place in .env");

  if (!confirmMutation(args)) {
    dryRunNotice(args);
    return;
  }

  // ---- 1. Rotate passwords -------------------------------------------------
  const rotated = [];
  for (const p of profiles) {
    const plain = newPassword();
    const digest = await hash(plain, ARGON2_OPTIONS);
    await sql`
      UPDATE credentials SET password_hash = ${digest} WHERE profile_id = ${p.id}
    `;
    rotated.push({ email: p.email, role: p.role, plain });
  }

  // ---- 2. Revoke sessions --------------------------------------------------
  let deleted = 0;
  if (revokeSessions) deleted = await revokeFor(sql, ids);

  // ---- 3. A new session secret --------------------------------------------
  const secret = newSecret();

  // ---- 4. Audit ------------------------------------------------------------
  // The new password and the new secret are NOT recorded. An audit log that
  // contains the credential it rotated has simply moved the leak.
  await recordIrEvent(sql, {
    event: "ir.secrets.rotated",
    outcome: "rotated",
    incidentId: args.incident,
    detail: {
      scope: auditScope,
      passwords_rotated: rotated.length,
      sessions_revoked: deleted,
      session_secret_rotated: true,
      accounts: rotated.map((r) => maskEmail(r.email)),
    },
  });

  // ---- 5. Report to the operator ------------------------------------------
  console.log(`\n  ROTATED ${rotated.length} password(s); revoked ${deleted} session(s).`);

  banner("NEW CREDENTIALS — transcribe now, they are not stored anywhere");
  for (const r of rotated) {
    console.log(`  ${r.email.padEnd(28)} ${r.plain}`);
  }

  banner("NEW SESSION_SECRET — put this in .env, then restart the server");
  console.log(`  SESSION_SECRET=${secret}`);
  console.log("\n  Rotating SESSION_SECRET also invalidates every outstanding CSRF");
  console.log("  token, because a token is HMAC(SESSION_SECRET, sid) — src/lib/csrf.ts.");
  console.log("\n  This output contains live secrets. It is printed UNMASKED on purpose");
  console.log("  (you need to use it) — do NOT paste it into evidence or a ticket.");
  console.log("\n  Verify with: npm run ir:status");
});
