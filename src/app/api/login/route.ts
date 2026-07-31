// ============================================================================
//  POST /api/login  — HARDENED (Task 2).
//
//  This is the "after" side of the before/after demonstration. Compare against
//  the same path at tag `v0-vulnerable`:  git diff v0-vulnerable -- this file
//
//  Every Task 2 defect that lived here is remediated:
//   1. SQL injection      -> [FIXED] parameterized postgres.js tagged template;
//                            sql.unsafe() and string concatenation are gone.
//   2. Plaintext password -> [FIXED] account is fetched BY EMAIL, then the
//                            password is checked with argon2.verify() against a
//                            stored Argon2id digest. See src/lib/password.ts.
//   3. Verbose errors     -> [FIXED] driver messages, stack traces and the raw
//                            query are logged server-side only; the client gets
//                            a fixed string.
//   4. User enumeration   -> [FIXED] the second email-only lookup is deleted.
//                            Unknown-email and wrong-password return byte-
//                            identical bodies, and both run one Argon2id
//                            verification so they cost the same time too.
//   5. No rate limiting   -> [FIXED] per-IP fixed window, checked before any DB
//                            or hashing work. See src/lib/rate-limit.ts.
//   6. No session regen   -> [FIXED] establishSession() mints a fresh id and
//                            destroys the presented one. See src/lib/session.ts.
//
//  Task 3 additions:
//   - Origin/Referer check (the token itself is not required here — login is
//     pre-session, and the Task 2 PoC scripts post to it directly).
//   - All logging goes through the structured logger; the email is masked.
//   - Incident-response lock (item 26): a LEFT JOIN on credential_resets makes
//     ir/force-reset.mjs --require actually deny the login. See step 4.
// ============================================================================
import { NextResponse, type NextRequest } from "next/server";
import { sql } from "@/lib/db";
import { verifyPassword } from "@/lib/password";
import { validateCredentials } from "@/lib/validate";
import { checkRateLimit, recordFailure, resetRateLimit, clientIp } from "@/lib/rate-limit";
import { establishSession, buildSessionCookie, getPresentedSid } from "@/lib/session";
import { checkOrigin } from "@/lib/csrf";
import { logger } from "@/lib/logger";

// argon2 is a native module — pin this handler to the Node.js runtime.
export const runtime = "nodejs";

/**
 * The ONE error the client ever sees for a failed authentication, whatever the
 * actual cause: malformed body, bad email format, password too short, no such
 * account, or wrong password. Anything more specific is an oracle.
 */
const GENERIC_ERROR = { error: "Invalid email or password" } as const;

const PATH = "/api/login";

type AuthRow = {
  id: number;
  email: string;
  role: "student" | "admin";
  display_name: string;
  password_hash: string;
  /**
   * True when an incident responder has locked this account pending a
   * credential reset (ir/force-reset.mjs --require). See step 4 below.
   */
  must_reset: boolean;
};

export async function POST(req: NextRequest) {
  const ip = clientIp(req);
  const rateKey = `login:${ip}`;

  // [FIXED — Task 3] Login is exempt from the CSRF TOKEN (it is pre-session,
  // and the Task 2 proof-of-concept scripts post here directly), but it still
  // gets the Origin check. A browser cross-site login attempt sends a
  // mismatched or "null" Origin and is refused; a Node client sends none and is
  // allowed. See the trade-off note in src/lib/csrf.ts.
  if (!checkOrigin(req)) {
    logger.loginFailed({ ip, method: "POST", path: PATH, actor: null, reason: "bad-origin" });
    return NextResponse.json(GENERIC_ERROR, { status: 403 });
  }

  // ---- 1. Rate limit, before any DB or Argon2 work -------------------------
  const limit = checkRateLimit(rateKey);
  if (!limit.allowed) {
    logger.loginThrottled({ ip, method: "POST", path: PATH, actor: null, retry_after_s: limit.retryAfterSec });
    return NextResponse.json(
      { error: "Too many login attempts. Please try again later." },
      { status: 429, headers: { "Retry-After": String(limit.retryAfterSec) } }
    );
  }

  // ---- 2. Validate ---------------------------------------------------------
  const body = await req.json().catch(() => null);
  const input = validateCredentials(body);
  if (!input.ok) {
    // `reason` is a server-side log label and never reaches the client.
    logger.validationRejected({ ip, method: "POST", path: PATH, actor: null, reason: input.reason });
    recordFailure(rateKey);
    return NextResponse.json(GENERIC_ERROR, { status: 401 });
  }

  // ---- 3. Fetch the account BY EMAIL — parameterized -----------------------
  // postgres.js sends this as an extended-query with a $1 placeholder, so the
  // interpolated value is bound as DATA. An injection string such as
  //   ' OR '1'='1' --
  // is compared as a literal email address, matches nothing, and cannot change
  // the structure of the statement.
  //
  // The LEFT JOIN on credential_resets adds the incident-response lock
  // (Task 3 item 26). It is a primary-key lookup folded into the statement that
  // was already being issued, so it costs no extra round trip — which matters,
  // because a second query would make a locked account measurably slower and
  // reintroduce the timing oracle Task 2 removed.
  let rows: AuthRow[];
  try {
    rows = await sql<AuthRow[]>`
      SELECT p.id, p.email, p.role, p.display_name, c.password_hash,
             (r.profile_id IS NOT NULL) AS must_reset
      FROM profiles p
      JOIN credentials c ON c.profile_id = p.id
      LEFT JOIN credential_resets r ON r.profile_id = p.id
      WHERE p.email = ${input.email}
      LIMIT 1
    `;
  } catch (err) {
    // Full detail to the server log; nothing but a fixed string to the client.
    logger.serverError({ event: "auth.login.db_error", ip, method: "POST", path: PATH, actor: null, reason: String((err as Error)?.name ?? "error") });
    return NextResponse.json({ error: "Login failed" }, { status: 500 });
  }

  const account = rows[0] ?? null;

  // ---- 4. Verify ----------------------------------------------------------
  // verifyPassword always performs exactly one Argon2id verification, even when
  // `account` is null, so an unknown email costs the same time as a known email
  // with the wrong password.
  const ok = await verifyPassword(account?.password_hash ?? null, input.password);

  // `must_reset` is checked HERE — after the Argon2id verification, inside the
  // existing failure branch — and the placement is load-bearing:
  //
  //   1. NOT A TIMING ORACLE. One Argon2id operation has already run on every
  //      path, so a locked account does not answer faster than a wrong password.
  //      Returning early on the lock would make it measurably quicker.
  //   2. NOT A RESPONSE ORACLE. Same status, same body, no Set-Cookie. An
  //      attacker cannot learn which accounts a responder has flagged, which
  //      would otherwise tell them exactly which stolen credentials still work.
  //   3. The distinction survives only in the SERVER LOG, as auth.login.blocked.
  //
  // A helpful "your account is locked, check your email" would hand back the
  // enumeration oracle Task 2 spent its effort removing.
  if (!account || !ok || account.must_reset) {
    // The email is MASKED by the logger (a***@campus.local). The previous
    // implementation logged it verbatim, which put PII in the log file.
    const fields = { ip, method: "POST", path: PATH, actor: null, email: input.email };
    if (account && ok) {
      // Correct password presented to a locked account — the case a responder
      // most wants to see during an incident.
      logger.loginBlocked({ ...fields, reason: "reset-required" });
    } else {
      logger.loginFailed({ ...fields, reason: account ? "bad-password" : "unknown-account" });
    }
    recordFailure(rateKey);
    // Identical response for "no such account", "wrong password" and "locked".
    return NextResponse.json(GENERIC_ERROR, { status: 401 });
  }

  // ---- 5. Success: rotate the session, clear the throttle ------------------
  resetRateLimit(rateKey);
  const sid = await establishSession(account.id, getPresentedSid(req));
  logger.loginSucceeded({
    ip,
    method: "POST",
    path: PATH,
    actor: { profile_id: account.id, role: account.role },
  });

  const res = NextResponse.json({
    ok: true,
    user: { id: account.id, email: account.email, role: account.role },
  });
  // [FIXED — Task 3] The cookie now carries HttpOnly + SameSite=Lax + Secure.
  res.headers.append("Set-Cookie", buildSessionCookie(sid));
  return res;
}
