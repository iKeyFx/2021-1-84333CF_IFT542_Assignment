// ============================================================================
//  POST /api/login  — the CENTREPIECE of the exercise.
//
//  This single handler concentrates the Task 2 authentication vulnerabilities:
//   1. SQL injection      — the login SQL is built by string-concatenating the
//                           raw email/password into sql.unsafe(...).
//   2. Plaintext password — the password is compared as plaintext in SQL.
//   3. Verbose errors     — DB errors, stack traces and the raw query are
//                           returned to the client (gated by DEBUG, on).
//   4. User enumeration   — failed logins reveal WHICH field was wrong.
//   5. No rate limiting   — there is no throttle/lockout on repeated attempts.
//   6. No session regen    — the presented sid is reused (session fixation).
//
//  A hardened version (parameterized query, hashed+salted password compare,
//  generic error, rate limit, session rotation) will replace this in the
//  follow-up session for the before/after demo.
// ============================================================================
import { NextResponse, type NextRequest } from "next/server";
import { sql } from "@/lib/db";
import { DEBUG } from "@/lib/config";
import { establishSession, buildSessionCookie, getPresentedSid } from "@/lib/session";

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const email = String(body.email ?? "");
  const password = String(body.password ?? "");

  // [VULN: No rate limiting — Task 2]
  // A real login would track attempts per account/IP and back off or lock out.
  // Nothing here does — an attacker can brute-force or spray freely.

  // --------------------------------------------------------------------------
  // [VULN: SQL injection — Task 2]  and  [VULN: Plaintext passwords — Task 2]
  //
  // The email and password are concatenated straight into the SQL string and
  // executed with sql.unsafe(). postgres.js would parameterize safely if we
  // used a tagged template (sql`... ${email} ...`); we deliberately do not.
  //
  // Classic bypass:  email = ' OR '1'='1' --      password = anything
  //   => WHERE p.email = '' OR '1'='1' -- ' AND c.password = '...'
  //      comments out the password check and returns the first row.
  //
  // The password is matched in plaintext (c.password = '<password>'), because
  // credentials.password stores the raw password (see db/migrations/001_init.sql).
  // --------------------------------------------------------------------------
  const authQuery =
    "SELECT p.id, p.email, p.role, p.display_name " +
    "FROM profiles p " +
    "JOIN credentials c ON c.profile_id = p.id " +
    "WHERE p.email = '" + email + "' AND c.password = '" + password + "'";

  let rows: any[];
  try {
    rows = await sql.unsafe(authQuery);
  } catch (err: any) {
    // [VULN: Verbose DB/stack errors — Task 2]
    // The raw driver message, stack trace and the exact SQL we ran are handed
    // straight back to the client whenever DEBUG is on (it is, by default).
    return NextResponse.json(
      DEBUG
        ? { error: err?.message, stack: err?.stack, query: authQuery }
        : { error: "Login failed" },
      { status: 500 }
    );
  }

  if (rows.length > 0) {
    const user = rows[0];

    // [VULN: No session-id regeneration — Task 2]
    // We pass the sid the browser already presented straight through, so an
    // attacker-fixed session id survives login (session fixation).
    const presented = getPresentedSid(req);
    const sid = await establishSession(user.id, presented);

    const res = NextResponse.json({
      ok: true,
      user: { id: user.id, email: user.email, role: user.role },
    });
    // Hand-built Set-Cookie with NO SameSite (see lib/session.ts).
    res.headers.append("Set-Cookie", buildSessionCookie(sid));
    return res;
  }

  // --------------------------------------------------------------------------
  // [VULN: User enumeration / field disclosure — Task 2]
  // On failure we run a second (also injectable) email-only lookup so we can
  // tell the caller PRECISELY which field was wrong — leaking which email
  // addresses exist and turning password guessing into a two-step oracle.
  // --------------------------------------------------------------------------
  const emailLookup = "SELECT id FROM profiles WHERE email = '" + email + "'";
  let byEmail: any[];
  try {
    byEmail = await sql.unsafe(emailLookup);
  } catch (err: any) {
    return NextResponse.json(
      DEBUG
        ? { error: err?.message, stack: err?.stack, query: emailLookup }
        : { error: "Login failed" },
      { status: 500 }
    );
  }

  if (byEmail.length === 0) {
    return NextResponse.json(
      { error: "No account exists with that email address." },
      { status: 401 }
    );
  }
  return NextResponse.json(
    { error: "Incorrect password for that account." },
    { status: 401 }
  );
}
