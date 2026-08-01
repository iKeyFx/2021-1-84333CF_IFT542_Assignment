// ============================================================================
//  Custom cookie-session auth (no third-party provider — by design, so the
//  login query is the centrepiece of the exercise).
//
//  Remediated (Task 2):
//   - Login now regenerates the session id. See establishSession() below.
//     [FIXED — Task 2: no session-id regeneration]
//
//  Remediated (Task 3):
//   - The hand-built Set-Cookie header now carries HttpOnly, SameSite=Lax and
//     Secure. See cookieAttrs() below.
//     [FIXED — Task 3: no SameSite on session cookie]
//
//  Incident response (Task 3, item 26): deleting a row from `sessions` revokes
//  that session immediately, because currentUser() resolves the cookie against
//  this table on every request. That is what `npm run ir:revoke-sessions` does.
// ============================================================================
import { randomUUID } from "node:crypto";
import { cookies } from "next/headers";
import type { NextRequest } from "next/server";
import { sql } from "./db";
import { SESSION_COOKIE, COOKIE_SECURE } from "./config";

export type SessionUser = {
  id: number;
  email: string;
  role: "student" | "admin";
  display_name: string;
  bio: string;
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Read the raw sid presented by the caller (may be attacker-chosen). */
export function getPresentedSid(req: NextRequest): string | null {
  return req.cookies.get(SESSION_COOKIE)?.value ?? null;
}

/**
 * Create a session for a freshly authenticated user.
 *
 * [FIXED — Task 2: no session-id regeneration]
 * A new, cryptographically random session id is minted on EVERY successful
 * login, and any session id the caller presented is destroyed first. A session
 * id fixed by an attacker before login therefore cannot survive across the
 * authentication boundary — the attacker is left holding a deleted id.
 */
export async function establishSession(
  profileId: number,
  presentedSid: string | null
): Promise<string> {
  // Invalidate whatever the caller presented. The UUID guard is REQUIRED:
  // sessions.id is Postgres type `uuid`, so binding a non-UUID string raises
  // 22P02 (invalid input syntax for type uuid) and would 500 the login.
  if (presentedSid && UUID_RE.test(presentedSid)) {
    await sql`DELETE FROM sessions WHERE id = ${presentedSid}`;
  }

  // randomUUID() is crypto-grade (node:crypto), 122 bits of entropy.
  const sid = randomUUID();

  // Plain INSERT, no upsert: a fresh v4 UUID cannot collide, and dropping the
  // ON CONFLICT means an unexpected collision fails loudly instead of silently
  // re-pointing somebody else's live session at this profile.
  await sql`INSERT INTO sessions (id, profile_id) VALUES (${sid}, ${profileId})`;

  return sid;
}

/**
 * Build the Set-Cookie header string by hand so we control EXACTLY which
 * attributes appear.
 *
 * [FIXED — Task 3: no SameSite / no Secure on the session cookie]
 * The cookie now carries all four protective attributes:
 *   HttpOnly  — unreadable from JavaScript, so an XSS foothold cannot steal it
 *   SameSite=Lax — not sent on cross-site POSTs, which alone defeats a forged
 *                  cross-origin form submission (see tests/csrf.test.ts)
 *   Secure    — HTTPS-only. Browsers treat loopback as a potentially
 *               trustworthy origin, so this still works over http://127.0.0.1
 *   Path=/    — scoped to the app
 *
 * Lax rather than Strict is deliberate: Strict would drop the session on every
 * inbound link into the app (the user would appear logged out after following
 * one), and Lax already blocks the cross-site POST that CSRF requires. The
 * anti-CSRF token in src/lib/csrf.ts is the primary control; this is defence
 * in depth behind it.
 */
export function buildSessionCookie(sid: string): string {
  return cookieAttrs(`${SESSION_COOKIE}=${sid}`, 86_400);
}

/** Header string that clears the session cookie (used by logout). */
export function buildClearCookie(): string {
  return cookieAttrs(`${SESSION_COOKIE}=`, 0);
}

function cookieAttrs(nameValue: string, maxAge: number): string {
  const parts = [nameValue, "Path=/", "HttpOnly", "SameSite=Lax", `Max-Age=${maxAge}`];
  if (COOKIE_SECURE) parts.push("Secure");
  return parts.join("; ");
}

/** Look up the current user from the session cookie (server components/routes). */
export async function getSessionUser(): Promise<SessionUser | null> {
  const sid = cookies().get(SESSION_COOKIE)?.value;
  if (!sid) return null;

  const rows = await sql<SessionUser[]>`
    SELECT p.id, p.email, p.role, p.display_name, p.bio
    FROM sessions s
    JOIN profiles p ON p.id = s.profile_id
    WHERE s.id = ${sid}
  `;
  return rows[0] ?? null;
}

/** Remove a session row (logout). */
export async function destroySession(sid: string): Promise<void> {
  await sql`DELETE FROM sessions WHERE id = ${sid}`;
}
