// ============================================================================
//  Custom cookie-session auth (no third-party provider — by design, so the
//  login query is the centrepiece of the exercise).
//
//  Planted vulnerabilities (Task 2 / Task 3):
//   - The session cookie is written via a HAND-BUILT Set-Cookie header with NO
//     SameSite attribute. [VULN: No SameSite on session cookie — Task 3]
//   - Login does NOT regenerate the session id: if the request already carries
//     a `sid` cookie, that same id is reused and simply bound to the freshly
//     authenticated user (session fixation).
//     [VULN: No session-id regeneration — Task 2]
// ============================================================================
import { randomUUID } from "node:crypto";
import { cookies } from "next/headers";
import type { NextRequest } from "next/server";
import { sql } from "./db";
import { SESSION_COOKIE } from "./config";

export type SessionUser = {
  id: number;
  email: string;
  role: "student" | "admin";
  display_name: string;
  bio: string;
};

/** Read the raw sid presented by the caller (may be attacker-chosen). */
export function getPresentedSid(req: NextRequest): string | null {
  return req.cookies.get(SESSION_COOKIE)?.value ?? null;
}

/**
 * Create (or, for the fixation vuln, REUSE) a session for a user.
 *
 * [VULN: No session-id regeneration — Task 2]
 * If `presentedSid` is a well-formed UUID we keep it instead of minting a new
 * one, so a session id fixed by an attacker before login survives across the
 * privilege boundary.
 */
export async function establishSession(
  profileId: number,
  presentedSid: string | null
): Promise<string> {
  const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const sid = presentedSid && uuidRe.test(presentedSid) ? presentedSid : randomUUID();

  // Upsert: reused ids just get re-pointed at the now-authenticated profile.
  await sql`
    INSERT INTO sessions (id, profile_id)
    VALUES (${sid}, ${profileId})
    ON CONFLICT (id) DO UPDATE SET profile_id = EXCLUDED.profile_id
  `;
  return sid;
}

/**
 * Build the Set-Cookie header string by hand so we control EXACTLY which
 * attributes appear.
 *
 * [VULN: No SameSite on session cookie — Task 3]
 * Note the absence of a `SameSite=` attribute and of `Secure`. Only HttpOnly
 * and Path are set, so the cookie is sent on cross-site requests (enabling the
 * CSRF demo against the profile-update and course-registration endpoints).
 */
export function buildSessionCookie(sid: string): string {
  // Intentionally NO "SameSite=..." and NO "Secure" here.
  return `${SESSION_COOKIE}=${sid}; Path=/; HttpOnly; Max-Age=86400`;
}

/** Header string that clears the session cookie (used by logout). */
export function buildClearCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Max-Age=0`;
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
