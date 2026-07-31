// ============================================================================
//  Custom cookie-session auth (no third-party provider — by design, so the
//  login query is the centrepiece of the exercise).
//
//  Planted vulnerabilities (Task 3):
//   - The session cookie is written via a HAND-BUILT Set-Cookie header with NO
//     SameSite attribute. [VULN: No SameSite on session cookie — Task 3]
//
//  Remediated (Task 2):
//   - Login now regenerates the session id. See establishSession() below.
//     [FIXED — Task 2: no session-id regeneration]
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
