// ============================================================================
//  POST /api/profile — update the logged-in student's display name + bio.
//
//  Planted vulnerabilities (Task 3):
//   - [VULN: No CSRF protection — Task 3] The handler authenticates using ONLY
//     the ambient session cookie. There is no CSRF token, no Origin/Referer
//     check, and (see lib/session.ts) the cookie has no SameSite attribute, so
//     any other site can submit this form on the victim's behalf.
//   - The submitted display_name is stored RAW (no sanitisation/encoding). It
//     is later rendered with dangerouslySetInnerHTML on the dashboard/profile,
//     which is the stored-XSS sink. [VULN: Stored XSS (source) — Task 3]
// ============================================================================
import { NextResponse, type NextRequest } from "next/server";
import { sql } from "@/lib/db";
import { getSessionUser } from "@/lib/session";

export async function POST(req: NextRequest) {
  const user = await getSessionUser();
  if (!user) {
    return NextResponse.redirect(new URL("/login", req.url), { status: 303 });
  }

  const form = await req.formData();
  const displayName = String(form.get("display_name") ?? "");
  const bio = String(form.get("bio") ?? "");

  // [VULN: No CSRF protection — Task 3]
  // No csrf token is read or verified here; the session cookie alone authorises
  // the state change. Combined with the missing SameSite attribute, a
  // cross-site auto-submitting form can silently rewrite the victim's profile.

  // [VULN: Stored XSS (source) — Task 3]
  // display_name is written verbatim — angle brackets, <script>, onerror=... all
  // survive to the database and are echoed unescaped on render.
  await sql`
    UPDATE profiles
    SET display_name = ${displayName}, bio = ${bio}
    WHERE id = ${user.id}
  `;

  return NextResponse.redirect(new URL("/profile?saved=1", req.url), { status: 303 });
}
