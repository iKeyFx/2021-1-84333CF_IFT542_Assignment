// ============================================================================
//  POST /api/profile — update the logged-in student's display name + bio.
//
//  [FIXED — Task 3: no CSRF protection]
//  The handler no longer trusts the ambient session cookie alone. It requires a
//  signed anti-CSRF token bound to that session and rejects a mismatched or
//  "null" Origin. With SameSite=Lax on the session cookie (src/lib/session.ts),
//  a cross-site form post now fails on three independent grounds.
//
//  [FIXED — Task 3: stored XSS (source)]
//  display_name is still stored VERBATIM — deliberately. What makes it harmless
//  is contextual output encoding at render time (dashboard/page.tsx,
//  profile/page.tsx). The length bounds applied here are a resource limit, not
//  a sanitiser: input filtering is the weaker half of the pair and stripping the
//  payload would hide the fact that it is stored intact and rendered inert.
// ============================================================================
import { NextResponse, type NextRequest } from "next/server";
import { sql } from "@/lib/db";
import { getSessionUser } from "@/lib/session";
import { requireCsrf } from "@/lib/csrf";
import { seeOther } from "@/lib/redirect";
import { validateProfile } from "@/lib/validate";
import { logger, clientIpOf } from "@/lib/logger";

const PATH = "/api/profile";

export async function POST(req: NextRequest) {
  const ip = clientIpOf(req);
  const user = await getSessionUser();

  if (!user) {
    logger.authzDenied({ ip, method: "POST", path: PATH, actor: null, reason: "no-session" });
    return seeOther("/login");
  }

  const actor = { profile_id: user.id, role: user.role };

  const csrf = await requireCsrf(req);
  if (!csrf.ok) {
    logger.csrfRejected({ ip, method: "POST", path: PATH, actor, reason: csrf.reason, observed: csrf.observed });
    return NextResponse.json({ error: "Request rejected" }, { status: 403 });
  }

  // requireCsrf consumed the body to read the hidden field. A request body can
  // only be read once, so reuse what it parsed rather than calling formData().
  const form = csrf.form ?? (await req.formData());
  const input = validateProfile(form);

  if (!input.ok) {
    logger.validationRejected({ ip, method: "POST", path: PATH, actor, reason: input.reason });
    return seeOther("/profile?error=invalid");
  }

  await sql`
    UPDATE profiles
    SET display_name = ${input.displayName}, bio = ${input.bio}
    WHERE id = ${user.id}
  `;

  return seeOther("/profile?saved=1");
}
