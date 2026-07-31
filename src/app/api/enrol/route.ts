// ============================================================================
//  POST /api/enrol — enrol the logged-in student in a course.
//
//  [FIXED — Task 3: no CSRF protection]
//  Requires a signed anti-CSRF token bound to the caller's session, and rejects
//  a mismatched or "null" Origin. Previously the session cookie alone authorised
//  the enrolment, so any site could enrol the victim without their knowledge.
// ============================================================================
import { NextResponse, type NextRequest } from "next/server";
import { sql } from "@/lib/db";
import { getSessionUser } from "@/lib/session";
import { requireCsrf } from "@/lib/csrf";
import { logger, clientIpOf } from "@/lib/logger";

export async function POST(req: NextRequest) {
  const ip = clientIpOf(req);
  const user = await getSessionUser();
  if (!user) {
    logger.authzDenied({ ip, method: "POST", path: "/api/enrol", actor: null, reason: "no-session" });
    return NextResponse.redirect(new URL("/login", req.url), { status: 303 });
  }

  const actor = { profile_id: user.id, role: user.role };

  const csrf = await requireCsrf(req);
  if (!csrf.ok) {
    logger.csrfRejected({ ip, method: "POST", path: "/api/enrol", actor, reason: csrf.reason });
    return NextResponse.json({ error: "Request rejected" }, { status: 403 });
  }

  const form = csrf.form ?? (await req.formData());
  const courseId = Number(form.get("course_id"));

  if (!Number.isInteger(courseId) || courseId <= 0) {
    logger.validationRejected({ ip, method: "POST", path: "/api/enrol", actor, reason: "course_id-invalid" });
  } else {
    await sql`
      INSERT INTO enrolments (profile_id, course_id)
      VALUES (${user.id}, ${courseId})
      ON CONFLICT (profile_id, course_id) DO NOTHING
    `;
  }

  return NextResponse.redirect(new URL("/courses?enrolled=1", req.url), { status: 303 });
}
