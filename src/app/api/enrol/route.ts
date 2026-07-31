// ============================================================================
//  POST /api/enrol — enrol the logged-in student in a course.
//
//  [VULN: No CSRF protection — Task 3]
//  Like the profile update, this state-changing POST is authorised by the
//  session cookie alone: no CSRF token, no Origin/Referer check, and the cookie
//  has no SameSite attribute. A cross-site form can enrol the victim without
//  their knowledge.
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
  const courseId = Number(form.get("course_id"));

  // [VULN: No CSRF protection — Task 3]  (no token / origin check)
  if (Number.isFinite(courseId)) {
    await sql`
      INSERT INTO enrolments (profile_id, course_id)
      VALUES (${user.id}, ${courseId})
      ON CONFLICT (profile_id, course_id) DO NOTHING
    `;
  }

  return NextResponse.redirect(new URL("/courses?enrolled=1", req.url), { status: 303 });
}
