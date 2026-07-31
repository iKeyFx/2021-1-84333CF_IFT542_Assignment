// ============================================================================
//  POST /api/admin/enrolments — admin removes an enrolment.
//  (Viewing is done on the server-rendered admin page; this endpoint handles
//  the "remove" action.)
// ============================================================================
import { NextResponse, type NextRequest } from "next/server";
import { sql } from "@/lib/db";
import { currentAdmin } from "@/lib/auth";
import { requireCsrf } from "@/lib/csrf";
import { seeOther } from "@/lib/redirect";
import { logger, clientIpOf } from "@/lib/logger";

export async function POST(req: NextRequest) {
  const ip = clientIpOf(req);
  // currentAdmin() logs the denial itself — it is the only place that can tell
  // an anonymous caller apart from a logged-in non-admin.
  const admin = await currentAdmin({ ip, method: "POST", path: "/api/admin/enrolments" });
  if (!admin) {
    return seeOther("/login");
  }

  const actor = { profile_id: admin.id, role: admin.role };

  const csrf = await requireCsrf(req);
  if (!csrf.ok) {
    logger.csrfRejected({ ip, method: "POST", path: "/api/admin/enrolments", actor, reason: csrf.reason });
    return NextResponse.json({ error: "Request rejected" }, { status: 403 });
  }

  const form = csrf.form ?? (await req.formData());
  const enrolmentId = Number(form.get("enrolment_id"));
  if (!Number.isInteger(enrolmentId) || enrolmentId <= 0) {
    logger.validationRejected({ ip, method: "POST", path: "/api/admin/enrolments", actor, reason: "enrolment_id-invalid" });
  } else {
    await sql`DELETE FROM enrolments WHERE id = ${enrolmentId}`;
  }

  return seeOther("/admin/enrolments?removed=1");
}
