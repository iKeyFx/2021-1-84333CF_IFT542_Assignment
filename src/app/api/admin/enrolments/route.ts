// ============================================================================
//  POST /api/admin/enrolments — admin removes an enrolment.
//  (Viewing is done on the server-rendered admin page; this endpoint handles
//  the "remove" action.)
// ============================================================================
import { NextResponse, type NextRequest } from "next/server";
import { sql } from "@/lib/db";
import { currentAdmin } from "@/lib/auth";

export async function POST(req: NextRequest) {
  const admin = await currentAdmin();
  if (!admin) {
    return NextResponse.redirect(new URL("/login", req.url), { status: 303 });
  }

  const form = await req.formData();
  const enrolmentId = Number(form.get("enrolment_id"));
  if (Number.isFinite(enrolmentId)) {
    await sql`DELETE FROM enrolments WHERE id = ${enrolmentId}`;
  }

  return NextResponse.redirect(new URL("/admin/enrolments?removed=1", req.url), { status: 303 });
}
