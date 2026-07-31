// ============================================================================
//  POST /api/admin/courses — admin course management (create / edit / delete).
//  Dispatched by a hidden `_action` field from the admin courses form.
//
//  (Admin-only feature. CSRF is not the designated sink here — the profile and
//  enrol endpoints carry that Task 3 vuln — but note this shares the same
//  no-SameSite cookie model.)
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
  const action = String(form.get("_action") ?? "create");

  try {
    if (action === "create") {
      await sql`
        INSERT INTO courses (code, title, description, capacity)
        VALUES (
          ${String(form.get("code") ?? "")},
          ${String(form.get("title") ?? "")},
          ${String(form.get("description") ?? "")},
          ${Number(form.get("capacity") ?? 30)}
        )
      `;
    } else if (action === "edit") {
      await sql`
        UPDATE courses SET
          code = ${String(form.get("code") ?? "")},
          title = ${String(form.get("title") ?? "")},
          description = ${String(form.get("description") ?? "")},
          capacity = ${Number(form.get("capacity") ?? 30)}
        WHERE id = ${Number(form.get("id"))}
      `;
    } else if (action === "delete") {
      await sql`DELETE FROM courses WHERE id = ${Number(form.get("id"))}`;
    }
  } catch (err: any) {
    return NextResponse.redirect(
      new URL(`/admin/courses?error=${encodeURIComponent(err?.message ?? "failed")}`, req.url),
      { status: 303 }
    );
  }

  return NextResponse.redirect(new URL("/admin/courses?saved=1", req.url), { status: 303 });
}
