// ============================================================================
//  POST /api/upload — document upload. Stores the file to local disk under
//  UPLOAD_DIR and records metadata in the `uploads` table.
//
//  (This is a required feature, not a designated planted vulnerability. The
//  stored filename is randomised to avoid collisions; the original name is
//  kept for display only.)
// ============================================================================
import { NextResponse, type NextRequest } from "next/server";
import { randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { sql } from "@/lib/db";
import { getSessionUser } from "@/lib/session";
import { UPLOAD_DIR } from "@/lib/config";
import { requireCsrf } from "@/lib/csrf";
import { seeOther } from "@/lib/redirect";
import { logger, clientIpOf } from "@/lib/logger";

export async function POST(req: NextRequest) {
  const ip = clientIpOf(req);
  const user = await getSessionUser();
  if (!user) {
    logger.authzDenied({ ip, method: "POST", path: "/api/upload", actor: null, reason: "no-session" });
    return seeOther("/login");
  }

  const actor = { profile_id: user.id, role: user.role };

  // [FIXED — Task 3] The token survives multipart/form-data: requireCsrf reads
  // the hidden _csrf field out of the parsed FormData and hands it back.
  const csrf = await requireCsrf(req);
  if (!csrf.ok) {
    logger.csrfRejected({ ip, method: "POST", path: "/api/upload", actor, reason: csrf.reason });
    return NextResponse.json({ error: "Request rejected" }, { status: 403 });
  }

  const form = csrf.form ?? (await req.formData());
  const file = form.get("document");
  if (!(file instanceof File) || file.size === 0) {
    logger.validationRejected({ ip, method: "POST", path: "/api/upload", actor, reason: "no-file" });
    return seeOther("/uploads?error=nofile");
  }

  const dir = resolve(process.cwd(), UPLOAD_DIR);
  await mkdir(dir, { recursive: true });

  const originalName = file.name || "upload.bin";
  const ext = originalName.includes(".") ? originalName.slice(originalName.lastIndexOf(".")) : "";
  const storedName = `${randomUUID()}${ext}`;
  const diskPath = join(dir, storedName);

  const bytes = Buffer.from(await file.arrayBuffer());
  await writeFile(diskPath, bytes);

  await sql`
    INSERT INTO uploads (profile_id, stored_name, original_name, mime, size, path)
    VALUES (${user.id}, ${storedName}, ${originalName}, ${file.type ?? ""}, ${bytes.length}, ${diskPath})
  `;

  return seeOther("/uploads?uploaded=1");
}
