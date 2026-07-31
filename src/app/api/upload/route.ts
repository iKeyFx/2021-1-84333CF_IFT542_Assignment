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

export async function POST(req: NextRequest) {
  const user = await getSessionUser();
  if (!user) {
    return NextResponse.redirect(new URL("/login", req.url), { status: 303 });
  }

  const form = await req.formData();
  const file = form.get("document");
  if (!(file instanceof File) || file.size === 0) {
    return NextResponse.redirect(new URL("/uploads?error=nofile", req.url), { status: 303 });
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

  return NextResponse.redirect(new URL("/uploads?uploaded=1", req.url), { status: 303 });
}
