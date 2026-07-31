// POST /api/logout — clear the session cookie and delete the session row.
import { NextResponse, type NextRequest } from "next/server";
import { destroySession, buildClearCookie, getPresentedSid } from "@/lib/session";

export async function POST(req: NextRequest) {
  const sid = getPresentedSid(req);
  if (sid) await destroySession(sid);
  const res = NextResponse.json({ ok: true });
  res.headers.append("Set-Cookie", buildClearCookie());
  return res;
}
