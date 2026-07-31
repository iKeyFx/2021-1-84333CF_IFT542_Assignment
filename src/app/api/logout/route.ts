// ============================================================================
//  POST /api/logout — clear the session cookie and delete the session row.
//
//  [FIXED — Task 3: no CSRF protection]
//  Logout is state-changing, so it is token-protected too. Forced logout is a
//  low-severity nuisance rather than a breach, but leaving one unguarded
//  state-changing endpoint undermines the claim that the app is CSRF-protected.
// ============================================================================
import { NextResponse, type NextRequest } from "next/server";
import { destroySession, buildClearCookie, getPresentedSid } from "@/lib/session";
import { requireCsrf } from "@/lib/csrf";
import { logger, clientIpOf } from "@/lib/logger";

export async function POST(req: NextRequest) {
  const ip = clientIpOf(req);

  const csrf = await requireCsrf(req);
  if (!csrf.ok) {
    logger.csrfRejected({ ip, method: "POST", path: "/api/logout", actor: null, reason: csrf.reason });
    return NextResponse.json({ error: "Request rejected" }, { status: 403 });
  }

  const sid = getPresentedSid(req);
  if (sid) await destroySession(sid);

  const res = NextResponse.json({ ok: true });
  res.headers.append("Set-Cookie", buildClearCookie());
  return res;
}
