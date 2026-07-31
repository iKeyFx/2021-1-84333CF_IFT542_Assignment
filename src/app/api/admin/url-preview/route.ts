// ============================================================================
//  POST /api/admin/url-preview — "URL preview / import" admin feature.
//
//  [FIXED — Task 3: Server-Side Request Forgery]
//  Every outbound request now goes through src/lib/url-guard.ts, which enforces
//  a scheme allowlist, a destination HOST allowlist, DNS resolution with
//  rejection of loopback / RFC1918 / link-local (169.254.169.254) / reserved
//  addresses, manual redirect handling that re-validates every hop, a 5s
//  timeout and a 64 KB body cap.
//
//  [FIXED — Task 3: verbose errors]
//  The DEBUG branch that returned err.message and err.stack to the client is
//  gone. A blocked URL gets a fixed message; the specific reason is logged
//  server-side only, because the reason itself ("blocked-loopback" vs
//  "dns-failed") is an internal-network oracle.
//
//  [FIXED — Task 3: no CSRF protection]
//  The endpoint is state-changing from the network's point of view, so it
//  requires the anti-CSRF token like every other POST.
// ============================================================================
import { NextResponse, type NextRequest } from "next/server";
import { currentAdmin } from "@/lib/auth";
import { requireCsrf } from "@/lib/csrf";
import { safeFetch } from "@/lib/url-guard";
import { logger, clientIpOf } from "@/lib/logger";

// node:dns via url-guard — pin to the Node runtime.
export const runtime = "nodejs";

const PATH = "/api/admin/url-preview";

export async function POST(req: NextRequest) {
  const ip = clientIpOf(req);

  const admin = await currentAdmin({ ip, method: "POST", path: PATH });
  if (!admin) {
    return NextResponse.json({ error: "Admin only" }, { status: 403 });
  }

  const actor = { profile_id: admin.id, role: admin.role };

  const csrf = await requireCsrf(req);
  if (!csrf.ok) {
    logger.csrfRejected({ ip, method: "POST", path: PATH, actor, reason: csrf.reason });
    return NextResponse.json({ error: "Request rejected" }, { status: 403 });
  }

  const body = await req.json().catch(() => ({}));
  const target = String(body.url ?? "");

  const result = await safeFetch(target);

  if (!result.ok) {
    // The blocked URL and the precise reason go to the log, never to the client.
    logger.ssrfBlocked({
      ip,
      method: "POST",
      path: PATH,
      actor,
      reason: result.reason,
      target_url: target.slice(0, 200),
    });
    return NextResponse.json(
      { ok: false, error: "URL not allowed" },
      { status: 403 }
    );
  }

  return NextResponse.json({
    ok: true,
    requestedUrl: target,
    finalUrl: result.finalUrl,
    status: result.status,
    statusText: result.statusText,
    elapsedMs: result.elapsedMs,
    headers: result.headers,
    bodySnippet: result.bodySnippet,
    truncated: result.truncated,
  });
}
