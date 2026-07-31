// ============================================================================
//  POST /api/admin/url-preview — "URL preview / import" admin feature.
//
//  [VULN: Server-Side Request Forgery (SSRF) — Task 3]
//  The server fetches ANY URL the admin submits, with NO guards whatsoever:
//   - no scheme allowlist (file://, http://, https:// all reach fetch),
//   - no blocking of loopback (127.0.0.1 / localhost),
//   - no blocking of link-local cloud metadata (169.254.169.254),
//   - no blocking of RFC1918 private ranges (10/8, 172.16/12, 192.168/16),
//   - no DNS-rebinding / redirect pinning.
//  The response status, headers and a body snippet are returned to the caller,
//  so the endpoint doubles as a read oracle for internal-only services.
// ============================================================================
import { NextResponse, type NextRequest } from "next/server";
import { currentAdmin } from "@/lib/auth";
import { DEBUG } from "@/lib/config";

export async function POST(req: NextRequest) {
  const admin = await currentAdmin();
  if (!admin) {
    return NextResponse.json({ error: "Admin only" }, { status: 403 });
  }

  const body = await req.json().catch(() => ({}));
  const target = String(body.url ?? "");

  // [VULN: SSRF — Task 3]
  // The user-supplied URL is passed straight to fetch(). No validation of the
  // host, scheme, or resolved IP is performed before the request leaves the
  // server, so this can be pointed at internal/loopback/metadata endpoints.
  try {
    const started = Date.now();
    const resp = await fetch(target, { redirect: "follow" });
    const text = await resp.text();
    const headers: Record<string, string> = {};
    resp.headers.forEach((value, key) => {
      headers[key] = value;
    });

    return NextResponse.json({
      ok: true,
      requestedUrl: target,
      status: resp.status,
      statusText: resp.statusText,
      elapsedMs: Date.now() - started,
      headers,
      bodySnippet: text.slice(0, 4000),
    });
  } catch (err: any) {
    // Verbose error surface again (debug on) so failures leak internal detail.
    return NextResponse.json(
      DEBUG
        ? { ok: false, requestedUrl: target, error: err?.message, stack: err?.stack }
        : { ok: false, error: "Fetch failed" },
      { status: 502 }
    );
  }
}
