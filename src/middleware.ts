// ============================================================================
//  Middleware: security headers, CSP nonce, CSRF token issuance, route gate.
//
//  [FIXED — Task 3] The vulnerable build had no headers at all and matched only
//  the five authenticated path prefixes. It now runs on every page request.
//
//  Runs on the EDGE runtime: no node: builtins, no database, no argon2.
// ============================================================================
import { NextResponse, type NextRequest } from "next/server";
import { SESSION_COOKIE, COOKIE_SECURE } from "@/lib/config";
import { buildCsp, staticSecurityHeaders } from "@/lib/security-headers";
import { CSRF_COOKIE, CSRF_HEADER } from "@/lib/csrf-constants";
import { issueToken } from "@/lib/csrf";

const PROTECTED = ["/dashboard", "/profile", "/courses", "/uploads", "/admin"];

const isDev = process.env.NODE_ENV !== "production";

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // ---- 1. Per-request CSP nonce -------------------------------------------
  const nonceBytes = new Uint8Array(16);
  crypto.getRandomValues(nonceBytes);
  const nonce = btoa(String.fromCharCode(...nonceBytes));
  const csp = buildCsp(nonce, isDev);

  // ---- 2. CSRF token, bound to the session when there is one ---------------
  // Minted here rather than at login because the logout form is rendered in
  // layout.tsx on EVERY page, including unauthenticated ones.
  const sid = req.cookies.get(SESSION_COOKIE)?.value ?? null;
  const existing = req.cookies.get(CSRF_COOKIE)?.value ?? null;
  const csrfToken = await issueToken(sid, existing);

  // ---- 3. Forward headers to the app --------------------------------------
  // CRITICAL: clone the incoming headers. `NextResponse.next({request:{headers}})`
  // REPLACES the request header set — anything not present here is deleted,
  // including `cookie`, which would log every user out. Never pass a bare
  // `new Headers()`.
  const requestHeaders = new Headers(req.headers);
  // Next reads the nonce out of the CSP on the REQUEST, not the response, and
  // applies it to its own RSC bootstrap <script> tags.
  requestHeaders.set("content-security-policy", csp);
  requestHeaders.set("x-nonce", nonce);
  // Server components render the hidden CSRF field from this header. Reading
  // cookies() instead would return nothing on a first visit, because the cookie
  // we are about to set lives on the RESPONSE.
  requestHeaders.set(CSRF_HEADER, csrfToken);

  // ---- 4. Route gate (unchanged behaviour) ---------------------------------
  const needsAuth = PROTECTED.some((p) => pathname === p || pathname.startsWith(p + "/"));
  if (needsAuth && !sid) {
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    return decorate(NextResponse.redirect(url), csp, csrfToken);
  }

  return decorate(
    NextResponse.next({ request: { headers: requestHeaders } }),
    csp,
    csrfToken
  );
}

function decorate(res: NextResponse, csp: string, csrfToken: string): NextResponse {
  res.headers.set("Content-Security-Policy", csp);
  for (const [key, value] of Object.entries(staticSecurityHeaders(isDev))) {
    res.headers.set(key, value);
  }
  // Readable by JavaScript BY DESIGN — the two fetch clients read it from
  // document.cookie. Its secrecy is not what makes the control work: the HMAC
  // binds it to the HttpOnly session id, so an attacker who cannot read the
  // session cookie cannot mint a matching token.
  res.cookies.set(CSRF_COOKIE, csrfToken, {
    path: "/",
    httpOnly: false,
    sameSite: "lax",
    secure: COOKIE_SECURE,
    maxAge: 86_400,
  });
  return res;
}

export const config = {
  // Everything except static assets and /api.
  //
  // /api is excluded deliberately: middleware Set-Cookie handling would clobber
  // the session cookie that /api/login sets, and JSON responses need no CSP.
  // API security headers come from next.config.js headers() instead.
  matcher: ["/((?!_next/static|_next/image|favicon.ico|api/).*)"],
};
