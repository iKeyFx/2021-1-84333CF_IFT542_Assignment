// ============================================================================
//  Route gate: bounces anonymous visitors (no session cookie) away from the
//  authenticated areas. This is a convenience check on cookie PRESENCE only;
//  the authoritative user/admin lookup happens in each page/route via
//  getSessionUser()/currentAdmin().
// ============================================================================
import { NextResponse, type NextRequest } from "next/server";
import { SESSION_COOKIE } from "@/lib/config";

const PROTECTED = ["/dashboard", "/profile", "/courses", "/uploads", "/admin"];

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const needsAuth = PROTECTED.some((p) => pathname === p || pathname.startsWith(p + "/"));
  if (!needsAuth) return NextResponse.next();

  const hasSession = Boolean(req.cookies.get(SESSION_COOKIE)?.value);
  if (!hasSession) {
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*", "/profile/:path*", "/courses/:path*", "/uploads/:path*", "/admin/:path*"],
};
