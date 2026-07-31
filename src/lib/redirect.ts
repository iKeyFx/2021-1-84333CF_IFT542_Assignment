// ============================================================================
//  Post-form redirects.  [FIXED — Task 3: cross-host redirect after a form POST]
//
//  THE BUG THIS REPLACES
//    Every form handler used to return
//        NextResponse.redirect(new URL("/profile?saved=1", req.url), { status: 303 })
//    Next normalises `req.url` to the LOOPBACK NAME regardless of what the
//    client actually addressed, so a browser on http://127.0.0.1:3000 received
//        Location: http://localhost:3000/profile?saved=1
//
//    `localhost` and `127.0.0.1` are DIFFERENT HOSTS for cookie purposes, even
//    though they resolve to the same address. The browser followed the redirect
//    to an origin where it held no `sid` cookie, middleware saw an anonymous
//    request, and the user was bounced to /login — appearing to be logged out
//    immediately after every successful save, enrol or upload.
//
//  THE FIX, AND WHY IT IS NOT "READ THE HOST HEADER"
//    Emitting a RELATIVE Location is what actually fixes this. RFC 7231 §7.1.2
//    permits a relative reference, and the browser resolves it against the URL
//    it is already on — so the response is correct for `127.0.0.1`, `localhost`
//    or any other name the app is reached by, without the server needing to know
//    which one that was.
//
//    Building an absolute URL from the Host header (as checkOrigin() does, where
//    it is only ever COMPARED) would also work here, but it would mean EMITTING
//    a client-controlled value in a Location header — an open redirect if the
//    app is ever put behind something that does not pin Host. Not worth it when
//    a relative reference is both simpler and strictly safer.
//
//  NextResponse.redirect() cannot be used: it requires an absolute URL and
//  would re-introduce the normalisation. The header is set directly instead.
// ============================================================================
import { NextResponse } from "next/server";

/**
 * 303 See Other to a same-origin path.
 *
 * 303 (not 302) is deliberate: it tells the browser to follow up with a GET,
 * which is the correct POST-Redirect-GET behaviour for a form submission and
 * stops a refresh from re-submitting it.
 *
 * @param path an absolute-path reference beginning with "/", e.g. "/profile?saved=1"
 */
export function seeOther(path: string): NextResponse {
  if (!path.startsWith("/")) {
    // Guards against a caller ever passing a full URL, which would turn this
    // into an open redirect.
    throw new Error(`seeOther() takes a same-origin path starting with "/", got: ${path}`);
  }
  return new NextResponse(null, {
    status: 303,
    headers: { Location: path },
  });
}
