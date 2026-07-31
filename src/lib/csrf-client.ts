// ============================================================================
//  Browser-side CSRF token reader.  [FIXED — Task 3: no CSRF protection]
//
//  For the two "use client" components that POST with fetch() instead of a
//  plain HTML form. Plain forms use <CsrfField /> instead.
//
//  ⚠️  This file must NEVER import @/lib/csrf — that module reads
//  process.env.SESSION_SECRET, which Next would inline into the client bundle,
//  shipping the HMAC key to the browser. Only the wire-name constants are safe
//  to share. See src/lib/csrf-constants.ts.
// ============================================================================
import { CSRF_COOKIE, CSRF_HEADER } from "./csrf-constants";

/**
 * Read the CSRF token from the (deliberately non-HttpOnly) `csrf` cookie.
 *
 * Being readable by JavaScript is by design and is not the weakness it looks
 * like: the token's value is an HMAC over the HttpOnly session id, so an
 * attacker on another origin cannot read it (same-origin policy) and an
 * attacker who can only WRITE cookies cannot forge one that matches the
 * victim's session.
 */
export function readCsrfToken(): string {
  const match = document.cookie.match(
    new RegExp(`(?:^|;\\s*)${CSRF_COOKIE}=([^;]*)`)
  );
  return match ? decodeURIComponent(match[1]) : "";
}

/** Headers for a same-origin JSON POST, including the CSRF token. */
export function csrfJsonHeaders(): Record<string, string> {
  return {
    "Content-Type": "application/json",
    [CSRF_HEADER]: readCsrfToken(),
  };
}
