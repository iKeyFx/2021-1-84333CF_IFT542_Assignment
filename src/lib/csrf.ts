// ============================================================================
//  Anti-CSRF: signed double-submit tokens.  [FIXED — Task 3: no CSRF protection]
//
//  THE TOKEN
//    <id>.<base64url(HMAC-SHA256(SESSION_SECRET, id))>
//  where `id` is the SESSION ID when the caller has one, else a random UUID.
//
//  WHY BIND IT TO THE SESSION
//    A plain double-submit cookie only proves the sender could both set and read
//    a cookie — which an attacker who can write cookies on the domain (a
//    sibling subdomain, a MITM on a sibling http origin) can also do. Signing
//    the SESSION ID defeats that: the session cookie is HttpOnly, so an attacker
//    who cannot read it cannot produce a token that matches it.
//
//    It also means the token ROTATES AT THE AUTHENTICATION BOUNDARY for free —
//    a token minted before login is worthless afterwards, mirroring the Task 2
//    session-id regeneration.
//
//  WHY HMAC AND NOT RANDOM+STORE
//    No server-side state. Middleware can recompute the token on every request
//    without a lookup, which is what makes it cheap enough to mint on every page.
//
//  Uses WEB CRYPTO (crypto.subtle), not node:crypto, so the same module works in
//  middleware (edge runtime) and in route handlers (node runtime).
//  crypto.subtle.verify does a constant-time comparison internally.
// ============================================================================
import type { NextRequest } from "next/server";
import { sessionSecret, SESSION_COOKIE } from "./config";
import { CSRF_COOKIE, CSRF_FIELD, CSRF_HEADER } from "./csrf-constants";

const encoder = new TextEncoder();
let keyPromise: Promise<CryptoKey> | null = null;

function hmacKey(): Promise<CryptoKey> {
  keyPromise ??= crypto.subtle.importKey(
    "raw",
    encoder.encode(sessionSecret()),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  return keyPromise;
}

function toBase64Url(bytes: ArrayBuffer): string {
  const bin = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(s: string): Uint8Array | null {
  try {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, "="));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

/** Mint a token for `id`. */
async function sign(id: string): Promise<string> {
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(), encoder.encode(id));
  return `${id}.${toBase64Url(sig)}`;
}

/**
 * Issue the token for this request.
 *
 * With a session: always bound to the session id, so the token rotates when the
 * session does. Without one: reuse a still-valid anonymous token so the value is
 * stable across a browsing session, otherwise mint a fresh random id.
 */
export async function issueToken(
  sid: string | null,
  existing: string | null
): Promise<string> {
  if (sid) return sign(sid);
  if (existing && (await verifyToken(existing, null))) return existing;
  return sign(crypto.randomUUID());
}

/**
 * Verify a token's signature and, when a session exists, its binding to that
 * session.
 */
export async function verifyToken(
  token: string | null | undefined,
  sid: string | null
): Promise<boolean> {
  if (!token) return false;

  const dot = token.lastIndexOf(".");
  if (dot <= 0) return false;

  const id = token.slice(0, dot);
  const sig = fromBase64Url(token.slice(dot + 1));
  if (!sig) return false;

  // Session binding: a token signed for a DIFFERENT session is rejected even
  // though its signature is perfectly valid. This is what stops an attacker
  // replaying their own legitimately-issued token against a victim's session.
  if (sid !== null && id !== sid) return false;

  // Constant-time inside subtle.verify.
  return crypto.subtle.verify("HMAC", await hmacKey(), sig, encoder.encode(id));
}

// ---------------------------------------------------------------------------
//  Origin / Referer checking
// ---------------------------------------------------------------------------

/**
 * Reject a request whose Origin (or Referer) names a different origin, or the
 * literal string "null" — which is what a `file://` page sends, and is exactly
 * what evidence/task3/csrf-poc.html produces.
 *
 * A MISSING Origin is allowed. That is a deliberate, documented trade-off:
 * non-browser clients (curl, the Node PoC scripts in tests/) send no Origin at
 * all, and browsers always send one on cross-site POSTs. It does mean a
 * non-browser attacker can skip this check — which is precisely why this is the
 * SECONDARY control and the signed token above is the primary one.
 */
export function checkOrigin(req: NextRequest): boolean {
  // Compare against the HOST HEADER, not req.nextUrl.host. Next normalises
  // nextUrl to "localhost:3000" even when the client connected to
  // "127.0.0.1:3000", so comparing against nextUrl rejects genuine same-origin
  // requests. The Host header is what the browser actually addressed.
  const expected = req.headers.get("host") ?? req.nextUrl.host;

  const sameHost = (value: string): boolean => {
    try {
      return new URL(value).host === expected;
    } catch {
      return false;
    }
  };

  const origin = req.headers.get("origin");
  if (origin !== null) {
    // "null" is what a file:// page sends — exactly the CSRF PoC. Never trust it.
    if (origin === "null") return false;
    return sameHost(origin);
  }

  const referer = req.headers.get("referer");
  if (referer !== null) return sameHost(referer);

  return true; // no Origin and no Referer — see the note above
}

// ---------------------------------------------------------------------------
//  Route-handler guard
// ---------------------------------------------------------------------------

export type CsrfResult =
  | { ok: true; form: FormData | null }
  | { ok: false; reason: "bad-origin" | "missing-token" | "bad-token" };

/**
 * Verify CSRF for a state-changing request.
 *
 * Reads the token from the `x-csrf-token` header (fetch callers) or the `_csrf`
 * form field (plain HTML forms, including multipart uploads). When it consumes
 * the body to find the field it returns the parsed FormData, because a request
 * body can only be read once — callers MUST use the returned value rather than
 * calling req.formData() again.
 */
export async function requireCsrf(req: NextRequest): Promise<CsrfResult> {
  if (!checkOrigin(req)) return { ok: false, reason: "bad-origin" };

  const sid = req.cookies.get(SESSION_COOKIE)?.value ?? null;
  const cookieToken = req.cookies.get(CSRF_COOKIE)?.value ?? null;

  let presented = req.headers.get(CSRF_HEADER);
  let form: FormData | null = null;

  if (!presented) {
    const contentType = req.headers.get("content-type") ?? "";
    if (
      contentType.includes("form-data") ||
      contentType.includes("x-www-form-urlencoded")
    ) {
      try {
        form = await req.formData();
        const field = form.get(CSRF_FIELD);
        presented = typeof field === "string" ? field : null;
      } catch {
        return { ok: false, reason: "missing-token" };
      }
    }
  }

  if (!presented) return { ok: false, reason: "missing-token" };

  // Double-submit: the value presented in the request must match the cookie...
  if (!cookieToken || presented !== cookieToken) {
    return { ok: false, reason: "bad-token" };
  }
  // ...and the cookie must itself be a valid signature bound to this session.
  if (!(await verifyToken(presented, sid))) {
    return { ok: false, reason: "bad-token" };
  }

  return { ok: true, form };
}
