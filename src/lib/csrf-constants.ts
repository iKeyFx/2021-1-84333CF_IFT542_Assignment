// ============================================================================
//  CSRF wire names. Three strings, nothing else.
//
//  ⚠️  THIS FILE EXISTS SO THAT CLIENT COMPONENTS NEVER IMPORT `@/lib/csrf`.
//
//  csrf.ts calls sessionSecret(), which reads process.env.SESSION_SECRET. Next
//  inlines `process.env.*` into the CLIENT bundle for any module reachable from
//  a "use client" entry point — so importing csrf.ts from, say,
//  UrlPreviewClient.tsx would ship the HMAC key to the browser and make every
//  CSRF token forgeable.
//
//  Client code imports these constants and src/lib/csrf-client.ts. Nothing else.
// ============================================================================

/** Non-HttpOnly cookie carrying the token (readable by the fetch clients). */
export const CSRF_COOKIE = "csrf";

/** Hidden form field name for plain HTML form posts. */
export const CSRF_FIELD = "_csrf";

/** Request header used by JSON/fetch callers, and by middleware to forward it. */
export const CSRF_HEADER = "x-csrf-token";
