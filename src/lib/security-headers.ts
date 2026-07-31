// ============================================================================
//  Security response headers.  [FIXED — Task 3: security misconfiguration]
//
//  Single source of truth for the header set. Applied by src/middleware.ts to
//  page requests (which need a per-request CSP nonce) and by next.config.js to
//  /api/* (which middleware deliberately does not match).
//
//  EDGE-SAFE: imported by middleware, so no node: builtins in this file.
// ============================================================================

/**
 * Build the Content-Security-Policy for one request.
 *
 * ORDERING MATTERS. Next 14 finds the nonce by scanning the policy for the
 * first directive whose name `startsWith("script-src")` (falling back to
 * `default-src`) and taking its first `'nonce-...'` source. If a
 * `script-src-elem` or `script-src-attr` directive were emitted BEFORE
 * `script-src`, that prefix match would grab the wrong directive and the nonce
 * would never reach Next's own bootstrap scripts. Keep `script-src` first among
 * the script directives, and do not add the `-elem`/`-attr` variants.
 */
export function buildCsp(nonce: string, isDev: boolean): string {
  const directives: string[] = [
    `default-src 'self'`,

    // 'unsafe-eval' is required by webpack's hot-module-replacement machinery
    // in `next dev` only. The production policy has no unsafe-* script source
    // at all — see evidence/task3 for the captured production header.
    `script-src 'self' 'nonce-${nonce}'${isDev ? " 'unsafe-eval'" : ""}`,

    // Tailwind compiles to a static stylesheet, so production needs no inline
    // styles. The dev server injects <style> blocks for HMR, hence the
    // relaxation there.
    `style-src 'self'${isDev ? " 'unsafe-inline'" : ""}`,

    `img-src 'self' data:`,
    `font-src 'self'`,

    // The HMR websocket in dev; nothing but same-origin XHR in production.
    `connect-src 'self'${isDev ? " ws: wss:" : ""}`,

    // No plugins, no <base> hijacking, no posting the app's forms off-site.
    `object-src 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,

    // Clickjacking. This is the modern control; X-Frame-Options below is the
    // legacy fallback for older browsers, not a duplicate.
    `frame-ancestors 'none'`,
  ];

  if (!isDev) {
    directives.push("upgrade-insecure-requests");
  }

  return directives.join("; ");
}

/**
 * Headers that do not vary per request.
 *
 * HSTS is deliberately production-only AND honestly inert here: browsers ignore
 * Strict-Transport-Security over plain HTTP, and this artefact runs on
 * http://127.0.0.1. It is emitted for completeness of the header set and would
 * only take effect behind TLS. Do not claim it as an active control on
 * localhost.
 */
export function staticSecurityHeaders(isDev: boolean): Record<string, string> {
  const headers: Record<string, string> = {
    // Stop the browser MIME-sniffing a response into something executable.
    "X-Content-Type-Options": "nosniff",
    // Legacy clickjacking control; CSP frame-ancestors is the real one.
    "X-Frame-Options": "DENY",
    // Do not leak the current URL (which can carry ids) to other origins.
    //
    // MUST NOT BE "no-referrer", even though that is the strictest value.
    //
    // Per the Fetch standard, the browser derives the ORIGIN header of a
    // non-CORS, non-GET request — i.e. every plain HTML <form> POST — from the
    // document's REFERRER POLICY. Under "no-referrer" it sends the literal
    // `Origin: null`, which is byte-identical to what a file:// page sends and
    // is exactly what checkOrigin() rejects as a CSRF attempt.
    //
    // With "no-referrer" set here, every form in this app (profile, enrol,
    // upload, admin courses, admin enrolments) was refused with 403
    // {"error":"Request rejected"} in a real browser, while the test suite
    // stayed green: Node's fetch sets Origin explicitly and does not implement
    // Referrer-Policy at all. Two Task 3 controls were fighting each other and
    // only a browser could see it.
    //
    // "same-origin" keeps the privacy property that matters (nothing at all is
    // sent to other origins) and costs nothing in CSRF strength: our own pages
    // now send their real Origin, while a cross-site attacker's page is
    // governed by ITS OWN referrer policy, so it either sends `null` or its own
    // origin — both rejected. See tests/security-headers.test.ts.
    "Referrer-Policy": "same-origin",
    // This app uses none of these APIs; deny them outright.
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
  };

  if (!isDev) {
    headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains";
  }

  return headers;
}
