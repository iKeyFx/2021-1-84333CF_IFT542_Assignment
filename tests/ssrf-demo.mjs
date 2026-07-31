// ============================================================================
//  LOCAL, APP-ONLY test case: SSRF via the admin URL-preview feature of THIS
//  app. Hard-wired to http://127.0.0.1:3000. Demonstrates the planted
//  [VULN: SSRF — Task 3] in src/app/api/admin/url-preview/route.ts by asking
//  the server to fetch a LOOPBACK URL it should never reach on the client's
//  behalf.
//
//  Usage:  node tests/ssrf-demo.mjs
// ============================================================================
const BASE = "http://127.0.0.1:3000";

// 1) Log in as the (default) admin to obtain a session cookie.
const loginRes = await fetch(`${BASE}/api/login`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    email: "admin@campus.local",
    // [Task 3] rotated off the well-known default; matches
    // ADMIN_PASSWORD_FALLBACK in db/hash-passwords.mjs.
    password: process.env.ADMIN_PASSWORD || "Adm1n-Str0ng-Dummy-2026-x7QF",
  }),
});
const cookies = loginRes.headers.getSetCookie?.() ?? [];
const jar = new Map(
  cookies.map((c) => {
    const kv = c.split(";")[0];
    const i = kv.indexOf("=");
    return [kv.slice(0, i), kv.slice(i + 1)];
  })
);
if (!jar.has("sid")) {
  console.error("Could not obtain admin session (is the DB seeded / server up?).");
  process.exitCode = 1;
  // Halt without process.exit() — see the note at the foot of this file.
  throw new Error("no admin session");
}
console.log("Logged in as admin; session cookie acquired.");

// 1b) [Task 3] Fetch a page to pick up the anti-CSRF token. Without this the
//     request is refused by the CSRF check BEFORE the SSRF guard ever runs,
//     which would make this script prove the wrong thing.
const page = await fetch(`${BASE}/admin/url-preview`, {
  headers: { Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; ") },
});
for (const c of page.headers.getSetCookie?.() ?? []) {
  const kv = c.split(";")[0];
  const i = kv.indexOf("=");
  jar.set(kv.slice(0, i), kv.slice(i + 1));
}
const cookieHeader = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
const csrfToken = decodeURIComponent(jar.get("csrf") ?? "");

// 2) Ask the server to fetch an internal/loopback URL. A safe implementation
//    would refuse 127.0.0.1 / localhost / link-local / private ranges.
const internalTarget = "http://127.0.0.1:3000/login";
console.log("\nAsking the SERVER to fetch:", internalTarget);

const res = await fetch(`${BASE}/api/admin/url-preview`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Cookie: cookieHeader,
    "x-csrf-token": csrfToken,
  },
  body: JSON.stringify({ url: internalTarget }),
});
const data = await res.json();

console.log("HTTP status of preview call:", res.status);
console.log("Server fetched status:", data.status, data.statusText);
console.log("Returned body snippet (first 200 chars):");
console.log("  " + String(data.bodySnippet ?? data.error ?? "").slice(0, 200).replace(/\n/g, " "));

if (data.ok) {
  console.log(
    "\n[SSRF CONFIRMED] The server followed a loopback URL and returned its body — " +
      "no host/scheme/IP restrictions are applied. Point this at any internal service to read it."
  );
  process.exitCode = 0;
} else {
  // [FIXED — Task 3] Expected outcome on the hardened build.
  console.log(
    "\n[SSRF BLOCKED] The server refused to fetch the loopback URL. " +
      "src/lib/url-guard.ts rejected it before any request left the process; the " +
      "specific reason is in the server log only, since the reason itself would " +
      "be an internal-network oracle."
  );
  process.exitCode = 1;
}

// NOTE: these scripts set `process.exitCode` instead of calling process.exit().
// On Windows, process.exit() while an undici keep-alive socket is still closing
// trips a libuv assertion (`!(handle->flags & UV_HANDLE_CLOSING)`) and aborts
// with exit 127, which corrupts the captured evidence. Setting exitCode lets the
// event loop drain and produces the same status cleanly.
