// ============================================================================
//  Trigger one of each required security-log event, in order.  Screenshot 21.
//
//  Task 3 deliverable 5 requires structured logs for FAILED-LOGIN,
//  DENIED-AUTHORIZATION and REJECTED-VALIDATION, "each containing who/what/when
//  and NO secrets, tokens, or unnecessary PII".
//
//  HOW TO USE — you need TWO terminals, because the log lines are printed by
//  the SERVER, not by this script:
//
//    terminal 1:  npm run dev            <- screenshot THIS one
//    terminal 2:  node evidence/task3/capture-security-logs.mjs
//
//  Then screenshot terminal 1. This script prints a checklist of exactly what
//  should have appeared there.
//
//  WHY A SCRIPT AND NOT "just trigger the three events": the third one is not
//  obvious. `authz.denied` with reason "not-admin" requires a LOGGED-IN STUDENT
//  posting to an admin endpoint. An anonymous post to the same URL logs
//  reason "no-session" instead — a different event, and the less interesting
//  one. The distinction between "nobody is logged in" and "a real user lacks
//  the role" is the whole point of that log line: only the second is worth
//  alerting on. See src/lib/auth.ts currentAdmin().
//
//  LOCALHOST ONLY. Fictitious data. See ETHICS.md.
// ============================================================================
const BASE = "http://127.0.0.1:3000";
const STUDENT = { email: "ada.learner@campus.local", password: "ada-pw-2025" };

// Distinct source addresses from the IANA benchmarking range, so the rate
// limiter never interferes with the capture. Never routed off this machine.
const IP_BAD_PASSWORD = "198.18.100.11";
const IP_BAD_EMAIL = "198.18.100.12";

const step = (n, title) => {
  console.log(`\n${"=".repeat(76)}`);
  console.log(` ${n}. ${title}`);
  console.log("=".repeat(76));
};

// ---------------------------------------------------------------------------
step(1, "FAILED LOGIN  ->  event: auth.login.failed");
console.log("A real account, a wrong password.");

const failed = await fetch(`${BASE}/api/login`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    origin: BASE,
    "x-forwarded-for": IP_BAD_PASSWORD,
  },
  body: JSON.stringify({ email: STUDENT.email, password: "not-the-right-password" }),
});
console.log(`   HTTP ${failed.status}  ${(await failed.text()).trim()}`);
console.log(`   expect in the server terminal:`);
console.log(`     {"event":"auth.login.failed", ... "email":"a***@campus.local",`);
console.log(`      "reason":"bad-password", "ip":"${IP_BAD_PASSWORD}"}`);

// ---------------------------------------------------------------------------
step(2, "REJECTED VALIDATION  ->  event: validation.rejected");
console.log("A malformed email, refused before any database or Argon2 work.");

const invalid = await fetch(`${BASE}/api/login`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    origin: BASE,
    "x-forwarded-for": IP_BAD_EMAIL,
  },
  body: JSON.stringify({ email: "not-an-email-at-all", password: "irrelevant" }),
});
console.log(`   HTTP ${invalid.status}  ${(await invalid.text()).trim()}`);
console.log(`   expect in the server terminal:`);
console.log(`     {"event":"validation.rejected", ... "reason":"email-format",`);
console.log(`      "ip":"${IP_BAD_EMAIL}"}`);
console.log(`   NOTE the client got the SAME generic 401 as step 1 — the reason`);
console.log(`   exists only in the log. That is the anti-enumeration control.`);

// ---------------------------------------------------------------------------
step(3, "DENIED AUTHORIZATION  ->  event: authz.denied");
console.log("A logged-in STUDENT posting to an admin-only endpoint.");
console.log("(Anonymous would log reason:'no-session' instead — the dull case.)");

// Log in properly first; without a session this logs "no-session", not "not-admin".
const jar = new Map();
const absorb = (res) => {
  for (const raw of res.headers.getSetCookie?.() ?? []) {
    const kv = raw.split(";")[0];
    const i = kv.indexOf("=");
    jar.set(kv.slice(0, i), kv.slice(i + 1));
  }
};
const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");

absorb(await fetch(`${BASE}/login`));
const login = await fetch(`${BASE}/api/login`, {
  method: "POST",
  headers: { "content-type": "application/json", origin: BASE, cookie: cookie() },
  body: JSON.stringify(STUDENT),
  redirect: "manual",
});
absorb(login);

if (!jar.has("sid")) {
  console.log(`\n   COULD NOT LOG IN (HTTP ${login.status}).`);
  console.log(`   Run "npm run db:reset" and make sure the app is running.`);
  process.exitCode = 1;
} else {
  // A page load so middleware issues a CSRF token bound to this session. Not
  // strictly needed — currentAdmin() runs BEFORE requireCsrf() so the authz
  // check fires either way — but sending a valid token proves the 403 is about
  // ROLE and not about a missing token.
  absorb(await fetch(`${BASE}/dashboard`, { headers: { cookie: cookie() }, redirect: "manual" }));
  const token = decodeURIComponent(jar.get("csrf") ?? "");

  const denied = await fetch(`${BASE}/api/admin/courses`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: cookie(),
      origin: BASE,
    },
    body: new URLSearchParams({ _action: "create", code: "HACK101", title: "x", _csrf: token }),
    redirect: "manual",
  });
  console.log(`   HTTP ${denied.status}  -> ${denied.headers.get("location") ?? "(no redirect)"}`);
  console.log(`   expect in the server terminal:`);
  console.log(`     {"event":"authz.denied", "actor":{"type":"user","profile_id":1,`);
  console.log(`      "role":"student"}, "reason":"not-admin", "required_role":"admin"}`);

  // -------------------------------------------------------------------------
  console.log(`\n${"=".repeat(76)}`);
  console.log(" NOW SCREENSHOT THE SERVER TERMINAL (the one running npm run dev)");
  console.log("=".repeat(76));
  console.log(`
 Three JSON lines should be there, newest last:

   1  "event":"auth.login.failed"      reason "bad-password"
   2  "event":"validation.rejected"    reason "email-format"
   3  "event":"authz.denied"           reason "not-admin"

 Check each line has all three of who / what / when:

   WHO   actor {profile_id, role} or {"type":"anonymous"}, and ip
   WHAT  event + method + path + outcome + reason
   WHEN  ts, ISO-8601 UTC

 And check what is NOT there. No password, no digest, no session id, no CSRF
 token — the logger drops those keys itself, so a caller cannot leak one even
 by passing it explicitly. The email appears MASKED as a***@campus.local.

 If the lines are buried in Next.js compile output, filter instead:

   npm run dev 2>&1 | grep --line-buffered '"event":'
`);
}
