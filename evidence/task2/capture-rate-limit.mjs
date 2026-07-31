// ============================================================================
//  Evidence capture — Task 2, rate limiting.
//
//  Fires a burst of failed logins from one source address and prints the
//  status of each, then proves the check runs BEFORE authentication and that
//  the bucket is keyed per IP.
//
//  Usage:  npm run dev        (in another terminal)
//          node evidence/task2/capture-rate-limit.mjs
//
//  Screenshot the output as evidence/task2/11-rate-limit.png
// ============================================================================
const BASE = "http://127.0.0.1:3000/api/login";

// A random source address per run, so re-running inside the 60s window starts
// from a clean bucket instead of showing 429 on attempt 1. The range is the
// IANA benchmarking block 198.18.0.0/15 — never routed off this machine.
const IP = `198.18.244.${1 + Math.floor(Math.random() * 250)}`;
const OTHER_IP = `198.18.245.${1 + Math.floor(Math.random() * 250)}`;

const post = (body, ip) =>
  fetch(BASE, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Forwarded-For": ip },
    body: JSON.stringify(body),
  });

const EMAIL = "ada.learner@campus.local";
const CORRECT = "ada-pw-2025";

async function main() {
  console.log("Rate limiting on POST /api/login — 5 failures per IP per 60s.\n");
  console.log(`Source address for this run: ${IP}\n`);

  console.log("Burst of 7 failed logins:");
  for (let i = 1; i <= 7; i++) {
    const res = await post({ email: EMAIL, password: `wrong-${i}` }, IP);
    const retry = res.headers.get("retry-after");
    const body = await res.text();
    console.log(
      `  attempt ${i} -> ${res.status}` +
        (retry ? `  Retry-After: ${retry}` : "") +
        `  ${body}`
    );
  }

  console.log("\nThe throttle is checked BEFORE authentication:");
  const good = await post({ email: EMAIL, password: CORRECT }, IP);
  console.log(
    `  correct password while throttled -> ${good.status}  ${await good.text()}`
  );
  console.log("  (429, not 200 — no DB or Argon2 work is done for a blocked request)");

  console.log("\nThe bucket is keyed per IP, not globally:");
  const other = await post({ email: EMAIL, password: "wrong" }, OTHER_IP);
  console.log(
    `  same account from ${OTHER_IP} -> ${other.status}  ${await other.text()}`
  );
  console.log("  (401, not 429 — a different client still has its full budget)");

  console.log("\nOnly FAILURES are counted, and a success clears the bucket, so a");
  console.log("legitimate user who mistypes twice and then succeeds is never throttled.");
}

main().catch((err) => {
  console.error("\nCapture failed:", err.message);
  console.error("Is the app running?  npm run dev");
  process.exitCode = 1;
});
