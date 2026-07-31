// ============================================================================
//  Evidence capture — Task 2, session-id regeneration (fixation closed).
//
//  Plants a session id the way an attacker would, has the victim log in with
//  CORRECT credentials, and shows that the planted id is replaced and deleted.
//
//  Usage:  npm run db:reset   (Postgres must be up and seeded)
//          npm run dev        (in another terminal)
//          node evidence/task2/capture-session-regen.mjs
//
//  Screenshot the output as evidence/task2/12-session-regeneration.png
// ============================================================================
import postgres from "postgres";
import { randomUUID } from "node:crypto";

const DATABASE_URL =
  process.env.DATABASE_URL || "postgres://ift542:ift542_dev_pw@127.0.0.1:5432/ift542";

const EMAIL = "ada.learner@campus.local";
const PASSWORD = "ada-pw-2025";
const IP = `198.18.246.${1 + Math.floor(Math.random() * 250)}`;

const sql = postgres(DATABASE_URL, { onnotice: () => {} });

async function main() {
  console.log("Session-id regeneration on POST /api/login.\n");

  const [profile] = await sql`SELECT id FROM profiles WHERE email = ${EMAIL}`;
  if (!profile) throw new Error(`no profile for ${EMAIL} — run: npm run db:reset`);

  // 1. Attacker fixes a session id in the victim's browser.
  const planted = randomUUID();
  await sql`INSERT INTO sessions (id, profile_id) VALUES (${planted}, ${profile.id})`;
  console.log("1. Attacker plants a session id in the victim's browser:");
  console.log(`     sid = ${planted}`);

  // 2. Victim logs in normally, presenting that cookie.
  const res = await fetch("http://127.0.0.1:3000/api/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Forwarded-For": IP,
      Cookie: `sid=${planted}`,
    },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });

  const setCookie = res.headers.getSetCookie();
  const issued = setCookie[0]?.split(";")[0]?.slice(4) ?? null;

  console.log("\n2. Victim logs in with CORRECT credentials, sending that cookie:");
  console.log(`     status      ${res.status}`);
  console.log(`     Set-Cookie  ${setCookie[0] ?? "(none)"}`);

  // 3. The planted id must be gone; the new one must be live.
  const survived = await sql`SELECT 1 FROM sessions WHERE id = ${planted}`;
  const bound = await sql`
    SELECT p.email FROM sessions s JOIN profiles p ON p.id = s.profile_id
    WHERE s.id = ${issued}
  `;

  console.log("\n3. Result:");
  console.log(`     issued sid differs from planted : ${issued !== planted}`);
  console.log(`     planted sid still in DB         : ${survived.length} rows  (0 = destroyed)`);
  console.log(`     issued sid resolves to          : ${bound[0]?.email ?? "NOTHING"}`);

  const ok = issued !== planted && survived.length === 0 && bound[0]?.email === EMAIL;
  console.log(
    `\n${ok ? "[FIXED]" : "[FAIL]"} ` +
      (ok
        ? "The fixed session did not survive login — the attacker holds a deleted id."
        : "Session fixation is NOT closed.")
  );

  await sql.end();
  process.exit(ok ? 0 : 1);
}

main().catch(async (err) => {
  console.error("\nCapture failed:", err.message);
  console.error("Is the app running (npm run dev) and the DB seeded (npm run db:reset)?");
  await sql.end({ timeout: 1 }).catch(() => {});
  process.exit(1);
});
