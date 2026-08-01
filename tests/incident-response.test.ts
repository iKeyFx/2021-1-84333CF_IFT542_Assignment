// ============================================================================
//  Task 3, item 26 — incident-response controls.
//
//  Proves the four CORRECTIVE controls the risk register promised
//  (report/2021-1-84333CF_IFT542_report.md Appendix A) are real and enforced, not documented:
//
//    T1  session revocation             ir/revoke-sessions.mjs
//    T9  invalidate sessions on leak    ir/rotate-secrets.mjs
//    T5  forced reset on breach         ir/force-reset.mjs
//    T4  append-only retention          ir/audit-log.mjs
//
//  These tests run the ACTUAL SCRIPTS with spawnSync and assert on exit code,
//  stdout and database state. Re-implementing the logic here would prove only
//  that the test agrees with itself; `npm run ir:*` is what a responder types
//  and therefore what has to work.
//
//  ORDERING MATTERS IN THIS FILE. The `--all` revocation destroys every live
//  session in the database, including any belonging to another test file, so it
//  runs LAST. Everything before it is scoped to a single account.
//
//  ACCOUNT CHOICE: nova.trainee@campus.local, which no other test file touches.
//  Locking it therefore cannot affect anything else even mid-run.
// ============================================================================
import { describe, it, expect, afterAll, beforeAll } from "vitest";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { db, login, authenticate, freshIp, BASE, GENERIC_ERROR, DEMO } from "./helpers";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FILE = "incident-response";
const ip = () => freshIp(FILE);

const SUBJECT = "nova.trainee@campus.local";
const SUBJECT_PASSWORD = "nova-pw-2025";

/** Scopes this file's security_events assertions — the table survives db:reset
 *  and the suite cannot delete its own rows, which is the control working. */
const INCIDENT = `TEST-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

type Run = { code: number; stdout: string; stderr: string; all: string };

/** Run an ir/ script exactly as `npm run ir:<name>` would. */
function ir(script: string, args: string[] = []): Run {
  const res = spawnSync(process.execPath, [join(ROOT, "ir", `${script}.mjs`), ...args], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 60_000,
    env: { ...process.env, IR_OPERATOR: "vitest@ift542-lab" },
  });
  const stdout = res.stdout ?? "";
  const stderr = res.stderr ?? "";
  return { code: res.status ?? -1, stdout, stderr, all: stdout + stderr };
}

/** A mutation, with this file's incident id already attached. */
const irApply = (script: string, args: string[]) =>
  ir(script, [...args, "--incident", INCIDENT, "--yes"]);

async function lockedCount(): Promise<number> {
  const sql = db();
  try {
    const rows = await sql<{ n: number }[]>`
      SELECT count(*)::int AS n FROM credential_resets r
      JOIN profiles p ON p.id = r.profile_id WHERE p.email = ${SUBJECT}
    `;
    return rows[0].n;
  } finally {
    await sql.end({ timeout: 1 });
  }
}

async function sessionCount(email: string): Promise<number> {
  const sql = db();
  try {
    const rows = await sql<{ n: number }[]>`
      SELECT count(*)::int AS n FROM sessions s
      JOIN profiles p ON p.id = s.profile_id WHERE p.email = ${email}
    `;
    return rows[0].n;
  } finally {
    await sql.end({ timeout: 1 });
  }
}

beforeAll(async () => {
  // Guard against a leaked lock from an earlier crashed run inside this file.
  if ((await lockedCount()) > 0) {
    irApply("force-reset", ["--complete", "--email", SUBJECT]);
  }
});

afterAll(async () => {
  // Never leave the subject locked: a stray credential_resets row would break
  // every later run of the whole suite. global-setup.ts also fails loudly on
  // one, but cleaning up here is what stops that from ever firing.
  if ((await lockedCount()) > 0) {
    irApply("force-reset", ["--complete", "--email", SUBJECT]);
  }
});

// ---------------------------------------------------------------------------
describe("IR tooling — CLI safety contract", () => {
  it("--help exits 0 for every script and needs no database mutation", () => {
    for (const script of [
      "status",
      "revoke-sessions",
      "rotate-secrets",
      "force-reset",
      "audit-log",
    ]) {
      const run = ir(script, ["--help"]);
      expect(run.code, `${script} --help`).toBe(0);
      expect(run.stdout).toContain(script);
    }
  });

  it("refuses to act without a scope (exit 2)", () => {
    const run = ir("revoke-sessions", []);
    expect(run.code).toBe(2);
    expect(run.all).toMatch(/scope is required/i);
  });

  it("refuses two scopes at once (exit 2)", () => {
    const run = ir("revoke-sessions", ["--all", "--role", "admin"]);
    expect(run.code).toBe(2);
    expect(run.all).toMatch(/mutually exclusive/i);
  });

  it("refuses --yes without --incident, so no action is unattributable", async () => {
    const before = await sessionCount(SUBJECT);
    const run = ir("revoke-sessions", ["--all", "--yes"]);

    expect(run.code).toBe(2);
    expect(run.all).toMatch(/--incident/);
    // The important half: it exited 2 AND changed nothing.
    expect(await sessionCount(SUBJECT)).toBe(before);
  });

  it("DEFAULTS TO A DRY RUN — a scope alone mutates nothing", async () => {
    const session = await authenticate(SUBJECT, SUBJECT_PASSWORD, ip());
    expect(session.sid).not.toBe("");
    const before = await sessionCount(SUBJECT);
    expect(before).toBeGreaterThan(0);

    const run = ir("revoke-sessions", ["--email", SUBJECT]);

    expect(run.code).toBe(0);
    expect(run.stdout).toMatch(/\[DRY RUN\]/);
    expect(await sessionCount(SUBJECT)).toBe(before);
  });

  it("rejects an unknown scope target as a runtime failure, not a silent no-op", () => {
    const run = ir("revoke-sessions", ["--email", "no.such.person@campus.local"]);
    expect(run.code).toBe(1);
    expect(run.all).toMatch(/no profile with email/i);
  });
});

// ---------------------------------------------------------------------------
describe("T1/T9 — session revocation ends an attacker's access", () => {
  it("revokes one account's sessions and logs the operator out (307)", async () => {
    const session = await authenticate(SUBJECT, SUBJECT_PASSWORD, ip());
    expect(await sessionCount(SUBJECT)).toBeGreaterThan(0);

    // The cookie works before revocation.
    const before = await fetch(`${BASE}/dashboard`, {
      headers: { Cookie: session.cookie },
      redirect: "manual",
    });
    expect(before.status).toBe(200);

    const run = irApply("revoke-sessions", ["--email", SUBJECT]);
    expect(run.code).toBe(0);
    expect(run.stdout).toMatch(/REVOKED \d+ session/);

    expect(await sessionCount(SUBJECT)).toBe(0);

    // The SAME cookie is now worthless. Middleware only redirects when `sid` is
    // ABSENT, so a revoked-but-present cookie falls through to currentUser()
    // and is redirected there instead — 307, not 200.
    const after = await fetch(`${BASE}/dashboard`, {
      headers: { Cookie: session.cookie },
      redirect: "manual",
    });
    expect(after.status).toBe(307);
    expect(after.headers.get("location")).toContain("/login");
  });

  it("scopes correctly: revoking one account leaves another's session alive", async () => {
    const subject = await authenticate(SUBJECT, SUBJECT_PASSWORD, ip());
    const bystander = await authenticate(DEMO.student.email, DEMO.student.password, ip());

    const run = irApply("revoke-sessions", ["--email", SUBJECT]);
    expect(run.code).toBe(0);

    expect(await sessionCount(SUBJECT)).toBe(0);
    expect(await sessionCount(DEMO.student.email)).toBeGreaterThan(0);

    const still = await fetch(`${BASE}/dashboard`, {
      headers: { Cookie: bystander.cookie },
      redirect: "manual",
    });
    expect(still.status).toBe(200);
    expect(subject.sid).not.toBe(bystander.sid);
  });

  it("records the revocation to the append-only audit log", async () => {
    const sql = db();
    try {
      const rows = await sql<{ event: string; outcome: string; detail: any }[]>`
        SELECT event, outcome, detail FROM security_events
        WHERE incident_id = ${INCIDENT} AND event = 'ir.sessions.revoked'
        ORDER BY id DESC LIMIT 1
      `;
      expect(rows.length).toBe(1);
      expect(rows[0].outcome).toBe("revoked");
      expect(rows[0].detail.sessions_deleted).toBeGreaterThan(0);

      // A session id is a bearer credential; it must never be written to a log.
      expect(JSON.stringify(rows[0].detail)).not.toMatch(
        /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i
      );
    } finally {
      await sql.end({ timeout: 1 });
    }
  });
});

// ---------------------------------------------------------------------------
describe("T5 — forced reset locks an account without becoming an oracle", () => {
  it("--require locks the account AND revokes its live sessions", async () => {
    await authenticate(SUBJECT, SUBJECT_PASSWORD, ip());
    expect(await sessionCount(SUBJECT)).toBeGreaterThan(0);

    const run = irApply("force-reset", ["--require", "--email", SUBJECT]);
    expect(run.code).toBe(0);
    expect(run.stdout).toMatch(/LOCKED 1 account/);

    expect(await lockedCount()).toBe(1);
    // The half that makes it a control: a lock that leaves sessions alive does
    // nothing to an attacker who already holds a sid.
    expect(await sessionCount(SUBJECT)).toBe(0);
  });

  it("refuses the login EVEN WITH THE CORRECT PASSWORD", async () => {
    expect(await lockedCount()).toBe(1);

    const res = await login(SUBJECT, SUBJECT_PASSWORD, { ip: ip() });
    expect(res.status).toBe(401);
    expect(res.body).toEqual(GENERIC_ERROR);
    expect(res.sid).toBeNull();
  });

  it("is BYTE-IDENTICAL to a wrong password and to an unknown account", async () => {
    const locked = await login(SUBJECT, SUBJECT_PASSWORD, { ip: ip() });
    const wrongPw = await login(SUBJECT, "definitely-not-the-password", { ip: ip() });
    const unknown = await login("nobody.at.all@campus.local", SUBJECT_PASSWORD, { ip: ip() });

    for (const other of [wrongPw, unknown]) {
      expect(locked.status).toBe(other.status);
      expect(JSON.stringify(locked.body)).toBe(JSON.stringify(other.body));
      expect(locked.setCookie.length).toBe(other.setCookie.length);
    }
    // No response header may differ either, or the lock is still detectable.
    expect(locked.setCookie).toEqual([]);
    expect(locked.headers.get("content-type")).toBe(wrongPw.headers.get("content-type"));
  });

  it("re-locking an already-locked account is a no-op, not an error", () => {
    const run = irApply("force-reset", ["--require", "--email", SUBJECT]);
    expect(run.code).toBe(0);
    expect(run.stdout).toMatch(/already locked/i);
  });

  it("--complete clears the lock and login works again", async () => {
    const run = irApply("force-reset", ["--complete", "--email", SUBJECT]);
    expect(run.code).toBe(0);
    expect(run.stdout).toMatch(/UNLOCKED 1 account/);

    expect(await lockedCount()).toBe(0);

    const res = await login(SUBJECT, SUBJECT_PASSWORD, { ip: ip() });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.sid).not.toBeNull();
  });

  it("records both the lock and the unlock, with the email masked", async () => {
    const sql = db();
    try {
      const rows = await sql<{ event: string; detail: any; actor_email: string }[]>`
        SELECT event, detail, actor_email FROM security_events
        WHERE incident_id = ${INCIDENT}
          AND event IN ('ir.credentials.reset_required', 'ir.credentials.reset_completed')
        ORDER BY id
      `;
      const events = rows.map((r) => r.event);
      expect(events).toContain("ir.credentials.reset_required");
      expect(events).toContain("ir.credentials.reset_completed");

      // Masked, never the full address — INCLUDING inside the `scope` string,
      // which used to echo whatever the operator typed after --email.
      const blob = JSON.stringify(rows.map((r) => r.detail));
      expect(blob).toContain("n***@campus.local");
      expect(blob).not.toContain(SUBJECT);
      // And no password, hash or token rode along.
      expect(blob).not.toContain(SUBJECT_PASSWORD);
      expect(blob).not.toContain("$argon2id$");

      // The operator IS recorded, unmasked and on purpose: an unattributable
      // response action is the T4 threat all over again. It must not be a
      // subject's address, though.
      for (const r of rows) {
        expect(r.actor_email).toBe("vitest@ift542-lab");
      }
    } finally {
      await sql.end({ timeout: 1 });
    }
  });
});

// ---------------------------------------------------------------------------
describe("T4 — the audit log is append-only", () => {
  it("--verify passes every check, including the zero-row DELETE", () => {
    const run = ir("audit-log", ["--verify"]);
    expect(run.code).toBe(0);
    expect(run.stdout).toMatch(/ALL \d+ CHECKS PASSED/);
    expect(run.stdout).not.toMatch(/\[FAIL\]/);
    // The check that distinguishes a statement-level trigger from a row-level
    // one. Without it the whole control is bypassable with `WHERE id = -1`.
    expect(run.stdout).toMatch(/DELETE matching ZERO rows is refused/);
  });

  it("UPDATE is refused with SQLSTATE 42501", async () => {
    const sql = db();
    try {
      await expect(
        sql`UPDATE security_events SET outcome = 'tampered' WHERE incident_id = ${INCIDENT}`
      ).rejects.toMatchObject({ code: "42501" });
    } finally {
      await sql.end({ timeout: 1 });
    }
  });

  it("DELETE is refused with SQLSTATE 42501", async () => {
    const sql = db();
    try {
      await expect(
        sql`DELETE FROM security_events WHERE incident_id = ${INCIDENT}`
      ).rejects.toMatchObject({ code: "42501" });
    } finally {
      await sql.end({ timeout: 1 });
    }
  });

  it("DELETE matching ZERO rows is STILL refused (the trigger is statement-level)", async () => {
    const sql = db();
    try {
      // A row-level BEFORE DELETE trigger never fires when nothing matches, so
      // this would succeed silently and every "DELETE is blocked" assertion
      // above would be satisfiable by an attacker with a narrow WHERE clause.
      await expect(
        sql`DELETE FROM security_events WHERE id = -1`
      ).rejects.toMatchObject({ code: "42501" });
    } finally {
      await sql.end({ timeout: 1 });
    }
  });

  it("TRUNCATE is refused with SQLSTATE 42501", async () => {
    const sql = db();
    try {
      await expect(sql.unsafe("TRUNCATE security_events")).rejects.toMatchObject({
        code: "42501",
      });
    } finally {
      await sql.end({ timeout: 1 });
    }
  });

  it("INSERT still works — append-only, not read-only", async () => {
    const sql = db();
    try {
      const before = await sql<{ n: number }[]>`
        SELECT count(*)::int AS n FROM security_events WHERE incident_id = ${INCIDENT}
      `;
      await sql`
        INSERT INTO security_events (event, level, outcome, incident_id)
        VALUES ('ir.audit.test_probe', 'debug', 'probe', ${INCIDENT})
      `;
      const after = await sql<{ n: number }[]>`
        SELECT count(*)::int AS n FROM security_events WHERE incident_id = ${INCIDENT}
      `;
      expect(after[0].n).toBe(before[0].n + 1);
    } finally {
      await sql.end({ timeout: 1 });
    }
  });

  it("--tail reads records back without needing a mutation flag", () => {
    const run = ir("audit-log", ["--tail", "5"]);
    expect(run.code).toBe(0);
    expect(run.stdout).toMatch(/AUDIT LOG — most recent 5/);
  });

  it("ir:status reports the triggers as present", () => {
    const run = ir("status", []);
    expect(run.code).toBe(0);
    expect(run.stdout).toMatch(/append-only triggers: BOTH PRESENT/);
  });
});

// ---------------------------------------------------------------------------
//  LAST IN THE FILE — --all destroys every session in the database, including
//  ones belonging to other test files. Vitest runs files sequentially
//  (fileParallelism: false) but tests within a file in order, so "last" is the
//  only safe place for it.
// ---------------------------------------------------------------------------
describe("T1 — mass revocation (runs last: it clears the whole database)", () => {
  it("--all revokes every session and audits the count", async () => {
    await authenticate(SUBJECT, SUBJECT_PASSWORD, ip());
    await authenticate(DEMO.student.email, DEMO.student.password, ip());

    const sql = db();
    let before: number;
    try {
      const rows = await sql<{ n: number }[]>`SELECT count(*)::int AS n FROM sessions`;
      before = rows[0].n;
    } finally {
      await sql.end({ timeout: 1 });
    }
    expect(before).toBeGreaterThan(0);

    const run = irApply("revoke-sessions", ["--all"]);
    expect(run.code).toBe(0);
    expect(run.stdout).toMatch(/REVOKED \d+ session/);

    const sql2 = db();
    try {
      const rows = await sql2<{ n: number }[]>`SELECT count(*)::int AS n FROM sessions`;
      expect(rows[0].n).toBe(0);
    } finally {
      await sql2.end({ timeout: 1 });
    }
  });

  it("a second --all is a recorded no-op rather than an error", () => {
    const run = irApply("revoke-sessions", ["--all"]);
    expect(run.code).toBe(0);
    expect(run.stdout).toMatch(/no live sessions in scope/);
    expect(run.stdout).toMatch(/recorded a no-op/);
  });
});
