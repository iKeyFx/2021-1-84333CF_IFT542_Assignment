// ============================================================================
//  Task 2, extra control (b) — the session id is regenerated on login.
//
//  The v0 build reused whatever `sid` the caller presented (session fixation):
//  an attacker could plant a known id in the victim's browser and still hold a
//  valid session after the victim authenticated.
// ============================================================================
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { randomUUID } from "node:crypto";
import { login, freshIp, db, DEMO } from "./helpers";

const ip = () => ({ ip: freshIp("session") });

let sql: ReturnType<typeof db>;

beforeAll(() => {
  sql = db();
});

afterAll(async () => {
  await sql.end({ timeout: 5 });
});

describe("session id is regenerated across the authentication boundary", () => {
  it("does not reuse a presented sid, and destroys it", async () => {
    // Plant a session id, as an attacker would before handing the victim a link.
    const fixed = randomUUID();
    const [{ id: profileId }] = await sql<[{ id: number }]>`
      SELECT id FROM profiles WHERE email = ${DEMO.student.email}`;
    await sql`INSERT INTO sessions (id, profile_id) VALUES (${fixed}, ${profileId})`;

    const res = await login(DEMO.student.email, DEMO.student.password, {
      ...ip(),
      cookie: `sid=${fixed}`,
    });

    expect(res.status).toBe(200);
    expect(res.sid).not.toBeNull();
    // A brand new id was issued...
    expect(res.sid).not.toBe(fixed);
    // ...and the planted one no longer exists, so the attacker holds nothing.
    const rows = await sql`SELECT 1 FROM sessions WHERE id = ${fixed}`;
    expect(rows.length).toBe(0);
  });

  it("issues a different sid on each successful login", async () => {
    const first = await login(DEMO.student.email, DEMO.student.password, ip());
    const second = await login(DEMO.student.email, DEMO.student.password, {
      ...ip(),
      cookie: `sid=${first.sid}`,
    });

    expect(first.sid).not.toBeNull();
    expect(second.sid).not.toBeNull();
    expect(second.sid).not.toBe(first.sid);
  });

  it("the new sid is a valid, live session bound to the right profile", async () => {
    const res = await login(DEMO.student.email, DEMO.student.password, ip());

    const rows = await sql<Array<{ email: string }>>`
      SELECT p.email FROM sessions s JOIN profiles p ON p.id = s.profile_id
      WHERE s.id = ${res.sid!}
    `;
    expect(rows.length).toBe(1);
    expect(rows[0].email).toBe(DEMO.student.email);
  });

  it("tolerates a malformed sid cookie without a 500", async () => {
    // Regression guard: sessions.id is Postgres type `uuid`, so binding a
    // non-UUID string raises 22P02 unless the DELETE is guarded.
    for (const junk of ["not-a-uuid", "", "'; DROP TABLE sessions; --", "x".repeat(500)]) {
      const res = await login(DEMO.student.email, DEMO.student.password, {
        ...ip(),
        cookie: `sid=${junk}`,
      });
      expect(res.status, `sid=${junk.slice(0, 20)}`).toBe(200);
      expect(res.sid).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
      );
    }
  });

  it("does not destroy OTHER users' sessions", async () => {
    const other = await login(DEMO.student2.email, DEMO.student2.password, ip());
    await login(DEMO.student.email, DEMO.student.password, ip());

    const rows = await sql`SELECT 1 FROM sessions WHERE id = ${other.sid!}`;
    expect(rows.length).toBe(1);
  });
});
