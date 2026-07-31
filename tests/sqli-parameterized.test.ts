// ============================================================================
//  Task 2 — the login query is parameterized: injection strings in the email
//  field are treated as DATA and cannot alter the query result.
//
//  This asserts BOTH halves:
//    A. HTTP  — the payloads produce a generic 401 and no session is issued.
//    B. DATA  — the query genuinely matched nothing, the database is untouched,
//               and a direct probe shows the payload binding as a literal.
//
//  Half B matters because validation ALSO rejects these payloads before the DB
//  is reached. Asserting only the HTTP status would prove validation works, not
//  that the query is safe. The direct probe tests the query itself.
// ============================================================================
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type postgres from "postgres";
import { login, freshIp, db, GENERIC_ERROR, DEMO } from "./helpers";

const ip = () => ({ ip: freshIp("sqli") });

const PAYLOADS = [
  "' OR '1'='1' -- ",
  "admin@campus.local' --",
  "x' OR 1=1--",
  "' UNION SELECT 1,2,3,4,5 --",
  "' OR ''='",
  "'; DROP TABLE sessions; --",
];

let sql: ReturnType<typeof db>;

beforeAll(() => {
  sql = db();
});

afterAll(async () => {
  await sql.end({ timeout: 5 });
});

describe("A. injection payloads do not bypass authentication", () => {
  for (const payload of PAYLOADS) {
    it(`rejects ${JSON.stringify(payload)} with the generic 401`, async () => {
      const res = await login(payload, "irrelevant", ip());

      expect(res.status).toBe(401);
      expect(res.body).toEqual(GENERIC_ERROR);
      // No session was issued — this is the v0 bypass, closed.
      expect(res.sid).toBeNull();
      expect(res.setCookie.find((c) => c.startsWith("sid="))).toBeUndefined();
    });
  }

  it("also resists the classic payload in the PASSWORD field", async () => {
    const res = await login(DEMO.student.email, "' OR '1'='1", ip());
    expect(res.status).toBe(401);
    expect(res.body).toEqual(GENERIC_ERROR);
    expect(res.sid).toBeNull();
  });
});

describe("B. the payload is bound as data, and the database is untouched", () => {
  it("creates no session rows during the injection burst", async () => {
    const [{ before }] = await sql<[{ before: number }]>`
      SELECT count(*)::int AS before FROM sessions`;

    for (const payload of PAYLOADS) {
      await login(payload, "irrelevant", ip());
    }

    const [{ after }] = await sql<[{ after: number }]>`
      SELECT count(*)::int AS after FROM sessions`;
    expect(after).toBe(before);
  });

  it("binds the payload as a literal string, matching zero rows", async () => {
    const payload = "' OR '1'='1' -- ";

    // This is the hardened query's WHERE clause, run through the same driver
    // and the same tagged-template mechanism the route uses.
    const rows = await sql`SELECT id FROM profiles WHERE email = ${payload}`;
    expect(rows.length).toBe(0);

    // For contrast: the v0 build concatenated the payload into the string,
    // producing  WHERE email = '' OR '1'='1' -- '  which matched every row.
    const [{ total }] = await sql<[{ total: number }]>`
      SELECT count(*)::int AS total FROM profiles`;
    expect(total).toBeGreaterThan(0);
    expect(rows.length).not.toBe(total);
  });

  it("does not execute a stacked DROP TABLE", async () => {
    await login("'; DROP TABLE sessions; --", "irrelevant", ip());

    const [{ tbl }] = await sql<[{ tbl: string | null }]>`
      SELECT to_regclass('sessions')::text AS tbl`;
    expect(tbl).toBe("sessions");

    const [{ profiles }] = await sql<[{ profiles: number }]>`
      SELECT count(*)::int AS profiles FROM profiles`;
    expect(profiles).toBe(7);
  });

  it("the login handler contains no sql.unsafe call and no concatenated SQL", async () => {
    // Static guard against a regression the HTTP tests could not see — e.g.
    // string building reintroduced on a code path these payloads do not reach.
    const { readFile } = await import("node:fs/promises");
    const raw = await readFile(
      new URL("../src/app/api/login/route.ts", import.meta.url),
      "utf8"
    );

    // Strip comments first: the file DESCRIBES the removed sql.unsafe() call in
    // its header, and we are asserting about code, not prose.
    const code = raw.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");

    expect(code).not.toMatch(/sql\.unsafe/);
    // No string concatenation building a SQL fragment.
    expect(code).not.toMatch(/["'](?:SELECT|WHERE|FROM)[^"']*["']\s*\+/i);
    // The query is a tagged template binding the validated email.
    expect(code).toMatch(/WHERE p\.email = \$\{input\.email\}/);
  });
});
