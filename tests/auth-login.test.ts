// ============================================================================
//  Task 2 — valid login works, invalid credentials are rejected, and every
//  failure mode returns ONE generic error.
//
//  Each test uses a freshly allocated source IP so that the per-IP rate
//  limiter (proved separately in rate-limit.test.ts) never interferes here.
// ============================================================================
import { describe, it, expect } from "vitest";
import {
  login,
  loginRaw,
  freshIp,
  DEMO,
  GENERIC_ERROR,
  RETIRED_ADMIN_PASSWORD,
} from "./helpers";

const ip = () => ({ ip: freshIp("auth-login") });

describe("valid credentials are accepted", () => {
  it("logs in a seeded student and issues a session cookie", async () => {
    const res = await login(DEMO.student.email, DEMO.student.password, ip());

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.user.email).toBe(DEMO.student.email);
    expect(res.body.user.role).toBe("student");

    const sid = res.setCookie.find((c) => c.startsWith("sid="));
    expect(sid).toMatch(/^sid=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12};/i);
  });

  it("never leaks the password hash or debug fields in the success body", async () => {
    const res = await login(DEMO.student2.email, DEMO.student2.password, ip());

    expect(res.status).toBe(200);
    const serialised = JSON.stringify(res.body);
    for (const leak of ["password", "password_hash", "argon2", "stack", "query"]) {
      expect(serialised).not.toContain(leak);
    }
  });

  it("logs in the admin with the rotated strong password", async () => {
    const res = await login(DEMO.admin.email, DEMO.admin.password, ip());

    expect(res.status).toBe(200);
    expect(res.body.user.role).toBe("admin");
  });

  it("REJECTS the retired default admin password (Task 3 fix)", async () => {
    // `admin123` was the well-known default seeded in the vulnerable build.
    // Task 3 rotated it; this asserts the old credential is genuinely dead
    // rather than merely undocumented.
    const res = await login(DEMO.admin.email, RETIRED_ADMIN_PASSWORD, ip());

    expect(res.status).toBe(401);
    expect(res.body).toEqual(GENERIC_ERROR);
    expect(res.sid).toBeNull();
  });
});

describe("invalid credentials are rejected with one generic error", () => {
  it("rejects a wrong password for a real account", async () => {
    const res = await login(DEMO.student.email, "definitely-not-the-password", ip());

    expect(res.status).toBe(401);
    expect(res.body).toEqual(GENERIC_ERROR);
    expect(res.setCookie.find((c) => c.startsWith("sid="))).toBeUndefined();
  });

  it("returns a BYTE-IDENTICAL response for an unknown email (no enumeration)", async () => {
    const unknown = await login("nobody.here@campus.local", "some-password", ip());
    const wrongPw = await login(DEMO.student.email, "some-password", ip());

    expect(unknown.status).toBe(wrongPw.status);
    expect(unknown.body).toEqual(wrongPw.body);
    expect(unknown.body).toEqual(GENERIC_ERROR);

    // The v0 build answered "No account exists with that email address." vs
    // "Incorrect password for that account." — the enumeration oracle.
    expect(JSON.stringify(unknown.body)).not.toMatch(/no account|exists|incorrect password/i);
  });

  it("never returns a stack trace, driver message or raw SQL", async () => {
    // In v0 this payload forced a DB cast error and the handler returned
    // err.message + err.stack + the concatenated query.
    const res = await login("' AND 1=CAST('x' AS int) -- ", "irrelevant", ip());

    expect(res.status).toBe(401);
    expect(res.body).toEqual(GENERIC_ERROR);
    expect(res.body.stack).toBeUndefined();
    expect(res.body.query).toBeUndefined();
    expect(JSON.stringify(res.body)).not.toMatch(/SELECT|FROM|postgres|invalid input syntax/i);
  });
});

describe("input validation — all failure modes collapse to the same reply", () => {
  const cases: Array<[string, unknown, unknown]> = [
    ["malformed email", "not-an-email", "some-password"],
    ["empty email", "", "some-password"],
    ["over-long email (300 chars)", `${"a".repeat(290)}@x.local`, "some-password"],
    ["email containing whitespace", "ada learner@campus.local", "some-password"],
    ["password too short", DEMO.student.email, "short"],
    ["password too long (200 chars)", DEMO.student.email, "p".repeat(200)],
    ["non-string email", 12345, "some-password"],
    ["non-string password", DEMO.student.email, { $ne: null }],
    ["array email (coercion probe)", [DEMO.student.email], DEMO.student.password],
    ["missing fields", undefined, undefined],
  ];

  for (const [name, email, password] of cases) {
    it(`rejects ${name} with the generic 401`, async () => {
      const res = await login(email, password, ip());
      expect(res.status).toBe(401);
      expect(res.body).toEqual(GENERIC_ERROR);
    });
  }

  it("rejects a non-JSON body without a 500", async () => {
    const res = await loginRaw("this is not json", ip());
    expect(res.status).toBe(401);
    expect(res.body).toEqual(GENERIC_ERROR);
  });

  it("rejects a JSON array body without a 500", async () => {
    const res = await loginRaw("[1,2,3]", ip());
    expect(res.status).toBe(401);
    expect(res.body).toEqual(GENERIC_ERROR);
  });
});
