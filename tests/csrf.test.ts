// ============================================================================
//  Task 3, control 2 — anti-CSRF tokens on every state-changing POST.
//
//  A forged cross-site request must fail, AND the state must be unchanged. A
//  test that only checks the status code would pass even if the handler applied
//  the change and then returned 403, so every rejection here is paired with a
//  database check where one is observable.
// ============================================================================
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  authenticate,
  anonymousCsrf,
  postForm,
  postJson,
  freshIp,
  db,
  DEMO,
  ADMIN_PASSWORD,
  type Session,
} from "./helpers";

let sql: ReturnType<typeof db>;
let student: Session;
let admin: Session;

async function displayName(): Promise<string> {
  const [row] = await sql<{ display_name: string }[]>`
    SELECT display_name FROM profiles WHERE email = ${DEMO.student.email}
  `;
  return row.display_name;
}

beforeAll(async () => {
  sql = db();
  student = await authenticate(DEMO.student.email, DEMO.student.password, freshIp("csrf"));
  admin = await authenticate(
    DEMO.admin.email,
    ADMIN_PASSWORD,
    freshIp("csrf"),
    "/admin/courses"
  );
  await postForm("/api/profile", { display_name: "Ada Learner", bio: "" }, { session: student });
});

afterAll(async () => {
  await postForm("/api/profile", { display_name: "Ada Learner", bio: "" }, { session: student });
  await sql.end({ timeout: 5 });
});

describe("a token is issued and is bound to the session", () => {
  it("issues a csrf token to an authenticated visitor", () => {
    expect(student.csrf).toBeTruthy();
    expect(student.csrf).toContain(".");
  });

  it("binds the token to the session id, so it rotates on login", () => {
    expect(student.csrf.split(".")[0]).toBe(student.sid);
  });

  it("issues a token to an anonymous visitor too (the logout form is on every page)", async () => {
    const anon = await anonymousCsrf();
    expect(anon.csrf).toBeTruthy();
  });
});

describe("POST /api/profile", () => {
  it("accepts a request carrying a valid token", async () => {
    const res = await postForm(
      "/api/profile",
      { display_name: "Ada Valid", bio: "ok" },
      { session: student }
    );
    expect(res.status).toBe(303);
    expect(await displayName()).toBe("Ada Valid");
  });

  it("rejects a request with NO token, and does not change state", async () => {
    const before = await displayName();
    const res = await postForm(
      "/api/profile",
      { display_name: "CSRF'd by another site", bio: "forged" },
      { session: student, csrf: null }
    );
    expect(res.status).toBe(403);
    expect(await displayName()).toBe(before);
  });

  it("rejects a tampered signature", async () => {
    const before = await displayName();
    const tampered = `${student.csrf.split(".")[0]}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
    const res = await postForm(
      "/api/profile",
      { display_name: "forged", bio: "" },
      { session: student, csrf: tampered }
    );
    expect(res.status).toBe(403);
    expect(await displayName()).toBe(before);
  });

  it("rejects a VALID token minted for a DIFFERENT session", async () => {
    // The admin's token is perfectly well signed — it is simply not bound to
    // this session. This is what stops an attacker replaying their own token.
    const before = await displayName();
    const res = await postForm(
      "/api/profile",
      { display_name: "forged", bio: "" },
      { session: student, csrf: admin.csrf }
    );
    expect(res.status).toBe(403);
    expect(await displayName()).toBe(before);
  });

  it("rejects Origin: null — the file:// PoC in evidence/task3", async () => {
    const before = await displayName();
    const res = await postForm(
      "/api/profile",
      { display_name: "CSRF'd by another site", bio: "" },
      { session: student, origin: "null" }
    );
    expect(res.status).toBe(403);
    expect(await displayName()).toBe(before);
  });

  it("rejects a foreign Origin even with a valid token", async () => {
    const before = await displayName();
    const res = await postForm(
      "/api/profile",
      { display_name: "forged", bio: "" },
      { session: student, origin: "http://evil.test" }
    );
    expect(res.status).toBe(403);
    expect(await displayName()).toBe(before);
  });

  it("accepts a same-origin Origin header", async () => {
    const res = await postForm(
      "/api/profile",
      { display_name: "Ada SameOrigin", bio: "" },
      { session: student, origin: "http://127.0.0.1:3000" }
    );
    expect(res.status).toBe(303);
  });
});

describe("POST /api/enrol", () => {
  it("rejects a forged enrolment and creates no row", async () => {
    const [{ before }] = await sql<[{ before: number }]>`
      SELECT count(*)::int AS before FROM enrolments`;

    const res = await postForm("/api/enrol", { course_id: "3" }, { session: student, csrf: null });
    expect(res.status).toBe(403);

    const [{ after }] = await sql<[{ after: number }]>`
      SELECT count(*)::int AS after FROM enrolments`;
    expect(after).toBe(before);
  });

  it("accepts an enrolment with a valid token", async () => {
    const res = await postForm("/api/enrol", { course_id: "3" }, { session: student });
    expect(res.status).toBe(303);
  });
});

describe("every other state-changing endpoint is protected", () => {
  const cases: Array<[string, Record<string, string>, "student" | "admin"]> = [
    ["/api/logout", {}, "student"],
    ["/api/admin/courses", { _action: "delete", id: "999999" }, "admin"],
    ["/api/admin/enrolments", { enrolment_id: "999999" }, "admin"],
  ];

  for (const [path, fields, who] of cases) {
    it(`rejects ${path} without a token`, async () => {
      const session = who === "admin" ? admin : student;
      const res = await postForm(path, fields, { session, csrf: null });
      expect(res.status).toBe(403);
    });
  }

  it("rejects /api/admin/url-preview without a token", async () => {
    const res = await postJson(
      "/api/admin/url-preview",
      { url: "https://example.com/" },
      { session: admin, csrf: null }
    );
    expect(res.status).toBe(403);
  });
});

describe("/api/login is token-exempt but origin-checked", () => {
  it("allows a login with no Origin header (non-browser client)", async () => {
    const res = await fetch("http://127.0.0.1:3000/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Forwarded-For": freshIp("csrf") },
      body: JSON.stringify({ email: DEMO.student.email, password: DEMO.student.password }),
      redirect: "manual",
    });
    expect(res.status).toBe(200);
  });

  it("rejects a cross-site login attempt (Origin: null)", async () => {
    const res = await fetch("http://127.0.0.1:3000/api/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Forwarded-For": freshIp("csrf"),
        Origin: "null",
      },
      body: JSON.stringify({ email: DEMO.student.email, password: DEMO.student.password }),
      redirect: "manual",
    });
    expect(res.status).toBe(403);
  });
});
