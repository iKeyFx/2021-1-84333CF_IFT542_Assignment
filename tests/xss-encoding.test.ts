// ============================================================================
//  Task 3, control 1 — contextual output encoding neutralises stored XSS.
//
//  The assertion has TWO halves and both matter:
//    (a) the payload is still stored VERBATIM in the database, and
//    (b) the served HTML contains only its ESCAPED form.
//
//  Testing (b) alone would pass just as well if the app silently stripped the
//  input, which is a different (and weaker) control. Testing both proves the
//  value is stored intact and rendered inert — which is what "contextual output
//  encoding" actually means.
// ============================================================================
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { authenticate, postForm, getPage, freshIp, db, DEMO, type Session } from "./helpers";
import { DISPLAY_NAME_MAX } from "@/lib/validate";

// Payloads lifted from tests/xss-payload.txt.
const PAYLOADS = [
  `<img src=x onerror="alert('xss-on-dashboard')">`,
  `<img src=x onerror="document.title='XSS'">`,
  `<svg onload="alert(document.cookie)">`,
  `<b style="color:red">not-really-my-name</b>`,
  `<script>alert(1)</script>`,
];

let sql: ReturnType<typeof db>;
let session: Session;

beforeAll(async () => {
  sql = db();
  session = await authenticate(
    DEMO.student.email,
    DEMO.student.password,
    freshIp("xss")
  );
});

afterAll(async () => {
  // Leave the account tidy for the next run / a manual demo.
  await postForm("/api/profile", { display_name: "Ada Learner", bio: "" }, { session });
  await sql.end({ timeout: 5 });
});

describe("a stored XSS payload is stored verbatim but rendered inert", () => {
  for (const payload of PAYLOADS) {
    it(`neutralises ${JSON.stringify(payload.slice(0, 34))}`, async () => {
      const save = await postForm(
        "/api/profile",
        { display_name: payload, bio: "xss probe" },
        { session }
      );
      expect(save.status).toBe(303);

      // (a) stored intact — no sanitiser mangled it
      const [row] = await sql<{ display_name: string }[]>`
        SELECT display_name FROM profiles WHERE email = ${DEMO.student.email}
      `;
      expect(row.display_name).toBe(payload);

      // (b) rendered escaped on BOTH pages that echo it
      for (const path of ["/dashboard", "/profile"]) {
        const { html } = await getPage(path, session);
        expect(html, `${path} must not contain the raw tag`).not.toContain(payload);
        expect(html, `${path} must contain an escaped form`).toContain("&lt;");
      }
    });
  }

  it("never emits an executable event handler attribute into the markup", async () => {
    await postForm(
      "/api/profile",
      { display_name: `<img src=x onerror="alert(1)">`, bio: "" },
      { session }
    );
    const { html } = await getPage("/dashboard", session);

    // The literal characters may appear escaped; what must NOT appear is a real
    // attribute — i.e. `onerror=` preceded by unescaped markup.
    expect(html).not.toMatch(/<img[^>]*onerror=/i);
    expect(html).not.toMatch(/<svg[^>]*onload=/i);
    expect(html).not.toMatch(/<script>alert/i);
  });
});

describe("profile input bounds (resource limits, not a sanitiser)", () => {
  it("rejects a display name over the maximum length", async () => {
    const res = await postForm(
      "/api/profile",
      { display_name: "a".repeat(DISPLAY_NAME_MAX + 1), bio: "" },
      { session }
    );
    expect(res.status).toBe(303);
    expect(res.location).toContain("error=invalid");
  });

  it("rejects an empty display name", async () => {
    const res = await postForm("/api/profile", { display_name: "   ", bio: "" }, { session });
    expect(res.status).toBe(303);
    expect(res.location).toContain("error=invalid");
  });

  it("accepts a payload that is within bounds — the length check is not a filter", async () => {
    const res = await postForm(
      "/api/profile",
      { display_name: `<b>still stored</b>`, bio: "" },
      { session }
    );
    expect(res.status).toBe(303);
    expect(res.location).toContain("saved=1");

    const [row] = await sql<{ display_name: string }[]>`
      SELECT display_name FROM profiles WHERE email = ${DEMO.student.email}
    `;
    expect(row.display_name).toBe("<b>still stored</b>");
  });
});
