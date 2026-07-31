// ============================================================================
//  Task 3, control 4 — security headers and the Content-Security-Policy.
//
//  These run against `next dev`, so the CSP asserted here is the DEVELOPMENT
//  policy, which deliberately relaxes script-src with 'unsafe-eval' (webpack
//  HMR) and style-src with 'unsafe-inline'. The STRICT production policy is
//  captured separately in evidence/task3 from a `next build && next start` run;
//  buildCsp() is unit-tested below for both modes so the production string is
//  still covered here.
// ============================================================================
import { describe, it, expect } from "vitest";
import { getPage, BASE } from "./helpers";
import { buildCsp, staticSecurityHeaders } from "@/lib/security-headers";

describe("page responses carry the security headers", () => {
  it("sets a Content-Security-Policy with a per-request nonce", async () => {
    const { headers } = await getPage("/login");
    const csp = headers.get("content-security-policy");

    expect(csp).toBeTruthy();
    expect(csp).toMatch(/script-src [^;]*'nonce-[A-Za-z0-9+/=]+'/);
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'self'");
    expect(csp).toContain("form-action 'self'");
  });

  it("issues a DIFFERENT nonce on every request", async () => {
    const a = (await getPage("/login")).headers.get("content-security-policy");
    const b = (await getPage("/login")).headers.get("content-security-policy");

    const nonceOf = (csp: string | null) => csp?.match(/'nonce-([^']+)'/)?.[1];
    expect(nonceOf(a)).toBeTruthy();
    expect(nonceOf(a)).not.toBe(nonceOf(b));
  });

  it("propagates the nonce to Next's own bootstrap script tags", async () => {
    // Without this, a strict production CSP would block Next's RSC payload and
    // the app would render blank. This is the assertion that catches it.
    const res = await fetch(`${BASE}/login`);
    const csp = res.headers.get("content-security-policy") ?? "";
    const nonce = csp.match(/'nonce-([^']+)'/)?.[1];
    const html = await res.text();

    expect(nonce).toBeTruthy();
    expect(html).toContain(`nonce="${nonce}"`);
  });

  it("sets the static hardening headers", async () => {
    const { headers } = await getPage("/login");

    expect(headers.get("x-content-type-options")).toBe("nosniff");
    expect(headers.get("x-frame-options")).toBe("DENY");
    expect(headers.get("referrer-policy")).toBe("no-referrer");
    expect(headers.get("permissions-policy")).toContain("camera=()");
  });
});

describe("API responses carry headers too (via next.config.js)", () => {
  it("applies the static headers and a tight CSP to /api/*", async () => {
    const res = await fetch(`${BASE}/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Forwarded-For": "198.19.200.9" },
      body: JSON.stringify({ email: "nobody@campus.local", password: "no-such-password" }),
    });

    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
  });
});

describe("the session cookie carries all four protective attributes", () => {
  it("sets HttpOnly, SameSite=Lax and Secure", async () => {
    const res = await fetch(`${BASE}/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Forwarded-For": "198.19.200.10" },
      body: JSON.stringify({
        email: "ada.learner@campus.local",
        password: "ada-pw-2025",
      }),
      redirect: "manual",
    });

    const sid = (res.headers.getSetCookie?.() ?? []).find((c) => c.startsWith("sid="));
    expect(sid).toBeTruthy();
    expect(sid).toContain("HttpOnly");
    expect(sid).toContain("SameSite=Lax");
    expect(sid).toContain("Secure");
  });
});

describe("buildCsp() — production is strict, development is not", () => {
  const prod = buildCsp("TESTNONCE", false);
  const dev = buildCsp("TESTNONCE", true);

  it("production has no unsafe-* script source", () => {
    const scriptSrc = prod.split(";").find((d) => d.trim().startsWith("script-src"))!;
    expect(scriptSrc).toContain("'nonce-TESTNONCE'");
    expect(scriptSrc).not.toContain("unsafe-inline");
    expect(scriptSrc).not.toContain("unsafe-eval");
  });

  it("production has no unsafe-inline style source", () => {
    const styleSrc = prod.split(";").find((d) => d.trim().startsWith("style-src"))!;
    expect(styleSrc).not.toContain("unsafe-inline");
  });

  it("production upgrades insecure requests; development does not", () => {
    expect(prod).toContain("upgrade-insecure-requests");
    expect(dev).not.toContain("upgrade-insecure-requests");
  });

  it("development relaxes only what HMR needs", () => {
    expect(dev).toContain("'unsafe-eval'");
    expect(dev).toContain("ws:");
  });

  it("puts script-src BEFORE any other script-* directive", () => {
    // Next finds the nonce by taking the FIRST directive whose name starts with
    // "script-src". A script-src-elem emitted first would shadow it and the
    // nonce would never reach Next's bootstrap scripts.
    const names = prod.split(";").map((d) => d.trim().split(" ")[0]);
    const scriptish = names.filter((n) => n.startsWith("script-src"));
    expect(scriptish[0]).toBe("script-src");
  });
});

describe("staticSecurityHeaders() — HSTS is production-only", () => {
  it("omits HSTS in development, where it would be inert over http", () => {
    expect(staticSecurityHeaders(true)["Strict-Transport-Security"]).toBeUndefined();
  });

  it("emits HSTS in production", () => {
    expect(staticSecurityHeaders(false)["Strict-Transport-Security"]).toContain("max-age=");
  });
});
