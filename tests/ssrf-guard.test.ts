// ============================================================================
//  Task 3, control 3 — the SSRF guard.
//
//  The range checks are unit-tested OFFLINE with an injected resolver, so the
//  whole matrix runs deterministically with no network and no DNS. The single
//  live-network test is skipped when the machine is offline, so the suite stays
//  green on a train.
// ============================================================================
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { assertSafeUrl, classifyIp, type Resolver } from "@/lib/url-guard";
import { authenticate, postJson, freshIp, DEMO, ADMIN_PASSWORD, type Session } from "./helpers";

/** Pretend every hostname resolves to whatever the test says. */
const resolvesTo = (...addresses: string[]): Resolver => async () => addresses;

/** example.com is on the default allowlist; give it a public address. */
const PUBLIC = resolvesTo("93.184.216.34");

describe("classifyIp — address ranges", () => {
  const blocked: Array<[string, string]> = [
    ["127.0.0.1", "loopback"],
    ["127.255.255.254", "loopback (rest of 127/8)"],
    ["0.0.0.0", "this-host"],
    ["10.0.0.5", "private 10/8"],
    ["172.16.0.1", "private 172.16/12"],
    ["172.31.255.255", "private 172.31 (upper bound)"],
    ["192.168.1.1", "private 192.168/16"],
    ["169.254.169.254", "cloud metadata"],
    ["169.254.0.1", "link-local"],
    ["100.64.0.1", "CGNAT"],
    ["224.0.0.1", "multicast"],
    ["::1", "IPv6 loopback"],
    ["fc00::1", "IPv6 unique-local"],
    ["fe80::1", "IPv6 link-local"],
    ["::ffff:127.0.0.1", "IPv4-mapped IPv6 loopback"],
    ["::ffff:169.254.169.254", "IPv4-mapped IPv6 metadata"],
  ];

  for (const [ip, label] of blocked) {
    it(`blocks ${ip} (${label})`, () => {
      expect(classifyIp(ip)).not.toBeNull();
    });
  }

  const allowed = ["93.184.216.34", "8.8.8.8", "172.15.0.1", "172.32.0.1", "2606:2800:220:1::1"];
  for (const ip of allowed) {
    it(`allows the public address ${ip}`, () => {
      expect(classifyIp(ip)).toBeNull();
    });
  }

  it("does not mistake 172.15/172.32 for the private 172.16/12 block", () => {
    // Off-by-one in the /12 boundary is the classic bug here.
    expect(classifyIp("172.15.255.255")).toBeNull();
    expect(classifyIp("172.32.0.0")).toBeNull();
    expect(classifyIp("172.16.0.0")).toBe("blocked-private");
    expect(classifyIp("172.31.255.255")).toBe("blocked-private");
  });
});

describe("assertSafeUrl — scheme and allowlist", () => {
  it("rejects a non-http(s) scheme", async () => {
    for (const url of ["file:///etc/passwd", "ftp://example.com/x", "data:text/html,<b>x"]) {
      const r = await assertSafeUrl(url, PUBLIC);
      expect(r.ok, url).toBe(false);
      if (!r.ok) expect(r.reason).toBe("scheme-not-allowed");
    }
  });

  it("rejects an unparseable URL", async () => {
    const r = await assertSafeUrl("not a url", PUBLIC);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("unparseable");
  });

  it("rejects a host that is not on the allowlist", async () => {
    const r = await assertSafeUrl("https://evil.test/x", PUBLIC);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("host-not-allowed");
  });

  it("allows an allowlisted host that resolves publicly", async () => {
    const r = await assertSafeUrl("https://example.com/syllabus.txt", PUBLIC);
    expect(r.ok).toBe(true);
  });

  it("allows a subdomain of an allowlisted host", async () => {
    const r = await assertSafeUrl("https://cdn.example.com/x", PUBLIC);
    expect(r.ok).toBe(true);
  });

  it("does not treat a look-alike suffix as allowlisted", async () => {
    // notexample.com must NOT match an allowlist entry of example.com.
    const r = await assertSafeUrl("https://notexample.com/x", PUBLIC);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("host-not-allowed");
  });
});

describe("assertSafeUrl — DNS results are re-checked", () => {
  it("blocks an allowlisted host that resolves to loopback (DNS rebinding)", async () => {
    const r = await assertSafeUrl("https://example.com/x", resolvesTo("127.0.0.1"));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("blocked-loopback");
  });

  it("blocks an allowlisted host that resolves to cloud metadata", async () => {
    const r = await assertSafeUrl("https://example.com/x", resolvesTo("169.254.169.254"));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("blocked-link-local");
  });

  it("blocks when ANY resolved address is private, not just the first", async () => {
    // A hostname returning one public and one internal address must be refused
    // outright rather than raced.
    const r = await assertSafeUrl("https://example.com/x", resolvesTo("93.184.216.34", "10.0.0.5"));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("blocked-private");
  });

  it("reports dns-failed when resolution throws", async () => {
    const r = await assertSafeUrl("https://example.com/x", async () => {
      throw new Error("ENOTFOUND");
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("dns-failed");
  });
});

describe("assertSafeUrl — IP literals never reach DNS", () => {
  const literals: Array<[string, string]> = [
    ["http://127.0.0.1:3000/login", "blocked-loopback"],
    ["http://169.254.169.254/latest/meta-data/", "blocked-link-local"],
    ["http://10.0.0.5/", "blocked-private"],
    ["http://192.168.1.1/", "blocked-private"],
    ["http://[::1]:3000/", "blocked-loopback"],
  ];

  for (const [url, reason] of literals) {
    it(`rejects ${url}`, async () => {
      const neverCalled: Resolver = async () => {
        throw new Error("resolver must not be called for an IP literal");
      };
      const r = await assertSafeUrl(url, neverCalled);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toBe(reason);
    });
  }

  it("rejects a PUBLIC ip literal too — being routable is not enough", async () => {
    const r = await assertSafeUrl("http://93.184.216.34/", PUBLIC);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("host-not-allowed");
  });
});

// ---------------------------------------------------------------------------
//  End-to-end through the route
// ---------------------------------------------------------------------------
let admin: Session;

beforeAll(async () => {
  admin = await authenticate(
    DEMO.admin.email,
    ADMIN_PASSWORD,
    freshIp("ssrf"),
    "/admin/url-preview"
  );
});

describe("POST /api/admin/url-preview refuses internal destinations", () => {
  const targets = [
    "http://127.0.0.1:3000/login", // the v0 proof-of-concept target
    "http://localhost:3000/login",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.5/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    "file:///etc/passwd",
    "http://evil.test/",
    "http://[::1]:3000/",
  ];

  for (const url of targets) {
    it(`blocks ${url}`, async () => {
      const res = await postJson("/api/admin/url-preview", { url }, { session: admin });
      expect(res.status).toBe(403);
      expect(res.body.ok).toBe(false);
    });
  }

  it("returns a FIXED message — the reason would itself be an oracle", async () => {
    const loopback = await postJson(
      "/api/admin/url-preview",
      { url: "http://127.0.0.1:9999/" },
      { session: admin }
    );
    const notAllowed = await postJson(
      "/api/admin/url-preview",
      { url: "http://evil.test/" },
      { session: admin }
    );

    // "port closed" vs "host not allowed" would let an admin map the internal
    // network. Both must be indistinguishable to the client.
    expect(loopback.body).toEqual(notAllowed.body);
  });

  it("never returns a stack trace or driver message", async () => {
    const res = await postJson(
      "/api/admin/url-preview",
      { url: "http://127.0.0.1:9/" },
      { session: admin }
    );
    const serialised = JSON.stringify(res.body);
    expect(serialised).not.toMatch(/stack|ECONNREFUSED|ETIMEDOUT|at Object|node:internal/i);
  });
});

describe("the allowed path (live network)", () => {
  it.skipIf(!process.env.ALLOW_NETWORK_TESTS)(
    "fetches an allowlisted public host when ALLOW_NETWORK_TESTS=1",
    async () => {
      const res = await postJson(
        "/api/admin/url-preview",
        { url: "https://example.com/" },
        { session: admin }
      );
      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
    }
  );
});
