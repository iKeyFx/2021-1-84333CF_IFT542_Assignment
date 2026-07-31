// ============================================================================
//  Task 3, control 5 — structured security logging.
//
//  Asserted IN-PROCESS with a console spy rather than by reading the dev
//  server's stdout: tests/setup/global-setup.ts spawns it with stdio:"ignore",
//  and switching that to a pipe risks a fill-the-buffer stall on Windows for no
//  extra assurance. The logger is pure and edge-safe, so calling it directly
//  exercises exactly the code the routes run.
// ============================================================================
import { describe, it, expect, vi, afterEach } from "vitest";
import { logger, redactEmail } from "@/lib/logger";

type Captured = Record<string, any>;

/** Capture whatever the logger writes, parsed back from JSON. */
function capture(fn: () => void): Captured {
  const lines: string[] = [];
  const spies = (["info", "warn", "error"] as const).map((level) =>
    vi.spyOn(console, level).mockImplementation((msg?: any) => {
      lines.push(String(msg));
    })
  );
  try {
    fn();
  } finally {
    spies.forEach((s) => s.mockRestore());
  }
  expect(lines.length, "logger emitted nothing").toBeGreaterThan(0);
  return JSON.parse(lines[lines.length - 1]);
}

afterEach(() => vi.restoreAllMocks());

describe("every event answers who / what / when", () => {
  it("emits an ISO-8601 timestamp, level, event and outcome", () => {
    const line = capture(() =>
      logger.loginFailed({ ip: "198.18.1.1", method: "POST", path: "/api/login" })
    );

    expect(line.ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(line.level).toBe("warn");
    expect(line.event).toBe("auth.login.failed");
    expect(line.outcome).toBe("denied");
    expect(line.ip).toBe("198.18.1.1");
    expect(line.method).toBe("POST");
    expect(line.path).toBe("/api/login");
  });

  it("labels an unauthenticated caller as anonymous", () => {
    const line = capture(() => logger.authzDenied({ actor: null, reason: "no-session" }));
    expect(line.actor).toEqual({ type: "anonymous" });
  });

  it("records profile_id and role for an authenticated caller", () => {
    const line = capture(() =>
      logger.authzDenied({ actor: { profile_id: 42, role: "student" }, reason: "not-admin" })
    );
    expect(line.actor).toEqual({ type: "user", profile_id: 42, role: "student" });
    expect(line.reason).toBe("not-admin");
  });
});

describe("the three required event types", () => {
  it("failed-login", () => {
    const line = capture(() =>
      logger.loginFailed({ ip: "198.18.1.2", email: "ada.learner@campus.local", reason: "bad-password" })
    );
    expect(line.event).toBe("auth.login.failed");
    expect(line.level).toBe("warn");
  });

  it("denied-authorization", () => {
    const line = capture(() =>
      logger.authzDenied({
        ip: "198.18.1.3",
        path: "/api/admin/courses",
        actor: { profile_id: 1, role: "student" },
        reason: "not-admin",
      })
    );
    expect(line.event).toBe("authz.denied");
    expect(line.level).toBe("warn");
  });

  it("rejected-validation", () => {
    const line = capture(() =>
      logger.validationRejected({ ip: "198.18.1.4", path: "/api/login", reason: "email-format" })
    );
    expect(line.event).toBe("validation.rejected");
    expect(line.level).toBe("warn");
  });
});

describe("redaction — no secrets, tokens or unnecessary PII", () => {
  it("masks an email to first-initial + domain", () => {
    expect(redactEmail("ada.learner@campus.local")).toBe("a***@campus.local");
    expect(redactEmail("admin@campus.local")).toBe("a***@campus.local");
  });

  it("masks the email inside a log line", () => {
    const line = capture(() => logger.loginFailed({ email: "ada.learner@campus.local" }));
    expect(line.email).toBe("a***@campus.local");
    expect(JSON.stringify(line)).not.toContain("ada.learner@campus.local");
  });

  it("DROPS deny-listed fields even when a caller passes them explicitly", () => {
    // This is the point of enforcing redaction in the logger rather than
    // trusting call sites: a careless caller cannot leak through it.
    const line = capture(() =>
      logger.loginFailed({
        ip: "198.18.1.5",
        password: "ada-pw-2025",
        password_hash: "$argon2id$v=19$m=19456,p=1,t=2$abc$def",
        csrf_token: "abc.def",
        sid: "0d7b756f-d602-4a53-a000-000000000000",
        session_secret: "super-secret",
        cookie: "sid=xyz",
        authorization: "Bearer xyz",
      } as any)
    );

    const serialised = JSON.stringify(line);
    for (const secret of [
      "ada-pw-2025",
      "$argon2id$",
      "abc.def",
      "0d7b756f",
      "super-secret",
      "Bearer",
    ]) {
      expect(serialised, `leaked ${secret}`).not.toContain(secret);
    }
    // ...while the useful fields survive.
    expect(line.ip).toBe("198.18.1.5");
  });

  it("omits undefined fields rather than emitting nulls", () => {
    const line = capture(() => logger.validationRejected({ ip: "198.18.1.6", reason: undefined }));
    expect("reason" in line).toBe(false);
  });
});

describe("level mapping", () => {
  it("uses info for success and error for faults", () => {
    expect(capture(() => logger.loginSucceeded({ actor: { profile_id: 1, role: "student" } })).level).toBe("info");
    expect(capture(() => logger.serverError({ event: "x.failed", reason: "TypeError" })).level).toBe("error");
  });

  it("routes each level to the matching console method", () => {
    const info = vi.spyOn(console, "info").mockImplementation(() => {});
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const error = vi.spyOn(console, "error").mockImplementation(() => {});

    logger.loginSucceeded({});
    logger.authzDenied({});
    logger.serverError({ reason: "x" });

    expect(info).toHaveBeenCalledOnce();
    expect(warn).toHaveBeenCalledOnce();
    expect(error).toHaveBeenCalledOnce();
    vi.restoreAllMocks();
  });
});

describe("output is machine-parseable", () => {
  it("emits exactly one JSON object per line", () => {
    const line = capture(() => logger.ssrfBlocked({ ip: "198.18.1.7", reason: "blocked-loopback" }));
    expect(typeof line).toBe("object");
    expect(line.event).toBe("ssrf.blocked");
    expect(line.reason).toBe("blocked-loopback");
  });
});
