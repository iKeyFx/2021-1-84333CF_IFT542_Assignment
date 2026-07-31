// ============================================================================
//  Task 2, extra control (a) — per-IP rate limiting on login.
//
//  This file owns two fixed source addresses so its buckets accumulate
//  deterministically; every other test file uses freshly allocated IPs.
// ============================================================================
import { describe, it, expect } from "vitest";
import { login, ipFor, freshIp, DEMO, GENERIC_ERROR } from "./helpers";
import {
  LOGIN_MAX_ATTEMPTS,
  checkRateLimit,
  recordFailure,
  resetRateLimit,
  __clearAllRateLimits,
} from "@/lib/rate-limit";

// Stable for this run so the bucket accumulates; drawn from one of 256 per-run
// address slices so a re-run inside the 60s window does not inherit the
// previous run's counter. This file is the reason that entropy has to be real:
// it is the only one that deliberately exhausts a bucket, so it is the first to
// fail when two runs collide. See the allocator note in helpers.ts.
const THROTTLED_IP = ipFor("rate-limit");
const OTHER_IP = freshIp("rate-limit");

describe("login is rate limited per IP", () => {
  it(`allows ${LOGIN_MAX_ATTEMPTS} failures then returns 429`, async () => {
    const statuses: number[] = [];

    for (let i = 0; i < LOGIN_MAX_ATTEMPTS; i++) {
      const res = await login(DEMO.student.email, `wrong-${i}`, { ip: THROTTLED_IP });
      statuses.push(res.status);
      expect(res.body).toEqual(GENERIC_ERROR);
    }
    expect(statuses).toEqual(Array(LOGIN_MAX_ATTEMPTS).fill(401));

    // The next attempt is refused before any DB or Argon2 work happens.
    const blocked = await login(DEMO.student.email, "wrong-again", { ip: THROTTLED_IP });
    expect(blocked.status).toBe(429);
    expect(blocked.body).toEqual({
      error: "Too many login attempts. Please try again later.",
    });

    const retryAfter = Number(blocked.headers.get("retry-after"));
    expect(retryAfter).toBeGreaterThan(0);
    expect(retryAfter).toBeLessThanOrEqual(60);
  });

  it("blocks even a CORRECT password once the window is exhausted", async () => {
    // Proves the check runs before authentication, not after it.
    const res = await login(DEMO.student.email, DEMO.student.password, { ip: THROTTLED_IP });
    expect(res.status).toBe(429);
    expect(res.sid).toBeNull();
  });

  it("throttles per IP, not globally", async () => {
    // A different source address still gets a normal auth failure, so the
    // limiter is keyed on the client and is not one shared counter.
    const res = await login(DEMO.student.email, "wrong-password", { ip: OTHER_IP });
    expect(res.status).toBe(401);
    expect(res.body).toEqual(GENERIC_ERROR);
  });
});

describe("limiter semantics (in-process unit tests)", () => {
  it("counts failures and blocks at the limit", () => {
    __clearAllRateLimits();
    const key = "unit:a";

    for (let i = 0; i < LOGIN_MAX_ATTEMPTS; i++) {
      expect(checkRateLimit(key).allowed).toBe(true);
      recordFailure(key);
    }
    expect(checkRateLimit(key).allowed).toBe(false);
    expect(checkRateLimit(key).remaining).toBe(0);
  });

  it("does not consume budget on a read-only check", () => {
    __clearAllRateLimits();
    const key = "unit:b";

    for (let i = 0; i < 20; i++) checkRateLimit(key);
    expect(checkRateLimit(key).allowed).toBe(true);
    expect(checkRateLimit(key).remaining).toBe(LOGIN_MAX_ATTEMPTS);
  });

  it("clears the bucket on success, so a user who mistypes is not punished", () => {
    __clearAllRateLimits();
    const key = "unit:c";

    recordFailure(key);
    recordFailure(key);
    expect(checkRateLimit(key).remaining).toBe(LOGIN_MAX_ATTEMPTS - 2);

    resetRateLimit(key); // what a successful login does
    expect(checkRateLimit(key).remaining).toBe(LOGIN_MAX_ATTEMPTS);
    expect(checkRateLimit(key).allowed).toBe(true);
  });

  it("keeps buckets independent", () => {
    __clearAllRateLimits();
    for (let i = 0; i < LOGIN_MAX_ATTEMPTS; i++) recordFailure("unit:d");

    expect(checkRateLimit("unit:d").allowed).toBe(false);
    expect(checkRateLimit("unit:e").allowed).toBe(true);
  });
});
