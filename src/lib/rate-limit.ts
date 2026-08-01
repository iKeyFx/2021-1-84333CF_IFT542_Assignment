// ============================================================================
//  Per-IP login rate limiting.  [FIXED — Task 2: no rate limiting]
//
//  Dependency-free fixed-window counter held in memory. The Map is pinned to
//  globalThis exactly as src/lib/db.ts pins its connection pool: Next re-
//  evaluates route modules on hot reload in dev, so plain module state would
//  silently reset and the limiter would appear not to work.
//
//  Design notes (see report/task1-threat-model.md):
//   - FAILURES ONLY are counted, and a successful login clears the bucket, so a
//     legitimate user who mistypes twice and then succeeds is never throttled
//     while a brute-forcer hits the wall in LOGIN_MAX_ATTEMPTS.
//   - Validation failures count too. Treating them differently would hand back
//     a new oracle ("that email was at least well-formed").
//   - Keyed per IP, as specified. Per-ACCOUNT bucketing is deliberately not
//     implemented: it is itself a lockout-denial-of-service vector against a
//     known user.
//   - Fixed window, not sliding: an attacker can burst 2x the limit across a
//     window boundary. Adequate here; a sliding log or token bucket removes it.
//   - In-memory state is per-process and is lost on restart. A real deployment
//     would use a shared store (Redis) so the limit survives restarts and holds
//     across instances.
// ============================================================================
import type { NextRequest } from "next/server";

type Bucket = { count: number; resetAt: number };

declare global {
  // eslint-disable-next-line no-var
  var __ift542_rate_limit: Map<string, Bucket> | undefined;
}

const buckets: Map<string, Bucket> = globalThis.__ift542_rate_limit ?? new Map();

if (process.env.NODE_ENV !== "production") {
  globalThis.__ift542_rate_limit = buckets;
}

export const LOGIN_MAX_ATTEMPTS = 5;
export const LOGIN_WINDOW_MS = 60_000; // small window, per the requirement

export type RateLimitResult = {
  allowed: boolean;
  retryAfterSec: number;
  remaining: number;
};

/** Drop expired buckets so the Map cannot grow without bound. */
function sweep(now: number): void {
  for (const [key, bucket] of buckets) {
    if (bucket.resetAt <= now) buckets.delete(key);
  }
}

/**
 * Read-only check — does NOT consume budget.
 *
 * Call this at the very top of the handler, before any database or Argon2
 * work, otherwise the limiter does not actually protect the expensive path.
 */
export function checkRateLimit(key: string): RateLimitResult {
  const now = Date.now();
  sweep(now);

  const bucket = buckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    return { allowed: true, retryAfterSec: 0, remaining: LOGIN_MAX_ATTEMPTS };
  }

  return {
    allowed: bucket.count < LOGIN_MAX_ATTEMPTS,
    retryAfterSec: Math.max(1, Math.ceil((bucket.resetAt - now) / 1000)),
    remaining: Math.max(0, LOGIN_MAX_ATTEMPTS - bucket.count),
  };
}

/** Consume one unit of budget. Call ONLY on a failed attempt. */
export function recordFailure(key: string): void {
  const now = Date.now();
  const bucket = buckets.get(key);

  if (!bucket || bucket.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
  } else {
    bucket.count += 1;
  }
}

/** Clear a bucket. Called on successful login. */
export function resetRateLimit(key: string): void {
  buckets.delete(key);
}

/** Test-only escape hatch for in-process unit tests of this module. */
export function __clearAllRateLimits(): void {
  buckets.clear();
}

/**
 * Derive the client IP for bucketing.
 *
 * NOTE: `NextRequest.ip` is only populated behind Vercel/edge infrastructure,
 * so locally the X-Forwarded-For fallback is what actually fires — and that
 * header is client-controlled. Trusting it is acceptable ONLY because this
 * artefact is a localhost-only teaching build. Behind a real proxy you must
 * take XFF solely from a known, trusted hop.
 */
export function clientIp(req: NextRequest): string {
  const forwarded = req.headers.get("x-forwarded-for");
  const first = forwarded?.split(",")[0]?.trim();
  // `||` not `??` for the header values: an empty header must fall through
  // rather than become an empty bucket key shared by every caller.
  return req.ip ?? (first || req.headers.get("x-real-ip") || "127.0.0.1");
}
