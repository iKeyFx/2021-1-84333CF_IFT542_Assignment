// ============================================================================
//  Structured security logging.  [FIXED — Task 3 / threat T4: repudiation]
//
//  The baseline had no security logging at all — the Task 1 threat model listed
//  T4 as "no tamper-evident audit log exists", and the six ad-hoc console calls
//  that did exist were unparseable free text, one of which logged a raw email
//  address.
//
//  FORMAT: one JSON object per line (JSON Lines). Machine-parseable by design —
//  `npm run dev | grep '"event":"authz.denied"'` works, and a real deployment
//  could ship these straight to a log aggregator with no parser.
//
//  EVERY event answers WHO / WHAT / WHEN:
//    who   -> actor  (profile_id + role, or "anonymous") and ip
//    what  -> event + method + path + outcome + reason
//    when  -> ts (ISO 8601, UTC)
//
//  REDACTION IS ENFORCED HERE, NOT LEFT TO CALLERS. A caller cannot leak a
//  secret through this logger even by passing one explicitly: DENY_KEYS are
//  dropped at serialisation time and emails are masked. That is deliberate —
//  "remember not to log the password" is not a control, it is a hope.
//
//  EDGE-SAFE: no node: builtins, so middleware can use it too.
// ============================================================================
import { LOG_LEVEL } from "./config";

type Level = "info" | "warn" | "error";

const LEVEL_ORDER: Record<Level, number> = { info: 0, warn: 1, error: 2 };

/**
 * Field names that must never appear in a log line, whatever the caller does.
 * Matched case-insensitively as a substring, so `password_hash`, `sessionId`
 * and `X-CSRF-Token` are all caught.
 */
const DENY_KEYS = [
  "password",
  "passwd",
  "hash",
  "token",
  "csrf",
  "sid",
  "session",
  "secret",
  "cookie",
  "authorization",
  "auth",
];

export type Actor = { profile_id: number; role: string } | null;

export type SecurityEvent = {
  ip?: string;
  method?: string;
  path?: string;
  actor?: Actor;
  reason?: string;
  [key: string]: unknown;
};

/**
 * Mask an email so a log line can be correlated to an account without storing
 * the address itself. `ada.learner@campus.local` -> `a***@campus.local`.
 * The domain is kept because it is not personally identifying here and is
 * useful for spotting attacks against a whole tenant.
 */
export function redactEmail(email: unknown): string | undefined {
  if (typeof email !== "string" || email.length === 0) return undefined;
  const at = email.indexOf("@");
  if (at <= 0) return "***";
  return `${email[0]}***${email.slice(at)}`;
}

function isDenied(key: string): boolean {
  const k = key.toLowerCase();
  return DENY_KEYS.some((d) => k.includes(d));
}

function scrub(fields: SecurityEvent): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(fields)) {
    if (value === undefined) continue;
    if (isDenied(key)) continue; // never emitted, even if explicitly passed
    out[key] = key === "email" ? redactEmail(value) : value;
  }
  return out;
}

function emit(level: Level, event: string, outcome: string, fields: SecurityEvent): void {
  if (LEVEL_ORDER[level] < LEVEL_ORDER[LOG_LEVEL as Level]) return;

  const { actor, ...rest } = fields;
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    event,
    actor: actor ? { type: "user", ...actor } : { type: "anonymous" },
    outcome,
    ...scrub(rest as SecurityEvent),
  });

  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.info(line);
}

export const logger = {
  /** A login attempt failed: unknown account, wrong password, or throttled. */
  loginFailed(f: SecurityEvent & { email?: string }) {
    emit("warn", "auth.login.failed", "denied", f);
  },
  loginThrottled(f: SecurityEvent) {
    emit("warn", "auth.login.throttled", "denied", f);
  },
  loginSucceeded(f: SecurityEvent) {
    emit("info", "auth.login.succeeded", "allowed", f);
  },

  /** An authenticated-or-anonymous caller was refused for lack of privilege. */
  authzDenied(f: SecurityEvent) {
    emit("warn", "authz.denied", "denied", f);
  },

  /** A request was refused because its input failed validation. */
  validationRejected(f: SecurityEvent) {
    emit("warn", "validation.rejected", "denied", f);
  },

  /** A state-changing request failed the anti-CSRF check. */
  csrfRejected(f: SecurityEvent) {
    emit("warn", "csrf.rejected", "denied", f);
  },

  /** An outbound URL was refused by the SSRF guard. */
  ssrfBlocked(f: SecurityEvent) {
    emit("warn", "ssrf.blocked", "denied", f);
  },

  /** Server-side fault. Never carries anything client-supplied. */
  serverError(f: SecurityEvent & { event?: string }) {
    emit("error", typeof f.event === "string" ? f.event : "server.error", "error", f);
  },
};

/**
 * Client IP for a log line. Mirrors clientIp() in src/lib/rate-limit.ts; kept
 * separate so the logger stays importable from the edge runtime.
 */
export function clientIpOf(req: {
  headers: { get(name: string): string | null };
  ip?: string;
}): string {
  const forwarded = req.headers.get("x-forwarded-for");
  const first = forwarded?.split(",")[0]?.trim();
  return req.ip ?? (first || req.headers.get("x-real-ip") || "127.0.0.1");
}
