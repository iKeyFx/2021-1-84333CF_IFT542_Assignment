// ============================================================================
//  Shared helpers for the Task 2 hardening tests.
//
//  RATE-LIMIT ISOLATION: the login endpoint throttles per IP, so every test
//  file sends its own X-Forwarded-For address (RFC 5737 documentation range,
//  203.0.113.0/24). No file can exhaust another file's budget, and no test
//  backdoor endpoint is needed — adding a state-clearing route to a security
//  deliverable would itself be a vulnerability.
// ============================================================================
import postgres from "postgres";

export const BASE = "http://127.0.0.1:3000";

export const DATABASE_URL =
  process.env.DATABASE_URL || "postgres://ift542:ift542_dev_pw@127.0.0.1:5432/ift542";

/** The single generic error the API is allowed to return for auth failures. */
export const GENERIC_ERROR = { error: "Invalid email or password" };

// Vitest workers do not load .env, so read it here or ADMIN_PASSWORD overrides
// would be invisible to the tests while being live in the app.
try {
  process.loadEnvFile();
} catch {
  // no .env — the fallback below matches db/hash-passwords.mjs
}

/** Must match ADMIN_PASSWORD_FALLBACK in db/hash-passwords.mjs. */
export const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Adm1n-Str0ng-Dummy-2026-x7QF";

/** The retired default admin password — must now be REJECTED. */
export const RETIRED_ADMIN_PASSWORD = "admin123";

/** Fictitious seeded credentials (see db/hash-passwords.mjs). */
export const DEMO = {
  student: { email: "ada.learner@campus.local", password: "ada-pw-2025" },
  student2: { email: "grace.coder@campus.local", password: "grace-pw-2025" },
  // [FIXED — Task 3] Rotated off the well-known `admin123`.
  admin: { email: "admin@campus.local", password: ADMIN_PASSWORD },
};

export const ALL_DEMO_PASSWORDS = [
  "ada-pw-2025",
  "grace-pw-2025",
  "linus-pw-2025",
  "mira-pw-2025",
  "otto-pw-2025",
  "nova-pw-2025",
  ADMIN_PASSWORD,
];

// ---------------------------------------------------------------------------
//  Source-IP allocation.
//
//  Two independent problems to solve, both about rate-limit budget:
//
//   1. ACROSS FILES / WITHIN A RUN — a test that makes several FAILED login
//      attempts must not exhaust a bucket another test depends on. Solved by
//      giving each file its own /24, so files cannot collide at all.
//
//   2. ACROSS RUNS — the limiter lives in the dev server's memory, and that
//      server outlives `npm test`. Re-running the suite inside the 60s window
//      would otherwise inherit the previous run's counters and see 429 where
//      401 was expected. Solved by randomising the SECOND octet per run, so
//      every run gets a fresh /16.
//
//  Addresses come from 198.18.0.0/15, the IANA benchmarking range — never
//  routed, so nothing leaves this machine. Layout: 198.<18|19>.<file>.<host>
//
//  NOTE: this used to pack all files into ONE /24 with 50-address bases
//  (1/50/100/150). That scheme had exactly one slot left — a fifth file at
//  base 200 was the last that fits, and base 250 would have produced invalid
//  octets like 198.18.7.298. Task 3 adds five files, so each file now owns a
//  whole third octet: 254 hosts each, and adding a file is a one-line change.
// ---------------------------------------------------------------------------
const RUN_NET = 18 + Math.floor(Math.random() * 2); // 198.18/16 or 198.19/16

/** One third-octet per test file. Add a new file by giving it an unused number. */
const FILE_OCTET: Record<string, number> = {
  // Task 2
  "auth-login": 1,
  "sqli": 2,
  "session": 3,
  "rate-limit": 4,
  // Task 3
  "xss": 5,
  "csrf": 6,
  "headers": 7,
  "ssrf": 8,
  "logging": 9,
};

const counters = new Map<string, number>();

/** A stable address for this file, for tests that need budget to accumulate. */
export function ipFor(file: string): string {
  const octet = FILE_OCTET[file];
  if (octet === undefined) throw new Error(`no test subnet registered for "${file}"`);
  return `198.${RUN_NET}.${octet}.254`;
}

/** A previously-unused address in this file's /24. */
export function freshIp(file: string): string {
  const octet = FILE_OCTET[file];
  if (octet === undefined) throw new Error(`no test subnet registered for "${file}"`);
  const n = (counters.get(file) ?? 0) + 1;
  counters.set(file, n);
  if (n > 253) throw new Error(`exhausted test addresses for "${file}"`);
  return `198.${RUN_NET}.${octet}.${n}`;
}

export type LoginResponse = {
  status: number;
  body: any;
  setCookie: string[];
  headers: Headers;
  /** The `sid=...` cookie value the server issued, if any. */
  sid: string | null;
};

/** POST /api/login with an explicit source IP and optional request cookie. */
export async function login(
  email: unknown,
  password: unknown,
  opts: { ip: string; cookie?: string }
): Promise<LoginResponse> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Forwarded-For": opts.ip,
  };
  if (opts.cookie) headers["Cookie"] = opts.cookie;

  const res = await fetch(`${BASE}/api/login`, {
    method: "POST",
    headers,
    body: JSON.stringify({ email, password }),
    redirect: "manual",
  });

  const setCookie = res.headers.getSetCookie?.() ?? [];
  const sidCookie = setCookie.find((c) => c.startsWith("sid="));
  const sid = sidCookie ? sidCookie.slice(4).split(";")[0] : null;

  return {
    status: res.status,
    body: await res.json().catch(() => null),
    setCookie,
    headers: res.headers,
    sid: sid || null,
  };
}

/** POST a raw body (for malformed-JSON / non-object cases). */
export async function loginRaw(
  raw: string,
  opts: { ip: string }
): Promise<LoginResponse> {
  const res = await fetch(`${BASE}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Forwarded-For": opts.ip },
    body: raw,
  });
  const setCookie = res.headers.getSetCookie?.() ?? [];
  return {
    status: res.status,
    body: await res.json().catch(() => null),
    setCookie,
    headers: res.headers,
    sid: null,
  };
}

/** A fresh postgres.js client. Caller must call .end(). */
export function db() {
  return postgres(DATABASE_URL, { max: 1, onnotice: () => {} });
}
