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

/** Fictitious seeded credentials (see db/hash-passwords.mjs). */
export const DEMO = {
  student: { email: "ada.learner@campus.local", password: "ada-pw-2025" },
  student2: { email: "grace.coder@campus.local", password: "grace-pw-2025" },
  // Deliberate Task 3 vulnerability, kept intact.
  admin: { email: "admin@campus.local", password: "admin123" },
};

export const ALL_DEMO_PASSWORDS = [
  "ada-pw-2025",
  "grace-pw-2025",
  "linus-pw-2025",
  "mira-pw-2025",
  "otto-pw-2025",
  "nova-pw-2025",
  "admin123",
];

// ---------------------------------------------------------------------------
//  Source-IP allocation.
//
//  Two independent problems to solve, both about rate-limit budget:
//
//   1. ACROSS FILES / WITHIN A RUN — a test that makes several FAILED login
//      attempts must not exhaust a bucket another test depends on. Solved by
//      giving each file its own host range and handing out a new address per
//      call via freshIp().
//
//   2. ACROSS RUNS — the limiter lives in the dev server's memory, and that
//      server outlives `npm test`. Re-running the suite inside the 60s window
//      would otherwise inherit the previous run's counters and see 429 where
//      401 was expected. Solved by randomising the third octet per run, so
//      every run gets a fresh /24.
//
//  Addresses come from 198.18.0.0/15, the IANA benchmarking range — never
//  routed, so nothing leaves this machine.
// ---------------------------------------------------------------------------
const RUN_OCTET = 1 + Math.floor(Math.random() * 250);

/** Host-range base per file, 50 addresses each. */
const FILE_BASE: Record<string, number> = {
  "auth-login": 1,
  "sqli": 50,
  "session": 100,
  "rate-limit": 150,
};

const counters = new Map<string, number>();

/** A stable address for this file, for tests that need budget to accumulate. */
export function ipFor(file: string): string {
  const base = FILE_BASE[file];
  if (base === undefined) throw new Error(`no test host range registered for "${file}"`);
  return `198.18.${RUN_OCTET}.${base}`;
}

/** A previously-unused address in this file's range. */
export function freshIp(file: string): string {
  const base = FILE_BASE[file];
  if (base === undefined) throw new Error(`no test host range registered for "${file}"`);
  const n = (counters.get(file) ?? 0) + 1;
  counters.set(file, n);
  if (n > 48) throw new Error(`exhausted test addresses for "${file}"`);
  return `198.18.${RUN_OCTET}.${base + n}`;
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
