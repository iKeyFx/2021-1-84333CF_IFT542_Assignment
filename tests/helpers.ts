// ============================================================================
//  Shared helpers for the Task 2 hardening tests.
//
//  RATE-LIMIT ISOLATION: the login endpoint throttles per IP, so every test
//  file sends its own X-Forwarded-For address from the IANA benchmarking range
//  198.18.0.0/15. No file can exhaust another file's budget, and no test
//  backdoor endpoint is needed — adding a state-clearing route to a security
//  deliverable would itself be a vulnerability. See the allocator below.
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
//  routed, so nothing leaves this machine.
//
//  HISTORY, because the layout has been wrong twice:
//
//   v1  All files packed into ONE /24 with 50-address bases (1/50/100/150).
//       Exactly one slot was left, and a fifth file at base 250 would have
//       produced invalid octets like 198.18.7.298.
//   v2  One whole third-octet per file: 198.<18|19>.<file>.<host>. This fixed
//       problem (1) but left problem (2) barely addressed — the ONLY per-run
//       entropy was the second octet, i.e. TWO possible values. Two runs inside
//       the 60s window therefore collided half the time, and rate-limit.test.ts
//       (the one file that deliberately exhausts a bucket at a STABLE address)
//       failed on roughly every other back-to-back `npm test`. The comment
//       claiming addresses were "randomised BETWEEN runs" was true in intent
//       and worth about one bit in practice.
//   v3  (this) The last three octets are treated as one flat index:
//
//         index = RUN_SLICE*512 + fileIndex*BLOCK + host
//         198.(18 + index>>16).((index>>8) & 255).(index & 255)
//
//       RUN_SLICE is 0..255, so there are 256 distinct address spaces and a
//       back-to-back re-run collides with probability 1/256 rather than 1/2.
//       Each file gets BLOCK = 32 addresses per run, and asking for a 33rd
//       throws rather than silently wrapping into the next file's block.
// ---------------------------------------------------------------------------

/** Addresses per test file per run. */
const BLOCK = 32;
/** Files per run slice. 16 * 32 = 512 addresses per slice; 131072/512 = 256. */
const MAX_FILES = 16;
/** Re-rolled on every `npm test`, giving 256 non-overlapping address spaces. */
const RUN_SLICE = Math.floor(Math.random() * 256);

/** One block per test file. Add a new file by giving it an unused number 0-15. */
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
  // Task 3 — item 26
  "incident-response": 10,
};

const counters = new Map<string, number>();

/** Address `host` (0..BLOCK-1) from `file`'s block in this run's slice. */
function address(file: string, host: number): string {
  const fileIndex = FILE_OCTET[file];
  if (fileIndex === undefined) throw new Error(`no test subnet registered for "${file}"`);
  if (fileIndex >= MAX_FILES) {
    throw new Error(`file index ${fileIndex} for "${file}" exceeds MAX_FILES=${MAX_FILES}`);
  }
  if (host < 0 || host >= BLOCK) {
    throw new Error(
      `exhausted test addresses for "${file}": ${BLOCK} per run. ` +
        `Raise BLOCK (and lower MAX_FILES to keep BLOCK*MAX_FILES <= 512).`
    );
  }
  const index = RUN_SLICE * (BLOCK * MAX_FILES) + fileIndex * BLOCK + host;
  return `198.${18 + (index >>> 16)}.${(index >>> 8) & 0xff}.${index & 0xff}`;
}

/**
 * A stable address for this file, for tests that need budget to ACCUMULATE
 * across several requests (only rate-limit.test.ts). Constant within a run,
 * different on the next run.
 */
export function ipFor(file: string): string {
  return address(file, BLOCK - 1);
}

/** A previously-unused address in this file's block. */
export function freshIp(file: string): string {
  const n = (counters.get(file) ?? 0) + 1;
  counters.set(file, n);
  // BLOCK-1 is reserved for ipFor(), so freshIp() must never reach it.
  if (n >= BLOCK - 1) {
    throw new Error(
      `exhausted test addresses for "${file}": ${BLOCK - 2} fresh per run (BLOCK=${BLOCK})`
    );
  }
  return address(file, n);
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

// ---------------------------------------------------------------------------
//  Task 3 helpers: authenticated sessions with CSRF tokens
// ---------------------------------------------------------------------------

export type Session = {
  /** Serialised Cookie header carrying both `sid` and `csrf`. */
  cookie: string;
  /** The anti-CSRF token, ready to send as a field or header. */
  csrf: string;
  sid: string;
};

function mergeSetCookie(jar: Map<string, string>, res: Response): void {
  for (const raw of res.headers.getSetCookie?.() ?? []) {
    const kv = raw.split(";")[0];
    const i = kv.indexOf("=");
    jar.set(kv.slice(0, i), kv.slice(i + 1));
  }
}

const serialise = (jar: Map<string, string>) =>
  [...jar].map(([k, v]) => `${k}=${v}`).join("; ");

/**
 * Log in and pick up a CSRF token.
 *
 * The token is issued by middleware on a PAGE response, not by /api/login
 * (middleware deliberately does not match /api), so this makes a second request
 * to a page to collect it — exactly what a browser does.
 */
export async function authenticate(
  email: string,
  password: string,
  ip: string,
  page = "/dashboard"
): Promise<Session> {
  const jar = new Map<string, string>();

  const login = await fetch(`${BASE}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Forwarded-For": ip },
    body: JSON.stringify({ email, password }),
    redirect: "manual",
  });
  mergeSetCookie(jar, login);

  if (!jar.has("sid")) {
    throw new Error(`authenticate(${email}) failed: HTTP ${login.status}`);
  }

  const pageRes = await fetch(`${BASE}${page}`, {
    headers: { Cookie: serialise(jar), "X-Forwarded-For": ip },
  });
  mergeSetCookie(jar, pageRes);

  return {
    cookie: serialise(jar),
    csrf: decodeURIComponent(jar.get("csrf") ?? ""),
    sid: jar.get("sid") ?? "",
  };
}

/** Fetch a CSRF token without logging in (anonymous visitor). */
export async function anonymousCsrf(page = "/login"): Promise<Session> {
  const jar = new Map<string, string>();
  const res = await fetch(`${BASE}${page}`);
  mergeSetCookie(jar, res);
  return {
    cookie: serialise(jar),
    csrf: decodeURIComponent(jar.get("csrf") ?? ""),
    sid: "",
  };
}

/** POST a urlencoded form, with control over the token and Origin. */
export async function postForm(
  path: string,
  fields: Record<string, string>,
  opts: { session: Session; csrf?: string | null; origin?: string | null }
): Promise<{ status: number; body: string; location: string }> {
  const token = opts.csrf === undefined ? opts.session.csrf : opts.csrf;
  const params = new URLSearchParams(fields);
  if (token !== null) params.set("_csrf", token);

  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
    Cookie: opts.session.cookie,
  };
  if (opts.origin) headers["Origin"] = opts.origin;

  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers,
    body: params,
    redirect: "manual",
  });
  // A 303 has an EMPTY body — the outcome is in the Location header.
  return {
    status: res.status,
    body: await res.text(),
    location: res.headers.get("location") ?? "",
  };
}

/** POST JSON with the token in the x-csrf-token header. */
export async function postJson(
  path: string,
  payload: unknown,
  opts: { session: Session; csrf?: string | null; origin?: string | null }
): Promise<{ status: number; body: any }> {
  const token = opts.csrf === undefined ? opts.session.csrf : opts.csrf;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Cookie: opts.session.cookie,
  };
  if (token !== null) headers["x-csrf-token"] = token;
  if (opts.origin) headers["Origin"] = opts.origin;

  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
    redirect: "manual",
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}

/** GET a page with a session, returning the raw HTML. */
export async function getPage(
  path: string,
  session?: Session
): Promise<{ status: number; html: string; headers: Headers }> {
  const res = await fetch(`${BASE}${path}`, {
    headers: session ? { Cookie: session.cookie } : {},
    redirect: "manual",
  });
  return { status: res.status, html: await res.text(), headers: res.headers };
}
