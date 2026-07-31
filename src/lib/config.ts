// ============================================================================
//  Central config for the IFT542 teaching artefact.
//
//  [FIXED — Task 3: security misconfiguration]
//  Everything here now fails CLOSED. Previously:
//   - DEBUG defaulted to TRUE and only the exact string "false" disabled it,
//     so DEBUG=0, DEBUG=off and production all left verbose errors ON.
//   - SESSION_SECRET fell back to a constant committed to source control, and
//     was never actually used by anything (dead code).
//   - DEFAULT_ADMIN documented a well-known password in source.
// ============================================================================

const isProduction = process.env.NODE_ENV === "production";

/**
 * [FIXED — Task 3: debug mode on]
 * Opt-IN, not opt-out. Anything other than the exact string "true" leaves
 * debug off, so a typo or a missing variable fails safe. Nothing in the app
 * returns stack traces to a client any more; this now only gates extra
 * server-side log detail.
 */
export const DEBUG = process.env.DEBUG === "true";

/** Name of the session cookie set at login. */
export const SESSION_COOKIE = "sid";

/**
 * [FIXED — Task 3: hardcoded secret]
 * The session secret is now LOAD-BEARING: it is the HMAC key for the CSRF
 * tokens in src/lib/csrf.ts. It used to be dead code, which is why nobody
 * noticed it was a committed constant.
 *
 * In production a missing secret is a hard failure — there is no fallback to
 * silently share a guessable key across deployments. In development a clearly
 * labelled ephemeral value is generated per process, so `npm run dev` works
 * without a .env while still never using a value committed to the repo.
 */
let devSecret: string | null = null;
let warnedAboutSecret = false;

export function sessionSecret(): string {
  const fromEnv = process.env.SESSION_SECRET;
  if (fromEnv && fromEnv.length > 0) return fromEnv;

  if (isProduction) {
    throw new Error(
      "SESSION_SECRET is not set. Refusing to start in production with a " +
        "default or empty session secret. Set it in the environment."
    );
  }

  if (!warnedAboutSecret) {
    console.warn(
      "[config] SESSION_SECRET is unset — generating an ephemeral development " +
        "secret. CSRF tokens will not survive a server restart. Set SESSION_SECRET " +
        "in .env to make them stable. This would be a hard error in production."
    );
    warnedAboutSecret = true;
  }
  // Random per process: never a committed constant, even in dev.
  // Uses Web Crypto (not node:crypto) because src/middleware.ts imports this
  // module and runs on the EDGE runtime, where node: builtins are unavailable.
  if (devSecret === null) {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    devSecret = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }
  return devSecret;
}

/**
 * [FIXED — Task 3: no SameSite/Secure on the session cookie]
 * `Secure` is ON by default. Browsers treat loopback as a potentially
 * trustworthy origin, so Secure cookies are accepted over http://127.0.0.1.
 * COOKIE_SECURE=false exists only as a documented escape hatch if a particular
 * browser refuses; it must never be set outside local development.
 */
export const COOKIE_SECURE = process.env.COOKIE_SECURE !== "false";

/**
 * [FIXED — Task 3: SSRF]
 * Destination allowlist for the admin URL-preview feature. Empty entries are
 * ignored. Loopback / private / link-local addresses are rejected regardless
 * of what appears here — see src/lib/url-guard.ts.
 */
export const URL_PREVIEW_ALLOWLIST = (
  process.env.URL_PREVIEW_ALLOWLIST ?? "example.com,www.example.com"
)
  .split(",")
  .map((h) => h.trim().toLowerCase())
  .filter(Boolean);

/** Minimum level emitted by src/lib/logger.ts. */
export const LOG_LEVEL = (process.env.LOG_LEVEL ?? "info") as "info" | "warn" | "error";

/** Where uploaded documents are written on local disk. */
export const UPLOAD_DIR = process.env.UPLOAD_DIR || "./uploads";

export const DATABASE_URL =
  process.env.DATABASE_URL || "postgres://ift542:ift542_dev_pw@127.0.0.1:5432/ift542";
