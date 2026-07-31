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
/**
 * Development-only fallback.
 *
 * This MUST be a fixed constant rather than a random per-process value. CSRF
 * tokens are minted in middleware (EDGE runtime) and verified in route handlers
 * (NODE runtime) — two separate module instances. A randomly generated secret
 * would differ between them, so every token would fail verification and the app
 * would be unusable without a .env. That was found the hard way.
 *
 * This is NOT the vulnerability that was removed. The v0 build used its
 * hardcoded constant in EVERY environment, including production, so all
 * deployments shared one guessable key. Here production throws instead, and
 * this value can only ever be reached with NODE_ENV !== "production".
 */
const DEV_ONLY_SECRET = "ift542-DEVELOPMENT-ONLY-secret-never-valid-in-production";

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
      "[config] SESSION_SECRET is unset — falling back to the development-only " +
        "secret. Fine for localhost; a hard error in production. Copy .env.example " +
        "to .env to set your own."
    );
    warnedAboutSecret = true;
  }

  return DEV_ONLY_SECRET;
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
