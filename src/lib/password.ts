// ============================================================================
//  Argon2id password hashing.  [FIXED — Task 2: plaintext passwords]
//
//  Every call into the `argon2` library goes through this module. Nothing else
//  in the codebase imports `argon2` directly, so swapping the implementation
//  (e.g. to @node-rs/argon2 if a prebuilt binary is unavailable) is a one-file
//  change.
//
//  Stored form is the standard PHC string produced by the library:
//    $argon2id$v=19$m=19456,p=1,t=2$<base64 salt>$<base64 digest>
//  A fresh 16-byte random salt is generated per hash, so two users with the
//  same password still get different digests.
// ============================================================================
import { hash as argon2Hash, verify as argon2Verify, argon2id } from "argon2";
import { logger } from "./logger";

/**
 * OWASP Password Storage Cheat Sheet minimum for Argon2id: 19 MiB, t=2, p=1.
 *
 * These are passed explicitly rather than relying on the library defaults
 * (64 MiB, t=3, p=4) so that the work factor is auditable straight from the
 * stored digest and matches what the report documents. `db/hash-passwords.mjs`
 * mirrors these values; tests/password-storage.test.ts asserts the two agree.
 */
export const ARGON2_OPTIONS = {
  type: argon2id,
  memoryCost: 19456, // KiB => 19 MiB
  timeCost: 2, // iterations
  parallelism: 1, // lanes
  hashLength: 32, // bytes of output
} as const;

/** Hash a plaintext password into an Argon2id PHC string. */
export function hashPassword(plain: string): Promise<string> {
  return argon2Hash(plain, ARGON2_OPTIONS);
}

// ---------------------------------------------------------------------------
//  Timing equalisation.
//
//  If we only ran Argon2id when the account existed, an unknown email would
//  return in ~2 ms (one indexed SELECT) while a known email with the wrong
//  password would take ~35 ms. That step-function is a TIMING user-enumeration
//  oracle — it leaks exactly the information the generic error message was
//  introduced to hide. Verifying against a decoy digest keeps both paths on the
//  same order of magnitude.
//
//  The decoy is computed lazily and memoised: computing it per request would
//  double login latency for nothing, and computing it at module scope would
//  run it during `next build`.
// ---------------------------------------------------------------------------
let decoyDigest: Promise<string> | null = null;

function getDecoyDigest(): Promise<string> {
  decoyDigest ??= hashPassword("argon2id-timing-equalisation-decoy-value");
  return decoyDigest;
}

/**
 * Verify a plaintext password against a stored Argon2id digest.
 *
 * Always performs exactly one Argon2id verification, even when `digest` is
 * null (unknown account), so response time does not distinguish the two cases.
 * The decoy can never authenticate: the result is gated on `digest !== null`.
 *
 * Note that argon2.verify() THROWS on a malformed digest (it deserializes the
 * PHC string first) rather than returning false, hence the try/catch.
 */
export async function verifyPassword(
  digest: string | null,
  plain: string
): Promise<boolean> {
  const target = digest ?? (await getDecoyDigest());
  try {
    const ok = await argon2Verify(target, plain);
    return digest !== null && ok;
  } catch (err) {
    // Structured, and deliberately carries NO digest/password material — the
    // logger would strip those field names anyway.
    logger.serverError({
      event: "auth.password.verify_error",
      reason: String((err as Error)?.name ?? "error"),
    });
    return false;
  }
}
