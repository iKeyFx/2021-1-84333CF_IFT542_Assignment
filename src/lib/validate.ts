// ============================================================================
//  Auth input validation.  [FIXED — Task 2: unvalidated login input]
//
//  Rejects malformed credentials BEFORE they reach the database or the Argon2
//  hasher. This is defence in depth: the login query is parameterized, so an
//  injection string would be inert anyway, but validating first means hostile
//  input never reaches the driver at all and never costs us 19 MiB of hashing.
//
//  The caller must map EVERY failure here onto the single generic error
//  ("Invalid email or password"). The `reason` field is a SERVER-SIDE LOG
//  LABEL ONLY and must never be returned to the client.
// ============================================================================

export const EMAIL_MIN = 3;
export const EMAIL_MAX = 254; // RFC 5321 reverse-path limit

/**
 * PASSWORD_MIN must stay <= 8. The seeded default admin (admin@campus.local /
 * admin123) is exactly 8 characters and is a deliberate Task 3 vulnerability
 * that must keep working; raising this would silently remove it.
 *
 * PASSWORD_MAX is a DoS control, not a password policy: without a cap an
 * attacker can POST a multi-megabyte password and make the server spend
 * 19 MiB of Argon2 work per request. Cap the length BEFORE hashing.
 */
export const PASSWORD_MIN = 8;
export const PASSWORD_MAX = 128;

/**
 * Deliberately simple and linear-time — no nested quantifiers, so there is no
 * ReDoS surface. Full RFC 5322 conformance is not the goal; rejecting anything
 * that is not recognisably an address is.
 */
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{1,63}$/;

export type CredentialsInput =
  | { ok: true; email: string; password: string }
  | { ok: false; reason: string };

/**
 * Validate and normalise a parsed JSON login body.
 *
 * Non-string email/password are rejected outright rather than coerced with
 * String(): String(["x"]) === "x", so coercion would let an array or a boxed
 * value through as a valid-looking credential.
 */
export function validateCredentials(body: unknown): CredentialsInput {
  if (typeof body !== "object" || body === null) {
    return { ok: false, reason: "body-not-object" };
  }

  const { email, password } = body as Record<string, unknown>;

  if (typeof email !== "string") return { ok: false, reason: "email-not-string" };
  if (typeof password !== "string") return { ok: false, reason: "password-not-string" };

  // All seeded addresses are lowercase, so normalising here is equivalent to
  // matching on lower(p.email). The rigorous variant for mixed-case data is
  // `WHERE lower(p.email) = ${email}` plus an index on lower(email).
  const normalised = email.trim().toLowerCase();

  if (normalised.length < EMAIL_MIN || normalised.length > EMAIL_MAX) {
    return { ok: false, reason: "email-length" };
  }
  if (!EMAIL_RE.test(normalised)) {
    return { ok: false, reason: "email-format" };
  }
  if (password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
    return { ok: false, reason: "password-length" };
  }

  return { ok: true, email: normalised, password };
}
