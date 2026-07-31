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
 * PASSWORD_MIN is a floor on what the app will even attempt to verify. It used
 * to be pinned at 8 because the Task 3 default admin (`admin123`) was exactly
 * that long; that account has since been rotated to a strong password, so the
 * constraint is now a genuine policy choice rather than a workaround.
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

/**
 * Profile field bounds. [Task 3 — supporting control for stored XSS]
 *
 * These are RESOURCE limits, not a security filter. The control that makes a
 * stored payload harmless is contextual output encoding at render time
 * (src/app/dashboard/page.tsx, src/app/profile/page.tsx). Deliberately nothing
 * here strips or rewrites markup: input filtering is the weaker, bypassable
 * half of the pair, and stripping would also make the demo dishonest by hiding
 * the fact that the payload is stored intact and rendered inert.
 */
export const DISPLAY_NAME_MAX = 100;
export const BIO_MAX = 1000;

export type CredentialsInput =
  | { ok: true; email: string; password: string }
  | { ok: false; reason: string };

export type ProfileInput =
  | { ok: true; displayName: string; bio: string }
  | { ok: false; reason: string };

/** Validate a profile-update form body. */
export function validateProfile(form: FormData): ProfileInput {
  const rawName = form.get("display_name");
  const rawBio = form.get("bio");

  if (typeof rawName !== "string") return { ok: false, reason: "display_name-not-string" };
  if (typeof rawBio !== "string") return { ok: false, reason: "bio-not-string" };

  const displayName = rawName.trim();
  if (displayName.length === 0) return { ok: false, reason: "display_name-empty" };
  if (displayName.length > DISPLAY_NAME_MAX) {
    return { ok: false, reason: "display_name-too-long" };
  }
  if (rawBio.length > BIO_MAX) return { ok: false, reason: "bio-too-long" };

  return { ok: true, displayName, bio: rawBio };
}

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
