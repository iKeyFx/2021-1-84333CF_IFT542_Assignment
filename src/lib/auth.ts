// ============================================================================
//  Small auth helpers used by pages and API routes.
//
//  [FIXED — Task 3 / threat T4: no security logging]
//  currentAdmin() used to return null for BOTH "anonymous" and "logged in but
//  not an admin", collapsing the one case actually worth alerting on: an
//  authenticated ordinary user probing an admin endpoint. It now distinguishes
//  them and emits a structured authz.denied event.
//
//  The signature only gains an OPTIONAL context argument, so existing callers
//  keep working; passing the context just makes the log line useful.
// ============================================================================
import { getSessionUser, type SessionUser } from "./session";
import { logger } from "./logger";

/** Returns the logged-in user or null. */
export async function currentUser(): Promise<SessionUser | null> {
  return getSessionUser();
}

export type AuthzContext = {
  ip?: string;
  method?: string;
  path?: string;
};

/**
 * Returns the user if they are an admin, else null — logging the denial.
 *
 * Two distinct reasons, because they mean very different things operationally:
 *   "no-session" — nobody is logged in. Usually just an expired tab.
 *   "not-admin"  — a REAL, authenticated user tried an admin action. That is
 *                  the one worth alerting on, and the case the old code threw
 *                  away.
 */
export async function currentAdmin(ctx: AuthzContext = {}): Promise<SessionUser | null> {
  const user = await getSessionUser();

  if (!user) {
    logger.authzDenied({ ...ctx, actor: null, reason: "no-session" });
    return null;
  }

  if (user.role !== "admin") {
    logger.authzDenied({
      ...ctx,
      actor: { profile_id: user.id, role: user.role },
      reason: "not-admin",
      required_role: "admin",
    });
    return null;
  }

  return user;
}
