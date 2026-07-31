// ============================================================================
//  Small auth helpers used by pages and API routes.
// ============================================================================
import { getSessionUser, type SessionUser } from "./session";

/** Returns the logged-in user or null. */
export async function currentUser(): Promise<SessionUser | null> {
  return getSessionUser();
}

/** Returns the user if they are an admin, else null. */
export async function currentAdmin(): Promise<SessionUser | null> {
  const user = await getSessionUser();
  return user && user.role === "admin" ? user : null;
}
