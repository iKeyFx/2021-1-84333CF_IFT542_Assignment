// ============================================================================
//  Hidden anti-CSRF form field.  [FIXED — Task 3: no CSRF protection]
//
//  Drop <CsrfField /> inside every state-changing <form>. Server component, so
//  it never reaches the client bundle.
// ============================================================================
import { headers } from "next/headers";
import { CSRF_FIELD, CSRF_HEADER } from "@/lib/csrf-constants";

export function CsrfField() {
  // Read the token from the REQUEST header that src/middleware.ts injected,
  // not from cookies(). The cookie middleware just issued lives on the
  // RESPONSE, so cookies() would come back empty on a visitor's first request
  // and render a blank token — which would then fail verification.
  const token = headers().get(CSRF_HEADER) ?? "";

  return <input type="hidden" name={CSRF_FIELD} value={token} />;
}
