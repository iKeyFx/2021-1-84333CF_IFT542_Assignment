// ============================================================================
//  postgres.js connection singleton.
//
//  postgres.js is parameterized/safe BY DEFAULT when you use tagged-template
//  calls, e.g.  sql`SELECT * FROM profiles WHERE email = ${email}`, which are
//  sent as extended queries with $1-style placeholders.
//
//  [FIXED — Task 2: SQL injection]
//  The login route used to bypass that with a string-concatenated sql.unsafe()
//  call. It now uses a tagged template, so the email is bound as data.
//  See src/app/api/login/route.ts.
// ============================================================================
import postgres from "postgres";
import { DATABASE_URL } from "./config";

// Reuse one pool across hot reloads in dev.
declare global {
  // eslint-disable-next-line no-var
  var __ift542_sql: ReturnType<typeof postgres> | undefined;
}

export const sql =
  global.__ift542_sql ??
  postgres(DATABASE_URL, {
    onnotice: () => {},
    max: 10,
  });

if (process.env.NODE_ENV !== "production") {
  global.__ift542_sql = sql;
}
