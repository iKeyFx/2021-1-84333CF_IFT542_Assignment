// ============================================================================
//  postgres.js connection singleton.
//
//  postgres.js is parameterized/safe BY DEFAULT when you use tagged-template
//  calls, e.g.  sql`SELECT * FROM profiles WHERE email = ${email}`.
//  The login route deliberately AVOIDS that and uses sql.unsafe(...) with a
//  string-concatenated query instead — that is the planted SQL-injection sink.
//  See src/app/api/login/route.ts. [VULN: SQL injection — Task 2]
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
