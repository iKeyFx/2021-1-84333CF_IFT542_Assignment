import Link from "next/link";
import { redirect } from "next/navigation";
import { currentUser } from "@/lib/auth";
import { sql } from "@/lib/db";

export default async function DashboardPage() {
  const user = await currentUser();
  if (!user) redirect("/login");

  const enrolments = await sql<{ code: string; title: string }[]>`
    SELECT c.code, c.title
    FROM enrolments e JOIN courses c ON c.id = e.course_id
    WHERE e.profile_id = ${user.id}
    ORDER BY c.code
  `;
  const uploads = await sql<{ count: number }[]>`
    SELECT count(*)::int AS count FROM uploads WHERE profile_id = ${user.id}
  `;

  return (
    <div className="space-y-6">
      {/*
        [FIXED — Task 3: stored XSS (sink)]
        Contextual output encoding. `{user.display_name}` renders the value as a
        TEXT NODE — React escapes <, >, &, " and ' on the way out, so a stored
        payload like <img src=x onerror=alert(document.cookie)> is displayed
        literally instead of being parsed as markup.

        Note the payload is still stored verbatim in the database. Encoding at
        the point of OUTPUT is the correct control: the same value is safe in a
        text node and dangerous in raw HTML, so safety is a property of how it is
        rendered, not of the value itself.
      */}
      <h1 className="text-2xl font-bold">Welcome, {user.display_name}</h1>

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded border border-slate-200 bg-white p-4">
          <p className="text-sm text-slate-500">Enrolled courses</p>
          <p className="text-2xl font-semibold">{enrolments.length}</p>
        </div>
        <div className="rounded border border-slate-200 bg-white p-4">
          <p className="text-sm text-slate-500">Uploaded documents</p>
          <p className="text-2xl font-semibold">{uploads[0]?.count ?? 0}</p>
        </div>
        <div className="rounded border border-slate-200 bg-white p-4">
          <p className="text-sm text-slate-500">Role</p>
          <p className="text-2xl font-semibold capitalize">{user.role}</p>
        </div>
      </div>

      <div className="rounded border border-slate-200 bg-white p-4">
        <h2 className="font-semibold mb-2">Your courses</h2>
        {enrolments.length === 0 ? (
          <p className="text-sm text-slate-500">
            No courses yet. <Link href="/courses" className="text-brand underline">Register</Link>.
          </p>
        ) : (
          <ul className="text-sm list-disc pl-5 space-y-1">
            {enrolments.map((c) => (
              <li key={c.code}>
                <span className="font-medium">{c.code}</span> — {c.title}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="flex gap-4 text-sm">
        <Link href="/profile" className="text-brand underline">Edit profile</Link>
        <Link href="/courses" className="text-brand underline">Register for courses</Link>
        <Link href="/uploads" className="text-brand underline">Upload documents</Link>
      </div>
    </div>
  );
}
