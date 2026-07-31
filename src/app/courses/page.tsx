import { redirect } from "next/navigation";
import { currentUser } from "@/lib/auth";
import { sql } from "@/lib/db";
import { CsrfField } from "@/app/_components/CsrfField";

export default async function CoursesPage({
  searchParams,
}: {
  searchParams: { enrolled?: string };
}) {
  const user = await currentUser();
  if (!user) redirect("/login");

  const courses = await sql<
    { id: number; code: string; title: string; description: string; enrolled: boolean }[]
  >`
    SELECT c.id, c.code, c.title, c.description,
           EXISTS (
             SELECT 1 FROM enrolments e
             WHERE e.course_id = c.id AND e.profile_id = ${user.id}
           ) AS enrolled
    FROM courses c
    ORDER BY c.code
  `;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Course Registration</h1>

      {searchParams.enrolled && (
        <div className="rounded border border-green-300 bg-green-50 p-3 text-sm text-green-800">
          Enrolment updated.
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2">
        {courses.map((c) => (
          <div key={c.id} className="rounded border border-slate-200 bg-white p-4">
            <div className="flex items-baseline justify-between">
              <h2 className="font-semibold">
                {c.code} — {c.title}
              </h2>
              {c.enrolled && (
                <span className="text-xs rounded bg-green-100 text-green-800 px-2 py-0.5">
                  Enrolled
                </span>
              )}
            </div>
            <p className="text-sm text-slate-600 mt-1">{c.description}</p>

            {!c.enrolled && (
              // [FIXED — Task 3: no CSRF protection] <CsrfField /> emits the
              // signed double-submit token bound to this session.
              <form action="/api/enrol" method="post" className="mt-3">
                <CsrfField />
                <input type="hidden" name="course_id" value={c.id} />
                <button
                  type="submit"
                  className="bg-brand text-white rounded px-3 py-1.5 text-sm font-medium"
                >
                  Enrol
                </button>
              </form>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
