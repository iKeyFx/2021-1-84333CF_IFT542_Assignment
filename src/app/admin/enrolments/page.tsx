import { redirect } from "next/navigation";
import { currentAdmin } from "@/lib/auth";
import { sql } from "@/lib/db";
import { CsrfField } from "@/app/_components/CsrfField";

export default async function AdminEnrolmentsPage({
  searchParams,
}: {
  searchParams: { removed?: string };
}) {
  const admin = await currentAdmin();
  if (!admin) redirect("/login");

  const rows = await sql<
    {
      id: number;
      student_email: string;
      display_name: string;
      code: string;
      title: string;
      created_at: string;
    }[]
  >`
    SELECT e.id, p.email AS student_email, p.display_name, c.code, c.title, e.created_at
    FROM enrolments e
    JOIN profiles p ON p.id = e.profile_id
    JOIN courses c ON c.id = e.course_id
    ORDER BY p.email, c.code
  `;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Admin — Manage Enrolments</h1>

      {searchParams.removed && (
        <div className="rounded border border-green-300 bg-green-50 p-3 text-sm text-green-800">
          Enrolment removed.
        </div>
      )}

      <div className="rounded border border-slate-200 bg-white p-4">
        {rows.length === 0 ? (
          <p className="text-sm text-slate-500">No enrolments.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-slate-500">
                <th className="py-2">Student</th>
                <th className="py-2">Course</th>
                <th className="py-2">Enrolled</th>
                <th className="py-2"></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className="border-t border-slate-100">
                  <td className="py-2">{r.student_email}</td>
                  <td className="py-2">
                    {r.code} — {r.title}
                  </td>
                  <td className="py-2">{new Date(r.created_at).toLocaleDateString()}</td>
                  <td className="py-2 text-right">
                    <form action="/api/admin/enrolments" method="post">
                      <CsrfField />
                      <input type="hidden" name="enrolment_id" value={r.id} />
                      <button className="text-red-700 underline">Remove</button>
                    </form>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
