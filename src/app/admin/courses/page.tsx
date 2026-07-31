import { redirect } from "next/navigation";
import { currentAdmin } from "@/lib/auth";
import { sql } from "@/lib/db";

export default async function AdminCoursesPage({
  searchParams,
}: {
  searchParams: { saved?: string; error?: string };
}) {
  const admin = await currentAdmin();
  if (!admin) redirect("/login");

  const courses = await sql<
    { id: number; code: string; title: string; description: string; capacity: number }[]
  >`SELECT id, code, title, description, capacity FROM courses ORDER BY code`;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Admin — Manage Courses</h1>

      {searchParams.saved && (
        <div className="rounded border border-green-300 bg-green-50 p-3 text-sm text-green-800">
          Saved.
        </div>
      )}
      {searchParams.error && (
        <div className="rounded border border-red-300 bg-red-50 p-3 text-sm text-red-800">
          {searchParams.error}
        </div>
      )}

      {/* Create */}
      <div className="rounded border border-slate-200 bg-white p-4">
        <h2 className="font-semibold mb-3">Create course</h2>
        <form action="/api/admin/courses" method="post" className="grid gap-3 sm:grid-cols-2">
          <input type="hidden" name="_action" value="create" />
          <input name="code" placeholder="Code (e.g. IFT606)" className="border rounded px-3 py-2" />
          <input name="title" placeholder="Title" className="border rounded px-3 py-2" />
          <input
            name="description"
            placeholder="Description"
            className="border rounded px-3 py-2 sm:col-span-2"
          />
          <input
            name="capacity"
            type="number"
            defaultValue={30}
            className="border rounded px-3 py-2 w-32"
          />
          <div className="sm:col-span-2">
            <button className="bg-brand text-white rounded px-4 py-2 text-sm font-medium">
              Create
            </button>
          </div>
        </form>
      </div>

      {/* Edit / delete each */}
      <div className="space-y-3">
        {courses.map((c) => (
          <div key={c.id} className="rounded border border-slate-200 bg-white p-4">
            <form action="/api/admin/courses" method="post" className="grid gap-3 sm:grid-cols-2">
              <input type="hidden" name="_action" value="edit" />
              <input type="hidden" name="id" value={c.id} />
              <input name="code" defaultValue={c.code} className="border rounded px-3 py-2" />
              <input name="title" defaultValue={c.title} className="border rounded px-3 py-2" />
              <input
                name="description"
                defaultValue={c.description}
                className="border rounded px-3 py-2 sm:col-span-2"
              />
              <input
                name="capacity"
                type="number"
                defaultValue={c.capacity}
                className="border rounded px-3 py-2 w-32"
              />
              <div className="sm:col-span-2">
                <button className="bg-slate-800 text-white rounded px-4 py-2 text-sm font-medium">
                  Save changes
                </button>
              </div>
            </form>
            <form action="/api/admin/courses" method="post" className="mt-2">
              <input type="hidden" name="_action" value="delete" />
              <input type="hidden" name="id" value={c.id} />
              <button className="text-red-700 text-sm underline">Delete course</button>
            </form>
          </div>
        ))}
      </div>
    </div>
  );
}
