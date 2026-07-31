import { redirect } from "next/navigation";
import { currentUser } from "@/lib/auth";
import { sql } from "@/lib/db";

export default async function UploadsPage({
  searchParams,
}: {
  searchParams: { uploaded?: string; error?: string };
}) {
  const user = await currentUser();
  if (!user) redirect("/login");

  const docs = await sql<
    { id: number; original_name: string; mime: string; size: number; created_at: string }[]
  >`
    SELECT id, original_name, mime, size, created_at
    FROM uploads
    WHERE profile_id = ${user.id}
    ORDER BY created_at DESC
  `;

  return (
    <div className="max-w-2xl space-y-6">
      <h1 className="text-2xl font-bold">Document Upload</h1>

      {searchParams.uploaded && (
        <div className="rounded border border-green-300 bg-green-50 p-3 text-sm text-green-800">
          File uploaded.
        </div>
      )}
      {searchParams.error === "nofile" && (
        <div className="rounded border border-red-300 bg-red-50 p-3 text-sm text-red-800">
          Please choose a file to upload.
        </div>
      )}

      <form
        action="/api/upload"
        method="post"
        encType="multipart/form-data"
        className="space-y-4 bg-white p-6 rounded border border-slate-200"
      >
        <div>
          <label className="block text-sm font-medium mb-1">Choose a document</label>
          <input type="file" name="document" className="block w-full text-sm" />
          <p className="text-xs text-slate-400 mt-1">Stored to local disk under ./uploads.</p>
        </div>
        <button type="submit" className="bg-brand text-white rounded py-2 px-4 font-medium">
          Upload
        </button>
      </form>

      <div className="rounded border border-slate-200 bg-white p-4">
        <h2 className="font-semibold mb-2">Your documents</h2>
        {docs.length === 0 ? (
          <p className="text-sm text-slate-500">No documents uploaded yet.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-slate-500">
                <th className="py-1">Name</th>
                <th className="py-1">Type</th>
                <th className="py-1">Size</th>
                <th className="py-1">Uploaded</th>
              </tr>
            </thead>
            <tbody>
              {docs.map((d) => (
                <tr key={d.id} className="border-t border-slate-100">
                  <td className="py-1">{d.original_name}</td>
                  <td className="py-1">{d.mime || "—"}</td>
                  <td className="py-1">{(d.size / 1024).toFixed(1)} KB</td>
                  <td className="py-1">{new Date(d.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
