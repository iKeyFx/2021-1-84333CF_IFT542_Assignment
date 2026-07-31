import { redirect } from "next/navigation";
import { currentAdmin } from "@/lib/auth";
import UrlPreviewClient from "./UrlPreviewClient";

export default async function AdminUrlPreviewPage() {
  const admin = await currentAdmin();
  if (!admin) redirect("/login");

  return (
    <div className="max-w-2xl space-y-6">
      <h1 className="text-2xl font-bold">Admin — URL Preview / Import</h1>
      <p className="text-sm text-slate-600">
        Fetch a remote URL (e.g. a syllabus or timetable) to preview before importing. In this build
        the server fetches whatever URL you give it, with no restrictions.
      </p>
      <UrlPreviewClient />
    </div>
  );
}
