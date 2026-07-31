import { redirect } from "next/navigation";
import { currentUser } from "@/lib/auth";

export default async function ProfilePage({
  searchParams,
}: {
  searchParams: { saved?: string };
}) {
  const user = await currentUser();
  if (!user) redirect("/login");

  return (
    <div className="max-w-2xl space-y-6">
      <h1 className="text-2xl font-bold">Edit Profile</h1>

      {searchParams.saved && (
        <div className="rounded border border-green-300 bg-green-50 p-3 text-sm text-green-800">
          Profile saved.
        </div>
      )}

      <div className="rounded border border-slate-200 bg-white p-4">
        <p className="text-sm text-slate-500 mb-1">Current display name (as rendered):</p>
        {/*
          [VULN: Stored XSS (sink) — Task 3]
          The saved display name is echoed back here as raw HTML too, so the
          payload fires on this page as well as on the dashboard.
        */}
        <div
          className="text-lg font-medium"
          dangerouslySetInnerHTML={{ __html: user.display_name }}
        />
      </div>

      {/*
        Plain HTML form POST — no CSRF token field. The matching handler
        (src/app/api/profile/route.ts) trusts the session cookie alone.
        [VULN: No CSRF protection — Task 3]
      */}
      <form
        action="/api/profile"
        method="post"
        className="space-y-4 bg-white p-6 rounded border border-slate-200"
      >
        <div>
          <label className="block text-sm font-medium mb-1">Display name</label>
          <input
            type="text"
            name="display_name"
            defaultValue={user.display_name}
            className="w-full border border-slate-300 rounded px-3 py-2"
          />
          <p className="text-xs text-slate-400 mt-1">
            Stored and rendered without encoding in this build.
          </p>
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Bio</label>
          <textarea
            name="bio"
            defaultValue={user.bio}
            rows={4}
            className="w-full border border-slate-300 rounded px-3 py-2"
          />
        </div>
        <button type="submit" className="bg-brand text-white rounded py-2 px-4 font-medium">
          Save profile
        </button>
      </form>
    </div>
  );
}
