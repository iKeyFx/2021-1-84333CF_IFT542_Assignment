import { redirect } from "next/navigation";
import { currentUser } from "@/lib/auth";
import { CsrfField } from "@/app/_components/CsrfField";

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
          [FIXED — Task 3: stored XSS (sink)]
          Rendered as a text node, so the value is escaped on output. See the
          matching comment in src/app/dashboard/page.tsx.
        */}
        <div className="text-lg font-medium">{user.display_name}</div>
      </div>

      {/*
        [FIXED — Task 3: no CSRF protection]
        The form now carries a hidden anti-CSRF token (<CsrfField />) which
        src/app/api/profile/route.ts verifies before applying any change.
      */}
      <form
        action="/api/profile"
        method="post"
        className="space-y-4 bg-white p-6 rounded border border-slate-200"
      >
        <CsrfField />
        <div>
          <label className="block text-sm font-medium mb-1">Display name</label>
          <input
            type="text"
            name="display_name"
            defaultValue={user.display_name}
            className="w-full border border-slate-300 rounded px-3 py-2"
          />
          <p className="text-xs text-slate-400 mt-1">
            Stored as-is and escaped on output, so markup is shown literally.
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
