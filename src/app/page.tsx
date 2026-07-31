import Link from "next/link";
import { currentUser } from "@/lib/auth";

export default async function HomePage() {
  const user = await currentUser();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Campus Student Registration</h1>
        <p className="text-slate-600 mt-1">
          A prototype registration portal used for the IFT542 web-security coursework. This build
          intentionally contains common web vulnerabilities for a before/after teaching
          demonstration.
        </p>
      </div>

      {user ? (
        <p>
          You are signed in as <span className="font-medium">{user.email}</span>. Go to your{" "}
          <Link href="/dashboard" className="text-brand underline">dashboard</Link>.
        </p>
      ) : (
        <p>
          Please{" "}
          <Link href="/login" className="text-brand underline">log in</Link> to continue.
        </p>
      )}

      <div className="rounded border border-slate-200 bg-white p-4 text-sm text-slate-600">
        <p className="font-medium text-slate-800">Scope reminder</p>
        <p className="mt-1">
          Isolated localhost artefact · fictitious data only · not for deployment. See{" "}
          <code>ETHICS.md</code> and <code>README.md</code>.
        </p>
      </div>
    </div>
  );
}
