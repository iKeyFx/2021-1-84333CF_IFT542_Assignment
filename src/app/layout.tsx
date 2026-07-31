import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";
import { currentUser } from "@/lib/auth";
import { CsrfField } from "@/app/_components/CsrfField";

export const metadata: Metadata = {
  title: "IFT542 Student Registration (Vulnerable Demo)",
  description: "Isolated localhost teaching artefact — deliberately vulnerable. Do not deploy.",
};

async function LogoutButton() {
  return (
    <form action="/api/logout" method="post">
      <CsrfField />
      <button className="text-sm text-white/80 hover:text-white underline">Log out</button>
    </form>
  );
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const user = await currentUser();

  return (
    <html lang="en">
      <body>
        <div className="bg-amber-100 border-b border-amber-300 text-amber-900 text-xs text-center py-1 px-2">
          ⚠️ DELIBERATELY VULNERABLE TEACHING ARTEFACT (IFT542) — localhost only, fictitious data,
          never deploy.
        </div>
        <header className="bg-brand text-white">
          <div className="max-w-5xl mx-auto px-4 py-3 flex items-center gap-4">
            <Link href="/" className="font-semibold">
              Campus Registration
            </Link>
            {user && (
              <nav className="flex items-center gap-4 text-sm text-white/90">
                <Link href="/dashboard" className="hover:underline">Dashboard</Link>
                <Link href="/profile" className="hover:underline">Profile</Link>
                <Link href="/courses" className="hover:underline">Courses</Link>
                <Link href="/uploads" className="hover:underline">Documents</Link>
                {user.role === "admin" && (
                  <>
                    <Link href="/admin/courses" className="hover:underline">Admin: Courses</Link>
                    <Link href="/admin/enrolments" className="hover:underline">Admin: Enrolments</Link>
                    <Link href="/admin/url-preview" className="hover:underline">Admin: URL Preview</Link>
                  </>
                )}
              </nav>
            )}
            <div className="ml-auto flex items-center gap-3">
              {user ? (
                <>
                  <span className="text-sm text-white/80">{user.email}</span>
                  <LogoutButton />
                </>
              ) : (
                <Link href="/login" className="text-sm hover:underline">
                  Log in
                </Link>
              )}
            </div>
          </div>
        </header>
        <main className="max-w-5xl mx-auto px-4 py-8">{children}</main>
      </body>
    </html>
  );
}
