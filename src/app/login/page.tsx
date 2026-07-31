"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (res.ok && data.ok) {
        router.push("/dashboard");
        router.refresh();
        return;
      }
      // [FIXED — Task 2: verbose errors]
      // The API now returns a single generic message and never sends `stack`
      // or `query`. This used to render whatever came back verbatim, which
      // amplified the server-side leak straight into the UI.
      setError(data.error ?? "Invalid email or password");
    } catch (err: any) {
      setError(err?.message ?? "Network error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-md mx-auto">
      <h1 className="text-xl font-bold mb-4">Student Login</h1>

      <form onSubmit={onSubmit} className="space-y-4 bg-white p-6 rounded border border-slate-200">
        <div>
          <label className="block text-sm font-medium mb-1">Email</label>
          <input
            type="text"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full border border-slate-300 rounded px-3 py-2"
            placeholder="ada.learner@campus.local"
            autoComplete="off"
          />
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full border border-slate-300 rounded px-3 py-2"
            autoComplete="off"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="w-full bg-brand text-white rounded py-2 font-medium disabled:opacity-60"
        >
          {loading ? "Signing in…" : "Sign in"}
        </button>
      </form>

      {error && (
        <div className="mt-4 rounded border border-red-300 bg-red-50 p-3 text-sm text-red-800">
          <p className="font-medium">{error}</p>
        </div>
      )}

      <div className="mt-6 text-xs text-slate-500 space-y-1">
        <p className="font-medium text-slate-700">Demo accounts (fictitious):</p>
        <p>Student — ada.learner@campus.local / ada-pw-2025</p>
        <p>Admin — admin@campus.local / admin123</p>
      </div>
    </div>
  );
}
