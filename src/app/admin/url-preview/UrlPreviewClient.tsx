"use client";

import { useState } from "react";

export default function UrlPreviewClient() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  async function preview(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch("/api/admin/url-preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      setResult(await res.json());
    } catch (err: any) {
      setResult({ ok: false, error: err?.message });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <form onSubmit={preview} className="flex gap-2 bg-white p-4 rounded border border-slate-200">
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com/syllabus.txt"
          className="flex-1 border border-slate-300 rounded px-3 py-2"
        />
        <button
          disabled={loading}
          className="bg-brand text-white rounded px-4 py-2 text-sm font-medium disabled:opacity-60"
        >
          {loading ? "Fetching…" : "Preview"}
        </button>
      </form>

      {result && (
        <div className="rounded border border-slate-200 bg-white p-4 text-sm">
          <p className="font-medium mb-2">
            {result.ok ? `HTTP ${result.status} ${result.statusText}` : "Fetch error"}
          </p>
          <pre className="overflow-x-auto text-xs whitespace-pre-wrap bg-slate-50 p-3 rounded">
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
