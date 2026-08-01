// ============================================================================
//  SSRF guard for the admin URL-preview feature.
//  [FIXED — Task 3: Server-Side Request Forgery]
//
//  The vulnerable build passed the admin's string straight to fetch() with
//  `redirect: "follow"` and no checks at all, turning the server into a read
//  oracle for anything reachable from it — loopback services, RFC1918 hosts,
//  and cloud metadata at 169.254.169.254.
//
//  Defence, in order:
//    1. Parse strictly (new URL) — no bare strings.
//    2. Scheme allowlist: http/https only. Kills file:, data:, ftp:, gopher:.
//    3. HOST ALLOWLIST — the destination must be explicitly permitted.
//    4. Resolve the host and reject every returned address that falls in a
//       loopback / private / link-local / reserved range.
//    5. Follow redirects MANUALLY, re-running 1-4 on every hop, so a permitted
//       host cannot bounce us to a forbidden one.
//    6. Cap time (5s) and body size (64 KB).
//
//  Node runtime only (node:dns) — never import this from middleware.
// ============================================================================
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { URL_PREVIEW_ALLOWLIST } from "./config";

const ALLOWED_SCHEMES = new Set(["http:", "https:"]);
const MAX_REDIRECTS = 3;
const TIMEOUT_MS = 5_000;
const MAX_BODY_BYTES = 64 * 1024;

export type GuardFailure =
  | "unparseable"
  | "scheme-not-allowed"
  | "host-not-allowed"
  | "dns-failed"
  | "blocked-loopback"
  | "blocked-private"
  | "blocked-link-local"
  | "blocked-reserved"
  | "too-many-redirects"
  | "redirect-missing-location";

export type GuardResult =
  | { ok: true; url: URL; addresses: string[] }
  | { ok: false; reason: GuardFailure };

/** Classify an IPv4/IPv6 literal. Returns null when the address is acceptable. */
export function classifyIp(ip: string): GuardFailure | null {
  const kind = isIP(ip);

  if (kind === 4) return classifyIpv4(ip);
  if (kind === 6) return classifyIpv6(ip.toLowerCase());
  return "blocked-reserved";
}

function classifyIpv4(ip: string): GuardFailure | null {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return "blocked-reserved";
  }
  const [a, b] = parts;

  if (a === 127) return "blocked-loopback"; // 127.0.0.0/8
  if (a === 0) return "blocked-reserved"; // 0.0.0.0/8 "this host"
  if (a === 10) return "blocked-private"; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return "blocked-private"; // 172.16.0.0/12
  if (a === 192 && b === 168) return "blocked-private"; // 192.168.0.0/16
  if (a === 169 && b === 254) return "blocked-link-local"; // incl. 169.254.169.254
  if (a === 100 && b >= 64 && b <= 127) return "blocked-private"; // CGNAT 100.64/10
  if (a >= 224) return "blocked-reserved"; // multicast + reserved + broadcast

  return null;
}

function classifyIpv6(ip: string): GuardFailure | null {
  // IPv4-mapped (::ffff:127.0.0.1) and IPv4-compatible forms must be unwrapped,
  // or a loopback address sails straight through the v6 branch.
  const mapped = ip.match(/^::(?:ffff:)?(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return classifyIpv4(mapped[1]);

  if (ip === "::1") return "blocked-loopback";
  if (ip === "::") return "blocked-reserved";
  if (ip.startsWith("fe80") || ip.startsWith("fe9") || ip.startsWith("fea") || ip.startsWith("feb")) {
    return "blocked-link-local"; // fe80::/10
  }
  if (/^f[cd]/.test(ip)) return "blocked-private"; // fc00::/7 unique-local
  if (ip.startsWith("ff")) return "blocked-reserved"; // ff00::/8 multicast

  return null;
}

function hostAllowed(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return URL_PREVIEW_ALLOWLIST.some(
    (allowed) => host === allowed || host.endsWith(`.${allowed}`)
  );
}

/** Injectable for tests, so the whole guard is exercisable with no network. */
export type Resolver = (hostname: string) => Promise<string[]>;

const defaultResolver: Resolver = async (hostname) => {
  const results = await lookup(hostname, { all: true, verbatim: true });
  return results.map((r) => r.address);
};

/**
 * Validate one URL. Returns the resolved addresses so a caller can log them.
 */
export async function assertSafeUrl(
  raw: string,
  resolve: Resolver = defaultResolver
): Promise<GuardResult> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: "unparseable" };
  }

  if (!ALLOWED_SCHEMES.has(url.protocol)) {
    return { ok: false, reason: "scheme-not-allowed" };
  }

  const hostname = url.hostname.replace(/^\[|\]$/g, ""); // strip IPv6 brackets

  // An IP literal never reaches DNS, so check it directly — this is what stops
  // the `http://127.0.0.1:3000/login` case asserted in tests/ssrf-guard.test.ts.
  if (isIP(hostname)) {
    const verdict = classifyIp(hostname);
    if (verdict) return { ok: false, reason: verdict };
    // A literal still has to be on the allowlist; being public is not enough.
    if (!hostAllowed(hostname)) return { ok: false, reason: "host-not-allowed" };
    return { ok: true, url, addresses: [hostname] };
  }

  if (!hostAllowed(hostname)) {
    return { ok: false, reason: "host-not-allowed" };
  }

  let addresses: string[];
  try {
    addresses = await resolve(hostname);
  } catch {
    return { ok: false, reason: "dns-failed" };
  }

  if (addresses.length === 0) return { ok: false, reason: "dns-failed" };

  // EVERY resolved address must pass. A hostname that returns one public and
  // one loopback address is rejected outright rather than being raced.
  for (const address of addresses) {
    const verdict = classifyIp(address);
    if (verdict) return { ok: false, reason: verdict };
  }

  return { ok: true, url, addresses };
}

export type FetchResult =
  | {
      ok: true;
      status: number;
      statusText: string;
      finalUrl: string;
      headers: Record<string, string>;
      bodySnippet: string;
      truncated: boolean;
      elapsedMs: number;
    }
  | { ok: false; reason: GuardFailure | "fetch-failed" };

/**
 * Fetch a URL through the guard, re-validating every redirect hop.
 *
 * `redirect: "manual"` is essential: with "follow", undici would chase a 302
 * into a blocked range internally and the guard would never see the new target.
 *
 * RESIDUAL RISK — TOCTOU / DNS rebinding. Between our lookup() and undici's own
 * connect(), the name can re-resolve to a different address. Closing that gap
 * properly needs a custom undici Agent whose connect hook pins the address we
 * already validated. Not implemented here; disclosed rather than papered over.
 */
export async function safeFetch(
  raw: string,
  resolve: Resolver = defaultResolver
): Promise<FetchResult> {
  const started = Date.now();
  let target = raw;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const guard = await assertSafeUrl(target, resolve);
    if (!guard.ok) return { ok: false, reason: guard.reason };

    let res: Response;
    try {
      res = await fetch(guard.url, {
        redirect: "manual",
        signal: AbortSignal.timeout(TIMEOUT_MS),
        headers: { accept: "text/*, application/json" },
      });
    } catch {
      return { ok: false, reason: "fetch-failed" };
    }

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      if (!location) return { ok: false, reason: "redirect-missing-location" };
      // Re-enter the loop so the new destination is fully re-validated.
      target = new URL(location, guard.url).toString();
      continue;
    }

    const { text, truncated } = await readCapped(res);
    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => {
      headers[key] = value;
    });

    return {
      ok: true,
      status: res.status,
      statusText: res.statusText,
      finalUrl: guard.url.toString(),
      headers,
      bodySnippet: text,
      truncated,
      elapsedMs: Date.now() - started,
    };
  }

  return { ok: false, reason: "too-many-redirects" };
}

/** Read at most MAX_BODY_BYTES, so a huge internal file cannot exhaust memory. */
async function readCapped(res: Response): Promise<{ text: string; truncated: boolean }> {
  const reader = res.body?.getReader();
  if (!reader) return { text: "", truncated: false };

  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;

  while (total < MAX_BODY_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.length;
    if (total >= MAX_BODY_BYTES) {
      truncated = true;
      break;
    }
  }
  await reader.cancel().catch(() => {});

  const buf = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    buf.set(c.subarray(0, Math.min(c.length, MAX_BODY_BYTES - offset)), offset);
    offset += c.length;
    if (offset >= MAX_BODY_BYTES) break;
  }

  return {
    text: new TextDecoder().decode(buf.subarray(0, Math.min(total, MAX_BODY_BYTES))),
    truncated,
  };
}
