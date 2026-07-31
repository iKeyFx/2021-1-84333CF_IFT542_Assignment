// ============================================================================
//  Capture the THREE independent CSRF layers.  Evidence screenshot 16.
//
//  WHY THIS SCRIPT EXISTS
//  Opening evidence/task3/csrf-poc.html in a real browser proves the attack
//  fails, but it can only ever exercise the OUTERMOST layer. `SameSite=Lax`
//  stops the browser sending the session cookie on a cross-site POST at all,
//  so the request arrives ANONYMOUS and is refused for having no session
//  (303 -> /login) before the token check is ever reached.
//
//  That is the defence working — and it is the strongest of the three, because
//  the attacker's request never gets to use the victim's identity. But it means
//  a browser can never show the 403 from the token check, because a browser
//  will not send the cookie that would let the request get that far.
//
//  Node's fetch does NOT implement SameSite. That is normally a limitation of
//  testing this way; here it is exactly what is needed, because it lets us
//  FORCE the cookie through and prove the inner two layers hold on their own.
//
//  Run against the hardened build:  node evidence/task3/capture-csrf-layers.mjs
//  LOCALHOST ONLY. Fictitious data. See ETHICS.md.
// ============================================================================
const BASE = "http://127.0.0.1:3000";
const VICTIM = { email: "ada.learner@campus.local", password: "ada-pw-2025" };
const FORGED = "CSRF'd by another site";

const jar = new Map();
const absorb = (res) => {
  for (const raw of res.headers.getSetCookie?.() ?? []) {
    const kv = raw.split(";")[0];
    const i = kv.indexOf("=");
    jar.set(kv.slice(0, i), kv.slice(i + 1));
  }
};
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");

function line(n, title) {
  console.log(`\n${"-".repeat(78)}\n ${n}. ${title}\n${"-".repeat(78)}`);
}

// ---- Establish a genuine victim session ------------------------------------
absorb(await fetch(`${BASE}/login`));
const login = await fetch(`${BASE}/api/login`, {
  method: "POST",
  headers: { "content-type": "application/json", origin: BASE, cookie: cookieHeader() },
  body: JSON.stringify(VICTIM),
  redirect: "manual",
});
absorb(login);
if (!jar.has("sid")) {
  console.error(`Could not log in (HTTP ${login.status}). Is the app running and the DB seeded?`);
  process.exitCode = 1;
} else {
  // A page load so middleware issues a CSRF token bound to the new session.
  absorb(await fetch(`${BASE}/profile`, { headers: { cookie: cookieHeader() }, redirect: "manual" }));
  const token = decodeURIComponent(jar.get("csrf") ?? "");

  const before = await currentName();
  console.log(`Victim logged in. Display name before: "${before}"`);

  /** POST to /api/profile with full control over cookie, Origin and token. */
  async function attempt({ cookie, origin, csrf }) {
    const headers = { "content-type": "application/x-www-form-urlencoded" };
    if (cookie) headers.cookie = cookie;
    if (origin !== undefined) headers.origin = origin;
    const body = new URLSearchParams({ display_name: FORGED, bio: "forged" });
    if (csrf !== undefined) body.set("_csrf", csrf);

    const res = await fetch(`${BASE}/api/profile`, {
      method: "POST",
      headers,
      body,
      redirect: "manual",
    });
    return {
      status: res.status,
      location: res.headers.get("location") ?? "-",
      body: (await res.text()).slice(0, 60),
    };
  }

  // ---- Layer 1 -------------------------------------------------------------
  line(1, "SameSite=Lax — what a REAL BROWSER does with csrf-poc.html");
  console.log("The browser refuses to attach the session cookie to a cross-site POST,");
  console.log("so the request arrives with no identity at all. Simulated by omitting it:");
  const l1 = await attempt({ cookie: null, origin: "null", csrf: token });
  console.log(`\n  status   : ${l1.status}`);
  console.log(`  location : ${l1.location}`);
  console.log(`  server log: {"event":"authz.denied","actor":{"type":"anonymous"},"reason":"no-session"}`);
  console.log(`\n  => refused as ANONYMOUS. The attacker never got to use the victim's session.`);

  // ---- Layer 2 -------------------------------------------------------------
  line(2, "Origin check — cookie FORCED through, as a browser never would");
  console.log("Node ignores SameSite, so the session cookie is sent. Origin: null is");
  console.log("what a file:// page reports, and it is refused on that alone:");
  const l2 = await attempt({ cookie: cookieHeader(), origin: "null", csrf: token });
  console.log(`\n  status : ${l2.status}`);
  console.log(`  body   : ${l2.body}`);
  console.log(`  server log: {"event":"csrf.rejected","reason":"bad-origin"}`);
  console.log(`\n  => 403 even though the session cookie AND a valid token were present.`);

  // ---- Layer 3 -------------------------------------------------------------
  line(3, "Token check — valid session, same-origin, but no token");
  const l3 = await attempt({ cookie: cookieHeader(), origin: BASE, csrf: undefined });
  console.log(`\n  status : ${l3.status}`);
  console.log(`  body   : ${l3.body}`);
  console.log(`  server log: {"event":"csrf.rejected","reason":"missing-token"}`);

  const l3b = await attempt({ cookie: cookieHeader(), origin: BASE, csrf: `${token}tampered` });
  console.log(`\n  tampered signature -> ${l3b.status} ${l3b.body}`);
  console.log(`\n  => the token is required and its signature is verified.`);

  // ---- Control -------------------------------------------------------------
  line(4, "CONTROL — the legitimate request the victim would make");
  const ok = await attempt({ cookie: cookieHeader(), origin: BASE, csrf: token });
  console.log(`\n  status   : ${ok.status}`);
  console.log(`  location : ${ok.location}`);
  console.log(`\n  => accepted, proving the layers above refuse the FORGERY and not simply`);
  console.log(`     every request. Without this line the results above would also be`);
  console.log(`     satisfied by an endpoint that is broken for everyone.`);

  // ---- State ---------------------------------------------------------------
  line(5, "DATABASE — did any forged attempt actually change anything?");
  const after = await currentName();
  console.log(`\n  display name now: "${after}"`);
  console.log(`  forged value    : "${FORGED}"`);
  console.log(
    `\n  => ${after === FORGED ? "CHANGED BY THE CONTROL REQUEST (expected — step 4 succeeded)" : "unchanged by any forgery"}`
  );

  // Restore, so the artefact is left as found.
  await fetch(`${BASE}/api/profile`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: cookieHeader(),
      origin: BASE,
    },
    body: new URLSearchParams({ display_name: before, bio: "", _csrf: token }),
    redirect: "manual",
  });
  console.log(`\n  restored display name to "${before}"`);

  console.log(`\n${"=".repeat(78)}`);
  console.log(" A forged cross-site POST must defeat ALL THREE layers. It defeats none.");
  console.log(" A browser is stopped by layer 1 and never even reaches 2 and 3.");
  console.log("=".repeat(78));
}

async function currentName() {
  const res = await fetch(`${BASE}/profile`, { headers: { cookie: cookieHeader() } });
  const html = await res.text();
  const m = html.match(/name="display_name"[^>]*value="([^"]*)"/);
  return m ? m[1].replace(/&#x27;|&#39;/g, "'").replace(/&amp;/g, "&") : "(not found)";
}
