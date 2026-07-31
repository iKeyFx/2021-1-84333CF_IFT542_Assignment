# Local test cases (app-only PoCs)

Every script here is **hard-wired to `http://127.0.0.1:3000`** and only exercises
*this* application. They are teaching repros of the planted vulnerabilities, not
reusable attack tools. Start the stack first:

```
npm run db:reset      # Postgres up + migrate + seed
npm run dev           # app on http://127.0.0.1:3000
```

Then, in another terminal:

| Script | Demonstrates | Task |
| --- | --- | --- |
| `node tests/sqli-login.mjs` | SQL-injection auth bypass on `/api/login` | 2 |
| `node tests/enum-and-verbose.mjs` | User enumeration + verbose DB/stack errors | 2 |
| `node tests/ssrf-demo.mjs` | SSRF via admin URL-preview (server fetches loopback) | 3 |
| `tests/xss-payload.txt` | Stored-XSS payloads for the profile display name (manual) | 3 |

CSRF is demonstrated with `evidence/task3/csrf-poc.html` — open it in a browser
while logged in (see that file's comments).

Plaintext passwords and the no-SameSite / no-session-regen behaviours are
verified by inspection (see `evidence/task2/README.md`).
