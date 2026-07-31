// ============================================================================
//  Task 2 — stored passwords are Argon2id digests, never plaintext.
//
//  Talks to the database directly (no HTTP), because the claim under test is
//  about what is ON DISK, not about what the API returns.
// ============================================================================
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { db, DEMO, ALL_DEMO_PASSWORDS } from "./helpers";
import { ARGON2_OPTIONS, verifyPassword } from "@/lib/password";

/**
 * PHC string, e.g.
 *   $argon2id$v=19$m=19456,p=1,t=2$<b64 salt>$<b64 digest>
 * Note the library serialises the parameters ALPHABETICALLY (m, p, t), so the
 * order is not the m/t/p people usually write.
 */
const PHC_RE =
  /^\$argon2id\$v=19\$(?:[a-z]+=\d+,){2}[a-z]+=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/;

/** Pull the m/t/p parameters out of a PHC string, order-independently. */
function phcParams(digest: string): Record<string, number> {
  const params = digest.split("$")[3] ?? "";
  return Object.fromEntries(
    params.split(",").map((kv) => {
      const [k, v] = kv.split("=");
      return [k, Number(v)];
    })
  );
}

let sql: ReturnType<typeof db>;
let rows: Array<{ profile_id: number; email: string; password_hash: string }>;

beforeAll(async () => {
  sql = db();
  rows = await sql`
    SELECT c.profile_id, p.email, c.password_hash
    FROM credentials c JOIN profiles p ON p.id = c.profile_id
    ORDER BY c.profile_id
  `;
});

afterAll(async () => {
  await sql.end({ timeout: 5 });
});

describe("stored credentials are Argon2id digests", () => {
  it("has one credential row per seeded profile", () => {
    expect(rows.length).toBe(7);
  });

  it("every stored value starts with the $argon2id$ prefix", () => {
    for (const r of rows) {
      expect(r.password_hash.startsWith("$argon2id$")).toBe(true);
    }
  });

  it("every stored value is a well-formed PHC string", () => {
    for (const r of rows) {
      expect(r.password_hash, r.email).toMatch(PHC_RE);
    }
  });

  it("the stored work factor matches ARGON2_OPTIONS in src/lib/password.ts", () => {
    // Drift detector: db/hash-passwords.mjs duplicates these constants because
    // a .mjs cannot import the .ts module. If the two ever diverge, this fails.
    for (const r of rows) {
      const p = phcParams(r.password_hash);
      expect(p.m, `memoryCost for ${r.email}`).toBe(ARGON2_OPTIONS.memoryCost);
      expect(p.t, `timeCost for ${r.email}`).toBe(ARGON2_OPTIONS.timeCost);
      expect(p.p, `parallelism for ${r.email}`).toBe(ARGON2_OPTIONS.parallelism);
    }
  });

  it("uses an independent random salt per row", () => {
    const salts = rows.map((r) => r.password_hash.split("$")[4]);
    expect(new Set(salts).size).toBe(rows.length);
  });
});

describe("no plaintext anywhere", () => {
  it("the legacy plaintext column no longer exists", async () => {
    const cols = await sql<Array<{ column_name: string }>>`
      SELECT column_name FROM information_schema.columns
      WHERE table_name = 'credentials'
      ORDER BY ordinal_position
    `;
    const names = cols.map((c) => c.column_name);

    expect(names).toEqual(["profile_id", "password_hash"]);
    expect(names).not.toContain("password");
  });

  it("no stored value equals any known demo password", () => {
    const stored = rows.map((r) => r.password_hash);
    for (const plain of ALL_DEMO_PASSWORDS) {
      expect(stored).not.toContain(plain);
    }
  });

  it("no stored value even contains a known demo password as a substring", () => {
    for (const r of rows) {
      for (const plain of ALL_DEMO_PASSWORDS) {
        expect(r.password_hash).not.toContain(plain);
      }
    }
  });

  it("the database itself rejects a non-Argon2id value (CHECK constraint)", async () => {
    // Rolled back, so the seeded data is untouched.
    await expect(
      sql.begin(async (tx) => {
        await tx`
          UPDATE credentials SET password_hash = 'ada-pw-2025'
          WHERE profile_id = ${rows[0].profile_id}
        `;
      })
    ).rejects.toMatchObject({ code: "23514" }); // check_violation
  });
});

describe("the digests correspond to the documented credentials", () => {
  it("verifies the correct password for the seeded student", async () => {
    const row = rows.find((r) => r.email === DEMO.student.email)!;
    expect(row).toBeDefined();
    await expect(verifyPassword(row.password_hash, DEMO.student.password)).resolves.toBe(true);
  });

  it("rejects a wrong password against the same digest", async () => {
    const row = rows.find((r) => r.email === DEMO.student.email)!;
    await expect(verifyPassword(row.password_hash, "wrong-password")).resolves.toBe(false);
  });

  it("never authenticates against a null digest (unknown account)", async () => {
    await expect(verifyPassword(null, DEMO.student.password)).resolves.toBe(false);
  });

  it("returns false rather than throwing on a malformed digest", async () => {
    await expect(verifyPassword("not-a-phc-string", "anything")).resolves.toBe(false);
  });
});
