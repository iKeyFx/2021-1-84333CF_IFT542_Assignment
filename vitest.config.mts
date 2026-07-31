import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// ============================================================================
//  Vitest config for the Task 2 hardening tests.
//
//  `include` deliberately matches only *.test.ts, so the hand-written PoC
//  scripts in tests/ (sqli-login.mjs, enum-and-verbose.mjs, ssrf-demo.mjs)
//  are NOT picked up — they are the "before" artefacts and are still run
//  manually with `node tests/<file>.mjs`.
// ============================================================================
export default defineConfig({
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    globalSetup: ["tests/setup/global-setup.ts"],
    // Sequential: every file shares one dev server and one database.
    fileParallelism: false,
    // The first request to a route compiles it in `next dev` (5-15s).
    testTimeout: 30_000,
    // Global setup may spawn a dev server and wait for it to come up.
    hookTimeout: 120_000,
  },
});
