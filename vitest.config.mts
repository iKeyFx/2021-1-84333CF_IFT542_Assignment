import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// ============================================================================
//  Vitest config for the Task 2 hardening tests.
//
//  `include` matches only *.test.ts. The hand-written v0 PoC scripts that
//  used to sit alongside them were removed before submission (the coursework
//  forbids shipping reusable payloads); their coverage now lives entirely in
//  the *.test.ts suite — sqli-parameterized, xss-encoding, csrf, ssrf-guard.
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
