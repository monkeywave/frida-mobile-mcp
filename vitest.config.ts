import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Device E2E suites all drive the same app; run files one at a time when a device is set.
    fileParallelism: !(process.env.FRIDA_MCP_E2E_DEVICE || process.env.FRIDA_E2E),
    include: ['test/**/*.test.ts'],
    globals: false,
    testTimeout: 10000,
    coverage: {
      provider: 'v8',
      include: ['src/**'],
      // Exclude entry/wiring and type-only surfaces that unit tests don't exercise directly.
      exclude: ['src/index.ts', 'src/**/*.d.ts', 'src/types.ts'],
      reporter: ['text-summary', 'lcov'],
      // Gate set just below the current coverage so it only catches regressions, not an
      // aspirational target. Ratchet upward as tool coverage grows.
      thresholds: {
        statements: 70,
        branches: 62,
        functions: 70,
        lines: 70,
      },
    },
  },
});
