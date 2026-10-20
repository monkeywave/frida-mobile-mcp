import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Device E2E suites all drive the same app; run files one at a time when a device is set.
    fileParallelism: !(process.env.FRIDA_MCP_E2E_DEVICE || process.env.FRIDA_E2E),
    include: ['test/**/*.test.ts'],
    globals: false,
    testTimeout: 10000,
  },
});
