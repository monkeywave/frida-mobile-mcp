import { describe, it, expect, afterEach, vi } from 'vitest';

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    existsSync: vi.fn().mockReturnValue(false),
    readFileSync: actual.readFileSync,
  };
});

describe('loadConfig', () => {
  const envBackup: Record<string, string | undefined> = {};

  afterEach(() => {
    for (const key of Object.keys(envBackup)) {
      if (envBackup[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = envBackup[key];
      }
    }
    vi.resetModules();
  });

  function setEnv(key: string, value: string): void {
    envBackup[key] = process.env[key];
    process.env[key] = value;
  }

  async function freshLoadConfig(
    overrides?: Parameters<typeof import('../src/config.js').loadConfig>[0],
  ) {
    const { loadConfig } = await import('../src/config.js');
    return loadConfig(overrides);
  }

  describe('defaults (no overrides)', () => {
    it('returns allowCustomScripts as false', async () => {
      const config = await freshLoadConfig();
      expect(config.allowCustomScripts).toBe(false);
    });

    it('returns memoryWriteEnabled as false', async () => {
      const config = await freshLoadConfig();
      expect(config.memoryWriteEnabled).toBe(false);
    });

    it('returns maxSessions as 4', async () => {
      const config = await freshLoadConfig();
      expect(config.maxSessions).toBe(4);
    });

    it('returns sessionTimeoutMinutes as 30', async () => {
      const config = await freshLoadConfig();
      expect(config.sessionTimeoutMinutes).toBe(30);
    });

    it('returns rateLimits.scriptsPerMinute as 10', async () => {
      const config = await freshLoadConfig();
      expect(config.rateLimits.scriptsPerMinute).toBe(10);
    });

    it('returns rateLimits.memoryReadsPerMinute as 60', async () => {
      const config = await freshLoadConfig();
      expect(config.rateLimits.memoryReadsPerMinute).toBe(60);
    });

    it('returns rateLimits.sessionsPerMinute as 5', async () => {
      const config = await freshLoadConfig();
      expect(config.rateLimits.sessionsPerMinute).toBe(5);
    });

    it('returns mobileMcp.enabled as true', async () => {
      const config = await freshLoadConfig();
      expect(config.mobileMcp.enabled).toBe(true);
    });
  });

  describe('overrides merge correctly', () => {
    it('overrides allowCustomScripts to true', async () => {
      const config = await freshLoadConfig({ allowCustomScripts: true });
      expect(config.allowCustomScripts).toBe(true);
    });

    it('overrides nested rateLimits.scriptsPerMinute while keeping other limits at defaults', async () => {
      const config = await freshLoadConfig({ rateLimits: { scriptsPerMinute: 20 } as any });
      expect(config.rateLimits.scriptsPerMinute).toBe(20);
      expect(config.rateLimits.memoryReadsPerMinute).toBe(60);
      expect(config.rateLimits.sessionsPerMinute).toBe(5);
    });
  });

  describe('environment variable overrides', () => {
    it('FRIDA_MCP_ALLOW_CUSTOM_SCRIPTS=1 sets allowCustomScripts to true', async () => {
      setEnv('FRIDA_MCP_ALLOW_CUSTOM_SCRIPTS', '1');
      const config = await freshLoadConfig();
      expect(config.allowCustomScripts).toBe(true);
    });

    it('FRIDA_MCP_MEMORY_WRITE=1 sets memoryWriteEnabled to true', async () => {
      setEnv('FRIDA_MCP_MEMORY_WRITE', '1');
      const config = await freshLoadConfig();
      expect(config.memoryWriteEnabled).toBe(true);
    });
  });
});
