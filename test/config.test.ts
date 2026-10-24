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

    it('FRIDA_MCP_REMOTE / _TOKEN / _CERT set the remote frida-server connection', async () => {
      setEnv('FRIDA_MCP_REMOTE', '192.168.1.20:27042');
      setEnv('FRIDA_MCP_REMOTE_TOKEN', ' s3cret ');
      setEnv('FRIDA_MCP_REMOTE_CERT', '/etc/frida/server.pem');
      const config = await freshLoadConfig();
      expect(config.remoteDevice).toBe('192.168.1.20:27042');
      expect(config.remoteToken).toBe('s3cret');
      expect(config.remoteCertificate).toBe('/etc/frida/server.pem');
    });

    it('blank FRIDA_MCP_REMOTE_TOKEN / _CERT keep the CLI override', async () => {
      setEnv('FRIDA_MCP_REMOTE_TOKEN', '  ');
      setEnv('FRIDA_MCP_REMOTE_CERT', '');
      const config = await freshLoadConfig({ remoteToken: 'from-cli', remoteCertificate: '/cli.pem' });
      expect(config.remoteToken).toBe('from-cli');
      expect(config.remoteCertificate).toBe('/cli.pem');
    });

    it('defaults to the full tool profile with no exclusions', async () => {
      const config = await freshLoadConfig();
      expect(config.toolProfile).toBe('full');
      expect(config.toolsExclude).toEqual([]);
    });

    it('FRIDA_MCP_TOOL_PROFILE=core (any case) selects the core profile', async () => {
      setEnv('FRIDA_MCP_TOOL_PROFILE', ' CORE ');
      const config = await freshLoadConfig();
      expect(config.toolProfile).toBe('core');
    });

    it('an unknown FRIDA_MCP_TOOL_PROFILE warns and keeps the current profile', async () => {
      const warn = vi.spyOn(console, 'error').mockImplementation(() => {});
      setEnv('FRIDA_MCP_TOOL_PROFILE', 'tiny');
      const config = await freshLoadConfig({ toolProfile: 'core' });
      expect(config.toolProfile).toBe('core');
      expect(warn.mock.calls.some((c) => String(c[0]).includes('FRIDA_MCP_TOOL_PROFILE'))).toBe(true);
      warn.mockRestore();
    });

    it('FRIDA_MCP_TOOLS_EXCLUDE is split on commas, trimmed, empties dropped', async () => {
      setEnv('FRIDA_MCP_TOOLS_EXCLUDE', ' adb_* , ,frida_server_*,');
      const config = await freshLoadConfig();
      expect(config.toolsExclude).toEqual(['adb_*', 'frida_server_*']);
    });

    it('CLI overrides for tool profile and exclusions apply when the env is unset', async () => {
      const config = await freshLoadConfig({ toolProfile: 'core', toolsExclude: ['adb_*'] });
      expect(config.toolProfile).toBe('core');
      expect(config.toolsExclude).toEqual(['adb_*']);
    });
  });
});

describe('evidence store config', () => {
  const keys = ['FRIDA_MCP_EVIDENCE', 'FRIDA_MCP_EVIDENCE_PATH', 'FRIDA_MCP_EVIDENCE_MAX_MB'];
  const backup = Object.fromEntries(keys.map((k) => [k, process.env[k]]));

  afterEach(() => {
    for (const k of keys) {
      if (backup[k] === undefined) delete process.env[k];
      else process.env[k] = backup[k];
    }
    vi.resetModules();
  });

  async function load(overrides?: Parameters<typeof import('../src/config.js').loadConfig>[0]) {
    const { loadConfig } = await import('../src/config.js');
    return loadConfig(overrides);
  }

  it('is enabled by default with the documented limits', async () => {
    for (const k of keys) delete process.env[k];
    const config = await load();
    expect(config.evidence).toEqual({ enabled: true, maxMb: 200, maxEntries: 5000, maxEntryKb: 2048 });
  });

  it('merges a partial evidence override with the defaults', async () => {
    for (const k of keys) delete process.env[k];
    const config = await load({ evidence: { maxEntries: 10 } });
    expect(config.evidence).toEqual({ enabled: true, maxMb: 200, maxEntries: 10, maxEntryKb: 2048 });
  });

  it('FRIDA_MCP_EVIDENCE / _PATH / _MAX_MB override the config', async () => {
    process.env.FRIDA_MCP_EVIDENCE = '0';
    process.env.FRIDA_MCP_EVIDENCE_PATH = ' /tmp/ev ';
    process.env.FRIDA_MCP_EVIDENCE_MAX_MB = '12.5';
    const config = await load();
    expect(config.evidence).toMatchObject({ enabled: false, path: '/tmp/ev', maxMb: 12.5 });
  });

  it('ignores an invalid FRIDA_MCP_EVIDENCE_MAX_MB', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    process.env.FRIDA_MCP_EVIDENCE_MAX_MB = '-3';
    const config = await load();
    expect(config.evidence?.maxMb).toBe(200);
    spy.mockRestore();
  });
});

describe('parsePositiveNumber and its env wrappers', () => {
  afterEach(() => vi.restoreAllMocks());

  async function parsers() {
    return await import('../src/config.js');
  }

  it('returns undefined without warning when the value is unset or empty', async () => {
    const warn = vi.spyOn(console, 'error').mockImplementation(() => {});
    const { parsePositiveNumber } = await parsers();
    expect(parsePositiveNumber('X', undefined)).toBeUndefined();
    expect(parsePositiveNumber('X', '')).toBeUndefined();
    expect(warn).not.toHaveBeenCalled();
  });

  it('warns with the env name and returns undefined for non-positive or non-numeric values', async () => {
    const warn = vi.spyOn(console, 'error').mockImplementation(() => {});
    const { parsePositiveNumber } = await parsers();
    expect(parsePositiveNumber('FRIDA_MCP_X', '-3')).toBeUndefined();
    expect(parsePositiveNumber('FRIDA_MCP_X', 'abc')).toBeUndefined();
    expect(parsePositiveNumber('FRIDA_MCP_X', '0', { integer: true })).toBeUndefined();
    expect(warn).toHaveBeenCalledTimes(3);
    expect(warn.mock.calls.every((c) => String(c[0]).includes('FRIDA_MCP_X="'))).toBe(true);
  });

  it('parseMaxResponseChars keeps integer semantics', async () => {
    const warn = vi.spyOn(console, 'error').mockImplementation(() => {});
    const { parseMaxResponseChars } = await parsers();
    expect(parseMaxResponseChars('12000')).toBe(12000);
    expect(parseMaxResponseChars('12.9')).toBe(12);
    expect(parseMaxResponseChars('-1')).toBeUndefined();
    expect(String(warn.mock.calls[0][0])).toContain('FRIDA_MCP_MAX_RESPONSE_CHARS="-1" is not a positive integer');
  });

  it('parseEvidenceMaxMb accepts fractional values', async () => {
    const warn = vi.spyOn(console, 'error').mockImplementation(() => {});
    const { parseEvidenceMaxMb } = await parsers();
    expect(parseEvidenceMaxMb(' 12.5 ')).toBe(12.5);
    expect(parseEvidenceMaxMb('x')).toBeUndefined();
    expect(String(warn.mock.calls[0][0])).toContain('FRIDA_MCP_EVIDENCE_MAX_MB="x" is not a positive number');
  });
});
