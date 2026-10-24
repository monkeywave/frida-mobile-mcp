import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('frida', () => ({
  default: {
    getDeviceManager: () => ({}),
    Cancellable: { withTimeout: vi.fn(() => ({ isCancelled: false })) },
  },
}));

// The module-enumeration tools compose a native agent script and run its `run`
// export once. There is no device under test, so we replace createAgentScript
// with a fake script whose `run` export returns whatever the agent would have.
const hoisted = vi.hoisted(() => ({
  runResult: { value: undefined as unknown },
  createAgentScript: undefined as unknown,
}));

vi.mock('../../src/agent/script-factory.js', () => {
  const createAgentScript = vi.fn(async () => ({
    load: vi.fn().mockResolvedValue(undefined),
    exports: { run: vi.fn(async () => hoisted.runResult.value) },
    unload: vi.fn().mockResolvedValue(undefined),
  }));
  hoisted.createAgentScript = createAgentScript;
  return { createAgentScript };
});

import { registerAdvancedModuleTools } from '../../src/tools/advanced/modules.js';
import { initState, getState } from '../../src/state.js';
import { seedSession, makeMcpHarness, callJson, TEST_CONFIG, DEFAULT_SESSION_ID, type McpHarness } from '../helpers/mock-fixtures.js';

const MODULES = [
  { name: 'libssl.so', base: '0x1000', end: '0x2000', size: 0x1000, path: '/system/lib/libssl.so' },
  { name: 'libc.so', base: '0x3000', end: '0x4000', size: 0x1000, path: '/system/lib/libc.so' },
];

function page<T>(items: T[], total = items.length, offset = 0, limit = 200) {
  return { total, offset, limit, items };
}

describe('advanced module tools', () => {
  let harness: McpHarness;

  beforeEach(async () => {
    initState({ ...TEST_CONFIG });
    hoisted.runResult.value = undefined;
    (hoisted.createAgentScript as any).mockClear();
    harness = await makeMcpHarness((server) => registerAdvancedModuleTools(server));
  });

  afterEach(async () => {
    await harness.close();
    getState().stopCleanupTimer();
    vi.restoreAllMocks();
  });

  function seed(platform = 'android') {
    seedSession(getState(), [], { platform });
  }

  describe('enumerate_modules', () => {
    it('returns every module when no filter is given', async () => {
      seed();
      hoisted.runResult.value = MODULES;

      const body = await callJson(harness.client, 'enumerate_modules', { session_id: DEFAULT_SESSION_ID });

      expect(body.result.module_count).toBe(2);
      expect(body.result.modules).toEqual(MODULES);
      expect(body.coverage.status).toBe('complete');
    });

    it('filters modules host-side by a case-insensitive regex', async () => {
      seed();
      hoisted.runResult.value = MODULES;

      const body = await callJson(harness.client, 'enumerate_modules', { session_id: DEFAULT_SESSION_ID, filter: 'LIBSSL' });

      expect(body.result.module_count).toBe(1);
      expect(body.result.modules[0].name).toBe('libssl.so');
      expect(body.result.filter).toBe('LIBSSL');
    });

    it('rejects an invalid filter regex with INVALID_FILTER', async () => {
      seed();

      const body = await callJson(harness.client, 'enumerate_modules', { session_id: DEFAULT_SESSION_ID, filter: '(' });

      expect(body.error.code).toBe('INVALID_FILTER');
      expect(hoisted.createAgentScript).not.toHaveBeenCalled();
    });

    it('errors with SESSION_NOT_FOUND for an unknown session', async () => {
      const body = await callJson(harness.client, 'enumerate_modules', { session_id: 'nope' });

      expect(body.error.code).toBe('SESSION_NOT_FOUND');
    });
  });

  describe('enumerate_exports', () => {
    it('returns a page of exports with pagination metadata', async () => {
      seed();
      hoisted.runResult.value = page(
        [{ type: 'function', name: 'SSL_read', address: '0x1100' }],
        5, 0, 200,
      );

      const body = await callJson(harness.client, 'enumerate_exports', { session_id: DEFAULT_SESSION_ID, module_name: 'libssl.so' });

      expect(body.result.module).toBe('libssl.so');
      expect(body.result.export_count).toBe(5);
      expect(body.result.exports).toHaveLength(1);
      expect(body.result.truncated).toBe(true);
      expect(body.suggested_next.map((a: any) => a.tool)).toContain('hook_method');
    });

    it('translates an agent module_not_found into MODULE_NOT_FOUND', async () => {
      seed();
      hoisted.runResult.value = { error: 'module_not_found', message: 'Module not found: ghost.so' };

      const body = await callJson(harness.client, 'enumerate_exports', { session_id: DEFAULT_SESSION_ID, module_name: 'ghost.so' });

      expect(body.error.code).toBe('MODULE_NOT_FOUND');
      expect(body.error.context.module).toBe('ghost.so');
    });
  });

  describe('enumerate_imports', () => {
    it('returns imports and suggests the providing module', async () => {
      seed();
      hoisted.runResult.value = page([{ name: 'memcpy', module: 'libc.so', address: '0x3100' }], 1);

      const body = await callJson(harness.client, 'enumerate_imports', { session_id: DEFAULT_SESSION_ID, module_name: 'libssl.so' });

      expect(body.result.import_count).toBe(1);
      expect(body.result.imports[0].name).toBe('memcpy');
      expect(body.result.truncated).toBe(false);
      const hook = body.suggested_next.find((a: any) => a.tool === 'hook_method');
      expect(hook.args.method).toBe('libc.so!memcpy');
    });
  });

  describe('enumerate_symbols', () => {
    it('returns symbols on a supported platform', async () => {
      seed('android');
      hoisted.runResult.value = page([{ name: 'SSL_new', type: 'function', isGlobal: true, address: '0x1200' }], 1);

      const body = await callJson(harness.client, 'enumerate_symbols', { session_id: DEFAULT_SESSION_ID, module_name: 'libssl.so' });

      expect(body.result.symbol_count).toBe(1);
      expect(body.result.symbols[0].name).toBe('SSL_new');
    });

    it('rejects an unsupported platform with SYMBOLS_UNSUPPORTED', async () => {
      seed('windows');

      const body = await callJson(harness.client, 'enumerate_symbols', { session_id: DEFAULT_SESSION_ID, module_name: 'foo.dll' });

      expect(body.error.code).toBe('SYMBOLS_UNSUPPORTED');
      expect(hoisted.createAgentScript).not.toHaveBeenCalled();
    });

    it('rejects an invalid filter regex before running the agent', async () => {
      seed('android');

      const body = await callJson(harness.client, 'enumerate_symbols', { session_id: DEFAULT_SESSION_ID, module_name: 'libssl.so', filter: '(' });

      expect(body.error.code).toBe('INVALID_FILTER');
      expect(hoisted.createAgentScript).not.toHaveBeenCalled();
    });
  });
  describe('coverage', () => {
    const SSL_READ = { type: 'function', name: 'SSL_read', address: '0x1100' };
    const SSL_WRITE = { type: 'function', name: 'SSL_write', address: '0x1200' };

    const SSL_NEW = { name: 'SSL_new', type: 'function', isGlobal: true, address: '0x1200' };
    const partial = (scope: string, next_offset: number) => ({ status: 'partial', scope, next_offset, truncated: true });
    const complete = (scope: string) => ({ status: 'complete', scope });

    it.each([
      ['enumerate_modules: complete', MODULES, 'enumerate_modules', {}, complete('loaded modules')],
      ['enumerate_exports: partial while short of the total', page([SSL_READ, SSL_WRITE], 5, 1, 2),
        'enumerate_exports', { module_name: 'libssl.so', offset: 1, limit: 2 }, partial('module libssl.so exports', 3)],
      ['enumerate_exports: complete on the last page', page([SSL_READ, SSL_WRITE], 5, 3, 2),
        'enumerate_exports', { module_name: 'libssl.so', offset: 3, limit: 2 }, complete('module libssl.so exports')],
      ['enumerate_imports: partial while more remain', page([{ name: 'memcpy', module: 'libc.so', address: '0x3100' }], 3, 0, 1),
        'enumerate_imports', { module_name: 'libssl.so', limit: 1 }, partial('module libssl.so imports', 1)],
      ['enumerate_symbols: filter-scoped, complete on the last page', page([SSL_NEW], 1),
        'enumerate_symbols', { module_name: 'libssl.so', filter: 'SSL_' }, complete('module libssl.so symbols matching SSL_')],
      ['enumerate_symbols: partial while more remain', page([SSL_NEW], 4, 2, 1),
        'enumerate_symbols', { module_name: 'libssl.so', offset: 2, limit: 1 }, partial('module libssl.so symbols', 3)],
    ] as const)('%s', async (_label, agentResult, tool, args, coverage) => {
      seed();
      hoisted.runResult.value = agentResult;

      const body = await callJson(harness.client, tool, { session_id: DEFAULT_SESSION_ID, ...args });

      expect(body.coverage).toEqual(coverage);
    });
  });
});
