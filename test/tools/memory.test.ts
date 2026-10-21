import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { registerMemoryTools } from '../../src/tools/memory.js';
import { initState, getState } from '../../src/state.js';
import { rateLimiter } from '../../src/helpers/rate-limiter.js';
import type { FridaMcpConfig } from '../../src/types.js';
import {
  callJson,
  makeMcpHarness,
  makeScriptingSession,
  seedSession,
  TEST_CONFIG,
  type FakeAgentScript,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

const SESSION_ID = 'mem-sess';

describe('memory MCP tools', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];
  let scripts: FakeAgentScript[];
  let session: ReturnType<typeof makeScriptingSession>['session'];
  // Mutable rpc results so each test picks what the agent "returns".
  let readResult: unknown;
  let writeResult: unknown;
  let scanResult: unknown;

  beforeAll(async () => {
    const made = makeScriptingSession(({ name }) => {
      if (name === 'read_memory:read') return { exports: { read: async () => readResult } };
      if (name === 'write_memory:write') return { exports: { write: async () => writeResult } };
      if (name === 'scan_memory:scan') return { exports: { scan: async () => scanResult } };
      return {};
    });
    session = made.session;
    scripts = made.scripts;
    ({ client, close } = await makeMcpHarness((server) => registerMemoryTools(server)));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
  });

  /** Re-init state (optionally with config overrides) and seed a scripting session. */
  function fresh(over: Partial<FridaMcpConfig> = {}) {
    const state = initState({ ...TEST_CONFIG, ...over });
    rateLimiter.reset();
    scripts.length = 0;
    const entry = seedSession(state, [], { id: SESSION_ID, platform: 'android' });
    (entry as any).session = session;
    readResult = { data: 'deadbeef', address: '0x7fff00001000', rva: 'libfoo.so+0x10' };
    writeResult = { ok: true, address: '0x7fff00001000', reprotected: false, original_protection: 'rw-' };
    scanResult = { results: [{ address: '0x7fff00002000', size: 6 }], errors: [] };
  }

  describe('read_memory', () => {
    it('is a read-only, idempotent tool', async () => {
      fresh();
      const { tools } = await client.listTools();
      const tool = tools.find((t) => t.name === 'read_memory')!;
      expect(tool.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false, idempotentHint: true });
    });

    it('returns the resolved address, rva and hex-decoded length', async () => {
      fresh();
      const parsed = await callJson(client, 'read_memory', { session_id: SESSION_ID, address: '0x7fff00001000', size: 4 });
      expect(parsed.error).toBeUndefined();
      expect(parsed.result).toMatchObject({
        address: '0x7fff00001000',
        rva: 'libfoo.so+0x10',
        target: '0x7fff00001000',
        size: 4,
        data: 'deadbeef',
        data_length: 4,
      });
      expect(scripts.find((s) => s.name === 'read_memory:read')!.unloadCalls).toBe(1);
    });

    it('suggests reading the next chunk at address + size', async () => {
      fresh();
      const parsed = await callJson(client, 'read_memory', { session_id: SESSION_ID, address: '0x7fff00001000', size: 4 });
      const next = parsed.suggested_next.find((s: any) => s.tool === 'read_memory');
      expect(next.args.address).toBe('0x7fff00001004');
    });

    it('returns SESSION_NOT_FOUND for an unknown session', async () => {
      fresh();
      const parsed = await callJson(client, 'read_memory', { session_id: 'nope', address: '0x1000', size: 4 });
      expect(parsed.error.code).toBe('SESSION_NOT_FOUND');
      expect(parsed.error.category).toBe('request');
    });

    it('enforces the per-minute memory read rate limit', async () => {
      fresh();
      for (let i = 0; i < TEST_CONFIG.rateLimits.memoryReadsPerMinute; i++) rateLimiter.record('memory_read');
      const parsed = await callJson(client, 'read_memory', { session_id: SESSION_ID, address: '0x1000', size: 4 });
      expect(parsed.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });

    it('rejects a read larger than the 4MB cap', async () => {
      fresh();
      const parsed = await callJson(client, 'read_memory', { session_id: SESSION_ID, address: '0x1000', size: 5 * 1024 * 1024 });
      expect(parsed.error).toBeDefined();
      expect(parsed.error.message).toMatch(/exceeds maximum/);
    });
  });

  describe('write_memory (memoryWriteEnabled guardrail)', () => {
    it('is a destructive, non-idempotent tool', async () => {
      fresh({ memoryWriteEnabled: true });
      const { tools } = await client.listTools();
      const tool = tools.find((t) => t.name === 'write_memory')!;
      expect(tool.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: true, idempotentHint: false });
    });

    it('refuses with MEMORY_WRITE_DISABLED when the guardrail is off (the default)', async () => {
      fresh({ memoryWriteEnabled: false });
      const parsed = await callJson(client, 'write_memory', { session_id: SESSION_ID, address: '0x1000', data: '90909090' });
      expect(parsed.error.code).toBe('MEMORY_WRITE_DISABLED');
      expect(parsed.error.category).toBe('authorization');
      // Never reaches the agent when disabled.
      expect(scripts.some((s) => s.name === 'write_memory:write')).toBe(false);
    });

    it('writes the bytes and reports the count when the guardrail is on', async () => {
      fresh({ memoryWriteEnabled: true });
      const parsed = await callJson(client, 'write_memory', { session_id: SESSION_ID, address: '0x7fff00001000', data: '90909090' });
      expect(parsed.error).toBeUndefined();
      expect(parsed.result).toMatchObject({
        address: '0x7fff00001000',
        target: '0x7fff00001000',
        bytes_written: 4,
        reprotected: false,
        original_protection: 'rw-',
      });
    });

    it('surfaces MEMORY_PROTECT_FAILED when the agent cannot make the page writable', async () => {
      fresh({ memoryWriteEnabled: true });
      writeResult = { error: 'protect_failed', message: 'Memory.protect(rw-) failed for 0x1000' };
      const parsed = await callJson(client, 'write_memory', { session_id: SESSION_ID, address: '0x1000', data: '90' });
      expect(parsed.error.code).toBe('MEMORY_PROTECT_FAILED');
      expect(parsed.error.message).toMatch(/protect/i);
    });

    it('returns SESSION_NOT_FOUND for an unknown session even when writes are enabled', async () => {
      fresh({ memoryWriteEnabled: true });
      const parsed = await callJson(client, 'write_memory', { session_id: 'nope', address: '0x1000', data: '90' });
      expect(parsed.error.code).toBe('SESSION_NOT_FOUND');
    });
  });

  describe('scan_memory', () => {
    it('returns matches and echoes the scanned scope', async () => {
      fresh();
      const parsed = await callJson(client, 'scan_memory', { session_id: SESSION_ID, pattern: '90 90 ?? 57' });
      expect(parsed.error).toBeUndefined();
      expect(parsed.result).toMatchObject({
        pattern: '90 90 ?? 57',
        module: 'all readable ranges',
        matches: 1,
        truncated: false,
      });
      expect(parsed.result.results).toEqual([{ address: '0x7fff00002000', size: 6 }]);
    });

    it('names the module when scope is limited to one', async () => {
      fresh();
      const parsed = await callJson(client, 'scan_memory', { session_id: SESSION_ID, pattern: '90', module: 'libssl.so' });
      expect(parsed.result.module).toBe('libssl.so');
    });

    it('raises SCAN_ERROR when the agent reports the module is missing', async () => {
      fresh();
      scanResult = { error: 'module_not_found', message: 'Module not found: ghost.so' };
      const parsed = await callJson(client, 'scan_memory', { session_id: SESSION_ID, pattern: '90', module: 'ghost.so' });
      expect(parsed.error.code).toBe('SCAN_ERROR');
      expect(parsed.error.message).toMatch(/ghost\.so/);
    });

    it('returns SESSION_NOT_FOUND for an unknown session', async () => {
      fresh();
      const parsed = await callJson(client, 'scan_memory', { session_id: 'nope', pattern: '90' });
      expect(parsed.error.code).toBe('SESSION_NOT_FOUND');
    });
  });
});
