import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { registerSecretsTool } from '../../src/tools/secrets.js';
import { initState, getState } from '../../src/state.js';
import { rateLimiter } from '../../src/helpers/rate-limiter.js';
import {
  agentOptions,
  callJson,
  makeMcpHarness,
  makeScriptingSetup,
  TEST_CONFIG,
  TARGET,
  type FakeAgentScript,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

describe('find_secrets_in_memory MCP tool', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];
  let scripts: FakeAgentScript[];
  let scanResult: unknown;

  beforeAll(async () => {
    const setup = makeScriptingSetup(({ name }) => {
      if (name.startsWith('find_secrets:')) return { exports: { scan: async () => scanResult } };
      return {};
    });
    scripts = setup.scripts;
    ({ client, close } = await makeMcpHarness((server) => registerSecretsTool(server, setup.deviceManager)));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
  });

  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    rateLimiter.reset();
    scripts.length = 0;
    scanResult = {
      candidates: [
        { type: 'rc4_sbox', address: 'libc.so+0x1234', size: 256, preview_hex: '00010203', note: 'RC4 S-box' },
      ],
      bytes_scanned: 1048576,
      ranges_scanned: 3,
      ranges_unreadable: 1,
      stopped: 'complete',
    };
  });

  it('is a read-only, open-world tool with an output schema', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'find_secrets_in_memory');
    expect(tool).toBeDefined();
    expect(tool!.annotations).toMatchObject({ readOnlyHint: true, openWorldHint: true });
    expect(tool!.outputSchema).toBeDefined();
  });

  it('returns the candidates and points read_memory at the top one', async () => {
    const parsed = await callJson(client, 'find_secrets_in_memory', { target: TARGET });
    expect(parsed.error).toBeUndefined();
    expect(parsed.result.candidate_count).toBe(1);
    expect(parsed.result.candidates[0]).toMatchObject({ type: 'rc4_sbox', address: 'libc.so+0x1234' });
    expect(parsed.result.bytes_scanned).toBe(1048576);
    const next = parsed.suggested_next.find((s: any) => s.tool === 'read_memory');
    expect(next.args).toMatchObject({ address: 'libc.so+0x1234', size: 256 });
  });

  it('defaults to the heap scope and all recognizers, passed as the agent options literal', async () => {
    await callJson(client, 'find_secrets_in_memory', { target: TARGET });
    const opts = agentOptions(scripts.find((s) => s.name.startsWith('find_secrets:'))!.source);
    expect(opts.scope).toBe('heap');
    expect(opts.recognizers).toEqual(['rc4_sbox', 'aes_key_schedule', 'chacha_key', 'salsa_key', 'high_entropy_key', 'pem_der', 'jwt']);
    expect(Array.isArray(opts.aesSbox)).toBe(true);
    expect(opts.aesSbox).toHaveLength(256);
  });

  it('passes a recognizer subset and scope through to the agent', async () => {
    await callJson(client, 'find_secrets_in_memory', { target: TARGET, recognizers: ['rc4_sbox'], scope: 'libfoo.so' });
    const opts = agentOptions(scripts.find((s) => s.name.startsWith('find_secrets:'))!.source);
    expect(opts.recognizers).toEqual(['rc4_sbox']);
    expect(opts.scope).toBe('libfoo.so');
  });

  it('marks coverage unknown and adds a limitation when the scan stops early', async () => {
    scanResult = { candidates: [], bytes_scanned: 999, ranges_scanned: 1, ranges_unreadable: 0, stopped: 'max_bytes' };
    const parsed = await callJson(client, 'find_secrets_in_memory', { target: TARGET });
    expect(parsed.result.stopped).toBe('max_bytes');
    expect(parsed.coverage.status).toBe('unknown');
    expect(parsed.limitations.join(' ')).toMatch(/stopped early/);
    // With no candidates, it suggests widening scope.
    expect(parsed.suggested_next.some((s: any) => s.args?.scope === 'all')).toBe(true);
  });

  it('unloads the scan script', async () => {
    await callJson(client, 'find_secrets_in_memory', { target: TARGET });
    expect(scripts.find((s) => s.name.startsWith('find_secrets:'))!.unloadCalls).toBe(1);
  });

  it('enforces the per-minute memory-read rate limit', async () => {
    for (let i = 0; i < TEST_CONFIG.rateLimits.memoryReadsPerMinute; i++) rateLimiter.record('memory_read');
    const parsed = await callJson(client, 'find_secrets_in_memory', { target: TARGET });
    expect(parsed.error.code).toBe('RATE_LIMIT_EXCEEDED');
  });
});
