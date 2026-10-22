import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { registerPatternTool } from '../../src/tools/pattern.js';
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

const SIGMA = Uint8Array.from(Buffer.from('expand 32-byte k', 'latin1'));

function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => ('0' + b.toString(16)).slice(-2))
    .join('');
}
function spaced(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => ('0' + b.toString(16)).slice(-2))
    .join(' ');
}

// A ChaCha window: sigma constant (16) + key (32) + trailing context (16), as hex with no spaces.
const KEY = Uint8Array.from({ length: 32 }, (_, i) => (0x40 + i) & 0xff);
const WINDOW_HEX = hex(SIGMA) + hex(KEY) + hex(new Uint8Array(16));

describe('generate_memory_pattern MCP tool', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];
  let scripts: FakeAgentScript[];
  let windowResult: unknown;

  beforeAll(async () => {
    const setup = makeScriptingSetup(({ name }) => {
      if (name.startsWith('generate_memory_pattern:')) return { exports: { readWindow: async () => windowResult } };
      return {};
    });
    scripts = setup.scripts;
    ({ client, close } = await makeMcpHarness((server) => registerPatternTool(server, setup.deviceManager)));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
  });

  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    rateLimiter.reset();
    scripts.length = 0;
    windowResult = {
      data: WINDOW_HEX,
      window_start: '0x1000',
      secret_offset: 16,
      address: '0x1010',
      rva: 'libfoo.so+0x1010',
      module: 'libfoo.so',
      module_offset: '0x1010',
    };
  });

  it('is a read-only, open-world tool with an output schema', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'generate_memory_pattern');
    expect(tool).toBeDefined();
    expect(tool!.annotations).toMatchObject({ readOnlyHint: true, openWorldHint: true });
    expect(tool!.outputSchema).toBeDefined();
  });

  it('builds a chacha anchor descriptor from the read window', async () => {
    const parsed = await callJson(client, 'generate_memory_pattern', { target: TARGET, address: 'libfoo.so+0x1010', size: 32, type: 'chacha_key' });
    expect(parsed.error).toBeUndefined();
    expect(parsed.result.offset_to_key).toBe(16);
    expect(parsed.result.key_len).toBe(32);
    expect(parsed.result.anchor.pattern).toBe(spaced(SIGMA));
    expect(parsed.result.scan_memory_pattern).toBe(spaced(SIGMA));
    expect(parsed.result.confidence).toBe('high');
    expect(parsed.result.secret.address).toBe('libfoo.so+0x1010');
    expect(parsed.result.fritap.offsets_entry).toEqual({ 'libfoo.so': { CHACHA_KEY: { address: '0x1010', absolute: false } } });
  });

  it('suggests scan_memory with the pattern and capture_tls with the offsets', async () => {
    const parsed = await callJson(client, 'generate_memory_pattern', { target: TARGET, address: 'libfoo.so+0x1010', size: 32, type: 'chacha_key' });
    const scan = parsed.suggested_next.find((s: any) => s.tool === 'scan_memory');
    expect(scan.args).toMatchObject({ pattern: parsed.result.scan_memory_pattern });
    const capture = parsed.suggested_next.find((s: any) => s.tool === 'capture_tls');
    expect(capture.args.offsets).toEqual(parsed.result.fritap.offsets_entry);
  });

  it('passes the target, size and default context_bytes to the agent options literal', async () => {
    await callJson(client, 'generate_memory_pattern', { target: TARGET, address: 'libfoo.so+0x1010', size: 32 });
    const opts = agentOptions(scripts.find((s) => s.name.startsWith('generate_memory_pattern:'))!.source);
    expect(opts.size).toBe(32);
    expect(opts.contextBytes).toBe(64);
    expect(opts.target).toMatchObject({ kind: 'offset', module: 'libfoo.so', offset: '0x1010' });
  });

  it('unloads the window-read script', async () => {
    await callJson(client, 'generate_memory_pattern', { target: TARGET, address: 'libfoo.so+0x1010', size: 32 });
    expect(scripts.find((s) => s.name.startsWith('generate_memory_pattern:'))!.unloadCalls).toBe(1);
  });

  it('enforces the per-minute memory-read rate limit', async () => {
    for (let i = 0; i < TEST_CONFIG.rateLimits.memoryReadsPerMinute; i++) rateLimiter.record('memory_read');
    const parsed = await callJson(client, 'generate_memory_pattern', { target: TARGET, address: 'libfoo.so+0x1010', size: 32 });
    expect(parsed.error.code).toBe('RATE_LIMIT_EXCEEDED');
  });
});
