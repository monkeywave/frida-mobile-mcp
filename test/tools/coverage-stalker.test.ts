import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import { registerCoverageTool } from '../../src/tools/coverage.js';
import {
  planStalkerCoverage,
  toModuleBlocks,
  stalkerCoverageStatus,
  stalkerLimitations,
  stalkerArmFailureHint,
  stalkerThreadSchema,
  STALKER_COVERAGE_SCRIPT,
  DEFAULT_STALKER_DURATION_SECONDS,
  DEFAULT_STALKER_MAX_BLOCKS,
  recordingWindow,
} from '../../src/tools/coverage-stalker.js';
import { findRemovedApis } from '../../src/agent/lint.js';
import { FridaMcpError } from '../../src/helpers/errors.js';
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

describe('planStalkerCoverage', () => {
  it('requires a module', () => {
    expect(() => planStalkerCoverage({})).toThrow(FridaMcpError);
    expect(() => planStalkerCoverage({ module: '  ' })).toThrow(/module is required/);
  });

  it('applies the defaults: whole module, main thread, default duration and block cap', () => {
    expect(planStalkerCoverage({ module: 'libfoo.so' })).toEqual({
      agentOptions: { moduleName: 'libfoo.so', rangeStart: '0x0', rangeSize: null, thread: 'main', maxBlocks: DEFAULT_STALKER_MAX_BLOCKS },
      durationSeconds: DEFAULT_STALKER_DURATION_SECONDS,
    });
  });

  it('normalises hex and decimal range starts and keeps explicit caps', () => {
    const hex = planStalkerCoverage({ module: 'libfoo.so', offset_range: { start: '0X1A00', size: 256 }, thread: 77, max_blocks: 10, duration_seconds: 3 });
    expect(hex.agentOptions).toMatchObject({ rangeStart: '0x1a00', rangeSize: 256, thread: 77, maxBlocks: 10 });
    expect(hex.durationSeconds).toBe(3);
    expect(planStalkerCoverage({ module: 'libfoo.so', offset_range: { start: 4096, size: 1 } }).agentOptions.rangeStart).toBe('0x1000');
    expect(planStalkerCoverage({ module: 'libfoo.so', thread: 1234 }).agentOptions.thread).toBe(1234);
  });

  it('rejects a malformed range start', () => {
    expect(() => planStalkerCoverage({ module: 'libfoo.so', offset_range: { start: 'zz', size: 1 } })).toThrow(/offset_range.start/);
  });
});

describe('toModuleBlocks', () => {
  it('dedupes, sorts and formats offsets as module+0xoff', () => {
    const { blocks, capHit } = toModuleBlocks('libfoo.so', ['0x20', '0x10', '0x20', '0x3'], 100);
    expect(blocks).toEqual(['libfoo.so+0x3', 'libfoo.so+0x10', 'libfoo.so+0x20']);
    expect(capHit).toBe(false);
  });

  it('caps the block list and flags the cap', () => {
    const { blocks, capHit } = toModuleBlocks('libfoo.so', ['0x1', '0x2', '0x3'], 2);
    expect(blocks).toEqual(['libfoo.so+0x1', 'libfoo.so+0x2']);
    expect(capHit).toBe(true);
  });
});

describe('stalker coverage status and limitations', () => {
  it('is complete only for a full window without the cap', () => {
    expect(stalkerCoverageStatus(true, false)).toBe('complete');
    expect(stalkerCoverageStatus(false, false)).toBe('unknown');
    expect(stalkerCoverageStatus(true, true)).toBe('unknown');
  });

  it('always warns about CPU cost and adds realm / cap / thread notes when relevant', () => {
    const base = stalkerLimitations({ realm: 'native', capHit: false, thread: 4242 });
    expect(base.some((l) => /CPU heavy/.test(l))).toBe(true);
    expect(base.some((l) => /Emulated realm/.test(l))).toBe(false);

    const all = stalkerLimitations({ realm: 'emulated', capHit: true, thread: 'main', agentErrors: ['parse: boom'] });
    expect(all.some((l) => /Emulated realm is not supported for Stalker/.test(l))).toBe(true);
    expect(all.some((l) => /Block cap/.test(l))).toBe(true);
    expect(all.some((l) => /main thread/.test(l))).toBe(true);
    expect(all).toContain('Agent reported: parse: boom');
  });

  it('suggests list_threads when zero blocks were recorded', () => {
    expect(stalkerLimitations({ realm: 'native', capHit: false, thread: 'main', blocksCount: 0 }).some((l) => /list_threads/.test(l))).toBe(true);
    expect(stalkerLimitations({ realm: 'native', capHit: false, thread: 'main', blocksCount: 5 }).some((l) => /0 blocks/.test(l))).toBe(false);
  });

  it('no longer accepts thread all', () => {
    expect(stalkerThreadSchema.safeParse('all').success).toBe(false);
    expect(stalkerThreadSchema.safeParse('main').success).toBe(true);
    expect(stalkerThreadSchema.safeParse(12).success).toBe(true);
  });
});

describe('STALKER_COVERAGE_SCRIPT', () => {
  it('follows with compile events and filters blocks to the module range', () => {
    expect(STALKER_COVERAGE_SCRIPT).toContain('Stalker.follow(');
    expect(STALKER_COVERAGE_SCRIPT).toContain('events: { compile: true }');
    expect(STALKER_COVERAGE_SCRIPT).toContain('Stalker.parse(');
    expect(STALKER_COVERAGE_SCRIPT).toContain('Process.findModuleByName(o.moduleName)');
    expect(STALKER_COVERAGE_SCRIPT).toMatch(/start\.compare\(lo\) < 0 \|\| start\.compare\(hi\) >= 0/);
  });

  it('always unfollows, flushes and garbage-collects, including on unload (dispose)', () => {
    expect(STALKER_COVERAGE_SCRIPT).toContain('Stalker.unfollow(');
    expect(STALKER_COVERAGE_SCRIPT).toContain('Stalker.flush()');
    expect(STALKER_COVERAGE_SCRIPT).toContain('Stalker.garbageCollect()');
    expect(STALKER_COVERAGE_SCRIPT).toMatch(/rpc\.exports\.dispose = function \(\) \{ stopFollowing\(\); \}/);
    expect(STALKER_COVERAGE_SCRIPT).toMatch(/catch \(e\) \{\s*stopFollowing\(\);\s*return \{ error: 'follow_failed/);
  });

  it('is free of removed Frida APIs', () => {
    expect(findRemovedApis(STALKER_COVERAGE_SCRIPT)).toEqual([]);
  });
});

describe('trace_coverage engine=stalker (MCP tool)', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];
  let scripts: FakeAgentScript[];
  let startResult: unknown;
  let stopResult: unknown;
  let emitCapOnStart: boolean;
  let startDelayMs: number;

  beforeAll(async () => {
    const setup = makeScriptingSetup(({ name }) => {
      if (name.startsWith('coverage:stalker:')) {
        return {
          exports: {
            start: async () => {
              if (startDelayMs > 0) await new Promise((r) => setTimeout(r, startDelayMs));
              if (emitCapOnStart) scripts[scripts.length - 1].emit({ type: 'send', payload: { stalker_cap: true } }, null);
              return startResult;
            },
            stop: async () => stopResult,
          },
        };
      }
      if (name.startsWith('coverage:')) return { exports: { arm: async () => ({ targets: ['x'], attempted: 1, installed: 1, skipped: 0 }) } };
      return {};
    });
    scripts = setup.scripts;
    ({ client, close } = await makeMcpHarness((server) => registerCoverageTool(server, setup.deviceManager)));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
  });

  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    rateLimiter.reset();
    scripts.length = 0;
    emitCapOnStart = false;
    startDelayMs = 0;
    startResult = { module: 'libfoo.so', base: '0x7000', range_start: '0x0', range_size: 4096, threads: [4242] };
    stopResult = { offsets: ['0x40', '0x10', '0x40'], cap_hit: false, errors: [] };
  });

  it('defaults to the hooks engine (unchanged path)', async () => {
    const parsed = await callJson(client, 'trace_coverage', { target: TARGET, scope: 'com.example.Crypto' });
    expect(parsed.result.kind).toBe('java');
    expect(scripts.some((s) => s.name!.startsWith('coverage:stalker:'))).toBe(false);
  });

  it('requires module for engine=stalker before touching the target', async () => {
    const parsed = await callJson(client, 'trace_coverage', { target: TARGET, engine: 'stalker' });
    expect(parsed.error.code).toBe('INVALID_ARGUMENT');
    expect(scripts).toHaveLength(0);
  });

  it('records a window and returns deduped module+0xoffset blocks with complete coverage', async () => {
    const parsed = await callJson(client, 'trace_coverage', { target: TARGET, engine: 'stalker', module: 'libfoo.so', duration_seconds: 0.01 });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result).toMatchObject({ engine: 'stalker', module: 'libfoo.so', blocks_count: 2, cap_hit: false, window_completed: true, threads: [4242] });
    expect(parsed.result.blocks).toEqual(['libfoo.so+0x10', 'libfoo.so+0x40']);
    expect(parsed.coverage.status).toBe('complete');
    expect(parsed.limitations.some((l: string) => /CPU heavy/.test(l))).toBe(true);

    const script = scripts.find((s) => s.name!.startsWith('coverage:stalker:'))!;
    expect(agentOptions(script.source)).toMatchObject({ moduleName: 'libfoo.so', thread: 'main', maxBlocks: DEFAULT_STALKER_MAX_BLOCKS });
    expect(script.unloadCalls).toBe(1);
  });

  it('stops early on the block cap and reports unknown coverage', async () => {
    emitCapOnStart = true;
    stopResult = { offsets: ['0x1', '0x2'], cap_hit: true, errors: [] };

    const parsed = await callJson(client, 'trace_coverage', { target: TARGET, engine: 'stalker', module: 'libfoo.so', max_blocks: 2, duration_seconds: 60 });

    expect(parsed.result).toMatchObject({ cap_hit: true, window_completed: false, blocks_count: 2 });
    expect(parsed.coverage.status).toBe('unknown');
    expect(parsed.limitations.some((l: string) => /Block cap/.test(l))).toBe(true);
  });

  it('surfaces a start failure and still unloads the script', async () => {
    startResult = { error: 'module_not_found: libnope.so' };

    const parsed = await callJson(client, 'trace_coverage', { target: TARGET, engine: 'stalker', module: 'libnope.so', duration_seconds: 0.01 });

    expect(parsed.error.code).toBe('COVERAGE_ARM_FAILED');
    const script = scripts.find((s) => s.name!.startsWith('coverage:stalker:'))!;
    expect(script.unloadCalls).toBe(1);
    for (const session of getState().sessions.values()) expect(session.scripts.size).toBe(0);
  });

  it('points a thread_not_found start failure at list_threads, not enumerate_modules', async () => {
    startResult = { error: 'thread_not_found: 4242' };

    const parsed = await callJson(client, 'trace_coverage', { target: TARGET, engine: 'stalker', module: 'libfoo.so', thread: 4242, duration_seconds: 0.01 });

    expect(parsed.error.code).toBe('COVERAGE_ARM_FAILED');
    const tools = JSON.stringify(parsed.error);
    expect(tools).toContain('list_threads');
    expect(tools).not.toContain('enumerate_modules');
  });

  it('starts the recording window only after the agent start succeeded', async () => {
    startDelayMs = 120;
    const began = Date.now();

    const parsed = await callJson(client, 'trace_coverage', { target: TARGET, engine: 'stalker', module: 'libfoo.so', duration_seconds: 0.12 });

    expect(parsed.result.window_completed).toBe(true);
    // Arming time is not deducted from the window: start delay + full window both elapsed.
    expect(Date.now() - began).toBeGreaterThanOrEqual(230);
  });

  it('rejects an unknown engine', async () => {
    const result = await client.callTool({ name: 'trace_coverage', arguments: { target: TARGET, engine: 'pin' } });
    expect(result.isError).toBe(true);
  });
});

describe('stalkerArmFailureHint', () => {
  it('suggests list_threads for a missing thread', () => {
    expect(stalkerArmFailureHint('thread_not_found: 77', 's1')).toMatchObject({ tool: 'list_threads', args: { session_id: 's1' } });
  });
  it('keeps enumerate_modules for module and range failures', () => {
    expect(stalkerArmFailureHint('module_not_found: libnope.so', 's1').tool).toBe('enumerate_modules');
    expect(stalkerArmFailureHint('follow_failed: boom', 's1').tool).toBe('enumerate_modules');
  });
});

describe('recordingWindow', () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it('does not run the timer until start() is called', async () => {
    const window = recordingWindow(1000);
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(5000);
    let resolved = false;
    void window.done.then(() => { resolved = true; });
    await vi.advanceTimersByTimeAsync(0);
    expect(resolved).toBe(false);

    window.start();
    expect(vi.getTimerCount()).toBe(1);
    await vi.advanceTimersByTimeAsync(999);
    expect(resolved).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await expect(window.done).resolves.toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('stopEarly resolves false and clears the timer; a later start() is a no-op', async () => {
    const window = recordingWindow(1000);
    window.start();
    window.stopEarly();
    expect(vi.getTimerCount()).toBe(0);
    await expect(window.done).resolves.toBe(false);
    window.start();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('cancel clears a pending timer on failure paths', () => {
    const window = recordingWindow(1000);
    window.cancel();
    expect(vi.getTimerCount()).toBe(0);
    window.start();
    expect(vi.getTimerCount()).toBe(1);
    window.cancel();
    expect(vi.getTimerCount()).toBe(0);
  });
});
