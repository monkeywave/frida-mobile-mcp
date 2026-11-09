import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest';
import { buildCaptureResult, getActiveFritapCaptures, takeFinalFritapStats, trackCapture, unloadScriptForTeardown, type CaptureTlsArgs } from '../../src/fritap/tool.js';
import { FritapCapture } from '../../src/fritap/capture.js';
import { FRITAP_JAVA_BRIDGE_PATCH_WARNING, type LocatedFritapAgent } from '../../src/fritap/agent-loader.js';
import { getState, initState } from '../../src/state.js';
import { fakeScript, scriptEntry, seedSession, TEST_CONFIG } from '../helpers/mock-fixtures.js';

const ARGS: CaptureTlsArgs = { target: 'com.example.app', spawn: true, anti_root: false, full_capture: true, duration_seconds: 0, allow_download: false, keylog_path: '/tmp/k.log' };

function agent(overrides: Partial<LocatedFritapAgent> = {}): LocatedFritapAgent {
  return { path: '/x/_ssl_log.js', source: '', version: '2.0.0', origin: 'env', ...overrides };
}

describe('capture_tls result: agent-loader warnings', () => {
  beforeAll(() => initState({ ...TEST_CONFIG }));
  afterAll(() => getState().stopCleanupTimer());

  it('surfaces loader warnings in limitations and warnings, with the patch status', () => {
    const session = seedSession(getState(), []);
    const result = buildCaptureResult(session, 's1', agent({ javaBridgePatch: 'pattern-not-found', warnings: [FRITAP_JAVA_BRIDGE_PATCH_WARNING] }), 4, new FritapCapture({}), [], ARGS, true);
    expect(result.limitations).toContain(FRITAP_JAVA_BRIDGE_PATCH_WARNING);
    expect((result.result as any).warnings).toEqual([FRITAP_JAVA_BRIDGE_PATCH_WARNING]);
    expect((result.result as any).java_bridge_patch).toBe('pattern-not-found');
    expect((result.result as any).stats_note).toMatch(/fritap_captures/);
  });

  it('reports no warnings and a null patch status for a raw agent', () => {
    const session = seedSession(getState(), []);
    const result = buildCaptureResult(session, 's1', agent(), 4, new FritapCapture({}), [], ARGS, true);
    expect((result.result as any).warnings).toEqual([]);
    expect((result.result as any).java_bridge_patch).toBeNull();
    expect(result.limitations).not.toContain(FRITAP_JAVA_BRIDGE_PATCH_WARNING);
  });
});

describe('friTap final stats', () => {
  beforeAll(() => initState({ ...TEST_CONFIG }));
  afterAll(() => getState().stopCleanupTimer());
  afterEach(() => vi.useRealTimers());

  it('records the final stats when duration_seconds expires; taken once', async () => {
    vi.useFakeTimers();
    const script = fakeScript();
    seedSession(getState(), [scriptEntry('dur-1', script, 'fritap')], { id: 'sess-dur' });
    const capture = new FritapCapture({});
    trackCapture('sess-dur', 'dur-1', script as any, capture, 2);
    capture.stats.per_library.boringssl = { read: 1, write: 0, bytes: 7 } as any;

    await vi.advanceTimersByTimeAsync(2_100);

    expect(getActiveFritapCaptures().has('dur-1')).toBe(false);
    expect(script.unloadCalls).toBe(1);
    const final = takeFinalFritapStats('sess-dur');
    expect(final).toHaveLength(1);
    expect(final[0].stats.per_library.boringssl).toEqual({ read: 1, write: 0, bytes: 7 });
    expect(takeFinalFritapStats('sess-dur')).toEqual([]);
  });

  it('snapshots the stats (later mutation does not change the final record)', async () => {
    const script = fakeScript();
    const entry = scriptEntry('snap-1', script, 'fritap');
    seedSession(getState(), [entry], { id: 'sess-snap' });
    const capture = new FritapCapture({});
    trackCapture('sess-snap', 'snap-1', script as any, capture, 0);
    capture.stats.records = 1;
    await unloadScriptForTeardown(entry);
    capture.stats.records = 99;
    expect(takeFinalFritapStats('sess-snap', ['snap-1'])[0].stats.records).toBe(1);
  });

  it('unloadScriptForTeardown just unloads non-friTap scripts', async () => {
    const script = fakeScript();
    await unloadScriptForTeardown(scriptEntry('plain', script));
    expect(script.unloadCalls).toBe(1);
  });
});
