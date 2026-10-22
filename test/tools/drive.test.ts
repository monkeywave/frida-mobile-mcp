import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';

// drive_coverage taps the UI through mobile-mcp, reached via a dynamic `import('../mobile-mcp/call.js')`.
// Mock that module: `listQueue` scripts what each list call returns; `tapQueue` holds the side effect
// (e.g. emit a crypto_event) each tap should cause. vi.hoisted lets the vi.mock factory close over them.
const { callMobileAction, listQueue, tapQueue } = vi.hoisted(() => {
  const listQueue: unknown[] = [];
  const tapQueue: Array<() => void> = [];
  const callMobileAction = vi.fn(async (action: string) => {
    if (action === 'mobile_list_elements_on_screen') {
      return listQueue.length > 0 ? listQueue.shift() : { content: [{ type: 'text', text: '[]' }] };
    }
    if (action === 'mobile_click_on_screen_at_coordinates') {
      const effect = tapQueue.shift();
      if (effect) effect();
      return { ok: true };
    }
    return { ok: true };
  });
  return { callMobileAction, listQueue, tapQueue };
});
vi.mock('../../src/mobile-mcp/call.js', () => ({ callMobileAction }));

import { registerDriveTool } from '../../src/tools/drive.js';
import { initState, getState } from '../../src/state.js';
import type { CoverageEntry } from '../../src/types.js';
import {
  callJson,
  fakeScript,
  makeMcpHarness,
  makeDeviceManager,
  makeDevice,
  scriptEntry,
  seedSession,
  DEFAULT_SESSION_ID,
  TEST_CONFIG,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

const SCRIPT = 'monitor-script';

/** An on-screen element list, as mobile-mcp returns it (JSON array in an MCP text block). */
function screen(...els: Array<{ label: string; x: number; y: number }>): unknown {
  const elements = els.map((e) => ({
    type: 'Button',
    text: e.label,
    clickable: true,
    rect: { x: e.x - 10, y: e.y - 10, width: 20, height: 20 },
  }));
  return { content: [{ type: 'text', text: JSON.stringify(elements) }] };
}

/** Add a message to SCRIPT, as a hook send would. */
function emit(type: string, payload: unknown): void {
  getState().addMessageToScript(DEFAULT_SESSION_ID, SCRIPT, { timestamp: Date.now(), type, payload, data: null });
}

function seedCoverage(sessionId: string, allTargets: string[]): CoverageEntry {
  const entry: CoverageEntry = {
    id: 'cov-1',
    scriptId: SCRIPT,
    sessionId,
    scope: 'com.example.*',
    allTargets,
    hits: new Map(),
    createdAt: Date.now(),
  };
  getState().coverage.set(entry.id, entry);
  return entry;
}

describe('drive_coverage', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];

  beforeAll(async () => {
    const deviceManager = makeDeviceManager(makeDevice());
    ({ client, close } = await makeMcpHarness((server) => registerDriveTool(server, deviceManager)));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
  });

  beforeEach(() => {
    initState({ ...TEST_CONFIG, mobileMcp: { enabled: true, command: '', args: [] } });
    callMobileAction.mockClear();
    listQueue.length = 0;
    tapQueue.length = 0;
    seedSession(getState(), [scriptEntry(SCRIPT, fakeScript())]);
  });

  it('is registered as a non-readonly, open-world tool with an output schema', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'drive_coverage');
    expect(tool).toBeDefined();
    expect(tool!.annotations).toMatchObject({ readOnlyHint: false, openWorldHint: true });
    expect(tool!.outputSchema).toBeDefined();
  });

  it('taps an element and stops with `captured` set when a crypto_event fires', async () => {
    listQueue.push(screen({ label: 'Encrypt', x: 100, y: 200 }));
    tapQueue.push(() => emit('crypto_event', { algorithm: 'RC4', key_hex: 'deadbeef' }));

    const parsed = await callJson(client, 'drive_coverage', { session_id: DEFAULT_SESSION_ID });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result.stopped_reason).toBe('captured');
    expect(parsed.result.captured).toMatchObject({ type: 'crypto_event', payload: { key_hex: 'deadbeef' } });
    expect(parsed.result.steps_taken).toBe(1);
    expect(parsed.result.steps[0].tapped).toMatchObject({ label: 'Encrypt', x: 100, y: 200 });
    // It tapped the element center and injected the session's device.
    expect(callMobileAction).toHaveBeenCalledWith('mobile_click_on_screen_at_coordinates', { x: 100, y: 200 }, 'emulator-5554');
  });

  it('matches a custom stop_on substring in the message payload', async () => {
    listQueue.push(screen({ label: 'Go', x: 50, y: 50 }));
    tapQueue.push(() => emit('hook_invocation', { note: 'reached SecretVault.unlock' }));

    const parsed = await callJson(client, 'drive_coverage', { session_id: DEFAULT_SESSION_ID, stop_on: 'SecretVault' });
    expect(parsed.result.stopped_reason).toBe('captured');
    expect(parsed.result.captured.type).toBe('hook_invocation');
  });

  it('stops at max_steps when no signal ever fires', async () => {
    for (let i = 0; i < 10; i++) {
      listQueue.push(screen({ label: `Btn${i}`, x: 10 + i, y: 20 + i }, { label: `Alt${i}`, x: 300 + i, y: 400 + i }));
    }
    const parsed = await callJson(client, 'drive_coverage', { session_id: DEFAULT_SESSION_ID, max_steps: 3, step_timeout_ms: 20 });

    expect(parsed.result.stopped_reason).toBe('max_steps');
    expect(parsed.result.steps_taken).toBe(3);
    expect(parsed.result.captured).toBeNull();
    // When nothing fired, steer toward the memory-based fallback (find_secrets then leads to
    // generate_memory_pattern with a concrete address, so we don't suggest it here with no args).
    expect(parsed.suggested_next.map((s: any) => s.tool)).toEqual(
      expect.arrayContaining(['get_messages', 'find_secrets_in_memory']),
    );
    expect(parsed.suggested_next.map((s: any) => s.tool)).not.toContain('generate_memory_pattern');
  });

  it('stops with no_more_elements once every element has been tried', async () => {
    for (let i = 0; i < 5; i++) listQueue.push(screen({ label: 'Only', x: 100, y: 100 }));
    const parsed = await callJson(client, 'drive_coverage', { session_id: DEFAULT_SESSION_ID, max_steps: 5, step_timeout_ms: 20 });

    expect(parsed.result.stopped_reason).toBe('no_more_elements');
    expect(parsed.result.steps_taken).toBe(1);
  });

  it('reports the newly-covered delta when a coverage_id is supplied', async () => {
    const entry = seedCoverage(DEFAULT_SESSION_ID, ['com.example.A.a', 'com.example.B.b']);
    listQueue.push(screen({ label: 'Trigger', x: 100, y: 200 }));
    tapQueue.push(() => {
      entry.hits.set('com.example.A.a', { hits: 1, firstSeenTs: Date.now() });
      emit('crypto_event', { key_hex: 'ab' });
    });

    const parsed = await callJson(client, 'drive_coverage', { session_id: DEFAULT_SESSION_ID, coverage_id: 'cov-1' });
    expect(parsed.result.stopped_reason).toBe('captured');
    expect(parsed.result.newly_covered).toEqual(['com.example.A.a']);
    expect(parsed.result.steps[0].newly_covered_this_step).toBe(1);
  });

  it('stops with coverage_stalled after 3 taps with no new coverage', async () => {
    seedCoverage(DEFAULT_SESSION_ID, ['com.example.A.a']);
    for (let i = 0; i < 10; i++) listQueue.push(screen({ label: `B${i}`, x: 10 + i, y: 20 + i }));
    const parsed = await callJson(client, 'drive_coverage', { session_id: DEFAULT_SESSION_ID, coverage_id: 'cov-1', max_steps: 8, step_timeout_ms: 20 });

    expect(parsed.result.stopped_reason).toBe('coverage_stalled');
    expect(parsed.result.steps_taken).toBe(3);
  });

  it('errors cleanly when mobile-mcp is disabled', async () => {
    initState({ ...TEST_CONFIG, mobileMcp: { enabled: false, command: '', args: [] } });
    seedSession(getState(), [scriptEntry(SCRIPT, fakeScript())]);
    const parsed = await callJson(client, 'drive_coverage', { session_id: DEFAULT_SESSION_ID });
    expect(parsed.error.code).toBe('MOBILE_ERROR');
  });

  it('errors when the session does not exist', async () => {
    const parsed = await callJson(client, 'drive_coverage', { session_id: 'nope' });
    expect(parsed.error.code).toBe('SESSION_NOT_FOUND');
  });
});
