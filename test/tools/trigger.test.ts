import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';

const { callMobileAction } = vi.hoisted(() => ({ callMobileAction: vi.fn() }));
vi.mock('../../src/mobile-mcp/call.js', () => ({ callMobileAction }));

import { registerTriggerTool } from '../../src/tools/trigger.js';
import { initState, getState } from '../../src/state.js';
import { loadConfig } from '../../src/config.js';
import {
  callJson,
  fakeScript,
  makeMcpHarness,
  scriptEntry,
  seedSession,
  seedHook,
  DEFAULT_SESSION_ID,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

const SCRIPT = 'hook-script';
const HOOK = 'hook-1';

/** A message on SCRIPT, as a hook send would produce. */
function emit(payload: unknown): void {
  getState().addMessageToScript(DEFAULT_SESSION_ID, SCRIPT, { timestamp: Date.now(), type: 'hook_invocation', payload, data: null });
}

describe('trigger_and_wait fired_hooks (no mobile action)', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];

  beforeAll(async () => {
    initState(loadConfig({ mobileMcp: { enabled: false } } as any));
    ({ client, close } = await makeMcpHarness((server) => registerTriggerTool(server)));
  });
  afterAll(async () => { await close(); getState().stopCleanupTimer(); });

  beforeEach(() => {
    const state = getState();
    state.sessions.clear();
    state.hooks.clear();
    seedSession(state, [scriptEntry(SCRIPT, fakeScript())]);
    seedHook(state, HOOK, SCRIPT); // hook whose scriptId === SCRIPT
  });

  it('reports a hook as fired whenever its script emits in the trigger window — including repeat triggers', async () => {
    // First trigger: deliver a message shortly after the wait starts.
    setTimeout(() => emit({ n: 1 }), 10);
    const first = await callJson(client, 'trigger_and_wait', { session_id: DEFAULT_SESSION_ID, expect_messages: 1, timeout_ms: 1500 });
    expect(first.result.reached).toBe(true);
    expect(first.result.fired_hooks.map((h: any) => h.id)).toContain(HOOK);

    // Second trigger: the hook already fired once (firstSeenTs is in the past). The delta-based
    // logic must STILL report it as fired for this new trigger — the regression code-review caught.
    setTimeout(() => emit({ n: 2 }), 10);
    const second = await callJson(client, 'trigger_and_wait', { session_id: DEFAULT_SESSION_ID, expect_messages: 1, timeout_ms: 1500 });
    expect(second.result.reached).toBe(true);
    expect(second.result.fired_hooks.map((h: any) => h.id)).toContain(HOOK);
    expect(second.result.new_message_count).toBe(1); // only the message from THIS trigger window
  });

  it('times out with no fired hooks when nothing emits', async () => {
    const res = await callJson(client, 'trigger_and_wait', { session_id: DEFAULT_SESSION_ID, expect_messages: 1, timeout_ms: 60 });
    expect(res.result.reached).toBe(false);
    expect(res.result.fired_hooks).toEqual([]);
  });
});

describe('trigger_and_wait action failure', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];

  beforeAll(async () => {
    initState(loadConfig({ mobileMcp: { enabled: true } } as any));
    ({ client, close } = await makeMcpHarness((server) => registerTriggerTool(server)));
  });
  afterAll(async () => { await close(); getState().stopCleanupTimer(); });

  beforeEach(() => {
    const state = getState();
    state.sessions.clear();
    state.hooks.clear();
    seedSession(state, [scriptEntry(SCRIPT, fakeScript())]);
  });

  it('keeps messages emitted before the action failed as details.partial_observation', async () => {
    const afterSeq = getState().currentMessageSeq();
    callMobileAction.mockImplementationOnce(async () => {
      emit({ n: 1 });
      throw new Error('device unplugged');
    });

    const res = await callJson(client, 'trigger_and_wait', { session_id: DEFAULT_SESSION_ID, action: 'mobile_click_on_screen_at_coordinates', params: { x: 1, y: 2 } });

    expect(res.error.message).toMatch(/device unplugged/);
    expect(res.error.details.partial_observation.after_seq).toBe(afterSeq);
    expect(res.error.details.partial_observation.delta.map((d: any) => d.payload)).toEqual([{ n: 1 }]);
  });

  it('caps partial_observation at 50 messages and marks it truncated with the total', async () => {
    callMobileAction.mockImplementationOnce(async () => {
      for (let n = 0; n < 60; n++) emit({ n });
      throw new Error('device unplugged');
    });

    const res = await callJson(client, 'trigger_and_wait', { session_id: DEFAULT_SESSION_ID, action: 'mobile_click_on_screen_at_coordinates' });

    const observation = res.error.details.partial_observation;
    expect(observation.delta).toHaveLength(50);
    expect(observation.delta[0].payload).toEqual({ n: 0 });
    expect(observation.truncated).toBe(true);
    expect(observation.total).toBe(60);
  });

  it('does not mark an uncapped partial_observation as truncated', async () => {
    callMobileAction.mockImplementationOnce(async () => {
      emit({ n: 1 });
      throw new Error('device unplugged');
    });

    const res = await callJson(client, 'trigger_and_wait', { session_id: DEFAULT_SESSION_ID, action: 'mobile_click_on_screen_at_coordinates' });

    expect(res.error.details.partial_observation.truncated).toBeUndefined();
    expect(res.error.details.partial_observation.total).toBeUndefined();
  });

  it('omits details when nothing was observed before the failure', async () => {
    callMobileAction.mockRejectedValueOnce(new Error('device unplugged'));

    const res = await callJson(client, 'trigger_and_wait', { session_id: DEFAULT_SESSION_ID, action: 'mobile_click_on_screen_at_coordinates' });

    expect(res.error.message).toMatch(/device unplugged/);
    expect(res.error.details).toBeUndefined();
  });
});
