import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
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
