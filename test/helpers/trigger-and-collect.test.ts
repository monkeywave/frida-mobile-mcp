import { describe, it, expect, beforeEach, vi } from 'vitest';

// triggerAndCollect performs the optional mobile action through a dynamic import of call.js.
// Mock it; `behavior.impl` lets each test script what the (mocked) mobile call does.
const { callMobileAction, behavior } = vi.hoisted(() => {
  const behavior: { impl: (action: string, params: unknown, device: unknown) => Promise<unknown> } = {
    impl: async () => ({ ok: true }),
  };
  const callMobileAction = vi.fn((action: string, params: unknown, device: unknown) => behavior.impl(action, params, device));
  return { callMobileAction, behavior };
});
vi.mock('../../src/mobile-mcp/call.js', () => ({ callMobileAction }));

import { triggerAndCollect } from '../../src/helpers/trigger-and-collect.js';
import { initState, getState } from '../../src/state.js';
import {
  fakeScript,
  scriptEntry,
  seedSession,
  DEFAULT_SESSION_ID,
  TEST_CONFIG,
} from './mock-fixtures.js';

const SCRIPT = 'trig-script';

/** Add a message to SCRIPT, as a hook send would. */
function emit(type: string, payload: unknown): void {
  getState().addMessageToScript(DEFAULT_SESSION_ID, SCRIPT, { timestamp: Date.now(), type, payload, data: null });
}

function session() {
  return seedSession(getState(), [scriptEntry(SCRIPT, fakeScript())]);
}

describe('triggerAndCollect', () => {
  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    callMobileAction.mockClear();
    behavior.impl = async () => ({ ok: true });
  });

  it('pure wait (no action): resolves on a new message and collects the delta', async () => {
    const s = session();
    // Snapshot happens synchronously inside the call, so emit AFTER starting it: the message
    // arrives during the wait and the event-driven waiter resolves.
    const p = triggerAndCollect(s, { minCount: 1, timeoutMs: 1000 });
    emit('crypto_event', { key_hex: 'deadbeef' });
    const r = await p;

    expect(callMobileAction).not.toHaveBeenCalled();
    expect(r.reached).toBe(true);
    expect(r.actionResult).toBeNull();
    expect(r.afterSeq).toBe(0);
    expect(r.delta.map((d) => d.type)).toEqual(['crypto_event']);
    expect(r.firedScriptIds.has(SCRIPT)).toBe(true);
  });

  it('times out to reached=false with an empty delta when nothing arrives', async () => {
    const s = session();
    const r = await triggerAndCollect(s, { minCount: 1, timeoutMs: 20 });
    expect(r.reached).toBe(false);
    expect(r.delta).toEqual([]);
    expect(r.firedScriptIds.size).toBe(0);
  });

  it('performs the action with the session device injected and returns its result + caused delta', async () => {
    const s = session();
    behavior.impl = async () => { emit('crypto_event', { key_hex: 'cafe' }); return { tapped: true }; };

    const r = await triggerAndCollect(s, {
      action: 'mobile_click_on_screen_at_coordinates',
      params: { x: 1, y: 2 },
      minCount: 1,
      timeoutMs: 1000,
    });

    expect(callMobileAction).toHaveBeenCalledWith('mobile_click_on_screen_at_coordinates', { x: 1, y: 2 }, s.deviceId);
    expect(r.actionResult).toEqual({ tapped: true });
    expect(r.reached).toBe(true);
    expect(r.delta).toHaveLength(1);
    expect(r.firedScriptIds.has(SCRIPT)).toBe(true);
  });

  it('bounds the mobile call with callTimeoutMs and throws when it stalls', async () => {
    const s = session();
    behavior.impl = () => new Promise(() => { /* never settles */ });

    await expect(
      triggerAndCollect(s, { action: 'mobile_click_on_screen_at_coordinates', minCount: 1, timeoutMs: 1000, callTimeoutMs: 20 }),
    ).rejects.toThrow(/timed out/);
  });
});
