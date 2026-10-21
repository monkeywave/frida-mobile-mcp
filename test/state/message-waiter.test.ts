import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { initState, getState } from '../../src/state.js';
import { loadConfig } from '../../src/config.js';
import { fakeScript, scriptEntry, seedSession, DEFAULT_SESSION_ID } from '../helpers/mock-fixtures.js';

initState(loadConfig({ mobileMcp: { enabled: false } } as any));

const SCRIPT = 'waiter-script';

function addMessage(payload: unknown): void {
  getState().addMessageToScript(DEFAULT_SESSION_ID, SCRIPT, { timestamp: Date.now(), type: 'hook_invocation', payload, data: null });
}

describe('ServerState.waitForNewMessages', () => {
  beforeEach(() => {
    const state = getState();
    state.sessions.clear();
    seedSession(state, [scriptEntry(SCRIPT, fakeScript())]);
  });
  afterAll(() => getState().stopCleanupTimer());

  it('resolves immediately when the required messages already exist', async () => {
    const state = getState();
    const after = state.currentMessageSeq();
    addMessage({ n: 1 });
    const reached = await state.waitForNewMessages(DEFAULT_SESSION_ID, after, 1, 1000);
    expect(reached).toBe(true);
  });

  it('resolves when a message arrives after the wait starts (event-driven, not polling)', async () => {
    const state = getState();
    const after = state.currentMessageSeq();
    const pending = state.waitForNewMessages(DEFAULT_SESSION_ID, after, 1, 2000);
    // Deliver a message on the next tick, after the waiter is registered.
    setTimeout(() => addMessage({ n: 'late' }), 10);
    expect(await pending).toBe(true);
  });

  it('times out to false when not enough messages arrive', async () => {
    const state = getState();
    const after = state.currentMessageSeq();
    addMessage({ n: 1 }); // only 1, but we require 2
    const reached = await state.waitForNewMessages(DEFAULT_SESSION_ID, after, 2, 60);
    expect(reached).toBe(false);
  });

  it('only counts messages strictly after the given cursor', async () => {
    const state = getState();
    addMessage({ n: 'old' });
    const after = state.currentMessageSeq(); // cursor now past the "old" message
    expect(state.countMessagesSince(DEFAULT_SESSION_ID, after)).toBe(0);
    addMessage({ n: 'new' });
    expect(state.countMessagesSince(DEFAULT_SESSION_ID, after)).toBe(1);
  });
});
