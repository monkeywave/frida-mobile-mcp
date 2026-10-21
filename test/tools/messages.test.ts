import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { registerMessagesTool } from '../../src/tools/messages.js';
import { initState, getState } from '../../src/state.js';
import { loadConfig } from '../../src/config.js';
import {
  callJson,
  fakeScript,
  makeMcpHarness,
  scriptEntry,
  seedSession,
  DEFAULT_SESSION_ID,
  type Json,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

const SCRIPT_A = 'script-a';
const SCRIPT_B = 'script-b';

/** Push a `send`-style message onto a seeded script through the public state path. */
function addMessage(scriptId: string, type: string, payload: unknown): void {
  getState().addMessageToScript(DEFAULT_SESSION_ID, scriptId, {
    timestamp: Date.now(),
    type,
    payload,
    data: null,
  });
}

describe('get_messages MCP tool', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];

  beforeAll(async () => {
    initState(loadConfig({ mobileMcp: { enabled: false } } as any));
    ({ client, close } = await makeMcpHarness((server) => registerMessagesTool(server)));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
  });

  beforeEach(() => {
    const state = getState();
    state.sessions.clear();
    state.hooks.clear();
    state.traces.clear();
  });

  it('is registered as a read-only, idempotent, closed-world tool', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'get_messages');
    expect(tool).toBeDefined();
    expect(tool!.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false });
    expect(tool!.outputSchema).toBeDefined();
  });

  it('returns SESSION_NOT_FOUND for an unknown session', async () => {
    const parsed = await callJson(client, 'get_messages', { session_id: 'nope' });
    expect(parsed.error.code).toBe('SESSION_NOT_FOUND');
    expect(parsed.error.category).toBe('request');
    expect(parsed.error.recovery_actions.map((a: Json) => a.tool)).toContain('get_status');
  });

  it('collects messages from every script, sorted by timestamp, and reports active scripts', async () => {
    const state = getState();
    seedSession(state, [scriptEntry(SCRIPT_A, fakeScript()), scriptEntry(SCRIPT_B, fakeScript())]);
    addMessage(SCRIPT_A, 'hook_invocation', { n: 1 });
    addMessage(SCRIPT_B, 'trace_hit', { n: 2 });
    addMessage(SCRIPT_A, 'hook_invocation', { n: 3 });

    const parsed = await callJson(client, 'get_messages', { session_id: DEFAULT_SESSION_ID });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result.messages_count).toBe(3);
    expect(parsed.result.truncated).toBe(false);
    // Each entry carries its originating script id/name.
    expect(parsed.result.messages.map((m: Json) => m.script_id).sort()).toEqual([SCRIPT_A, SCRIPT_A, SCRIPT_B]);
    expect(parsed.result.active_scripts.map((s: Json) => s.id).sort()).toEqual([SCRIPT_A, SCRIPT_B]);
    const perScript = Object.fromEntries(parsed.result.active_scripts.map((s: Json) => [s.id, s.message_count]));
    expect(perScript[SCRIPT_A]).toBe(2);
    expect(perScript[SCRIPT_B]).toBe(1);
  });

  it('filters to a single script when script_id is given', async () => {
    const state = getState();
    seedSession(state, [scriptEntry(SCRIPT_A, fakeScript()), scriptEntry(SCRIPT_B, fakeScript())]);
    addMessage(SCRIPT_A, 'hook_invocation', { n: 1 });
    addMessage(SCRIPT_B, 'trace_hit', { n: 2 });

    const parsed = await callJson(client, 'get_messages', { session_id: DEFAULT_SESSION_ID, script_id: SCRIPT_A });

    expect(parsed.result.messages_count).toBe(1);
    expect(parsed.result.messages.every((m: Json) => m.script_id === SCRIPT_A)).toBe(true);
  });

  it('limits results and flags truncation, then paginates with since', async () => {
    const state = getState();
    seedSession(state, [scriptEntry(SCRIPT_A, fakeScript())]);
    for (let i = 0; i < 5; i++) addMessage(SCRIPT_A, 'hook_invocation', { i });

    const first = await callJson(client, 'get_messages', { session_id: DEFAULT_SESSION_ID, limit: 2 });
    expect(first.result.messages_count).toBe(2);
    expect(first.result.truncated).toBe(true);
    // A follow-up suggestion seeds the next page with since = last_index (exclusive cursor).
    const more = first.suggested_next.find((s: Json) => s.tool === 'get_messages');
    expect(more.args.since).toBe(first.result.last_index);

    const next = await callJson(client, 'get_messages', { session_id: DEFAULT_SESSION_ID, since: more.args.since });
    expect(next.result.messages.every((m: Json) => m.seq > more.args.since)).toBe(true);
  });

  it('paginates across multiple scripts without skipping or duplicating messages', async () => {
    const state = getState();
    seedSession(state, [scriptEntry(SCRIPT_A, fakeScript()), scriptEntry(SCRIPT_B, fakeScript())]);
    // Interleave messages across two scripts: per-script indices collide (both start at 0),
    // so only the global seq cursor can page a merged stream correctly.
    addMessage(SCRIPT_A, 'hook_invocation', { n: 'a0' });
    addMessage(SCRIPT_B, 'hook_invocation', { n: 'b0' });
    addMessage(SCRIPT_A, 'hook_invocation', { n: 'a1' });
    addMessage(SCRIPT_B, 'hook_invocation', { n: 'b1' });

    const seen: unknown[] = [];
    let since = 0;
    for (let guard = 0; guard < 10; guard++) {
      const page = await callJson(client, 'get_messages', { session_id: DEFAULT_SESSION_ID, since, limit: 2 });
      seen.push(...page.result.messages.map((m: Json) => (m.payload as Json).n));
      if (!page.result.truncated) break;
      since = page.result.last_index;
    }

    // Every message exactly once, in global order.
    expect(seen).toEqual(['a0', 'b0', 'a1', 'b1']);
  });

  it('returns an empty set with last_index echoing the since cursor when nothing is buffered', async () => {
    seedSession(getState(), [scriptEntry(SCRIPT_A, fakeScript())]);

    const parsed = await callJson(client, 'get_messages', { session_id: DEFAULT_SESSION_ID, since: 7 });

    expect(parsed.result.messages_count).toBe(0);
    expect(parsed.result.last_index).toBe(7);
    expect(parsed.result.truncated).toBe(false);
  });
});
