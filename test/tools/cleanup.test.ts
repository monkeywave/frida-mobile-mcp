import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { registerCleanupTool } from '../../src/tools/cleanup.js';
import { registerHookTool } from '../../src/tools/hook.js';
import { registerTraceTool } from '../../src/tools/trace.js';
import { initState, getState } from '../../src/state.js';
import { loadConfig } from '../../src/config.js';
import type { DeviceManager } from '../../src/device/manager.js';
import {
  callJson,
  fakeScript,
  makeMcpHarness,
  scriptEntry,
  seedHook,
  seedSession,
  seedTrace,
  type Json,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

const SESSION_ID = 'sess-1';
const SCRIPT_ID = 'script-1';
const OTHER_SCRIPT_ID = 'script-2';

describe('unload_script MCP tool', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];

  beforeAll(async () => {
    initState(loadConfig({ mobileMcp: { enabled: false } } as any));
    ({ client, close } = await makeMcpHarness((server) => registerCleanupTool(server)));
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

  it('is registered as a destructive, idempotent, closed-world tool', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'unload_script');
    expect(tool).toBeDefined();
    expect(tool!.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false });
    expect(tool!.outputSchema).toBeDefined();
  });

  it('unloads the script, drops it from the session and removes its hooks and traces', async () => {
    const state = getState();
    const target = fakeScript();
    const other = fakeScript();
    const session = seedSession(state, [scriptEntry(SCRIPT_ID, target), scriptEntry(OTHER_SCRIPT_ID, other)]);
    seedHook(state, 'hook-a', SCRIPT_ID);
    seedHook(state, 'hook-b', SCRIPT_ID);
    seedHook(state, 'hook-other', OTHER_SCRIPT_ID);
    seedTrace(state, 'trace-a', SCRIPT_ID);
    seedTrace(state, 'trace-other', OTHER_SCRIPT_ID);

    const parsed = await callJson(client, 'unload_script', { session_id: SESSION_ID, script_id: SCRIPT_ID });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result).toEqual({
      session_id: SESSION_ID,
      script_id: SCRIPT_ID,
      name: `hook:${SCRIPT_ID}`,
      unloaded: true,
      removed_hooks: 2,
      removed_traces: 1,
    });
    expect(target.unloadCalls).toBe(1);
    expect(other.unloadCalls).toBe(0);
    expect(session.scripts.has(SCRIPT_ID)).toBe(false);
    expect(session.scripts.has(OTHER_SCRIPT_ID)).toBe(true);
    expect(state.sessions.has(SESSION_ID)).toBe(true);
    expect(Array.from(state.hooks.keys())).toEqual(['hook-other']);
    expect(Array.from(state.traces.keys())).toEqual(['trace-other']);
    expect(parsed.suggested_next.map((s: Json) => s.tool)).toEqual(['get_status', 'get_messages']);
  });

  it('tolerates a script that frida already destroyed', async () => {
    const state = getState();
    const session = seedSession(state, [scriptEntry(SCRIPT_ID, fakeScript({ failWith: 'Script is already destroyed' }))]);

    const parsed = await callJson(client, 'unload_script', { session_id: SESSION_ID, script_id: SCRIPT_ID });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result.unloaded).toBe(true);
    expect(session.scripts.size).toBe(0);
  });

  it('skips unload() for a script flagged isDestroyed but still cleans up state', async () => {
    const state = getState();
    const script = fakeScript({ destroyed: true });
    const session = seedSession(state, [scriptEntry(SCRIPT_ID, script)]);
    seedHook(state, 'hook-a', SCRIPT_ID);

    const parsed = await callJson(client, 'unload_script', { session_id: SESSION_ID, script_id: SCRIPT_ID });

    expect(parsed.result.removed_hooks).toBe(1);
    expect(script.unloadCalls).toBe(0);
    expect(session.scripts.size).toBe(0);
  });

  it('returns SESSION_NOT_FOUND for an unknown session', async () => {
    const parsed = await callJson(client, 'unload_script', { session_id: 'nope', script_id: SCRIPT_ID });
    expect(parsed.error.code).toBe('SESSION_NOT_FOUND');
    expect(parsed.error.category).toBe('request');
  });

  it('returns SCRIPT_NOT_FOUND for an unknown script and lists the loaded ones', async () => {
    seedSession(getState(), [scriptEntry(OTHER_SCRIPT_ID, fakeScript())]);
    const parsed = await callJson(client, 'unload_script', { session_id: SESSION_ID, script_id: SCRIPT_ID });
    expect(parsed.error.code).toBe('SCRIPT_NOT_FOUND');
    expect(parsed.error.category).toBe('request');
    expect(parsed.error.context.loaded_scripts).toEqual([OTHER_SCRIPT_ID]);
  });

  it('is idempotent: a second unload of the same script reports SCRIPT_NOT_FOUND without touching the session', async () => {
    const state = getState();
    seedSession(state, [scriptEntry(SCRIPT_ID, fakeScript())]);
    await callJson(client, 'unload_script', { session_id: SESSION_ID, script_id: SCRIPT_ID });
    const second = await callJson(client, 'unload_script', { session_id: SESSION_ID, script_id: SCRIPT_ID });
    expect(second.error.code).toBe('SCRIPT_NOT_FOUND');
    expect(state.sessions.has(SESSION_ID)).toBe(true);
  });
});

describe('hook_method / trace_method target and session_id validation', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];
  // Validation fails before the device manager is touched, so a stub is enough.
  const deviceManager = {} as unknown as DeviceManager;

  beforeAll(async () => {
    initState(loadConfig({ mobileMcp: { enabled: false } } as any));
    ({ client, close } = await makeMcpHarness((server) => {
      registerHookTool(server, deviceManager);
      registerTraceTool(server, deviceManager);
    }));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
  });

  it('exposes target as optional and session_id as an input on both tools', async () => {
    const { tools } = await client.listTools();
    for (const name of ['hook_method', 'trace_method']) {
      const tool = tools.find((t) => t.name === name)!;
      const schema = tool.inputSchema as Json;
      expect(schema.properties.session_id).toBeDefined();
      expect(schema.required ?? []).not.toContain('target');
      // hook_method takes either method or static-analysis evidence, so neither is schema-required.
      if (name === 'hook_method') expect(schema.properties.evidence).toBeDefined();
      else expect(schema.required ?? []).toContain('method');
    }
  });

  it.each(['hook_method', 'trace_method'])('%s rejects a call with neither target nor session_id', async (name) => {
    const parsed = await callJson(client, name, { method: 'com.example.Foo.bar' });
    expect(parsed.error.code).toBe('INVALID_ARGUMENT');
    expect(parsed.error.category).toBe('request');
    expect(parsed.error.message).toMatch(/target.*session_id/);
  });

  it.each(['hook_method', 'trace_method'])('%s rejects an unknown session_id instead of spawning by target', async (name) => {
    const parsed = await callJson(client, name, { session_id: 'missing', target: 'com.example.app', method: 'com.example.Foo.bar' });
    expect(parsed.error.code).toBe('SESSION_NOT_FOUND');
  });
});
