import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { registerCleanupTool } from '../../src/tools/cleanup.js';
import { registerHookTool } from '../../src/tools/hook.js';
import { registerTraceTool } from '../../src/tools/trace.js';
import { initState, getState } from '../../src/state.js';
import { loadConfig } from '../../src/config.js';
import type { DeviceManager } from '../../src/device/manager.js';
import { recordJavaBridgeUsage } from '../../src/agent/script-traits.js';
import { FritapCapture } from '../../src/fritap/capture.js';
import { stopFritapCapture, trackCapture } from '../../src/fritap/tool.js';
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
    state.coverage.clear();
    state.oracles.clear();
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
    state.coverage.set('cov-a', { id: 'cov-a', scriptId: SCRIPT_ID, sessionId: SESSION_ID, scope: 'x', allTargets: [], hits: new Map(), createdAt: Date.now() });
    state.coverage.set('cov-other', { id: 'cov-other', scriptId: OTHER_SCRIPT_ID, sessionId: SESSION_ID, scope: 'y', allTargets: [], hits: new Map(), createdAt: Date.now() });
    state.oracles.set('oracle-a', { id: 'oracle-a', scriptId: SCRIPT_ID, sessionId: SESSION_ID, pattern: 'rc4', eventCount: 0, createdAt: Date.now() });
    state.oracles.set('oracle-other', { id: 'oracle-other', scriptId: OTHER_SCRIPT_ID, sessionId: SESSION_ID, pattern: 'rc4', eventCount: 0, createdAt: Date.now() });

    const parsed = await callJson(client, 'unload_script', { session_id: SESSION_ID, script_id: SCRIPT_ID });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result).toEqual({
      session_id: SESSION_ID,
      script_id: SCRIPT_ID,
      name: `hook:${SCRIPT_ID}`,
      unloaded: true,
      removed_hooks: 2,
      removed_traces: 1,
      removed_coverage: 1,
      removed_oracles: 1,
    });
    expect(target.unloadCalls).toBe(1);
    expect(other.unloadCalls).toBe(0);
    expect(session.scripts.has(SCRIPT_ID)).toBe(false);
    expect(session.scripts.has(OTHER_SCRIPT_ID)).toBe(true);
    expect(state.sessions.has(SESSION_ID)).toBe(true);
    expect(Array.from(state.hooks.keys())).toEqual(['hook-other']);
    expect(Array.from(state.traces.keys())).toEqual(['trace-other']);
    expect(Array.from(state.coverage.keys())).toEqual(['cov-other']);
    expect(Array.from(state.oracles.keys())).toEqual(['oracle-other']);
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

/** Fake script that records its unload in `order` and carries the Java-bridge trait. */
function javaScript(id: string, order: string[], java = true) {
  const script = fakeScript();
  const unload = script.unload.bind(script);
  script.unload = async () => { order.push(id); await unload(); };
  recordJavaBridgeUsage(script, java);
  return script;
}

describe('unload ordering for Java-bridge scripts', () => {
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
  });

  it('refuses to unload an older Java-bridge script while newer ones are loaded (nothing unloaded)', async () => {
    const order: string[] = [];
    const state = getState();
    const session = seedSession(state, [
      scriptEntry('old', javaScript('old', order)),
      scriptEntry('native', javaScript('native', order, false)),
      scriptEntry('new', javaScript('new', order)),
    ]);

    const parsed = await callJson(client, 'unload_script', { session_id: SESSION_ID, script_id: 'old' });

    expect(parsed.error.code).toBe('UNLOAD_ORDER_UNSAFE');
    expect(parsed.error.category).toBe('request');
    expect(parsed.error.context.newer_java_bridge_scripts).toEqual([{ script_id: 'new', name: 'hook:new' }]);
    expect(parsed.error.recovery_actions[0]).toMatchObject({ tool: 'unload_script', args: { script_id: 'old', cascade: true } });
    expect(order).toEqual([]);
    expect(Array.from(session.scripts.keys())).toEqual(['old', 'native', 'new']);
  });

  it('cascade=true unloads the newer Java-bridge scripts newest-first, then the requested one', async () => {
    const order: string[] = [];
    const state = getState();
    const session = seedSession(state, [
      scriptEntry('old', javaScript('old', order)),
      scriptEntry('mid', javaScript('mid', order)),
      scriptEntry('native', javaScript('native', order, false)),
      scriptEntry('new', javaScript('new', order)),
    ]);
    seedHook(state, 'hook-mid', 'mid');

    const parsed = await callJson(client, 'unload_script', { session_id: SESSION_ID, script_id: 'old', cascade: true });

    expect(parsed.error).toBeUndefined();
    expect(order).toEqual(['new', 'mid', 'old']);
    expect(parsed.result.cascaded_scripts.map((c: Json) => c.script_id)).toEqual(['new', 'mid']);
    expect(parsed.result.cascaded_scripts[1].removed_hooks).toBe(1);
    expect(parsed.limitations.join(' ')).toMatch(/cascade=true also unloaded 2/);
    expect(Array.from(session.scripts.keys())).toEqual(['native']);
  });

  it('unloads the newest Java-bridge script or a non-bridge script without a guard', async () => {
    const order: string[] = [];
    seedSession(getState(), [
      scriptEntry('native', javaScript('native', order, false)),
      scriptEntry('old', javaScript('old', order)),
      scriptEntry('new', javaScript('new', order)),
    ]);
    const newest = await callJson(client, 'unload_script', { session_id: SESSION_ID, script_id: 'new' });
    const native = await callJson(client, 'unload_script', { session_id: SESSION_ID, script_id: 'native' });
    expect(newest.error).toBeUndefined();
    expect(newest.result.cascaded_scripts).toBeUndefined();
    expect(native.error).toBeUndefined();
    expect(order).toEqual(['new', 'native']);
  });

  it('stop_instrumentation unloads every script newest-first and skips eternalized ones', async () => {
    const order: string[] = [];
    const pinned = scriptEntry('pinned', javaScript('pinned', order));
    pinned.eternalized = true;
    seedSession(getState(), [scriptEntry('a', javaScript('a', order)), pinned, scriptEntry('b', javaScript('b', order)), scriptEntry('c', javaScript('c', order, false))]);

    const parsed = await callJson(client, 'stop_instrumentation', { session_id: SESSION_ID });

    expect(parsed.error).toBeUndefined();
    expect(order).toEqual(['c', 'b', 'a']);
    expect(parsed.result.fritap_captures).toBeUndefined();
  });

  it('stop_instrumentation returns the final friTap stats (per_library) of captures in the session', async () => {
    const order: string[] = [];
    const fritapScript = javaScript('fritap-1', order);
    seedSession(getState(), [scriptEntry('hook-1', javaScript('hook-1', order)), scriptEntry('fritap-1', fritapScript, 'fritap')]);
    const capture = new FritapCapture({});
    trackCapture(SESSION_ID, 'fritap-1', fritapScript as any, capture, 0);
    capture.stats.records = 3;
    capture.stats.per_library.libssl = { read: 2, write: 1, bytes: 42 } as any;

    const parsed = await callJson(client, 'stop_instrumentation', { session_id: SESSION_ID });

    expect(order).toEqual(['fritap-1', 'hook-1']);
    expect(parsed.result.fritap_captures).toHaveLength(1);
    expect(parsed.result.fritap_captures[0]).toMatchObject({
      session_id: SESSION_ID,
      script_id: 'fritap-1',
      stats: { records: 3, per_library: { libssl: { read: 2, write: 1, bytes: 42 } } },
    });
  });

  it('unload_script of a friTap capture returns its final stats', async () => {
    const order: string[] = [];
    const fritapScript = javaScript('fritap-2', order, false);
    seedSession(getState(), [scriptEntry('fritap-2', fritapScript, 'fritap')]);
    const capture = new FritapCapture({});
    trackCapture(SESSION_ID, 'fritap-2', fritapScript as any, capture, 0);
    capture.stats.keylog_lines = 5;

    const parsed = await callJson(client, 'unload_script', { session_id: SESSION_ID, script_id: 'fritap-2' });

    expect(parsed.error).toBeUndefined();
    expect(order).toEqual(['fritap-2']);
    expect(parsed.result.fritap_captures[0]).toMatchObject({ script_id: 'fritap-2', stats: { keylog_lines: 5 } });
  });

  async function endCaptureOnItsOwn(scriptId: string, keylogLines: number): Promise<void> {
    const fritapScript = javaScript(scriptId, [], false);
    seedSession(getState(), [scriptEntry('hook-keep', fakeScript()), scriptEntry(scriptId, fritapScript, 'fritap')]);
    const capture = new FritapCapture({});
    trackCapture(SESSION_ID, scriptId, fritapScript as any, capture, 0);
    capture.stats.keylog_lines = keylogLines;
    // What the duration_seconds timer does: stop the capture and drop the script from the session.
    await stopFritapCapture(scriptId);
  }

  it('unload_script returns the final stats of a capture that already ended (duration_seconds expiry)', async () => {
    await endCaptureOnItsOwn('fritap-dur', 7);

    const parsed = await callJson(client, 'unload_script', { session_id: SESSION_ID, script_id: 'fritap-dur' });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result).toMatchObject({ unloaded: false, already_ended: true });
    expect(parsed.result.fritap_captures[0]).toMatchObject({ script_id: 'fritap-dur', stats: { keylog_lines: 7 } });
    expect(getState().getSession(SESSION_ID)?.scripts.has('hook-keep')).toBe(true);
    // Handed out once; a second call reports SCRIPT_NOT_FOUND again.
    const again = await callJson(client, 'unload_script', { session_id: SESSION_ID, script_id: 'fritap-dur' });
    expect(again.error.code).toBe('SCRIPT_NOT_FOUND');
  });

  it('unload_script returns the final stats when the session is already gone (app exit)', async () => {
    await endCaptureOnItsOwn('fritap-exit', 3);
    getState().sessions.delete(SESSION_ID);

    const parsed = await callJson(client, 'unload_script', { session_id: SESSION_ID, script_id: 'fritap-exit' });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result.fritap_captures[0]).toMatchObject({ session_id: SESSION_ID, script_id: 'fritap-exit', stats: { keylog_lines: 3 } });
  });

  it('stop_instrumentation(session_id) returns the final stats of a session that is already gone', async () => {
    await endCaptureOnItsOwn('fritap-gone', 9);
    getState().sessions.delete(SESSION_ID);

    const parsed = await callJson(client, 'stop_instrumentation', { session_id: SESSION_ID });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result.cleaned_sessions).toEqual([]);
    expect(parsed.result.fritap_captures[0]).toMatchObject({ script_id: 'fritap-gone', stats: { keylog_lines: 9 } });
    const again = await callJson(client, 'stop_instrumentation', { session_id: SESSION_ID });
    expect(again.error.code).toBe('SESSION_NOT_FOUND');
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
