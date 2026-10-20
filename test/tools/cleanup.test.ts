import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { Client } from '@modelcontextprotocol/client';
import { McpServer, InMemoryTransport } from '@modelcontextprotocol/server';
import { registerCleanupTool } from '../../src/tools/cleanup.js';
import { registerHookTool } from '../../src/tools/hook.js';
import { registerTraceTool } from '../../src/tools/trace.js';
import { initState, getState, type ServerState } from '../../src/state.js';
import { loadConfig } from '../../src/config.js';
import type { DeviceManager } from '../../src/device/manager.js';
import type { SessionEntry, ScriptEntry } from '../../src/types.js';

type Json = Record<string, any>;

const SESSION_ID = 'sess-1';
const SCRIPT_ID = 'script-1';
const OTHER_SCRIPT_ID = 'script-2';

interface FakeScript {
  isDestroyed: boolean;
  unloadCalls: number;
  unload: () => Promise<void>;
}

function fakeScript(options: { failWith?: string; destroyed?: boolean } = {}): FakeScript {
  const script: FakeScript = {
    isDestroyed: options.destroyed ?? false,
    unloadCalls: 0,
    async unload() {
      script.unloadCalls++;
      if (options.failWith) throw new Error(options.failWith);
      script.isDestroyed = true;
    },
  };
  return script;
}

function scriptEntry(id: string, script: FakeScript, name = `hook:${id}`): ScriptEntry {
  return { id, script: script as unknown as ScriptEntry['script'], messages: [], name, persistent: true, createdAt: Date.now() };
}

function seedSession(state: ServerState, scripts: ScriptEntry[]): SessionEntry {
  const entry = {
    id: SESSION_ID,
    session: { detach: async () => undefined },
    pid: 4242,
    deviceId: 'emulator-5554',
    target: 'com.example.app',
    platform: 'android',
    scripts: new Map(scripts.map((s) => [s.id, s])),
    createdAt: Date.now(),
  } as unknown as SessionEntry;
  state.sessions.set(entry.id, entry);
  return entry;
}

function seedHook(state: ServerState, id: string, scriptId: string): void {
  state.hooks.set(id, { id, scriptId, sessionId: SESSION_ID, target: 'm', type: 'java', invocations: [], status: 'active', createdAt: Date.now() });
}

function seedTrace(state: ServerState, id: string, scriptId: string): void {
  state.traces.set(id, { id, scriptId, sessionId: SESSION_ID, targets: ['m'], callCount: 0, startedAt: Date.now() });
}

async function callJson(client: Client, name: string, args: Record<string, unknown>): Promise<Json> {
  const response = (await client.callTool({ name, arguments: { ...args, response_format: 'json' } })) as Json;
  return JSON.parse(response.content[0].text);
}

describe('unload_script MCP tool', () => {
  let client: Client;
  let server: McpServer;

  beforeAll(async () => {
    initState(loadConfig({ mobileMcp: { enabled: false } } as any));
    server = new McpServer({ name: 't', version: '0' });
    registerCleanupTool(server);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    client = new Client({ name: 'test-client', version: '0' });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  });

  afterAll(async () => {
    await client.close();
    await server.close();
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
  let client: Client;
  let server: McpServer;
  // Validation fails before the device manager is touched, so a stub is enough.
  const deviceManager = {} as unknown as DeviceManager;

  beforeAll(async () => {
    initState(loadConfig({ mobileMcp: { enabled: false } } as any));
    server = new McpServer({ name: 't', version: '0' });
    registerHookTool(server, deviceManager);
    registerTraceTool(server, deviceManager);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    client = new Client({ name: 'test-client', version: '0' });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  });

  afterAll(async () => {
    await client.close();
    await server.close();
    getState().stopCleanupTimer();
  });

  it('exposes target as optional and session_id as an input on both tools', async () => {
    const { tools } = await client.listTools();
    for (const name of ['hook_method', 'trace_method']) {
      const tool = tools.find((t) => t.name === name)!;
      const schema = tool.inputSchema as Json;
      expect(schema.properties.session_id).toBeDefined();
      expect(schema.required ?? []).not.toContain('target');
      expect(schema.required ?? []).toContain('method');
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
