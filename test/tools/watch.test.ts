import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { registerWatchTool } from '../../src/tools/watch.js';
import { initState, getState } from '../../src/state.js';
import { rateLimiter } from '../../src/helpers/rate-limiter.js';
import {
  agentOptions,
  callJson,
  makeMcpHarness,
  makeDevice,
  makeDeviceManager,
  makeScriptingSession,
  seedSession,
  TEST_CONFIG,
  type FakeAgentScript,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

/**
 * watch_loads installs a PERSISTENT watcher: it loads an agent script, registers it in the
 * session's script map, records send payloads as watch_event entries, and — unlike the
 * one-shot RPC tools — never unloads. These tests reuse a seeded session whose frida
 * `session` is the scripting fake, so the composed agent source and load/unload are visible.
 */
describe('watch_loads MCP tool', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];
  let scripts: FakeAgentScript[];

  beforeAll(async () => {
    const deviceManager = makeDeviceManager(makeDevice());
    ({ client, close } = await makeMcpHarness((server) => registerWatchTool(server, deviceManager)));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
  });

  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    rateLimiter.reset();
  });

  /** Seed a session whose frida `session` is a scripting fake that records created scripts. */
  function seedScriptingSession(platform = 'android') {
    const { session, scripts: created } = makeScriptingSession();
    scripts = created;
    const entry = seedSession(getState(), [], { platform });
    (entry as unknown as { session: unknown }).session = session;
    return entry;
  }

  const watchScript = () => scripts.find((s) => s.name?.startsWith('watch_loads:'))!;

  it('registers as a non-read-only tool with an output schema', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'watch_loads')!;
    expect(tool).toBeDefined();
    expect(tool.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: false });
    expect(tool.outputSchema).toBeDefined();
  });

  it('accepts session_id and an optional (not required) target', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'watch_loads')!;
    const schema = tool.inputSchema as { properties?: Record<string, unknown>; required?: string[] };
    expect(schema.properties?.session_id).toBeDefined();
    expect(schema.properties?.target).toBeDefined();
    expect(schema.required ?? []).not.toContain('target');
  });

  it('loads a persistent watcher on a seeded session and returns script_id and watching flags', async () => {
    const entry = seedScriptingSession();
    const parsed = await callJson(client, 'watch_loads', { session_id: entry.id });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result.session_id).toBe(entry.id);
    expect(parsed.result.script_id).toEqual(expect.any(String));
    expect(parsed.result.watching).toEqual({ native: true, classes: true, tamper: true });

    // The script was loaded and registered in the session — and NOT unloaded (it keeps watching).
    const script = watchScript();
    expect(script.loadCalls).toBe(1);
    expect(script.unloadCalls).toBe(0);
    expect(entry.scripts.get(parsed.result.script_id)).toBeDefined();
  });

  it('forwards the watch toggles to the agent as options', async () => {
    const entry = seedScriptingSession();
    const parsed = await callJson(client, 'watch_loads', {
      session_id: entry.id,
      watch_native: true,
      watch_classes: false,
      watch_tamper: false,
    });
    expect(parsed.result.watching).toEqual({ native: true, classes: false, tamper: false });
    expect(agentOptions(watchScript().source)).toMatchObject({ watchNative: true, watchClasses: false, watchTamper: false });
  });

  it('suggests driving the app and reading watch_event messages next', async () => {
    const entry = seedScriptingSession();
    const parsed = await callJson(client, 'watch_loads', { session_id: entry.id });
    const tools = (parsed.suggested_next as Array<{ tool: string }>).map((s) => s.tool);
    expect(tools).toContain('mobile_action');
    expect(tools).toContain('get_messages');
  });

  it('rejects an empty target with no session to fall back on', async () => {
    const parsed = await callJson(client, 'watch_loads', { target: '' });
    expect(parsed.error).toBeDefined();
    expect(parsed.error.message).toMatch(/provide target.*or session_id/i);
  });
});
