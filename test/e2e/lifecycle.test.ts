/**
 * End-to-end check of the per-script lifecycle against a real device/emulator:
 * explore_app -> hook_method with session_id (no target) -> unload_script -> get_status shows 0 scripts.
 *
 * Opt in with:
 *   FRIDA_MCP_E2E_DEVICE=emulator-5556 [FRIDA_MCP_E2E_TARGET=com.example.rc4demo] npx vitest run test/e2e/lifecycle.test.ts
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { InMemoryTransport } from '@modelcontextprotocol/server';
import type { McpServer } from '@modelcontextprotocol/server';
import { Client } from '@modelcontextprotocol/client';
import { createServer } from '../../src/server.js';

const DEVICE_ID = process.env.FRIDA_MCP_E2E_DEVICE;
const TARGET = process.env.FRIDA_MCP_E2E_TARGET ?? 'com.example.rc4demo';
const HOOKED_METHOD = 'libc.so!open';
const TEST_TIMEOUT_MS = 90_000;

type Json = Record<string, any>;

interface ToolCall {
  (name: string, args: Record<string, unknown>): Promise<Json>;
}

function makeCaller(client: Client): ToolCall {
  return async (name, args) => {
    const response = (await client.callTool({ name, arguments: { ...args, response_format: 'json' } })) as Json;
    const text = response.content?.[0]?.text ?? '{}';
    const parsed = JSON.parse(text) as Json;
    if (response.isError || parsed.error) {
      throw new Error(`${name} failed: ${text}`);
    }
    return parsed.result as Json;
  };
}

async function sessionSummary(call: ToolCall, sessionId: string): Promise<Json | undefined> {
  const status = await call('get_status', {});
  return (status.sessions as Json[]).find((s) => s.id === sessionId);
}

describe.skipIf(!DEVICE_ID)('e2e: script lifecycle (hook with session_id, unload_script)', () => {
  let server: McpServer;
  let client: Client;
  let call: ToolCall;
  let sessionId: string;

  beforeAll(async () => {
    process.env.FRIDA_DEVICE_ID = DEVICE_ID;
    server = createServer();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    client = new Client({ name: 'lifecycle-e2e', version: '0.0.0' });
    await client.connect(clientTransport);
    call = makeCaller(client);

    const explored = await call('explore_app', { target: TARGET, device: DEVICE_ID });
    sessionId = explored.session_id;
    expect(sessionId).toBeTruthy();
  }, TEST_TIMEOUT_MS);

  afterAll(async () => {
    if (sessionId) await call('stop_instrumentation', { session_id: sessionId }).catch(() => undefined);
    await client?.close().catch(() => undefined);
    await server?.close().catch(() => undefined);
  }, TEST_TIMEOUT_MS);

  it('explore_app leaves the session attached with no scripts loaded', async () => {
    const summary = await sessionSummary(call, sessionId);
    expect(summary).toBeDefined();
    expect(summary!.target).toBe(TARGET);
    expect(summary!.scripts).toBe(0);
  }, TEST_TIMEOUT_MS);

  it('hook_method with session_id and no target attaches to the existing session, then unload_script removes it', async () => {
    const hooked = await call('hook_method', { session_id: sessionId, method: HOOKED_METHOD });
    expect(hooked.session_id).toBe(sessionId);
    expect(hooked.script_id).toBeTruthy();
    expect(hooked.hook_id).toBeTruthy();

    const withHook = await sessionSummary(call, sessionId);
    expect(withHook!.scripts).toBe(1);
    expect(withHook!.script_names).toEqual([`hook:${HOOKED_METHOD}`]);
    const statusWithHook = await call('get_status', {});
    expect((statusWithHook.hooks as Json[]).map((h) => h.id)).toContain(hooked.hook_id);

    const unloaded = await call('unload_script', { session_id: sessionId, script_id: hooked.script_id });
    expect(unloaded).toMatchObject({
      session_id: sessionId,
      script_id: hooked.script_id,
      name: `hook:${HOOKED_METHOD}`,
      unloaded: true,
      removed_hooks: 1,
      removed_traces: 0,
    });

    const afterUnload = await sessionSummary(call, sessionId);
    expect(afterUnload, 'session must survive unload_script').toBeDefined();
    expect(afterUnload!.scripts).toBe(0);
    const statusAfter = await call('get_status', {});
    expect((statusAfter.hooks as Json[]).map((h) => h.id)).not.toContain(hooked.hook_id);
  }, TEST_TIMEOUT_MS);

  it('a second unload_script of the same script reports SCRIPT_NOT_FOUND', async () => {
    const hooked = await call('hook_method', { session_id: sessionId, method: HOOKED_METHOD });
    await call('unload_script', { session_id: sessionId, script_id: hooked.script_id });

    const response = (await client.callTool({
      name: 'unload_script',
      arguments: { session_id: sessionId, script_id: hooked.script_id, response_format: 'json' },
    })) as Json;
    const parsed = JSON.parse(response.content[0].text) as Json;
    expect(parsed.error?.code).toBe('SCRIPT_NOT_FOUND');
    expect((await sessionSummary(call, sessionId))!.scripts).toBe(0);
  }, TEST_TIMEOUT_MS);

  it('trace_method with session_id runs inside the same session and returns a script_id', async () => {
    const traced = await call('trace_method', { session_id: sessionId, method: HOOKED_METHOD, duration_seconds: 2 });
    expect(traced.session_id).toBe(sessionId);
    expect(traced.script_id).toBeTruthy();
    expect((await sessionSummary(call, sessionId))!.scripts).toBe(0);
  }, TEST_TIMEOUT_MS);
});
