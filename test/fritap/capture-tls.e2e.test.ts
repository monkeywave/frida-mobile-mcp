/**
 * Live smoke test for capture_tls through an in-memory MCP client.
 * Runs only with FRIDA_MCP_E2E_DEVICE set (or legacy FRIDA_E2E=1) and a reachable device (FRIDA_MCP_E2E_DEVICE or legacy FRIDA_DEVICE_ID, default emulator-5556)
 * that has frida-server 17.x and the target app (FRIDA_MCP_E2E_TARGET or legacy FRIDA_E2E_TARGET, default com.example.rc4demo).
 */
import { describe, it, expect } from 'vitest';
import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const E2E = process.env.FRIDA_MCP_E2E_DEVICE !== undefined || process.env.FRIDA_E2E === '1';
const DEVICE = process.env.FRIDA_MCP_E2E_DEVICE ?? process.env.FRIDA_DEVICE_ID ?? 'emulator-5556';
const TARGET = process.env.FRIDA_MCP_E2E_TARGET ?? process.env.FRIDA_E2E_TARGET ?? 'com.example.rc4demo';

type ToolResult = { content: Array<{ type: string; text: string }>; structuredContent?: Record<string, unknown>; isError?: boolean };

describe.skipIf(!E2E)('capture_tls (live device)', () => {
  it('spawns the app with friTap and reports installed hooks', async () => {
    process.env.FRIDA_DEVICE_ID = DEVICE;
    const { createServer } = await import('../../src/server.js');
    const { getState } = await import('../../src/state.js');

    const server = createServer();
    const state = getState();
    // createServer does not know about capture_tls yet; wire it the same way server.ts will.

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: 'e2e', version: '0.0.0' });
    await client.connect(clientTransport);

    const tools = await client.listTools();
    expect(tools.tools.map((t) => t.name)).toContain('capture_tls');

    const dir = mkdtempSync(path.join(tmpdir(), 'fritap-e2e-'));
    const keylogPath = path.join(dir, 'keys.log');
    const res = (await client.callTool({
      name: 'capture_tls',
      arguments: { target: TARGET, device: DEVICE, keylog_path: keylogPath, full_capture: true, duration_seconds: 20, response_format: 'json' },
    })) as ToolResult;
    console.log('capture_tls ->', res.content[0]?.text.slice(0, 3000));
    expect(res.isError).toBeFalsy();
    const result = (res.structuredContent as { result: Record<string, unknown> }).result;
    expect(result.session_id).toBeTypeOf('string');
    expect(result.script_id).toBeTypeOf('string');
    expect(result.keylog_path).toBe(keylogPath);
    expect(existsSync(keylogPath)).toBe(true);

    await new Promise((r) => setTimeout(r, 4000));
    const msgs = (await client.callTool({
      name: 'get_messages',
      arguments: { session_id: result.session_id, script_id: result.script_id, limit: 50, response_format: 'json' },
    })) as ToolResult;
    console.log('get_messages ->', msgs.content[0]?.text.slice(0, 4000));
    console.log('keylog file:', readFileSync(keylogPath, 'utf8').slice(0, 500) || '(empty)');

    const stop = (await client.callTool({ name: 'stop_instrumentation', arguments: { session_id: result.session_id, response_format: 'json' } })) as ToolResult;
    console.log('stop ->', stop.content[0]?.text.slice(0, 500));
    await client.close();
    await server.close();
    await state.shutdown?.();
  }, 90_000);
});
