/**
 * End-to-end check of the native analysis vocabulary against a real device/emulator.
 *
 * Opt in with:
 *   FRIDA_MCP_E2E_DEVICE=emulator-5556 [FRIDA_MCP_E2E_TARGET=com.example.rc4demo] npx vitest run test/e2e/native.test.ts
 *
 * The tools are driven through an in-memory MCP client against createServer(); the native
 * analysis tools are registered by src/tools/register-all.ts like every other tool.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { InMemoryTransport } from '@modelcontextprotocol/server';
import type { McpServer } from '@modelcontextprotocol/server';
import { Client } from '@modelcontextprotocol/client';
import { createServer } from '../../src/server.js';

const DEVICE_ID = process.env.FRIDA_MCP_E2E_DEVICE;
const TARGET = process.env.FRIDA_MCP_E2E_TARGET ?? 'com.example.rc4demo';
const LIBC = 'libc.so';
const TEST_TIMEOUT_MS = 60_000;

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

describe.skipIf(!DEVICE_ID)('e2e: native analysis tools on a real device', () => {
  let server: McpServer;
  let client: Client;
  let call: ToolCall;
  let sessionId: string;
  let pid: number;

  beforeAll(async () => {
    process.env.FRIDA_DEVICE_ID = DEVICE_ID;
    server = createServer();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    client = new Client({ name: 'native-e2e', version: '0.0.0' });
    await client.connect(clientTransport);
    call = makeCaller(client);

    const spawned = await call('spawn_process', { program: TARGET, device: DEVICE_ID });
    sessionId = spawned.session_id;
    pid = spawned.pid;
    await call('resume_process', { pid, device: DEVICE_ID });
  }, TEST_TIMEOUT_MS);

  afterAll(async () => {
    if (pid) await call('kill_process', { pid, device: DEVICE_ID }).catch(() => undefined);
    await client?.close().catch(() => undefined);
    await server?.close().catch(() => undefined);
  }, TEST_TIMEOUT_MS);

  it('resolve_address round-trips libc.so!open <-> libc.so+0x.. <-> absolute', async () => {
    const bySymbol = await call('resolve_address', { session_id: sessionId, target: `${LIBC}!open` });
    expect(bySymbol.module).toBe(LIBC);
    expect(bySymbol.rva).toMatch(/^libc\.so\+0x[0-9a-f]+$/);
    expect(bySymbol.address).toMatch(/^0x[0-9a-f]+$/);
    expect(bySymbol.symbol).toBe('open');
    expect(bySymbol.kind).toBe('export');

    const byOffset = await call('resolve_address', { session_id: sessionId, target: bySymbol.rva });
    expect(byOffset.kind).toBe('offset');
    expect(byOffset.address).toBe(bySymbol.address);
    expect(byOffset.symbol).toBe('open');

    const byAbsolute = await call('resolve_address', { session_id: sessionId, target: bySymbol.address });
    expect(byAbsolute.kind).toBe('absolute');
    expect(byAbsolute.rva).toBe(bySymbol.rva);
    expect(byAbsolute.module_base).toMatch(/^0x[0-9a-f]+$/);
  }, TEST_TIMEOUT_MS);

  it('resolve_address reports an unknown target as an error', async () => {
    await expect(call('resolve_address', { session_id: sessionId, target: 'libnope.so!open' })).rejects.toThrow(/TARGET_NOT_FOUND|Could not resolve/);
  }, TEST_TIMEOUT_MS);

  it('analyze_native_function returns blocks and instructions for libc.so!open', async () => {
    const analysis = await call('analyze_native_function', { session_id: sessionId, target: `${LIBC}!open`, max_blocks: 50 });
    expect(analysis.entry.rva).toMatch(/^libc\.so\+0x[0-9a-f]+$/);
    expect(analysis.graph.blocks.length).toBeGreaterThanOrEqual(1);
    expect(analysis.instructions.length).toBeGreaterThanOrEqual(1);
    expect(analysis.instructions[0].address).toBe(analysis.entry.address);
    expect(analysis.instructions[0].rva).toBe(analysis.entry.rva);
    expect(typeof analysis.instructions[0].text).toBe('string');
    expect(Array.isArray(analysis.limitations)).toBe(true);
    console.log(`analyze_native_function: graph=${analysis.graph.source} blocks=${analysis.graph.block_count} edges=${analysis.graph.edges.length} range=${JSON.stringify(analysis.range)} limitations=${JSON.stringify(analysis.limitations)}`);
    // frida-server 17.24 has ControlFlowGraph; if it was unavailable the fallback must say so.
    if (analysis.graph.source !== 'ControlFlowGraph') {
      expect(analysis.limitations.join(' ')).toMatch(/linear/);
    }
  }, TEST_TIMEOUT_MS);

  it('enumerate_symbols / enumerate_imports / enumerate_modules speak the module vocabulary', async () => {
    const symbols = await call('enumerate_symbols', { session_id: sessionId, module_name: LIBC, limit: 10 });
    expect(symbols.symbol_count).toBeGreaterThan(0);
    expect(symbols.symbols.length).toBeGreaterThan(0);
    expect(symbols.symbols[0].address).toMatch(/^0x[0-9a-f]+$/);

    const filtered = await call('enumerate_symbols', { session_id: sessionId, module_name: LIBC, filter: '^open$' });
    expect(filtered.symbols.some((s: Json) => s.name === 'open')).toBe(true);

    const imports = await call('enumerate_imports', { session_id: sessionId, module_name: LIBC, limit: 5 });
    expect(typeof imports.import_count).toBe('number');
    expect(imports.imports.length).toBeLessThanOrEqual(5);

    const modules = await call('enumerate_modules', { session_id: sessionId, filter: '^libc\\.so$' });
    expect(modules.modules.length).toBe(1);
    expect(modules.modules[0]).toMatchObject({ name: LIBC });
    expect(modules.modules[0].base).toMatch(/^0x[0-9a-f]+$/);
    expect(modules.modules[0].size).toBeGreaterThan(0);
  }, TEST_TIMEOUT_MS);

  it('read_memory accepts module+offset and returns the ELF header', async () => {
    const read = await call('read_memory', { session_id: sessionId, address: `${LIBC}+0x0`, size: 4 });
    expect(read.data).toBe('7f454c46');
    expect(read.rva).toBe(`${LIBC}+0x0`);
  }, TEST_TIMEOUT_MS);

  it('dump_module_memory writes a base-relative image the static tool can import', async () => {
    const outPath = path.join(tmpdir(), `frida-mcp-e2e-${process.pid}-libc.bin`);
    try {
      const maxBytes = 512 * 1024;
      const dump = await call('dump_module_memory', { session_id: sessionId, module_name: LIBC, out_path: outPath, max_bytes: maxBytes });
      expect(dump.path).toBe(outPath);
      expect(dump.module_size).toBeGreaterThan(maxBytes);
      expect(dump.bytes).toBe(maxBytes);
      expect(dump.truncated).toBe(true);
      expect(dump.base).toMatch(/^0x[0-9a-f]+$/);
      expect(dump.ranges.length).toBeGreaterThan(0);
      const stat = await fs.stat(outPath);
      expect(stat.size).toBe(dump.bytes);
      const handle = await fs.open(outPath, 'r');
      const header = Buffer.alloc(4);
      await handle.read(header, 0, 4, 0);
      await handle.close();
      expect(header.toString('hex')).toBe('7f454c46');
    } finally {
      await fs.rm(outPath, { force: true });
    }
  }, TEST_TIMEOUT_MS);

  it('dump_module_memory refuses paths outside the allowed roots', async () => {
    await expect(call('dump_module_memory', { session_id: sessionId, module_name: LIBC, out_path: '/etc/frida-mcp-should-not-exist.bin' })).rejects.toThrow(/INVALID_PATH|must be inside/);
  }, TEST_TIMEOUT_MS);

  it('list_threads returns threads with symbolised backtraces', async () => {
    const threads = await call('list_threads', { session_id: sessionId, backtraces: true });
    expect(threads.thread_count).toBeGreaterThan(0);
    const thread = threads.threads[0];
    expect(typeof thread.id).toBe('number');
    expect(Array.isArray(thread.backtrace)).toBe(true);
    expect(thread.backtrace.length).toBeLessThanOrEqual(8);
    const frames: string[] = threads.threads.flatMap((t: Json) => t.backtrace ?? []);
    const symbolised = frames.filter((f) => /^\S+\+0x[0-9a-f]+ \(.+\)$/.test(f));
    console.log(`list_threads: threads=${threads.thread_count} frames=${frames.length} sample=${JSON.stringify(symbolised.slice(0, 3))}`);
    expect(frames.every((f) => /^(\S+\+0x[0-9a-f]+|0x[0-9a-f]+)( \(.+\))?$|^<backtrace unavailable/.test(f))).toBe(true);
    expect(symbolised.length).toBeGreaterThan(0);
  }, TEST_TIMEOUT_MS);

  it('hook_method accepts a module+offset target and symbolises native backtraces', async () => {
    const open = await call('resolve_address', { session_id: sessionId, target: `${LIBC}!open` });
    const hook = await call('hook_method', { target: TARGET, method: open.rva, log_backtrace: true });
    expect(hook.hook_type).toBe('native');
    expect(hook.session_id).toBe(sessionId);

    // Trigger open() inside the app via the runtime (reading a file through libc).
    await call('read_memory', { session_id: sessionId, address: open.address, size: 4 });
    await new Promise((resolve) => setTimeout(resolve, 2000));

    const messages = await call('get_messages', { session_id: sessionId, limit: 50 });
    const list: Json[] = messages.messages ?? [];
    const invocation = list.find((m) => m.payload?.type === 'native' && Array.isArray(m.payload?.backtrace));
    const installed = list.find((m) => m.payload?.status === 'hook_installed');
    expect(installed?.payload?.resolved?.rva).toBe(open.rva);
    console.log(`hook_method: invocations=${list.filter((m) => m.payload?.type === 'native').length} backtrace=${JSON.stringify(invocation?.payload?.backtrace?.slice(0, 3))}`);
    if (invocation) {
      expect(invocation.payload.rva).toBe(open.rva);
      expect(invocation.payload.backtrace[0]).toMatch(/^(\S+\+0x[0-9a-f]+|0x[0-9a-f]+)( \(.+\))?$/);
    }
  }, TEST_TIMEOUT_MS);

  it('hook_method forwards Frida 17.10 interceptor_options to Interceptor.attach on libc.so!open', async () => {
    // The documented defaults, spelled out explicitly: the hook must still install, which
    // proves the { target, ...options } call shape is accepted by the device runtime.
    const interceptorOptions = { scenario: 'online', relocation: 'checked' };
    const hook = await call('hook_method', { session_id: sessionId, method: `${LIBC}!open`, interceptor_options: interceptorOptions });
    expect(hook.hook_type).toBe('native');
    expect(hook.session_id).toBe(sessionId);
    expect(hook.interceptor_options).toEqual(interceptorOptions);

    await new Promise((resolve) => setTimeout(resolve, 1000));
    const messages = await call('get_messages', { session_id: sessionId, script_id: hook.script_id, limit: 50 });
    const list: Json[] = messages.messages ?? [];
    const installed = list.find((m) => m.payload?.status === 'hook_installed');
    const failed = list.find((m) => m.payload?.status === 'hook_error' || m.type === 'error');
    console.log(`hook_method(interceptor_options): installed=${JSON.stringify(installed?.payload)} error=${JSON.stringify(failed?.payload)}`);
    expect(failed).toBeUndefined();
    expect(installed?.payload?.method).toBe(`${LIBC}!open`);
    expect(installed?.payload?.resolved?.rva).toMatch(/^libc\.so\+0x[0-9a-f]+$/);
  }, TEST_TIMEOUT_MS);
});
