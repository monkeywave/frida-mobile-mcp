/**
 * End-to-end check of the evidence store against a real device/emulator:
 * hook_method -> _meta.evidence_id -> get_evidence -> export_evidence_bundle, plus provenance
 * and error records.
 *
 * Opt in with:
 *   FRIDA_MCP_E2E_DEVICE=emulator-5556 FRIDA_MCP_E2E_TARGET=com.example.rc4demo npx vitest run test/e2e/evidence.e2e.test.ts
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { InMemoryTransport } from '@modelcontextprotocol/server';
import type { McpServer } from '@modelcontextprotocol/server';
import { Client } from '@modelcontextprotocol/client';
import { createServer } from '../../src/server.js';

const DEVICE_ID = process.env.FRIDA_MCP_E2E_DEVICE;
const TARGET = process.env.FRIDA_MCP_E2E_TARGET ?? 'com.example.rc4demo';
const TEST_TIMEOUT_MS = 90_000;

type Json = Record<string, any>;

interface Reply {
  parsed: Json;
  meta: Json;
  isError: boolean;
  text: string;
}

function adb(...args: string[]): string {
  try {
    return execFileSync('adb', ['-s', DEVICE_ID!, ...args], { encoding: 'utf-8', timeout: 20_000 });
  } catch {
    return '';
  }
}

describe.skipIf(!DEVICE_ID)('e2e: evidence store (hook -> get_evidence -> export bundle)', () => {
  let server: McpServer;
  let client: Client;
  let sessionId: string;
  let evidenceRoot: string;
  let exportDir: string;
  let hookedMethod: string;
  let hookReply: Reply;
  let statusReply: Reply;

  async function raw(name: string, args: Record<string, unknown>, format: 'json' | 'markdown' = 'json'): Promise<Reply> {
    const response = (await client.callTool({ name, arguments: { ...args, response_format: format } })) as Json;
    const text: string = response.content?.[0]?.text ?? '';
    const parsed = format === 'json' ? (JSON.parse(text || '{}') as Json) : {};
    return { parsed, meta: (response._meta ?? {}) as Json, isError: Boolean(response.isError), text };
  }

  async function call(name: string, args: Record<string, unknown>): Promise<Json> {
    const reply = await raw(name, args);
    if (reply.isError || reply.parsed.error) throw new Error(`${name} failed: ${reply.text}`);
    return reply.parsed.result as Json;
  }

  beforeAll(async () => {
    evidenceRoot = mkdtempSync(path.join(tmpdir(), 'fmm-evidence-store-'));
    exportDir = mkdtempSync(path.join(tmpdir(), 'fmm-evidence-export-'));
    // vitest.config.ts disables the store via env; enable it explicitly with a temp root.
    process.env.FRIDA_MCP_EVIDENCE = '1';
    process.env.FRIDA_MCP_EVIDENCE_PATH = evidenceRoot;
    process.env.FRIDA_DEVICE_ID = DEVICE_ID;
    server = createServer();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    client = new Client({ name: 'evidence-e2e', version: '0.0.0' });
    await client.connect(clientTransport);

    statusReply = await raw('get_status', {});
    const explored = await call('explore_app', { target: TARGET, device: DEVICE_ID });
    sessionId = explored.session_id;
    expect(sessionId).toBeTruthy();

    const found = await call('search_classes_and_methods', { target: TARGET, pattern: 'Rc4', include_methods: true });
    hookedMethod = pickMethod(found);
    hookReply = await raw('hook_method', { target: TARGET, method: hookedMethod, log_args: true });
    expect(hookReply.isError, hookReply.text).toBe(false);

    adb('shell', 'monkey', '-p', TARGET, '1');
    await new Promise((r) => setTimeout(r, 3000));
    await call('get_messages', { session_id: sessionId }).catch(() => undefined);
  }, TEST_TIMEOUT_MS);

  afterAll(async () => {
    await raw('stop_instrumentation', { target: TARGET }).catch(() => undefined);
    adb('shell', 'am', 'force-stop', TARGET);
    await client?.close().catch(() => undefined);
    await server?.close().catch(() => undefined);
    rmSync(evidenceRoot, { recursive: true, force: true });
    rmSync(exportDir, { recursive: true, force: true });
  }, TEST_TIMEOUT_MS);

  it('the hook result carries an evidence_id and untrusted-content provenance; get_status has none', () => {
    expect(hookReply.meta.evidence_id).toBeTruthy();
    expect(hookReply.meta.provenance?.untrusted_content).toBe(true);
    expect(statusReply.meta.evidence_id).toBeTruthy();
    expect(statusReply.meta.provenance?.untrusted_content).toBeUndefined();
  });

  it('get_evidence returns the hook record with a 64-hex script hash and the same result', async () => {
    const { record } = await call('get_evidence', { evidence_id: hookReply.meta.evidence_id });
    expect(record).toMatchObject({ evidence_id: hookReply.meta.evidence_id, tool: 'hook_method', status: 'success' });
    expect(record.script_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(record.structured.result).toEqual(hookReply.parsed.result);
  }, TEST_TIMEOUT_MS);

  it('export_evidence_bundle writes a JSON bundle containing the hook record', async () => {
    const outPath = path.join(exportDir, 'bundle.json');
    const written = await call('export_evidence_bundle', { session_id: sessionId, format: 'json', out_path: outPath });
    expect(written.count).toBeGreaterThanOrEqual(2);
    const bundle = JSON.parse(readFileSync(written.out_path, 'utf-8')) as Json;
    expect(bundle.count).toBeGreaterThanOrEqual(2);
    expect(bundle.records.map((r: Json) => r.evidence_id)).toContain(hookReply.meta.evidence_id);
  }, TEST_TIMEOUT_MS);

  it('export_evidence_bundle markdown inline mentions the hook tool', async () => {
    const reply = await raw('export_evidence_bundle', { evidence_ids: [hookReply.meta.evidence_id], format: 'markdown' });
    expect(reply.isError, reply.text).toBe(false);
    expect(JSON.stringify(reply.parsed)).toContain('hook_method');
  }, TEST_TIMEOUT_MS);

  it('an error call is stored with status "error" and retrievable by its evidence_id', async () => {
    const failed = await raw('read_memory', { session_id: 'bogus-session', address: '0x1000', size: 4 });
    expect(failed.parsed.error ?? failed.isError).toBeTruthy();
    const evidenceId = failed.meta.evidence_id ?? failed.parsed.error?.evidence_id;
    expect(evidenceId).toBeTruthy();
    const { record } = await call('get_evidence', { evidence_id: evidenceId });
    expect(record).toMatchObject({ tool: 'read_memory', status: 'error' });
  }, TEST_TIMEOUT_MS);
});

/** Choose a hookable "Class.method" from a search_classes_and_methods result. */
function pickMethod(found: Json): string {
  const text = JSON.stringify(found);
  const preferred = 'com.example.rc4demo.Rc4Client.encrypt';
  if (text.includes('Rc4Client') && text.includes('encrypt')) return preferred;
  const methods = (found.methods ?? found.matches ?? []) as Json[];
  const first = methods.find((m) => typeof m === 'string' || m.class || m.name);
  if (!first) throw new Error(`No Rc4 method found: ${text.slice(0, 500)}`);
  return typeof first === 'string' ? first : `${first.class}.${first.name}`;
}
