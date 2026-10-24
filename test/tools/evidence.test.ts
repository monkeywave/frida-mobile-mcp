import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { audit } from '../../src/helpers/logger.js';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { registerAllTools } from '../../src/tools/register-all.js';
import { initState, getState } from '../../src/state.js';
import { initEvidenceStore } from '../../src/helpers/evidence-store.js';
import {
  fakeScript,
  makeDevice,
  makeDeviceManager,
  makeMcpHarness,
  scriptEntry,
  seedSession,
  DEFAULT_SESSION_ID,
  FULL_TOOL_POLICY,
  TEST_CONFIG,
  type Json,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

vi.mock('../../src/helpers/logger.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/helpers/logger.js')>()),
  audit: vi.fn(),
}));

type CallResult = Json & { isError?: boolean; structuredContent?: Json; _meta?: Json; content: Array<{ text: string }> };

describe('evidence tools (end to end through registerAllTools)', () => {
  let root: string;
  let harness: McpHarness;

  const call = async (name: string, args: Record<string, unknown>): Promise<CallResult> =>
    (await harness.client.callTool({ name, arguments: args })) as CallResult;

  beforeAll(async () => {
    root = mkdtempSync(path.join(tmpdir(), 'evidence-tools-'));
    initState({ ...TEST_CONFIG });
    initEvidenceStore({ enabled: true, path: root });
    seedSession(getState(), [scriptEntry('script-a', fakeScript())]);
    harness = await makeMcpHarness((server) =>
      registerAllTools(server, makeDeviceManager(makeDevice()), { resources: true, prompts: false, ...FULL_TOOL_POLICY })
    );
  });

  afterAll(async () => {
    await harness.close();
    getState().stopCleanupTimer();
    initEvidenceStore({ enabled: false });
    rmSync(root, { recursive: true, force: true });
  });

  it('writes exactly one central audit line per tool call', async () => {
    vi.mocked(audit).mockClear();
    const ok = await call('get_messages', { session_id: DEFAULT_SESSION_ID, response_format: 'json' });
    expect(vi.mocked(audit)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(audit).mock.calls[0][0]).toMatchObject({
      tool: 'get_messages',
      status: 'success',
      evidence_id: ok._meta?.evidence_id,
    });
  });

  it('persists a successful call and get_evidence returns the full record', async () => {
    const ok = await call('get_messages', { session_id: DEFAULT_SESSION_ID, response_format: 'json' });
    expect(ok.isError).toBeFalsy();
    const id = ok._meta?.evidence_id as string;
    expect(id).toBe(ok.structuredContent?.evidence_id);

    const fetched = await call('get_evidence', { evidence_id: id, response_format: 'json' });
    expect(fetched.isError).toBeFalsy();
    const record = fetched.structuredContent?.result.record;
    expect(record).toMatchObject({ evidence_id: id, tool: 'get_messages', status: 'success', session_id: DEFAULT_SESSION_ID });
    expect(record.params).toMatchObject({ session_id: DEFAULT_SESSION_ID });
    expect(record.structured.result.session_id).toBe(DEFAULT_SESSION_ID);
    expect(typeof record.duration_ms).toBe('number');
  });

  it('persists an error call with status error and the error body', async () => {
    const failed = await call('read_memory', { session_id: 'bogus', address: '0x1000', size: 4, response_format: 'json' });
    expect(failed.isError).toBe(true);
    const id = failed._meta?.evidence_id as string;
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
    expect(JSON.parse(failed.content[0].text).error.evidence_id).toBe(id);

    const record = (await call('get_evidence', { evidence_id: id, response_format: 'json' })).structuredContent?.result.record;
    expect(record).toMatchObject({ tool: 'read_memory', status: 'error', session_id: 'bogus' });
    expect(record.structured.code).toBe('SESSION_NOT_FOUND');
  });

  it('get_evidence reports EVIDENCE_NOT_FOUND for an unknown id', async () => {
    const res = await call('get_evidence', { evidence_id: '00000000-0000-0000-0000-000000000000', response_format: 'json' });
    expect(res.isError).toBe(true);
    const body = JSON.parse(res.content[0].text).error;
    expect(body).toMatchObject({ code: 'EVIDENCE_NOT_FOUND', category: 'request', retryable: false });
  });

  it('does not record get_evidence / export_evidence_bundle calls themselves', async () => {
    const res = await call('get_evidence', { evidence_id: 'nope', response_format: 'json' });
    const again = await call('get_evidence', { evidence_id: res._meta?.evidence_id as string, response_format: 'json' });
    expect(again.isError).toBe(true);
  });

  it('exports an inline JSON bundle filtered by session', async () => {
    const res = await call('export_evidence_bundle', { session_id: DEFAULT_SESSION_ID, response_format: 'json' });
    expect(res.isError).toBeFalsy();
    const result = res.structuredContent?.result;
    expect(result.format).toBe('json');
    expect(result.count).toBeGreaterThanOrEqual(1);
    expect(result.bundle.server.name).toBe('frida-mobile-mcp');
    expect(result.bundle.records.every((r: Json) => r.session_id === DEFAULT_SESSION_ID)).toBe(true);
  });

  it('caps an inline export at 20 records unless limit is given', async () => {
    for (let i = 0; i < 21; i++) await call('get_messages', { session_id: DEFAULT_SESSION_ID });
    const inline = await call('export_evidence_bundle', { response_format: 'json' });
    expect(inline.structuredContent?.result.count).toBe(20);
    const explicit = await call('export_evidence_bundle', { limit: 25, response_format: 'json' });
    expect(explicit.structuredContent?.result.count).toBeGreaterThan(20);
  });

  it('exports an inline Markdown bundle for explicit ids', async () => {
    const ok = await call('get_messages', { session_id: DEFAULT_SESSION_ID });
    const res = await call('export_evidence_bundle', { evidence_ids: [ok._meta?.evidence_id], format: 'markdown', response_format: 'json' });
    const result = res.structuredContent?.result;
    expect(result.count).toBe(1);
    expect(result.bundle).toContain('## 1. get_messages (success)');
  });

  it('writes the bundle to out_path under an allowed root', async () => {
    const outPath = path.join(root, 'bundle.json');
    const res = await call('export_evidence_bundle', { out_path: outPath, response_format: 'json' });
    expect(res.isError).toBeFalsy();
    const result = res.structuredContent?.result;
    expect(result).toMatchObject({ out_path: outPath, format: 'json' });
    expect(existsSync(outPath)).toBe(true);
    const written = JSON.parse(readFileSync(outPath, 'utf-8'));
    expect(written.count).toBe(result.count);
    expect(result.bytes).toBe(readFileSync(outPath).length);
  });

  it('rejects an out_path outside the allowed roots', async () => {
    const outside = path.join(path.parse(process.cwd()).root, 'frida-mcp-not-allowed', 'bundle.json');
    const res = await call('export_evidence_bundle', { out_path: outside, response_format: 'json' });
    expect(res.isError).toBe(true);
    expect(JSON.parse(res.content[0].text).error.code).toBe('INVALID_PATH');
    expect(existsSync(outside)).toBe(false);
  });

  it('serves frida://evidence and frida://evidence/{id}', async () => {
    const ok = await call('get_messages', { session_id: DEFAULT_SESSION_ID });
    const id = ok._meta?.evidence_id as string;
    const index = JSON.parse((await harness.client.readResource({ uri: 'frida://evidence' })).contents[0].text as string);
    expect(index[0].id).toBe(id);
    const record = JSON.parse((await harness.client.readResource({ uri: `frida://evidence/${id}` })).contents[0].text as string);
    expect(record.tool).toBe('get_messages');
  });

  it('records nothing when registered with evidence: false', async () => {
    const plain = await makeMcpHarness((server) =>
      registerAllTools(server, makeDeviceManager(makeDevice()), { resources: false, prompts: false, evidence: false, ...FULL_TOOL_POLICY })
    );
    try {
      const ok = (await plain.client.callTool({ name: 'get_messages', arguments: { session_id: DEFAULT_SESSION_ID } })) as CallResult;
      const res = await call('get_evidence', { evidence_id: ok._meta?.evidence_id as string });
      expect(res.isError).toBe(true);
    } finally {
      await plain.close();
    }
  });
});
