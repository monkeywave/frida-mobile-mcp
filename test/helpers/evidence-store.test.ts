import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  buildEvidenceBundle,
  getEvidence,
  getEvidenceRoot,
  initEvidenceStore,
  isEvidenceStoreEnabled,
  listEvidence,
  parseSince,
  recordEvidence,
  redactParams,
  renderBundle,
  MAX_PARAM_STRING,
  NESTED_TOO_DEEP,
  type EvidenceRecord,
} from '../../src/helpers/evidence-store.js';
import { sha256Hex } from '../../src/helpers/sanitize.js';

function makeRecord(overrides: Partial<EvidenceRecord> = {}): EvidenceRecord {
  return {
    evidence_id: randomUUID(),
    timestamp: new Date().toISOString(),
    tool: 'get_status',
    status: 'success',
    params: {},
    duration_ms: 3,
    structured: { result: { ok: true }, limitations: [], coverage: { status: 'complete' } },
    ...overrides,
  };
}

function indexLines(root: string): string[] {
  return readFileSync(path.join(root, 'index.jsonl'), 'utf-8').split('\n').filter(Boolean);
}

describe('evidence store', () => {
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(path.join(tmpdir(), 'evidence-store-'));
    initEvidenceStore({ enabled: true, path: root });
  });

  afterEach(() => {
    initEvidenceStore({ enabled: false });
    rmSync(root, { recursive: true, force: true });
  });

  it('is disabled with enabled: false and then records nothing', () => {
    initEvidenceStore({ enabled: false, path: root });
    expect(isEvidenceStoreEnabled()).toBe(false);
    expect(recordEvidence(makeRecord())).toBeNull();
    expect(listEvidence()).toEqual([]);
  });

  it('writes a dated record file plus an index row and reads it back', () => {
    const rec = makeRecord({ session_id: 's1', device: 'Pixel (usb:1)', script_sha256: 'a'.repeat(64) });
    const row = recordEvidence(rec);
    expect(getEvidenceRoot()).toBe(path.resolve(root));
    expect(row?.path).toBe(path.join(rec.timestamp.slice(0, 10), `${rec.evidence_id}.json`));
    expect(existsSync(path.join(root, row!.path))).toBe(true);
    expect(getEvidence(rec.evidence_id)).toEqual(rec);
    const indexed = JSON.parse(indexLines(root)[0]);
    expect(indexed).toMatchObject({ id: rec.evidence_id, tool: 'get_status', status: 'success', session_id: 's1', device: 'Pixel (usb:1)' });
    expect(indexed.bytes).toBeGreaterThan(0);
  });

  it('returns null for unknown or malformed ids', () => {
    expect(getEvidence(randomUUID())).toBeNull();
    expect(getEvidence('../../etc/passwd')).toBeNull();
  });

  it.skipIf(process.platform === 'win32')('creates files with mode 0600 and directories with 0700', () => {
    const row = recordEvidence(makeRecord())!;
    expect(statSync(path.join(root, row.path)).mode & 0o777).toBe(0o600);
    expect(statSync(path.dirname(path.join(root, row.path))).mode & 0o777).toBe(0o700);
    expect(statSync(path.join(root, 'index.jsonl')).mode & 0o777).toBe(0o600);
  });

  it('lists newest first with session, tool, since and limit filters', () => {
    const a = makeRecord({ tool: 'hook_method', session_id: 's1', timestamp: '2026-01-01T00:00:00.000Z' });
    const b = makeRecord({ tool: 'get_messages', session_id: 's1', timestamp: '2026-01-02T00:00:00.000Z' });
    const c = makeRecord({ tool: 'hook_method', session_id: 's2', timestamp: '2026-01-03T00:00:00.000Z' });
    for (const r of [a, b, c]) recordEvidence(r);
    expect(listEvidence().map((r) => r.id)).toEqual([c.evidence_id, b.evidence_id, a.evidence_id]);
    expect(listEvidence({ session_id: 's1' }).map((r) => r.id)).toEqual([b.evidence_id, a.evidence_id]);
    expect(listEvidence({ tool: 'hook_method' }).map((r) => r.id)).toEqual([c.evidence_id, a.evidence_id]);
    expect(listEvidence({ since: '2026-01-02T00:00:00.000Z' }).map((r) => r.id)).toEqual([c.evidence_id, b.evidence_id]);
    expect(listEvidence({ since: Date.parse('2026-01-03T00:00:00.000Z') }).map((r) => r.id)).toEqual([c.evidence_id]);
    expect(listEvidence({ limit: 1 }).map((r) => r.id)).toEqual([c.evidence_id]);
  });

  it('parses since as epoch ms (number or numeric string) or ISO', () => {
    expect(parseSince(5)).toBe(5);
    expect(parseSince('1700000000000')).toBe(1700000000000);
    expect(parseSince('2026-01-01T00:00:00Z')).toBe(Date.parse('2026-01-01T00:00:00Z'));
    expect(parseSince('not a date')).toBeUndefined();
    expect(parseSince(undefined)).toBeUndefined();
  });

  it('evicts the oldest records beyond maxEntries and deletes their files', () => {
    initEvidenceStore({ enabled: true, path: root, maxEntries: 2 });
    const recs = [makeRecord(), makeRecord(), makeRecord()];
    const rows = recs.map((r) => recordEvidence(r)!);
    expect(getEvidence(recs[0].evidence_id)).toBeNull();
    expect(existsSync(path.join(root, rows[0].path))).toBe(false);
    expect(listEvidence().map((r) => r.id)).toEqual([recs[2].evidence_id, recs[1].evidence_id]);
  });

  it('evicts the oldest records beyond maxMb', () => {
    initEvidenceStore({ enabled: true, path: root, maxMb: 0.002, maxEntryKb: 1024 }); // ~2 KB
    const big = () => makeRecord({ structured: { result: { blob: 'x'.repeat(900) } } });
    const recs = [big(), big(), big()];
    for (const r of recs) recordEvidence(r);
    const live = listEvidence();
    expect(live.length).toBeLessThan(3);
    expect(live[0].id).toBe(recs[2].evidence_id);
    expect(live.reduce((sum, r) => sum + r.bytes, 0)).toBeLessThanOrEqual(0.002 * 1024 * 1024);
  });

  it('compacts index.jsonl once it holds more than twice the live entries', () => {
    initEvidenceStore({ enabled: true, path: root, maxEntries: 2 });
    for (let i = 0; i < 6; i++) recordEvidence(makeRecord());
    expect(indexLines(root).length).toBeLessThanOrEqual(4);
    expect(listEvidence()).toHaveLength(2);
  });

  it('stores an oversize record with its result replaced by a truncation marker', () => {
    initEvidenceStore({ enabled: true, path: root, maxEntryKb: 1 });
    const rec = makeRecord({ structured: { result: { blob: 'y'.repeat(5000) }, raw_result: 'z'.repeat(5000), coverage: { status: 'complete' } } });
    recordEvidence(rec);
    const stored = getEvidence(rec.evidence_id)!;
    const structured = stored.structured as Record<string, any>;
    expect(structured.result).toMatchObject({ truncated: true });
    expect(structured.result.bytes).toBeGreaterThan(10_000);
    expect(structured.raw_result).toBeUndefined();
    expect(structured.coverage).toEqual({ status: 'complete' });
    expect(stored.limitations?.[0]).toMatch(/truncated/);
  });

  it('rebuilds its index on init, skipping rows whose file is gone and garbage lines', () => {
    const keep = makeRecord();
    const gone = makeRecord();
    recordEvidence(keep);
    const goneRow = recordEvidence(gone)!;
    rmSync(path.join(root, goneRow.path));
    appendFileSync(path.join(root, 'index.jsonl'), 'not json\n');
    initEvidenceStore({ enabled: true, path: root });
    expect(listEvidence().map((r) => r.id)).toEqual([keep.evidence_id]);
    expect(getEvidence(keep.evidence_id)).toEqual(keep);
    expect(indexLines(root)).toHaveLength(1);
  });

  it('exports a JSON bundle with server info and missing ids', () => {
    const rec = makeRecord();
    recordEvidence(rec);
    const missing = randomUUID();
    const bundle = JSON.parse(renderBundle(buildEvidenceBundle([rec.evidence_id, missing]), 'json'));
    expect(bundle.server.name).toBe('frida-mobile-mcp');
    expect(typeof bundle.server.version).toBe('string');
    expect(bundle.count).toBe(1);
    expect(bundle.records[0]).toEqual(rec);
    expect(bundle.missing).toEqual([missing]);
    expect(buildEvidenceBundle([]).count).toBe(0);
  });

  it('exports a Markdown report with one section per record', () => {
    const ok = makeRecord({ tool: 'hook_method', session_id: 's1', script_sha256: 'b'.repeat(64), structured: { result: { hook_id: 'h1' }, limitations: ['partial'], coverage: { status: 'unknown', note: 'n' } } });
    const err = makeRecord({ tool: 'read_memory', status: 'error', structured: { code: 'SESSION_NOT_FOUND', category: 'request', message: 'gone', retryable: false, recovery_actions: [] } });
    recordEvidence(ok);
    recordEvidence(err);
    const md = renderBundle(buildEvidenceBundle([ok.evidence_id, err.evidence_id]), 'markdown');
    expect(md).toContain('# Evidence bundle');
    expect(md).toContain('## 1. hook_method (success)');
    expect(md).toContain(`- **Script SHA-256**: ${'b'.repeat(64)}`);
    expect(md).toContain('- **Session**: s1');
    expect(md).toContain('  - partial');
    expect(md).toContain('- **Coverage**: unknown (n)');
    expect(md).toContain('**Hook ID**: h1');
    expect(md).toContain('## 2. read_memory (error)');
    expect(md).toContain('**Error**: SESSION_NOT_FOUND');
  });
});

describe('redactParams', () => {
  const sha = sha256Hex;

  it('hashes code/payload fields', () => {
    const out = redactParams({ source: 'send(1)', script: 'x', data: 'deadbeef', on_enter: 'a', on_leave: 'b' });
    expect(out.source).toEqual({ sha256: sha('send(1)'), length: 7 });
    expect(out.script).toEqual({ sha256: sha('x'), length: 1 });
    expect(out.data).toEqual({ sha256: sha('deadbeef'), length: 8 });
    expect(out.on_enter).toEqual({ sha256: sha('a'), length: 1 });
    expect(out.on_leave).toEqual({ sha256: sha('b'), length: 1 });
  });

  it('drops credentials, also nested', () => {
    const out = redactParams({ token: 't', certificate: 'c', http_token: 'h', nested: { token: 'x', keep: 1 } });
    expect(out).toEqual({ nested: { keep: 1 } });
  });

  it('caps long strings and leaves short values and nested objects untouched', () => {
    const evidence = { enabled: true, path: '/tmp/e', maxMb: 5, tags: ['a', 'b'] };
    const out = redactParams({ target: 'x'.repeat(MAX_PARAM_STRING + 10), session_id: 's1', limit: 5, evidence });
    expect(out.target).toBe('x'.repeat(MAX_PARAM_STRING) + '…[truncated]');
    expect(out.session_id).toBe('s1');
    expect(out.limit).toBe(5);
    expect(out.evidence).toEqual(evidence);
  });

  it('replaces objects and arrays nested beyond the depth limit with a marker', () => {
    let deep: Record<string, unknown> = { token: 'deep-secret', blob: 'y'.repeat(MAX_PARAM_STRING + 10), list: [{ token: 'deep-secret' }] };
    for (let i = 0; i < 12; i++) deep = { level: i, child: deep };
    const serialized = JSON.stringify(redactParams({ deep }));
    expect(serialized).not.toContain('deep-secret');
    expect(serialized).not.toContain('y'.repeat(MAX_PARAM_STRING + 1));
    expect(serialized).toContain(JSON.stringify(NESTED_TOO_DEEP));
  });

  it('keeps primitives at the depth limit and caps strings at any depth', () => {
    let deep: unknown = 'z'.repeat(MAX_PARAM_STRING + 10);
    for (let i = 0; i < 12; i++) deep = { n: i, child: deep };
    const serialized = JSON.stringify(redactParams({ deep }));
    expect(serialized).toContain('"n":11');
    expect(serialized).not.toContain('z'.repeat(MAX_PARAM_STRING + 1));
  });

  it('returns an empty object for non-object input', () => {
    expect(redactParams(undefined)).toEqual({});
    expect(redactParams('x')).toEqual({});
  });
});
