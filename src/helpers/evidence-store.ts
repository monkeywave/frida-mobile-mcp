/**
 * Persistent evidence store: every tool result (success or error) is written as one JSON file
 * so an agent or a human can cite, re-read and export it later by its `evidence_id`.
 *
 * Layout under the root (default `~/.config/frida-mobile-mcp/evidence`):
 *   <root>/YYYY-MM-DD/<evidence_id>.json   one record per tool call (mode 0600, dirs 0700)
 *   <root>/index.jsonl                     append-only index rows (compacted when stale)
 *
 * All I/O is synchronous (like the audit log) and never throws into a tool call: failures are
 * logged and the call proceeds without a stored record.
 */
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { EVIDENCE_DEFAULTS, getConfigPath } from '../config.js';
import { getPackageVersion } from './version.js';
import { log } from './logger.js';
import { isRecord, sha256Hex } from './sanitize.js';
import { formatErrorAsMarkdown, resultToMarkdown } from './result-builder.js';
import type { ErrorResponse, EvidenceStoreConfig, ToolResult } from '../types.js';

export type EvidenceStatus = 'success' | 'error';

/** One stored tool call. `structured` is the tool's structuredContent, or the error body. */
export interface EvidenceRecord {
  evidence_id: string;
  timestamp: string;
  tool: string;
  status: EvidenceStatus;
  params: Record<string, unknown>;
  session_id?: string;
  device?: string;
  duration_ms: number;
  script_sha256?: string;
  structured: unknown;
  /** Store-level notes (e.g. the record was truncated to fit `maxEntryKb`). */
  limitations?: string[];
}

/** One row of `index.jsonl`; `path` is relative to the store root. */
export interface EvidenceIndexRow {
  id: string;
  timestamp: string;
  tool: string;
  status: EvidenceStatus;
  session_id?: string;
  device?: string;
  bytes: number;
  path: string;
}

export interface EvidenceBundle {
  generated_at: string;
  server: { name: string; version: string };
  count: number;
  records: EvidenceRecord[];
  /** Requested ids that are not (or no longer) in the store. */
  missing?: string[];
}

export type EvidenceBundleFormat = 'json' | 'markdown';

interface StoreState {
  root: string;
  maxBytes: number;
  maxEntries: number;
  maxEntryBytes: number;
  /** Live entries in insertion (= chronological) order. */
  entries: Map<string, EvidenceIndexRow>;
  totalBytes: number;
  /** Rows of evicted records still in index.jsonl since the last compaction. */
  staleRows: number;
  /** The day directory most recently created, so `mkdirSync` runs once per day. */
  lastDayDir?: string;
}

const INDEX_FILE = 'index.jsonl';
const DIR_MODE = 0o700;
const FILE_MODE = 0o600;
const EVIDENCE_ID_PATTERN = /^[A-Za-z0-9-]{1,128}$/;
const SERVER_NAME = 'frida-mobile-mcp';

let store: StoreState | null = null;

/** Default store root, next to the config file and audit log. */
function defaultEvidenceRoot(): string {
  return path.join(path.dirname(getConfigPath()), 'evidence');
}

/** Whether `initEvidenceStore` enabled the store. */
export function isEvidenceStoreEnabled(): boolean {
  return store !== null;
}

/** Root of the active store, or null when disabled. */
export function getEvidenceRoot(): string | null {
  return store?.root ?? null;
}

/** (Re)initialise the store; reads index.jsonl once, drops rows whose file is gone and rewrites it compacted. */
export function initEvidenceStore(opts: EvidenceStoreConfig = {}): void {
  store = null;
  if (opts.enabled === false) return;
  const root = path.resolve(opts.path ?? defaultEvidenceRoot());
  try {
    mkdirSync(root, { recursive: true, mode: DIR_MODE });
    const next: StoreState = {
      root,
      maxBytes: (opts.maxMb ?? EVIDENCE_DEFAULTS.maxMb) * 1024 * 1024,
      maxEntries: opts.maxEntries ?? EVIDENCE_DEFAULTS.maxEntries,
      maxEntryBytes: (opts.maxEntryKb ?? EVIDENCE_DEFAULTS.maxEntryKb) * 1024,
      entries: new Map(),
      totalBytes: 0,
      staleRows: 0,
    };
    loadIndex(next);
    rewriteIndex(next);
    store = next;
  } catch (err) {
    log('error', `Evidence store disabled: cannot initialise ${root}: ${String(err)}`);
  }
}

function loadIndex(state: StoreState): void {
  const indexPath = path.join(state.root, INDEX_FILE);
  if (!existsSync(indexPath)) return;
  const present = listRecordFiles(state.root);
  for (const line of readFileSync(indexPath, 'utf-8').split('\n')) {
    const row = line.trim() ? parseIndexRow(line) : null;
    if (row && present.has(row.path)) replaceEntry(state, row);
  }
}

/** Relative paths (`YYYY-MM-DD/<id>.json`) of every record file under the root. */
function listRecordFiles(root: string): Set<string> {
  const files = new Set<string>();
  for (const day of readdirSync(root, { withFileTypes: true })) {
    if (!day.isDirectory()) continue;
    for (const file of readdirSync(path.join(root, day.name))) files.add(path.join(day.name, file));
  }
  return files;
}

function parseIndexRow(line: string): EvidenceIndexRow | null {
  try {
    const row = JSON.parse(line) as EvidenceIndexRow;
    if (typeof row.id !== 'string' || typeof row.path !== 'string' || typeof row.bytes !== 'number') return null;
    if (!EVIDENCE_ID_PATTERN.test(row.id) || row.path.includes('..')) return null;
    return row;
  } catch {
    return null;
  }
}

function rewriteIndex(state: StoreState): void {
  const indexPath = path.join(state.root, INDEX_FILE);
  const tmpPath = `${indexPath}.tmp`;
  const body = Array.from(state.entries.values()).map((row) => JSON.stringify(row) + '\n').join('');
  writeFileSync(tmpPath, body, { mode: FILE_MODE });
  renameSync(tmpPath, indexPath);
  state.staleRows = 0;
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/** Persist `rec`; returns its index row, or null when the store is disabled or the write failed. */
export function recordEvidence(rec: EvidenceRecord): EvidenceIndexRow | null {
  const state = store;
  if (!state || !EVIDENCE_ID_PATTERN.test(rec.evidence_id)) return null;
  try {
    const { json, bytes } = serializeWithinLimit(rec, state.maxEntryBytes);
    const fileName = `${rec.evidence_id}.json`;
    const day = rec.timestamp.slice(0, 10);
    writeFileSync(path.join(ensureDayDir(state, day), fileName), json, { mode: FILE_MODE });
    const row = indexRowFor(rec, path.join(day, fileName), bytes);
    appendFileSync(path.join(state.root, INDEX_FILE), JSON.stringify(row) + '\n', { mode: FILE_MODE });
    replaceEntry(state, row);
    evictOldest(state);
    return row;
  } catch (err) {
    log('error', `Failed to store evidence ${rec.evidence_id}: ${String(err)}`);
    return null;
  }
}

function indexRowFor(rec: EvidenceRecord, relPath: string, bytes: number): EvidenceIndexRow {
  const row: EvidenceIndexRow = { id: rec.evidence_id, timestamp: rec.timestamp, tool: rec.tool, status: rec.status, bytes, path: relPath };
  if (rec.session_id) row.session_id = rec.session_id;
  if (rec.device) row.device = rec.device;
  return row;
}

/** Create the day directory for `day` unless it is the one created last. */
function ensureDayDir(state: StoreState, day: string): string {
  const dir = path.join(state.root, day);
  if (state.lastDayDir !== dir) {
    mkdirSync(dir, { recursive: true, mode: DIR_MODE });
    state.lastDayDir = dir;
  }
  return dir;
}

function replaceEntry(state: StoreState, row: EvidenceIndexRow): void {
  const previous = state.entries.get(row.id);
  if (previous) {
    state.totalBytes -= previous.bytes;
    state.entries.delete(row.id);
  }
  state.entries.set(row.id, row);
  state.totalBytes += row.bytes;
}

/** Serialize `rec`; when it exceeds `maxBytes`, replace the bulky result with a size marker. */
function serializeWithinLimit(rec: EvidenceRecord, maxBytes: number): { json: string; bytes: number } {
  const json = JSON.stringify(rec);
  const bytes = Buffer.byteLength(json, 'utf-8');
  if (bytes <= maxBytes) return { json, bytes };
  const truncated: EvidenceRecord = {
    ...rec,
    structured: truncateStructured(rec.structured, bytes),
    limitations: [
      ...(rec.limitations ?? []),
      `Stored record truncated: ${bytes} bytes exceeds the evidence maxEntryKb limit (${Math.floor(maxBytes / 1024)} KB); the result payload was not persisted.`,
    ],
  };
  const truncatedJson = JSON.stringify(truncated);
  return { json: truncatedJson, bytes: Buffer.byteLength(truncatedJson, 'utf-8') };
}

function truncateStructured(structured: unknown, bytes: number): unknown {
  const marker = { truncated: true, bytes };
  if (!structured || typeof structured !== 'object' || !('result' in structured)) return marker;
  const { raw_result: _dropped, ...rest } = structured as Record<string, unknown>;
  return { ...rest, result: marker };
}

/**
 * Delete the oldest records until the store is within `maxBytes` and `maxEntries`, and compact
 * index.jsonl once the evicted rows outnumber the live ones.
 */
function evictOldest(state: StoreState): void {
  for (const [id, row] of state.entries) {
    if (state.entries.size <= 1) break;
    if (state.totalBytes <= state.maxBytes && state.entries.size <= state.maxEntries) break;
    removeRecordFile(state, row.path);
    state.entries.delete(id);
    state.totalBytes -= row.bytes;
    state.staleRows += 1;
  }
  if (state.staleRows > state.entries.size) rewriteIndex(state);
}

function removeRecordFile(state: StoreState, relPath: string): void {
  const absPath = path.join(state.root, relPath);
  try {
    unlinkSync(absPath);
  } catch { /* already gone */ }
  const dayDir = path.dirname(absPath);
  if (dayDir === state.lastDayDir) return; // the newest record's day directory stays in use
  try {
    rmdirSync(dayDir); // only succeeds once the day directory is empty
  } catch { /* not empty */ }
}

// ---------------------------------------------------------------------------
// Parameter redaction
// ---------------------------------------------------------------------------

/** Keys whose string value is code/payload: stored as `{ sha256, length }` only. */
const HASHED_KEYS = new Set(['source', 'script', 'data', 'on_enter', 'on_leave']);
/** Keys holding credentials: never stored. */
const DROPPED_KEYS = new Set(['token', 'certificate', 'http_token']);
export const MAX_PARAM_STRING = 2048;
const TRUNCATION_SUFFIX = '…[truncated]';
const MAX_REDACT_DEPTH = 8;
/** Stored in place of an object/array nested beyond MAX_REDACT_DEPTH (it is not redacted, so not kept). */
export const NESTED_TOO_DEEP = '[nested too deep]';

/** Tool arguments as they are stored in evidence records and the audit log. */
export function redactParams(args: unknown): Record<string, unknown> {
  if (!isRecord(args)) return {};
  return redactObject(args, 0);
}

function redactObject(obj: Record<string, unknown>, depth: number): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (DROPPED_KEYS.has(key)) continue;
    if (HASHED_KEYS.has(key) && typeof value === 'string') {
      out[key] = { sha256: sha256Hex(value), length: value.length };
    } else {
      out[key] = redactValue(value, depth + 1);
    }
  }
  return out;
}

function redactValue(value: unknown, depth: number): unknown {
  if (typeof value === 'string') return capString(value);
  if (depth > MAX_REDACT_DEPTH) return Array.isArray(value) || isRecord(value) ? NESTED_TOO_DEEP : value;
  if (Array.isArray(value)) return value.map((item) => redactValue(item, depth + 1));
  if (isRecord(value)) return redactObject(value, depth);
  return value;
}

function capString(value: string): string {
  return value.length <= MAX_PARAM_STRING ? value : value.slice(0, MAX_PARAM_STRING) + TRUNCATION_SUFFIX;
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/** The stored record for `id`, or null when unknown, evicted or unreadable. */
export function getEvidence(id: string): EvidenceRecord | null {
  const state = store;
  if (!state || !EVIDENCE_ID_PATTERN.test(id)) return null;
  const row = state.entries.get(id);
  if (!row) return null;
  try {
    return JSON.parse(readFileSync(path.join(state.root, row.path), 'utf-8')) as EvidenceRecord;
  } catch (err) {
    log('warn', `Failed to read evidence ${id}: ${String(err)}`);
    return null;
  }
}

export interface ListEvidenceOptions {
  session_id?: string;
  tool?: string;
  /** ISO timestamp or epoch milliseconds (number or numeric string). */
  since?: string | number;
  limit?: number;
}

/** Index rows matching the filters, newest first. */
export function listEvidence(opts: ListEvidenceOptions = {}): EvidenceIndexRow[] {
  const state = store;
  if (!state) return [];
  const sinceMs = parseSince(opts.since);
  const limit = opts.limit ?? Number.POSITIVE_INFINITY;
  const rows = Array.from(state.entries.values()).reverse();
  const matches: EvidenceIndexRow[] = [];
  for (const row of rows) {
    if (matches.length >= limit) break;
    if (opts.session_id !== undefined && row.session_id !== opts.session_id) continue;
    if (opts.tool !== undefined && row.tool !== opts.tool) continue;
    if (sinceMs !== undefined && Date.parse(row.timestamp) < sinceMs) continue;
    matches.push(row);
  }
  return matches;
}

/** `since` as epoch ms: numbers and numeric strings are epoch ms, anything else is parsed as a date. */
export function parseSince(since: string | number | undefined): number | undefined {
  if (since === undefined || since === '') return undefined;
  if (typeof since === 'number') return since;
  if (/^\d+$/.test(since.trim())) return Number(since.trim());
  const parsed = Date.parse(since);
  return Number.isNaN(parsed) ? undefined : parsed;
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/** Bundle the stored records for `ids` (in the given order). */
export function buildEvidenceBundle(ids: string[]): EvidenceBundle {
  const records: EvidenceRecord[] = [];
  const missing: string[] = [];
  for (const id of ids) {
    const record = getEvidence(id);
    if (record) records.push(record);
    else missing.push(id);
  }
  const bundle: EvidenceBundle = {
    generated_at: new Date().toISOString(),
    server: { name: SERVER_NAME, version: getPackageVersion() },
    count: records.length,
    records,
  };
  if (missing.length > 0) bundle.missing = missing;
  return bundle;
}

/** `bundle` rendered as pretty JSON or as a Markdown report. */
export function renderBundle(bundle: EvidenceBundle, format: EvidenceBundleFormat): string {
  return format === 'markdown' ? bundleToMarkdown(bundle) : JSON.stringify(bundle, null, 2);
}

function bundleToMarkdown(bundle: EvidenceBundle): string {
  const lines: string[] = [
    '# Evidence bundle',
    '',
    `- **Generated**: ${bundle.generated_at}`,
    `- **Server**: ${bundle.server.name} ${bundle.server.version}`,
    `- **Records**: ${bundle.count}`,
  ];
  if (bundle.missing?.length) lines.push(`- **Missing ids**: ${bundle.missing.join(', ')}`);
  bundle.records.forEach((record, index) => lines.push('', ...recordToMarkdown(record, index + 1)));
  return lines.join('\n') + '\n';
}

function recordToMarkdown(record: EvidenceRecord, position: number): string[] {
  const structured = isRecord(record.structured) ? record.structured : {};
  const lines: string[] = [
    `## ${position}. ${record.tool} (${record.status})`,
    '',
    `- **Evidence ID**: ${record.evidence_id}`,
    `- **Timestamp**: ${record.timestamp}`,
    `- **Duration**: ${record.duration_ms} ms`,
    `- **Session**: ${record.session_id ?? '—'}`,
    `- **Device**: ${record.device ?? '—'}`,
    `- **Script SHA-256**: ${record.script_sha256 ?? '—'}`,
  ];
  const limitations = [...(record.limitations ?? []), ...asStringArray(structured.limitations)];
  lines.push(`- **Limitations**: ${limitations.length ? '' : 'none'}`);
  for (const limitation of limitations) lines.push(`  - ${limitation}`);
  lines.push(`- **Coverage**: ${formatCoverage(structured.coverage)}`);
  lines.push('', '**Parameters:**', '', '```json', JSON.stringify(record.params, null, 2), '```', '');
  lines.push(...renderPayload(record, structured));
  return lines;
}

function renderPayload(record: EvidenceRecord, structured: Record<string, unknown>): string[] {
  if (record.status === 'error' && typeof structured.code === 'string') {
    return [formatErrorAsMarkdown({ error: structured } as unknown as ErrorResponse)];
  }
  if ('result' in structured) {
    return ['**Result:**', '', resultToMarkdown({ result: structured.result } as ToolResult)];
  }
  return ['```json', JSON.stringify(record.structured, null, 2), '```'];
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

function formatCoverage(coverage: unknown): string {
  if (!isRecord(coverage) || typeof coverage.status !== 'string') return 'unknown';
  return coverage.note ? `${coverage.status} (${String(coverage.note)})` : coverage.status;
}
