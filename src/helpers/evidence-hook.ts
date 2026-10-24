/**
 * Tool handler decorator (plugged into `ToolPolicy.wrapHandler`) that times every tool call,
 * persists its result in the evidence store and writes one central audit line per call.
 *
 * `formatToolResponse` is the single place that mints an `evidence_id` (on the envelope, the
 * error body and `_meta`); this hook only reads it back. The one exception is a handler that
 * throws before it could build a response: that call still gets a record and an audit line.
 */
import { randomUUID } from 'node:crypto';
import { audit } from './logger.js';
import { isRecord } from './sanitize.js';
import {
  isEvidenceStoreEnabled,
  recordEvidence,
  redactParams,
  type EvidenceRecord,
  type EvidenceStatus,
} from './evidence-store.js';

type ToolHandler = (...args: any[]) => unknown;

interface ToolResponse {
  content?: Array<{ type: string; text?: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
}

/**
 * Tools that read the store itself: recording them would copy stored records into new ones
 * (a `get_evidence` of a `get_evidence` record doubles in size each time).
 */
const NOT_RECORDED = new Set(['get_evidence', 'export_evidence_bundle']);

export function evidenceWrapHandler(name: string, cb: ToolHandler): ToolHandler {
  return async (...callArgs: unknown[]) => {
    const params = toolParams(callArgs);
    const startedAt = Date.now();
    let response: ToolResponse | undefined;
    try {
      response = (await cb(...callArgs)) as ToolResponse | undefined;
    } catch (err) {
      persist(name, params, startedAt, randomUUID(), 'error', { message: err instanceof Error ? err.message : String(err) });
      throw err;
    }
    if (!isRecord(response)) return response;
    const status: EvidenceStatus = response.isError ? 'error' : 'success';
    const structured = status === 'error' ? errorBody(response) : response.structuredContent;
    persist(name, params, startedAt, evidenceIdOf(response), status, structured);
    return response;
  };
}

/**
 * Tool arguments of a handler call. Tools with an input schema get `(args, extra)`; tools
 * without one get only `(extra)`, which is not user input.
 */
function toolParams(callArgs: unknown[]): unknown {
  return callArgs.length >= 2 ? callArgs[0] : {};
}

/** The id `formatToolResponse` stamped on the success envelope, the error body or `_meta`. */
function evidenceIdOf(response: ToolResponse): string | undefined {
  const error = isRecord(response._meta?.error) ? response._meta.error : {};
  const id = response.structuredContent?.evidence_id ?? error.evidence_id ?? response._meta?.evidence_id;
  return typeof id === 'string' ? id : undefined;
}

function errorBody(response: ToolResponse): unknown {
  if (response._meta?.error) return response._meta.error;
  const text = response.content?.map((c) => c.text ?? '').join('\n') ?? '';
  return { message: text };
}

function persist(
  tool: string,
  rawParams: unknown,
  startedAt: number,
  evidenceId: string | undefined,
  status: EvidenceStatus,
  structured: unknown,
): void {
  const record = buildRecord(tool, rawParams, startedAt, evidenceId ?? '', status, structured);
  if (evidenceId && isEvidenceStoreEnabled() && !NOT_RECORDED.has(tool)) recordEvidence(record);
  audit({
    timestamp: record.timestamp,
    sessionId: record.session_id,
    tool,
    params: record.params,
    status,
    durationMs: record.duration_ms,
    evidence_id: evidenceId,
    scriptHash: record.script_sha256,
  });
}

function buildRecord(
  tool: string,
  rawParams: unknown,
  startedAt: number,
  evidenceId: string,
  status: EvidenceStatus,
  structured: unknown,
): EvidenceRecord {
  const args = isRecord(rawParams) ? rawParams : {};
  const envelope = isRecord(structured) ? structured : {};
  const result = isRecord(envelope.result) ? envelope.result : {};
  const sessionContext = isRecord(envelope.session_context) ? envelope.session_context : {};
  const record: EvidenceRecord = {
    evidence_id: evidenceId,
    timestamp: new Date().toISOString(),
    tool,
    status,
    params: redactParams(args),
    duration_ms: Date.now() - startedAt,
    structured: structured ?? null,
  };
  const sessionId = stringOrUndefined(args.session_id) ?? stringOrUndefined(result.session_id);
  if (sessionId) record.session_id = sessionId;
  const device = stringOrUndefined(sessionContext.device);
  if (device) record.device = device;
  const scriptSha = stringOrUndefined(result.source_sha256);
  if (scriptSha) record.script_sha256 = scriptSha;
  return record;
}

function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}
