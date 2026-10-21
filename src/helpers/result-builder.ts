import { randomUUID } from 'node:crypto';
import { encode as encodeToon } from '@toon-format/toon';
import type { ToolResult, SuggestedAction, ErrorResponse, EvidenceMeta } from '../types.js';
import { getState } from '../state.js';
import { FridaMcpError } from './errors.js';
import { getCharacterLimit, ResponseFormat } from '../constants.js';

const MAX_MARKDOWN_DEPTH = 10;
const keyCache = new Map<string, string>();
const INDENTS = Array.from({ length: MAX_MARKDOWN_DEPTH + 1 }, (_, i) => '  '.repeat(i));

/**
 * Wrap a tool result in the standard envelope. Every result carries an `evidence_id`,
 * `limitations` (default none) and `coverage` (default unknown) so downstream agents can
 * cite it next to static-analysis evidence. Pass `meta.coverage = { status: 'complete' }`
 * when the tool knows it returned everything.
 */
export function buildResult<T>(
  result: T,
  suggestedNext: SuggestedAction[] = [],
  meta: EvidenceMeta = {}
): ToolResult<T> {
  const state = getState();
  const envelope: ToolResult<T> = {
    result,
    session_context: state.getSessionContext(),
    suggested_next: suggestedNext,
    evidence_id: randomUUID(),
    limitations: meta.limitations ? [...meta.limitations] : [],
    coverage: meta.coverage ? { ...meta.coverage } : { status: 'unknown' },
  };
  if (meta.raw_result !== undefined) envelope.raw_result = meta.raw_result;
  return envelope;
}

export function buildErrorResult(error: FridaMcpError): ErrorResponse {
  return error.toErrorResponse();
}

export function formatToolResponse(
  result: ToolResult | ErrorResponse,
  format: ResponseFormat = ResponseFormat.TOON,
): {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
} {
  if ('error' in result) {
    return {
      content: [{ type: 'text', text: renderText(result, format) }],
      isError: true,
    };
  }

  // Keep the text channel under the character limit WITHOUT ever slicing a serialized
  // structure mid-way (which turned a 342-module JSON response into unparseable text).
  // Instead we trim the largest array in a clone and re-render, so the output stays valid
  // JSON/TOON/Markdown; structuredContent below always carries the full, untrimmed result.
  const text = fitRenderedResult(result, format, getCharacterLimit());

  return {
    content: [{ type: 'text', text }],
    structuredContent: { ...result } as Record<string, unknown>,
  };
}

/** A trimmable array on the cloned result payload, with its original length and current kept count. */
interface ArrayHandle {
  label: string;
  originalLength: number;
  kept: number;
  /** Write the current `kept`-length slice back onto the clone's payload. */
  apply(): void;
  /** The current kept slice (for measuring its serialized size). */
  slice(): unknown[];
}

/**
 * Collect every trimmable array: the result payload itself (when it is an array) or each
 * array-valued property. Operates on a shallow clone of the payload so the caller's original
 * result (and thus structuredContent) is never mutated.
 */
function collectArrayHandles(clone: ToolResult): ArrayHandle[] {
  const payload = clone.result;
  if (Array.isArray(payload)) {
    const arr = payload;
    return [{ label: 'result', originalLength: arr.length, kept: arr.length, apply() { clone.result = arr.slice(0, this.kept); }, slice() { return arr.slice(0, this.kept); } }];
  }
  const handles: ArrayHandle[] = [];
  if (payload && typeof payload === 'object') {
    const obj: Record<string, unknown> = { ...(payload as Record<string, unknown>) };
    clone.result = obj;
    for (const [k, v] of Object.entries(obj)) {
      if (Array.isArray(v)) {
        const arr = v;
        handles.push({ label: k, originalLength: arr.length, kept: arr.length, apply() { obj[k] = arr.slice(0, this.kept); }, slice() { return arr.slice(0, this.kept); } });
      }
    }
  }
  return handles;
}

/**
 * Render `result`, trimming to fit `limit` while always producing output valid in `format`.
 * Repeatedly shrinks whichever array is currently largest, so a result with several big arrays
 * (e.g. discover_crypto's java + native + candidates) is trimmed evenly instead of falling back
 * to an empty envelope. structuredContent still carries the full, untrimmed data.
 */
function fitRenderedResult(result: ToolResult, format: ResponseFormat, limit: number): string {
  let text = renderText(result, format);
  if (text.length <= limit) return text;

  const limitations: string[] = [...(result.limitations ?? [])];
  const clone: ToolResult = { ...result, limitations };
  const handles = collectArrayHandles(clone);

  if (handles.length > 0) {
    // Trim to a slightly tighter budget so the truncation note we add afterwards (which isn't
    // present while measuring) does not push the result back over the real limit.
    const budget = Math.max(limit - 400, Math.floor(limit / 2));
    let guard = 0;
    while (guard++ < 10_000) {
      for (const h of handles) h.apply();
      text = renderText(clone, format);
      if (text.length <= budget) break;
      // Shrink the array whose current slice serializes largest.
      let largest: ArrayHandle | null = null;
      let largestSize = -1;
      for (const h of handles) {
        if (h.kept <= 0) continue;
        const size = JSON.stringify(h.slice())?.length ?? 0;
        if (size > largestSize) { largestSize = size; largest = h; }
      }
      if (!largest) break; // everything trimmed to empty and still over budget
      largest.kept = largest.kept > 20 ? Math.floor(largest.kept / 2) : largest.kept - 1;
      if (largest.kept < 0) largest.kept = 0;
    }

    const trimmed = handles.filter((h) => h.kept < h.originalLength);
    if (trimmed.length > 0) {
      const parts = trimmed.map((h) => `${h.kept} of ${h.originalLength} \`${h.label}\``);
      limitations.push(
        `Result truncated to fit the ${limit}-char response limit: showing ${parts.join(', ')}. ` +
          `Request the rest with pagination (limit/offset/since) or read the full structuredContent.`,
      );
      clone.coverage = { status: 'unknown', note: 'truncated to fit response limit' };
    }
    text = renderText(clone, format);
    if (text.length <= limit) return text;
  }

  // Non-array fields alone exceed the limit: emit a minimal, valid envelope rather than an
  // invalid sliced one. The complete data remains available in structuredContent.
  const minimal: ToolResult = {
    ...clone,
    result: {
      truncated: true,
      note: 'Result exceeds the response character limit. Read structuredContent for the full data, or narrow the query / use pagination.',
    },
    coverage: { status: 'unknown', note: 'truncated to fit response limit' },
  };
  return renderText(minimal, format);
}

function renderText(data: ToolResult | ErrorResponse, format: ResponseFormat): string {
  switch (format) {
    case ResponseFormat.TOON:
      return encodeToon(data);
    case ResponseFormat.MARKDOWN:
      return 'error' in data ? formatErrorAsMarkdown(data) : resultToMarkdown(data);
    case ResponseFormat.JSON:
      return JSON.stringify(data, null, 2);
  }
}

// ---------------------------------------------------------------------------
// Markdown formatters
// ---------------------------------------------------------------------------

function formatErrorAsMarkdown(err: ErrorResponse): string {
  const lines: string[] = [
    `**Error**: ${err.error.code} (${err.error.category}${err.error.retryable ? ', retryable' : ''})`,
    '',
    err.error.message,
  ];
  if (err.error.remediation) {
    lines.push('', `**Remediation**: ${err.error.remediation}`);
  }
  if (err.error.recovery_actions?.length) {
    lines.push('', '**Recovery options:**');
    for (const a of err.error.recovery_actions) {
      const desc = a.reason || a.message || a.action || '';
      lines.push(`- ${a.tool ? `\`${a.tool}\`` : 'Action'}: ${desc}`);
    }
  }
  return lines.join('\n');
}

function resultToMarkdown(toolResult: ToolResult): string {
  const { result, session_context, suggested_next, limitations, coverage, evidence_id } = toolResult;
  const lines: string[] = [];

  formatObject(result as Record<string, unknown>, lines, 0);

  if (limitations?.length) {
    lines.push('', '**Limitations:**');
    for (const limitation of limitations) lines.push(`- ${limitation}`);
  }
  const evidenceParts: string[] = [];
  if (evidence_id) evidenceParts.push(`evidence: ${evidence_id}`);
  if (coverage) evidenceParts.push(`coverage: ${coverage.status}${coverage.note ? ` (${coverage.note})` : ''}`);
  if (evidenceParts.length > 0) lines.push('', `_${evidenceParts.join(' | ')}_`);

  if (session_context) {
    const ctx = session_context;
    const parts: string[] = [];
    if (ctx.device) parts.push(`device: ${ctx.device}`);
    if (ctx.platform) parts.push(`platform: ${ctx.platform}`);
    if (ctx.active_sessions?.length) parts.push(`sessions: ${ctx.active_sessions.length}`);
    if (ctx.active_hooks) parts.push(`hooks: ${ctx.active_hooks}`);
    if (ctx.active_scripts) parts.push(`scripts: ${ctx.active_scripts}`);
    if (parts.length > 0) {
      lines.push('', `_Context: ${parts.join(' | ')}_`);
    }
  }

  if (suggested_next?.length) {
    lines.push('', '**Suggested next:**');
    for (const action of suggested_next) {
      const argStr = action.args ? ` ${JSON.stringify(action.args)}` : '';
      lines.push(`- \`${action.tool}${argStr}\` — ${action.reason}`);
    }
  }

  return lines.join('\n');
}

function formatObject(obj: Record<string, unknown>, lines: string[], depth: number): void {
  if (depth >= MAX_MARKDOWN_DEPTH) {
    lines.push(`${indent(depth)}- ${JSON.stringify(obj)}`);
    return;
  }

  for (const [key, value] of Object.entries(obj)) {
    if (value === null || value === undefined) continue;

    const label = humanizeKey(key);

    if (typeof value === 'string' && value.includes('\n')) {
      lines.push(`${indent(depth)}**${label}**:`);
      lines.push(value);
    } else if (Array.isArray(value)) {
      formatArray(label, value, lines, depth);
    } else if (typeof value === 'object') {
      lines.push(`${indent(depth)}**${label}**:`);
      formatObject(value as Record<string, unknown>, lines, depth + 1);
    } else {
      lines.push(`${indent(depth)}- **${label}**: ${formatScalar(value)}`);
    }
  }
}

function formatArray(label: string, arr: unknown[], lines: string[], depth: number): void {
  if (arr.length === 0) {
    lines.push(`${indent(depth)}- **${label}**: _(none)_`);
    return;
  }

  if (arr.every((v) => typeof v !== 'object' || v === null)) {
    if (arr.length <= 5) {
      lines.push(`${indent(depth)}- **${label}**: ${arr.map(formatScalar).join(', ')}`);
    } else {
      lines.push(`${indent(depth)}- **${label}** (${arr.length} items): ${arr.slice(0, 5).map(formatScalar).join(', ')}...`);
    }
    return;
  }

  lines.push(`${indent(depth)}**${label}** (${arr.length}):`);
  const maxItems = 30;
  for (let i = 0; i < Math.min(arr.length, maxItems); i++) {
    const item = arr[i];
    if (item && typeof item === 'object') {
      const compact = compactObject(item as Record<string, unknown>);
      if (compact) {
        lines.push(`${indent(depth + 1)}- ${compact}`);
      } else {
        lines.push(`${indent(depth + 1)}- _item ${i + 1}_:`);
        formatObject(item as Record<string, unknown>, lines, depth + 2);
      }
    } else {
      lines.push(`${indent(depth + 1)}- ${formatScalar(item)}`);
    }
  }
  if (arr.length > maxItems) {
    lines.push(`${indent(depth + 1)}- _...and ${arr.length - maxItems} more_`);
  }
}

function compactObject(obj: Record<string, unknown>): string | null {
  const entries = Object.entries(obj);
  if (entries.length > 6) return null;

  const parts: string[] = [];
  for (const [k, v] of entries) {
    if (v === null || v === undefined) continue;
    if (typeof v === 'object' && v !== null && !Array.isArray(v)) return null;
    if (Array.isArray(v) && v.length > 3) return null;
    if (Array.isArray(v)) {
      parts.push(`${humanizeKey(k)}: [${v.map(formatScalar).join(', ')}]`);
    } else {
      parts.push(`${humanizeKey(k)}: ${formatScalar(v)}`);
    }
  }
  return parts.join(' | ');
}

function formatScalar(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (value === null || value === undefined) return '—';
  return String(value);
}

function humanizeKey(key: string): string {
  const cached = keyCache.get(key);
  if (cached) return cached;
  const result = key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
    .replace(/\bId\b/g, 'ID')
    .replace(/\bPid\b/g, 'PID')
    .replace(/\bSsl\b/g, 'SSL')
    .replace(/\bUrl\b/g, 'URL');
  keyCache.set(key, result);
  return result;
}

function indent(depth: number): string {
  return INDENTS[Math.min(depth, MAX_MARKDOWN_DEPTH)] ?? '  '.repeat(depth);
}
