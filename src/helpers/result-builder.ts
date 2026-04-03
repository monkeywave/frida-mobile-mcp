import { encode as encodeToon } from '@toon-format/toon';
import type { ToolResult, SuggestedAction, SessionContext, ErrorResponse } from '../types.js';
import { getState } from '../state.js';
import { FridaMcpError } from './errors.js';
import { CHARACTER_LIMIT, ResponseFormat } from '../constants.js';

const MAX_MARKDOWN_DEPTH = 10;
const keyCache = new Map<string, string>();
const INDENTS = Array.from({ length: MAX_MARKDOWN_DEPTH + 1 }, (_, i) => '  '.repeat(i));

export function buildResult<T>(
  result: T,
  suggestedNext: SuggestedAction[] = []
): ToolResult<T> {
  const state = getState();
  return {
    result,
    session_context: state.getSessionContext(),
    suggested_next: suggestedNext,
  };
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

  let text = renderText(result, format);

  if (text.length > CHARACTER_LIMIT) {
    text = text.slice(0, CHARACTER_LIMIT) +
      '\n\n_...response truncated. Use pagination parameters (limit, offset/since) or switch to `response_format: "json"` for full data._';
  }

  return {
    content: [{ type: 'text', text }],
    structuredContent: { ...result } as Record<string, unknown>,
  };
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
    `**Error**: ${err.error.code}`,
    '',
    err.error.message,
  ];
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
  const { result, session_context, suggested_next } = toolResult;
  const lines: string[] = [];

  formatObject(result as Record<string, unknown>, lines, 0);

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
