import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import { getState } from '../state.js';
import { buildResult, formatToolResponse, formatToolResponseDetailed, pagedCoverage, type TrimmedArray } from '../helpers/result-builder.js';
import { FridaMcpError } from '../helpers/errors.js';
import { responseFormatSchema, getCharacterLimit, type ResponseFormat } from '../constants.js';
import type { EvidenceMeta, ScriptEntry } from '../types.js';

/**
 * Whether maxMessageBuffer evicted messages a reader at `cursor` never saw: some script's
 * newest evicted message is after the cursor. Returns the newest such seq, or null.
 */
export function findEvictionLoss(scripts: Iterable<ScriptEntry>, cursor: number): number | null {
  const lost = Array.from(scripts, (s) => s.lastEvictedSeq ?? -1).filter((seq) => seq > cursor);
  return lost.length > 0 ? Math.max(...lost) : null;
}

/** Coverage/limitations for one get_messages page (REA `coverage { scope, status, next_offset }`). */
export function messagesEvidenceMeta(
  sessionId: string,
  nextCursor: number,
  limitHit: boolean,
  lastEvictedSeq: number | null,
  maxMessageBuffer: number,
): EvidenceMeta {
  const evicted = lastEvictedSeq !== null;
  return {
    limitations: evicted
      ? [
          `messages before seq ${lastEvictedSeq + 1} were evicted (maxMessageBuffer=${maxMessageBuffer}); ` +
            'raise maxMessageBuffer or poll more often',
        ]
      : [],
    coverage: pagedCoverage(`session:${sessionId}`, evicted || limitHit, nextCursor),
  };
}


export type MessageRow = { script_id: string; script_name?: string; index: number; seq: number; timestamp: number; type: string; payload: unknown };

/** A returned message whose payload was cut to a preview so it fits the response on its own. */
export type CutMessageRow = MessageRow & { payload_truncated: true; payload_chars: number };

type DetailedResponse = ReturnType<typeof formatToolResponseDetailed>;

/** Renders the first `count` messages; with `payloadPreviewChars`, the last one's payload is cut. */
export type MessagesPageRenderer = (count: number, payloadPreviewChars?: number) => DetailedResponse;

interface MessagesPageInput {
  sessionId: string;
  session: { scripts: Map<string, ScriptEntry> };
  matched: MessageRow[];
  count: number;
  startCursor: number;
  matchingScripts: ScriptEntry[];
  maxMessageBuffer: number;
  format: ResponseFormat | undefined;
  /** Cut the last shown message's payload to this many serialized chars (oversized single message). */
  payloadPreviewChars?: number;
}

/** Replace a payload by a prefix of its JSON serialization, recording the original size. */
export function cutMessagePayload(row: MessageRow, previewChars: number): CutMessageRow {
  const serialized = JSON.stringify(row.payload) ?? String(row.payload);
  return { ...row, payload: serialized.slice(0, Math.max(0, previewChars)), payload_truncated: true, payload_chars: serialized.length };
}

function shownMessages(matched: MessageRow[], count: number, payloadPreviewChars: number | undefined): Array<MessageRow | CutMessageRow> {
  const shown: Array<MessageRow | CutMessageRow> = matched.slice(0, count);
  if (payloadPreviewChars !== undefined && shown.length > 0) {
    shown[shown.length - 1] = cutMessagePayload(matched[shown.length - 1], payloadPreviewChars);
  }
  return shown;
}

function payloadCutLimitation(seq: number): string {
  return `message seq ${seq} alone exceeds the response character limit; its payload was cut to a preview ` +
    '(payload_truncated: true, payload_chars = original size). The cursor moves past it; read structuredContent for the full payload.';
}

/**
 * Render the first `count` messages. The cursor (`last_index`, coverage.next_offset) points right
 * after the last message actually returned, so paging with `since` never skips messages that were
 * cut by `limit` or by the response character limit.
 */
function renderMessagesPage(input: MessagesPageInput) {
  const { sessionId, session, matched, count, startCursor, matchingScripts, maxMessageBuffer, format, payloadPreviewChars } = input;
  const shown = shownMessages(matched, count, payloadPreviewChars);
  const payloadCut = payloadPreviewChars !== undefined && shown.length > 0;
  const remaining = matched.length - shown.length;
  const truncated = remaining > 0 || payloadCut;
  const lastIndex = shown.at(-1)?.seq ?? startCursor; // matched is sorted by seq
  const meta = messagesEvidenceMeta(sessionId, lastIndex, truncated, findEvictionLoss(matchingScripts, startCursor), maxMessageBuffer);
  if (payloadCut) meta.limitations = [...(meta.limitations ?? []), payloadCutLimitation(lastIndex)];
  return formatToolResponseDetailed(
    buildResult(
      {
        session_id: sessionId,
        messages_count: shown.length,
        messages: shown,
        last_index: lastIndex,
        truncated,
        remaining,
        active_scripts: Array.from(session.scripts.values()).map((s) => ({
          id: s.id,
          name: s.name,
          message_count: s.messages.length,
        })),
      },
      [
        ...(remaining > 0
          ? [{ tool: 'get_messages', args: { session_id: sessionId, since: lastIndex }, reason: `Get the ${remaining} remaining messages` }]
          : []),
        { tool: 'hook_method', reason: 'Add more hooks to capture more data' },
        { tool: 'stop_instrumentation', args: { session_id: sessionId }, reason: 'Clean up when done' },
      ],
      meta,
    ),
    format,
  );
}

/**
 * Estimated page size after the formatter trimmed the first render, never more than
 * min(maxCount, matched.length). The formatter's own cut (`kept`) is a floor; beyond it, extend
 * while the cumulative serialized size stays within the room the trimmed render left (its
 * serialized kept-slice plus the unused part of the character limit). Only a guess: the size
 * model is JSON while the output may be TOON/Markdown, so callers must verify the render.
 */
export function pageCountAfterTrim(
  matched: readonly MessageRow[],
  trimmed: readonly TrimmedArray[],
  renderedLength: number,
  limit: number,
  maxCount: number = matched.length,
): number {
  const cap = Math.max(0, Math.min(maxCount, matched.length));
  if (cap === 0) return 0;
  const kept = Math.min(trimmed.find((t) => t.label === 'messages')?.kept ?? 0, cap);
  const sizes = matched.slice(0, cap).map((m) => JSON.stringify(m).length);
  const sumOf = (count: number) => sizes.slice(0, count).reduce((a, b) => a + b, 0);
  const allowed = sumOf(kept) + Math.max(0, limit - renderedLength);
  let count = Math.max(1, kept);
  let total = sumOf(count);
  while (count < cap && total + sizes[count] <= allowed) total += sizes[count++];
  return count;
}

/**
 * Whether the render hid some of its `messages` (response character limit or the Markdown list
 * cap). Other arrays (active_scripts) being cut does not move the cursor, so it is ignored.
 */
export function messagesTrimmed(rendered: DetailedResponse): boolean {
  return rendered.trimmed.some((t) => t.label === 'messages');
}

/**
 * Largest page in [1, cap) whose render is untrimmed, found by binary search on the structured
 * `trimmed` signal (`cap` itself is known to be trimmed); `guess` is probed first to save renders.
 * Null when even a single message is trimmed.
 */
export function largestUntrimmedPage(render: MessagesPageRenderer, cap: number, guess: number): DetailedResponse | null {
  let fits = 0;
  let overflows = cap;
  let best: DetailedResponse | null = null;
  const probe = (count: number) => {
    const rendered = render(count);
    if (!messagesTrimmed(rendered)) { fits = count; best = rendered; } else overflows = count;
  };
  if (guess > fits && guess < overflows) probe(guess);
  while (overflows - fits > 1) probe(Math.floor((fits + overflows) / 2));
  return best;
}

/** A single oversized message: cut its payload preview until the render is untrimmed. */
export function singleMessageWithCutPayload(render: MessagesPageRenderer, characterLimit: number): DetailedResponse {
  let preview = Math.floor(characterLimit / 2);
  let rendered = render(1, preview);
  while (messagesTrimmed(rendered) && preview > 0) {
    preview = Math.floor(preview / 2);
    rendered = render(1, preview);
  }
  return rendered;
}

/**
 * The page actually returned: the largest render whose text is untrimmed, so the cursor always
 * equals the last message present in the rendered text (whatever the response format).
 */
export function fitMessagesPage(
  render: MessagesPageRenderer,
  cap: number,
  estimate: (trimmedFirst: DetailedResponse) => number,
  characterLimit: number,
): DetailedResponse {
  const first = render(cap);
  if (!messagesTrimmed(first) || cap === 0) return first;
  return largestUntrimmedPage(render, cap, estimate(first)) ?? singleMessageWithCutPayload(render, characterLimit);
}

export function registerMessagesTool(server: McpServer): void {
  server.registerTool(
    'get_messages',
    {
      title: 'Get Script Messages',
      description: 'Retrieve buffered messages from active scripts and hooks. Messages include hook invocations, trace hits, script output (send() calls), and errors. Use "since" for pagination to get only new messages.',
      inputSchema: z.object({
        session_id: z.string().describe('Session ID to get messages from'),
        script_id: z.string().optional().describe('Filter to a specific script'),
        since: z.number().optional().describe('Session-global cursor: pass the `last_index` from the previous call to get only messages strictly after it (exclusive). Pages correctly even across multiple scripts.'),
        limit: z.number().optional().default(50).describe('Max messages to return (default: 50)'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ session_id, script_id, since, limit, response_format }) => {
      try {
        const state = getState();
        const session = state.getSession(session_id);
        if (!session) {
          throw new FridaMcpError(
            'SESSION_NOT_FOUND',
            `Session "${session_id}" not found.`,
            [{ tool: 'get_status', reason: 'List active sessions' }]
          );
        }

        const maxMessages = limit ?? 50;
        const startCursor = since ?? 0;
        let allMessages: Array<{ script_id: string; script_name?: string; index: number; seq: number; timestamp: number; type: string; payload: unknown }> = [];
        const matchingScripts: ScriptEntry[] = [];

        for (const [sid, scriptEntry] of session.scripts) {
          if (script_id && sid !== script_id) continue;
          matchingScripts.push(scriptEntry);

          const filtered = scriptEntry.messages
            .filter((m) => m.seq > startCursor)
            .map((m) => ({
              script_id: sid,
              script_name: scriptEntry.name,
              index: m.index,
              seq: m.seq,
              timestamp: m.timestamp,
              type: m.type,
              payload: m.payload,
            }));
          allMessages.push(...filtered);
        }

        // Order by the global sequence so a merged multi-script stream is stable (timestamps
        // can tie at millisecond resolution; seq cannot).
        allMessages.sort((a, b) => a.seq - b.seq);

        const matched = allMessages;
        const render: MessagesPageRenderer = (count, payloadPreviewChars) => renderMessagesPage({
          sessionId: session_id,
          session,
          matched,
          count,
          startCursor,
          matchingScripts,
          maxMessageBuffer: state.config.maxMessageBuffer,
          format: response_format,
          payloadPreviewChars,
        });
        const cap = Math.max(0, Math.min(maxMessages, matched.length));
        const characterLimit = getCharacterLimit();
        const estimate = (first: { response: { content: Array<{ text: string }> }; trimmed: TrimmedArray[] }) =>
          pageCountAfterTrim(matched, first.trimmed, first.response.content[0].text.length, characterLimit, cap);
        const page = fitMessagesPage(render, cap, estimate, characterLimit);
        return page.response;
      } catch (err) {
        if (err instanceof FridaMcpError) {
          return formatToolResponse(err.toErrorResponse(), response_format);
        }
        throw err;
      }
    }
  );
}
