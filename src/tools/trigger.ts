import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../helpers/errors.js';
import { responseFormatSchema } from '../constants.js';
import { triggerAndCollect } from '../helpers/trigger-and-collect.js';
import { collectDelta } from '../helpers/message-delta.js';
import type { SessionEntry } from '../types.js';

const DEFAULT_TIMEOUT_MS = 6000;
const MAX_DELTA_MESSAGES = 50;

export function registerTriggerTool(server: McpServer): void {
  server.registerTool(
    'trigger_and_wait',
    {
      title: 'Trigger and Wait for Instrumentation',
      description:
        'Correlate a UI action with instrumentation output in one round-trip: optionally perform a mobile_action (tap/launch/type) on the session\'s device, then block until at least `expect_messages` new messages/hook hits arrive (or timeout). Returns exactly the messages the trigger produced and which hooks fired. This is how you confirm "this tap ran the hooked code" — or learn "nothing fired, the hypothesis is wrong" — instead of tapping blindly and polling get_messages. Install hooks first (hook_method / discover_crypto → hook_method), then trigger_and_wait.',
      inputSchema: z.object({
        session_id: z.string().describe('Session with the hooks/scripts whose output to wait for (from explore_app/get_status).'),
        action: z.string().optional().describe('Optional mobile-mcp action to perform as the trigger (e.g. "mobile_click_on_screen_at_coordinates"). Omit to just wait for the next messages.'),
        params: z.record(z.string(), z.unknown()).optional().describe('Parameters for the trigger action (e.g. { x, y }). The session device is injected automatically.'),
        expect_messages: z.number().int().min(1).optional().default(1).describe('Resolve once this many new messages have arrived (default: 1).'),
        timeout_ms: z.number().int().min(0).optional().default(DEFAULT_TIMEOUT_MS).describe(`Max time to wait for new messages after the trigger (default: ${DEFAULT_TIMEOUT_MS}).`),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async ({ session_id, action, params, expect_messages, timeout_ms, response_format }) => {
      // Set just before the trigger so a failure can still report what was already observed.
      let triggerWindow: TriggerWindow | undefined;
      try {
        const state = getState();
        const session = state.getSession(session_id);
        if (!session) {
          throw new FridaMcpError('SESSION_NOT_FOUND', `Session "${session_id}" not found.`, [
            { tool: 'get_status', reason: 'List active sessions' },
          ]);
        }

        const minCount = expect_messages ?? 1;
        const timeoutMs = timeout_ms ?? DEFAULT_TIMEOUT_MS;

        // Guard the capability before the shared primitive performs the action. The single-shot
        // call is intentionally left unbounded (no callTimeoutMs) — only the wait is bounded.
        if (action) guardMobileEnabled();

        triggerWindow = { session, afterSeq: state.currentMessageSeq() };
        const { reached, delta, firedScriptIds, actionResult: triggerResult, afterSeq } =
          await triggerAndCollect(session, { action, params, minCount, timeoutMs });

        // Which hooks fired: a hook whose script emitted a message in this delta. Deriving it from
        // the delta (not a one-time firstSeenTs) means a hook that already fired before still shows
        // up as fired on later triggers — which is the whole point of the tool.
        const firedHooks = Array.from(state.hooks.values())
          .filter((h) => h.sessionId === session_id && firedScriptIds.has(h.scriptId))
          .map((h) => ({ id: h.id, target: h.target, type: h.type }));

        return formatToolResponse(
          buildResult(
            {
              session_id,
              triggered: action ?? null,
              trigger_result: triggerResult,
              reached,
              timed_out: !reached,
              new_message_count: delta.length,
              fired_hooks: firedHooks,
              new_messages: delta.slice(0, MAX_DELTA_MESSAGES),
            },
            reached
              ? [
                  { tool: 'get_messages', args: { session_id, since: afterSeq }, reason: 'Read the full set of new messages' },
                ]
              : [
                  { tool: 'get_status', args: { session_id }, reason: 'Nothing fired — check hook liveness (installed but not fired? wrong class/overload?)' },
                  { tool: 'discover_crypto', args: { session_id }, reason: 'Re-discover the real target if the hypothesis missed' },
                ],
            !reached
              ? { limitations: [`No new instrumentation output within ${timeoutMs}ms of the trigger. The hooked code path may not have run, or the hook did not attach — check get_status hook liveness.`] }
              : {},
          ),
          response_format,
        );
      } catch (err) {
        const error = err instanceof FridaMcpError ? err : wrapFridaError(err);
        return formatToolResponse(withObservedDelta(error, triggerWindow).toErrorResponse(), response_format);
      }
    },
  );
}

interface TriggerWindow {
  session: SessionEntry;
  afterSeq: number;
}

/**
 * The trigger failed (e.g. the mobile action threw or timed out): keep any messages the
 * instrumentation produced since the trigger started as `details.partial_observation`.
 */
function withObservedDelta(error: FridaMcpError, window: TriggerWindow | undefined): FridaMcpError {
  if (!window) return error;
  const delta = collectDelta(window.session, window.afterSeq);
  if (delta.length === 0) return error;
  return error.withPartialObservation(capObservedDelta(window.afterSeq, delta));
}

/** Error responses bypass `fitRenderedResult`, so cap the delta like the success path does. */
function capObservedDelta(afterSeq: number, delta: unknown[]): Record<string, unknown> {
  if (delta.length <= MAX_DELTA_MESSAGES) return { after_seq: afterSeq, delta };
  return { after_seq: afterSeq, delta: delta.slice(0, MAX_DELTA_MESSAGES), truncated: true, total: delta.length };
}

/** Refuse an action trigger when mobile-mcp is off, with the contextual "just wait" suggestion. */
function guardMobileEnabled(): void {
  if (!getState().config.mobileMcp.enabled) {
    throw new FridaMcpError('MOBILE_ERROR', 'mobile-mcp integration is disabled in config; omit `action` to just wait.', [
      { tool: 'trigger_and_wait', reason: 'Call without an action to wait for the next messages' },
    ]);
  }
}

