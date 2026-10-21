import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../helpers/errors.js';
import { responseFormatSchema } from '../constants.js';
import { audit } from '../helpers/logger.js';
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
        // Cursor BEFORE the trigger, so any message the trigger causes counts as new.
        const afterSeq = state.currentMessageSeq();

        let triggerResult: unknown = null;
        if (action) {
          triggerResult = await performMobileTrigger(action, params, session.deviceId);
        }

        const reached = await state.waitForNewMessages(session_id, afterSeq, minCount, timeoutMs);

        // Collect exactly the messages produced since the trigger, and which hooks fired.
        // "Fired" = a hook whose script emitted a message in this delta. Deriving it from the
        // delta (not a one-time firstSeenTs) means a hook that already fired before still shows
        // up as fired on later triggers — which is the whole point of the tool.
        const delta = collectDelta(session, afterSeq);
        const firedScriptIds = new Set(delta.map((d) => d.script_id));
        const firedHooks = Array.from(state.hooks.values())
          .filter((h) => h.sessionId === session_id && firedScriptIds.has(h.scriptId))
          .map((h) => ({ id: h.id, target: h.target, type: h.type }));

        audit({
          timestamp: new Date().toISOString(),
          sessionId: session_id,
          tool: 'trigger_and_wait',
          params: { action, expect_messages: minCount, timeout_ms: timeoutMs },
          status: 'success',
        });

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
        if (err instanceof FridaMcpError) return formatToolResponse(err.toErrorResponse(), response_format);
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    },
  );
}

/** Perform a mobile-mcp action as the trigger, injecting the session's device like mobile_action does. */
async function performMobileTrigger(action: string, params: Record<string, unknown> | undefined, deviceId: string | undefined): Promise<unknown> {
  const state = getState();
  if (!state.config.mobileMcp.enabled) {
    throw new FridaMcpError('MOBILE_ERROR', 'mobile-mcp integration is disabled in config; omit `action` to just wait.', [
      { tool: 'trigger_and_wait', reason: 'Call without an action to wait for the next messages' },
    ]);
  }
  const { callMobileAction } = await import('../mobile-mcp/call.js');
  return callMobileAction(action, params, deviceId);
}

interface DeltaMessage {
  script_id: string;
  script_name?: string;
  seq: number;
  type: string;
  payload: unknown;
}

/** Messages across all of a session's scripts with seq strictly greater than `afterSeq`, in order. */
function collectDelta(session: SessionEntry, afterSeq: number): DeltaMessage[] {
  const out: DeltaMessage[] = [];
  for (const [sid, script] of session.scripts) {
    for (const m of script.messages) {
      if (m.seq > afterSeq) out.push({ script_id: sid, script_name: script.name, seq: m.seq, type: m.type, payload: m.payload });
    }
  }
  out.sort((a, b) => a.seq - b.seq);
  return out;
}
