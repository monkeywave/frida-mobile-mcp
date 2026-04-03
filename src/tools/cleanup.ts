import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../helpers/errors.js';
import { responseFormatSchema } from '../constants.js';
import { log, audit } from '../helpers/logger.js';

export function registerCleanupTool(server: McpServer): void {
  server.registerTool(
    'stop_instrumentation',
    {
      title: 'Stop Instrumentation',
      description: 'Clean up all hooks, scripts, and traces on a target. The "undo everything" tool. Detaches the Frida session and frees all resources. Use when you are done analyzing an app or want to start fresh.',
      inputSchema: {
        session_id: z.string().optional().describe('Specific session to clean up'),
        target: z.string().optional().describe('Clean up by app target name/bundle ID'),
        all: z.boolean().optional().default(false).describe('Clean up ALL sessions (default: false)'),
        response_format: responseFormatSchema,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ session_id, target, all, response_format }) => {
      try {
        const state = getState();
        const cleaned: string[] = [];

        if (all) {
          // Clean everything
          for (const [sid, entry] of state.sessions) {
            await cleanupSession(state, sid, entry);
            cleaned.push(sid);
          }
        } else if (session_id) {
          const entry = state.getSession(session_id);
          if (!entry) {
            throw new FridaMcpError(
              'SESSION_NOT_FOUND',
              `Session "${session_id}" not found.`,
              [{ tool: 'get_status', reason: 'List active sessions' }]
            );
          }
          await cleanupSession(state, session_id, entry);
          cleaned.push(session_id);
        } else if (target) {
          const entry = state.findSessionByTarget(target);
          if (!entry) {
            throw new FridaMcpError(
              'SESSION_NOT_FOUND',
              `No session found for target "${target}".`,
              [{ tool: 'get_status', reason: 'List active sessions' }]
            );
          }
          await cleanupSession(state, entry.id, entry);
          cleaned.push(entry.id);
        } else {
          throw new FridaMcpError(
            'INVALID_ARGUMENT',
            'Provide session_id, target, or set all=true.',
            [{ tool: 'get_status', reason: 'List sessions to clean up' }]
          );
        }

        audit({
          timestamp: new Date().toISOString(),
          tool: 'stop_instrumentation',
          params: { session_id, target, all },
          status: 'success',
        });

        return formatToolResponse(
          buildResult(
            {
              cleaned_sessions: cleaned,
              message: `Cleaned up ${cleaned.length} session(s). All hooks, scripts, and traces removed.`,
            },
            [
              { tool: 'get_status', reason: 'Verify cleanup' },
              { tool: 'explore_app', reason: 'Start fresh with a new app' },
            ]
          ),
          response_format
        );
      } catch (err) {
        if (err instanceof FridaMcpError) {
          return formatToolResponse(err.toErrorResponse(), response_format);
        }
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}

async function cleanupSession(state: ReturnType<typeof getState>, sessionId: string, entry: { session: any; scripts: Map<string, { script: any }> }): Promise<void> {
  // Unload all scripts
  for (const scriptEntry of entry.scripts.values()) {
    try {
      await scriptEntry.script.unload();
    } catch { /* script may already be unloaded */ }
  }

  // Detach session
  try {
    await entry.session.detach();
  } catch { /* session may already be detached */ }

  // Remove from state
  state.removeSession(sessionId);
  log('info', `Session ${sessionId} cleaned up`);
}
