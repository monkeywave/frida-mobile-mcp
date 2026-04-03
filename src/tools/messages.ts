import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError } from '../helpers/errors.js';
import { responseFormatSchema } from '../constants.js';

export function registerMessagesTool(server: McpServer): void {
  server.registerTool(
    'get_messages',
    {
      title: 'Get Script Messages',
      description: 'Retrieve buffered messages from active scripts and hooks. Messages include hook invocations, trace hits, script output (send() calls), and errors. Use "since" for pagination to get only new messages.',
      inputSchema: {
        session_id: z.string().describe('Session ID to get messages from'),
        script_id: z.string().optional().describe('Filter to a specific script'),
        since: z.number().optional().describe('Message index to start from (for pagination)'),
        limit: z.number().optional().default(50).describe('Max messages to return (default: 50)'),
        response_format: responseFormatSchema,
      },
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
        const startIndex = since ?? 0;
        let allMessages: Array<{ script_id: string; script_name?: string; index: number; timestamp: number; type: string; payload: unknown }> = [];

        for (const [sid, scriptEntry] of session.scripts) {
          if (script_id && sid !== script_id) continue;

          const filtered = scriptEntry.messages
            .filter((m) => m.index >= startIndex)
            .map((m) => ({
              script_id: sid,
              script_name: scriptEntry.name,
              index: m.index,
              timestamp: m.timestamp,
              type: m.type,
              payload: m.payload,
            }));
          allMessages.push(...filtered);
        }

        // Sort by timestamp
        allMessages.sort((a, b) => a.timestamp - b.timestamp);

        // Apply limit
        const truncated = allMessages.length > maxMessages;
        allMessages = allMessages.slice(0, maxMessages);

        const lastIndex = allMessages.length > 0
          ? Math.max(...allMessages.map((m) => m.index))
          : startIndex;

        return formatToolResponse(
          buildResult(
            {
              session_id,
              messages_count: allMessages.length,
              messages: allMessages,
              last_index: lastIndex,
              truncated,
              active_scripts: Array.from(session.scripts.values()).map((s) => ({
                id: s.id,
                name: s.name,
                message_count: s.messages.length,
              })),
            },
            [
              ...(truncated
                ? [{ tool: 'get_messages', args: { session_id, since: lastIndex + 1 }, reason: 'Get more messages' }]
                : []),
              { tool: 'hook_method', reason: 'Add more hooks to capture more data' },
              { tool: 'stop_instrumentation', args: { session_id }, reason: 'Clean up when done' },
            ]
          ),
          response_format
        );
      } catch (err) {
        if (err instanceof FridaMcpError) {
          return formatToolResponse(err.toErrorResponse(), response_format);
        }
        throw err;
      }
    }
  );
}
