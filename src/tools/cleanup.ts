import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import { getState } from '../state.js';
import type { ScriptEntry, SessionEntry } from '../types.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../helpers/errors.js';
import { responseFormatSchema } from '../constants.js';
import { log, audit } from '../helpers/logger.js';

export function registerCleanupTool(server: McpServer): void {
  registerStopInstrumentationTool(server);
  registerUnloadScriptTool(server);
}

function registerStopInstrumentationTool(server: McpServer): void {
  server.registerTool(
    'stop_instrumentation',
    {
      title: 'Stop Instrumentation',
      description: 'Clean up all hooks, scripts, and traces on a target. The "undo everything" tool. Detaches the Frida session and frees all resources. Use when you are done analyzing an app or want to start fresh.',
      inputSchema: z.object({
        session_id: z.string().optional().describe('Specific session to clean up'),
        target: z.string().optional().describe('Clean up by app target name/bundle ID'),
        all: z.boolean().optional().default(false).describe('Clean up ALL sessions (default: false)'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
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

function registerUnloadScriptTool(server: McpServer): void {
  server.registerTool(
    'unload_script',
    {
      title: 'Unload Script',
      description: 'Unload a single script (hook, trace or custom script) from a session while keeping the session attached. Use the script_id returned by hook_method, trace_method, execute_script or run_prebuilt_script. Hooks and traces that belong to the script are removed from the server state. Use stop_instrumentation to tear down a whole session instead.',
      inputSchema: z.object({
        session_id: z.string().describe('Session the script belongs to (from hook_method/explore_app/get_status)'),
        script_id: z.string().describe('Script to unload (script_id from hook_method, trace_method, execute_script, ...)'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ session_id, script_id, response_format }) => {
      try {
        const state = getState();
        const sessionEntry = requireSession(state, session_id);
        const scriptEntry = requireScript(sessionEntry, script_id);

        await unloadScriptQuietly(scriptEntry.script);
        sessionEntry.scripts.delete(script_id);
        const removedHooks = dropHooksForScript(state, script_id);
        const removedTraces = dropTracesForScript(state, script_id);
        state.touchSession(session_id);

        log('info', `Script ${script_id} (${scriptEntry.name ?? 'unnamed'}) unloaded from session ${session_id}`);
        audit({
          timestamp: new Date().toISOString(),
          sessionId: session_id,
          tool: 'unload_script',
          params: { session_id, script_id },
          status: 'success',
        });

        return formatToolResponse(
          buildResult(
            {
              session_id,
              script_id,
              name: scriptEntry.name ?? null,
              unloaded: true,
              removed_hooks: removedHooks,
              removed_traces: removedTraces,
            },
            [
              { tool: 'get_status', reason: 'Verify the remaining scripts on the session' },
              { tool: 'get_messages', args: { session_id }, reason: 'Read messages buffered by the other scripts' },
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

function requireSession(state: ReturnType<typeof getState>, sessionId: string): SessionEntry {
  const entry = state.getSession(sessionId);
  if (!entry) {
    throw new FridaMcpError(
      'SESSION_NOT_FOUND',
      `Session "${sessionId}" not found.`,
      [{ tool: 'get_status', reason: 'List active sessions' }],
      { session_id: sessionId }
    );
  }
  return entry;
}

function requireScript(sessionEntry: SessionEntry, scriptId: string): ScriptEntry {
  const scriptEntry = sessionEntry.scripts.get(scriptId);
  if (!scriptEntry) {
    throw new FridaMcpError(
      'SCRIPT_NOT_FOUND',
      `Script "${scriptId}" not found in session "${sessionEntry.id}". It may already have been unloaded.`,
      [{ tool: 'get_status', reason: 'List the scripts loaded in each session' }],
      { session_id: sessionEntry.id, script_id: scriptId, loaded_scripts: Array.from(sessionEntry.scripts.keys()) }
    );
  }
  return scriptEntry;
}

/** Unload a script, tolerating one that frida already destroyed (process gone, session detached). */
async function unloadScriptQuietly(script: ScriptEntry['script']): Promise<void> {
  if (script.isDestroyed) return;
  try {
    await script.unload();
  } catch (err) {
    if (isAlreadyDestroyed(err)) return;
    throw err;
  }
}

function isAlreadyDestroyed(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return /destroyed|detached|invalid operation/i.test(message);
}

function dropHooksForScript(state: ReturnType<typeof getState>, scriptId: string): number {
  let removed = 0;
  for (const [hookId, hook] of state.hooks) {
    if (hook.scriptId === scriptId) {
      state.hooks.delete(hookId);
      removed++;
    }
  }
  return removed;
}

function dropTracesForScript(state: ReturnType<typeof getState>, scriptId: string): number {
  let removed = 0;
  for (const [traceId, trace] of state.traces) {
    if (trace.scriptId === scriptId) {
      state.traces.delete(traceId);
      removed++;
    }
  }
  return removed;
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
