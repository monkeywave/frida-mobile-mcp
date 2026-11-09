import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import { getState, newerJavaBridgeScripts, unloadScriptsNewestFirst } from '../state.js';
import type { ScriptEntry, SessionEntry } from '../types.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../helpers/errors.js';
import { responseFormatSchema } from '../constants.js';
import { log } from '../helpers/logger.js';
import {
  getActiveFritapCaptures,
  stopFritapCapture,
  takeFinalFritapStats,
  unloadScriptForTeardown,
  type FinalFritapCapture,
} from '../fritap/tool.js';

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
        const fritapCaptures: FinalFritapCapture[] = [];

        if (all) {
          // Clean everything
          for (const [sid, entry] of state.sessions) {
            fritapCaptures.push(...await cleanupSession(state, sid, entry));
            cleaned.push(sid);
          }
        } else if (session_id) {
          const entry = state.getSession(session_id);
          if (!entry) {
            // A session that ended on its own (app exit) may still have final friTap totals to hand out.
            const ended = takeFinalFritapStats(session_id);
            if (ended.length > 0) return formatToolResponse(endedSessionResult(session_id, ended), response_format);
            throw new FridaMcpError(
              'SESSION_NOT_FOUND',
              `Session "${session_id}" not found.`,
              [{ tool: 'get_status', reason: 'List active sessions' }]
            );
          }
          fritapCaptures.push(...await cleanupSession(state, session_id, entry));
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
          fritapCaptures.push(...await cleanupSession(state, entry.id, entry));
          cleaned.push(entry.id);
        } else {
          throw new FridaMcpError(
            'INVALID_ARGUMENT',
            'Provide session_id, target, or set all=true.',
            [{ tool: 'get_status', reason: 'List sessions to clean up' }]
          );
        }

        return formatToolResponse(
          buildResult(
            {
              cleaned_sessions: cleaned,
              message: `Cleaned up ${cleaned.length} session(s). All hooks, scripts, and traces removed.`,
              // Final friTap totals (incl. per_library) of captures that ended in these sessions.
              ...(fritapCaptures.length > 0 ? { fritap_captures: fritapCaptures } : {}),
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
      description: 'Unload a single script (hook, trace or custom script) from a session while keeping the session attached. Use the script_id returned by hook_method, trace_method, execute_script or run_prebuilt_script. Hooks and traces that belong to the script are removed from the server state. Use stop_instrumentation to tear down a whole session instead. ' +
        'Java-bridge scripts must be unloaded newest-first (unloading an older one first can crash the app): if newer Java-bridge scripts are loaded, the call fails with UNLOAD_ORDER_UNSAFE listing them, unless cascade=true, which unloads those newer scripts first and reports them in cascaded_scripts.',
      inputSchema: z.object({
        session_id: z.string().describe('Session the script belongs to (from hook_method/explore_app/get_status)'),
        script_id: z.string().describe('Script to unload (script_id from hook_method, trace_method, execute_script, ...)'),
        cascade: z.boolean().optional().default(false).describe('Also unload the newer Java-bridge scripts that must go first (newest-first) instead of failing with UNLOAD_ORDER_UNSAFE'),
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
    async ({ session_id, script_id, cascade, response_format }) => {
      try {
        const state = getState();
        // A friTap capture that ended on its own (duration_seconds expiry, app exit) is already gone
        // from the session (or the session itself is gone); hand out its stored final totals instead.
        if (!state.getSession(session_id)?.scripts.has(script_id)) {
          const ended = takeFinalFritapStats(session_id, [script_id]);
          if (ended.length > 0) return formatToolResponse(endedCaptureResult(session_id, script_id, ended), response_format);
        }
        const sessionEntry = requireSession(state, session_id);
        const scriptEntry = requireScript(sessionEntry, script_id);

        const newer = newerJavaBridgeScripts(sessionEntry, script_id);
        if (newer.length > 0 && !cascade) throw unloadOrderUnsafeError(sessionEntry.id, scriptEntry, newer);

        // Newest-first: the newer Java-bridge scripts go before the requested one.
        const cascaded: CascadedScript[] = [];
        for (const newerEntry of newer) {
          cascaded.push({ script_id: newerEntry.id, name: newerEntry.name ?? null, ...await unloadAndForgetScript(state, sessionEntry, newerEntry) });
        }
        const removed = await unloadAndForgetScript(state, sessionEntry, scriptEntry);
        state.touchSession(session_id);
        const fritapCaptures = takeFinalFritapStats(session_id, [script_id, ...cascaded.map((c) => c.script_id)]);

        log('info', `Script ${script_id} (${scriptEntry.name ?? 'unnamed'}) unloaded from session ${session_id}` +
          (cascaded.length > 0 ? ` after ${cascaded.length} newer Java-bridge script(s)` : ''));

        return formatToolResponse(
          buildResult(
            {
              session_id,
              script_id,
              name: scriptEntry.name ?? null,
              unloaded: true,
              ...removed,
              ...(cascaded.length > 0 ? { cascaded_scripts: cascaded } : {}),
              ...(fritapCaptures.length > 0 ? { fritap_captures: fritapCaptures } : {}),
            },
            [
              { tool: 'get_status', reason: 'Verify the remaining scripts on the session' },
              { tool: 'get_messages', args: { session_id }, reason: 'Read messages buffered by the other scripts' },
            ],
            cascaded.length > 0
              ? { limitations: [`cascade=true also unloaded ${cascaded.length} newer Java-bridge script(s) (see cascaded_scripts) so the Java bridge teardown stays newest-first; re-create them if still needed.`] }
              : {}
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

/** stop_instrumentation for a session that is already gone but left final friTap totals behind. */
function endedSessionResult(sessionId: string, fritapCaptures: FinalFritapCapture[]) {
  return buildResult(
    {
      cleaned_sessions: [],
      message: `Session ${sessionId} had already ended (e.g. the app exited); returning the final totals of its friTap capture(s).`,
      fritap_captures: fritapCaptures,
    },
    [{ tool: 'get_status', reason: 'List active sessions' }]
  );
}

/** unload_script for a friTap capture that already ended on its own (script or session already gone). */
function endedCaptureResult(sessionId: string, scriptId: string, fritapCaptures: FinalFritapCapture[]) {
  return buildResult(
    {
      session_id: sessionId,
      script_id: scriptId,
      name: null,
      unloaded: false,
      already_ended: true,
      message: `friTap capture ${scriptId} had already ended (duration_seconds expiry or app exit); returning its final totals.`,
      fritap_captures: fritapCaptures,
    },
    [{ tool: 'get_status', reason: 'Verify the remaining sessions and scripts' }]
  );
}

interface RemovedScriptState {
  removed_hooks: number;
  removed_traces: number;
  removed_coverage: number;
  removed_oracles: number;
}

interface CascadedScript extends RemovedScriptState {
  script_id: string;
  name: string | null;
}

/** Unload one script (stopping a friTap capture gracefully) and drop everything it owned from the server state. */
async function unloadAndForgetScript(state: ReturnType<typeof getState>, sessionEntry: SessionEntry, scriptEntry: ScriptEntry): Promise<RemovedScriptState> {
  if (getActiveFritapCaptures().has(scriptEntry.id)) {
    await stopFritapCapture(scriptEntry.id);
  } else {
    await unloadScriptQuietly(scriptEntry.script);
  }
  sessionEntry.scripts.delete(scriptEntry.id);
  return {
    removed_hooks: dropHooksForScript(state, scriptEntry.id),
    removed_traces: dropTracesForScript(state, scriptEntry.id),
    removed_coverage: dropCoverageForScript(state, scriptEntry.id),
    removed_oracles: dropOraclesForScript(state, scriptEntry.id),
  };
}

/** Refuse an out-of-order Java-bridge unload; the caller decides between cascade and manual LIFO. */
function unloadOrderUnsafeError(sessionId: string, scriptEntry: ScriptEntry, newer: ScriptEntry[]): FridaMcpError {
  const newerScripts = newer.map((entry) => ({ script_id: entry.id, name: entry.name ?? null }));
  return new FridaMcpError(
    'UNLOAD_ORDER_UNSAFE',
    `Script "${scriptEntry.id}" uses the Java bridge and ${newer.length} newer Java-bridge script(s) are still loaded in session "${sessionId}". ` +
      'Java hooks must be unloaded newest-first; unloading this one first can crash the app (SIGBUS). Nothing was unloaded.',
    [
      { tool: 'unload_script', args: { session_id: sessionId, script_id: scriptEntry.id, cascade: true }, reason: 'Unload the newer Java-bridge scripts first, then this one' },
      { tool: 'unload_script', args: { session_id: sessionId, script_id: newer[0].id }, reason: 'Unload the newest script yourself, then retry' },
      { tool: 'stop_instrumentation', args: { session_id: sessionId }, reason: 'Tear down the whole session (always newest-first)' },
    ],
    { session_id: sessionId, script_id: scriptEntry.id, newer_java_bridge_scripts: newerScripts },
    { category: 'request', retryable: false }
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

function dropCoverageForScript(state: ReturnType<typeof getState>, scriptId: string): number {
  let removed = 0;
  for (const [coverageId, entry] of state.coverage) {
    if (entry.scriptId === scriptId) {
      state.coverage.delete(coverageId);
      removed++;
    }
  }
  return removed;
}

function dropOraclesForScript(state: ReturnType<typeof getState>, scriptId: string): number {
  let removed = 0;
  for (const [oracleId, entry] of state.oracles) {
    if (entry.scriptId === scriptId) {
      state.oracles.delete(oracleId);
      removed++;
    }
  }
  return removed;
}

/** Tear a session down; returns the final stats of the friTap captures that ended in it. */
async function cleanupSession(state: ReturnType<typeof getState>, sessionId: string, entry: SessionEntry): Promise<FinalFritapCapture[]> {
  // Unload all scripts newest-first: Java-bridge ART patches can only be reverted LIFO.
  await unloadScriptsNewestFirst(entry, unloadScriptForTeardown);

  // Detach session
  try {
    await entry.session.detach();
  } catch { /* session may already be detached */ }

  // Remove from state
  state.removeSession(sessionId);
  log('info', `Session ${sessionId} cleaned up`);
  return takeFinalFritapStats(sessionId);
}
