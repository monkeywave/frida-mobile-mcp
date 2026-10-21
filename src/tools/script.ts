import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import type frida from 'frida';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError, CustomScriptDisabledError, ScriptError, FridaMcpError } from '../helpers/errors.js';
import { validateProcessTarget, validateScriptSource, validateFilePath } from '../helpers/sanitize.js';
import { log, audit } from '../helpers/logger.js';
import { rateLimiter } from '../helpers/rate-limiter.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
import { createHash } from 'node:crypto';
import { responseFormatSchema } from '../constants.js';
import { createAgentScript, isFridaCompileBundle } from '../agent/script-factory.js';
import { compileEsmAgent } from '../agent/compiler.js';
import { detectScriptKind, validateScriptSource as runScriptValidation, type ValidateScriptResult } from './validate.js';
import { attachScriptSinks } from '../helpers/script-sink.js';
import type { BridgeName } from '../agent/bridges.js';

export type SourceKind = 'auto' | 'classic' | 'esm' | 'bundle';
export type ResolvedSourceKind = Exclude<SourceKind, 'auto'>;

/** Default initial-run timeout for one-shot scripts; persistent scripts default to no timeout. */
export const DEFAULT_ONESHOT_TIMEOUT_MS = 30_000;
/** How long to wait after `script.interrupt()` before falling back to `script.terminate()`. */
const TERMINATE_GRACE_MS = 2_000;
/** Collection window for one-shot scripts after their initial run. */
const ONESHOT_COLLECT_MS = 2_000;

export class ScriptTimeoutError extends FridaMcpError {
  constructor(timeoutMs: number, scriptId: string, partialMessages: unknown[], terminated: boolean) {
    super(
      'SCRIPT_TIMEOUT',
      `Script did not finish its initial run within ${timeoutMs} ms and was ${terminated ? 'terminated' : 'interrupted and unloaded'}.`,
      [
        { tool: 'execute_script', args: { timeout_ms: 0 }, reason: 'Re-run without a timeout if the script is expected to block' },
        { tool: 'get_messages', reason: 'Inspect output from other scripts in the session' },
      ],
      { timeout_ms: timeoutMs, script_id: scriptId, terminated, partial_messages: partialMessages.slice(0, 50) }
    );
  }
}

/** Resolve 'auto' by sniffing the source; explicit kinds are returned unchanged. */
export function detectSourceKind(source: string, requested: SourceKind = 'auto'): ResolvedSourceKind {
  return requested === 'auto' ? detectScriptKind(source) : requested;
}

/**
 * Run the same host-side checks as `validate_script` (classic syntax via node:vm or ESM
 * Compiler diagnostics, plus the Frida 17 removed-API lint) and throw a line-numbered
 * SCRIPT_ERROR if the source would not load cleanly. Bundles are trusted pass-through.
 * Runs before the device is touched, so a bad script never spawns or attaches to a process.
 */
async function assertScriptPassesLint(source: string, kind: ResolvedSourceKind): Promise<void> {
  if (kind === 'bundle') return;
  const result = await runScriptValidation({ source });
  if (result.ok) return;
  throw scriptLintError(result, source);
}

/** Build a readable, line-numbered SCRIPT_ERROR from a failed validation result. */
function scriptLintError(result: ValidateScriptResult, source: string): FridaMcpError {
  const lines: string[] = [];
  for (const d of result.diagnostics) {
    if (d.severity !== 'error') continue;
    const loc = d.line != null ? `:${d.line}${d.column != null ? `:${d.column}` : ''}` : '';
    lines.push(`${d.severity}${loc} — ${d.message}`);
  }
  for (const r of result.removed_apis) {
    lines.push(`removed API at line ${r.line}: ${r.match} — use ${r.replacement}`);
  }
  const summary = lines.length === 1 ? lines[0] : `script would not load:\n  ${lines.join('\n  ')}`;
  return new FridaMcpError(
    'SCRIPT_ERROR',
    `Script error: ${summary}`,
    [
      { tool: 'validate_script', args: {}, reason: 'Re-check the script without a device' },
      { tool: 'frida_help', args: { topic: 'scripts' }, reason: 'Frida 17 API rules and preamble helpers' },
    ],
    {
      kind: result.kind,
      diagnostics: result.diagnostics.filter((d) => d.severity === 'error'),
      removed_apis: result.removed_apis,
      script_preview: source.slice(0, 200),
    },
  );
}

/** Effective timeout: explicit value wins; otherwise one-shot scripts get a default, persistent ones none. */
export function resolveTimeoutMs(timeoutMs: number | undefined, persistent: boolean): number {
  if (timeoutMs !== undefined) return timeoutMs;
  return persistent ? 0 : DEFAULT_ONESHOT_TIMEOUT_MS;
}

function readScriptSource(source: string | undefined, filePath: string | undefined): string {
  if (source) return source;
  if (!filePath) throw new ScriptError('Either source or file_path must be provided');
  validateFilePath(filePath);
  try {
    return readFileSync(filePath, 'utf-8');
  } catch {
    throw new ScriptError(`Cannot read file: ${filePath}`);
  }
}

interface PreparedSource {
  source: string;
  kind: ResolvedSourceKind;
  compileMs: number | null;
}

/** Turn the user source into something createAgentScript accepts: compile ESM, pass bundles through. */
async function prepareAgentSource(
  source: string,
  kind: ResolvedSourceKind,
  platform: string,
  name: string
): Promise<PreparedSource> {
  switch (kind) {
    case 'bundle':
      if (!isFridaCompileBundle(source)) {
        throw new ScriptError('source_kind "bundle" requires frida-compile output (source starting with the 📦 marker)', source);
      }
      return { source, kind, compileMs: null };
    case 'esm': {
      const startedAt = Date.now();
      const bundle = await compileEsmAgent(source, { platform, name });
      return { source: bundle, kind, compileMs: Date.now() - startedAt };
    }
    default:
      return { source, kind: 'classic', compileMs: null };
  }
}

type Settled<T> = { timedOut: false; value: T } | { timedOut: true };

async function settleWithin<T>(promise: Promise<T>, timeoutMs: number): Promise<Settled<T>> {
  if (timeoutMs <= 0) return { timedOut: false, value: await promise };
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<Settled<T>>((resolve) => {
    timer = setTimeout(() => resolve({ timedOut: true }), timeoutMs);
  });
  try {
    return await Promise.race([promise.then((value) => ({ timedOut: false as const, value })), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Stop a script whose JS thread did not settle in time: `interrupt()` first (Frida >= 17.14),
 * then `terminate()` after a grace period. Returns true when terminate was needed.
 */
async function stopRunawayScript(script: frida.Script, pending: Promise<unknown>): Promise<boolean> {
  await script.interrupt().catch((err) => log('debug', `script.interrupt() failed: ${String(err)}`));
  const afterInterrupt = await settleWithin(pending.catch(() => undefined), TERMINATE_GRACE_MS);
  if (!afterInterrupt.timedOut) {
    const unloaded = await settleWithin(script.unload().catch(() => undefined), TERMINATE_GRACE_MS);
    if (!unloaded.timedOut) return false;
  }
  await script.terminate().catch((err) => log('debug', `script.terminate() failed: ${String(err)}`));
  return true;
}

/** Run a script operation (load/unload) under the timeout; throws ScriptTimeoutError after stopping the script. */
export async function runGuarded(
  script: frida.Script,
  operation: Promise<void>,
  timeoutMs: number,
  scriptId: string,
  partialMessages: unknown[]
): Promise<void> {
  const settled = await settleWithin(operation, timeoutMs);
  if (!settled.timedOut) return;
  const terminated = await stopRunawayScript(script, operation);
  throw new ScriptTimeoutError(timeoutMs, scriptId, partialMessages, terminated);
}

export function registerScriptTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'execute_script',
    {
      title: 'Execute Custom Frida Script',
      description: 'Execute a custom Frida JavaScript/TypeScript script in a target process (Frida 17 agent). Provide either inline source code or a file path. Three source kinds are supported and detected automatically (override with `source_kind`): classic (non-module) JavaScript, where the `Java` and `ObjC` globals are auto-injected by platform (Java on Android, ObjC on iOS/macOS; override with `bridges`) so legacy Java.perform()/ObjC scripts keep working with their own line numbers; ES modules (import/export, JS or TS) such as `import Java from "frida-java-bridge"`, which are compiled on the host with the Frida Compiler (bridges are bundled by the imports, so `bridges` is ignored); and frida-compile bundles (source starting with the 📦 marker), which are loaded as-is. The full Frida API (Interceptor, Memory, Module, Process, NativePointer, ...) is available everywhere. Results are sent via send() and retrieved with get_messages. `timeout_ms` bounds the script\'s initial run (default 30000 for one-shot scripts, 0 for persistent ones); a script that overruns is interrupted, then terminated, and the call fails with SCRIPT_TIMEOUT including the partial messages. Use validate_script to check syntax/types without a device. Note: custom scripts must be explicitly enabled in config (allowCustomScripts: true).',
      inputSchema: z.object({
        target: z.string().describe('App bundle ID, process name, or PID'),
        source: z.string().optional().describe('Inline JavaScript/TypeScript source code'),
        file_path: z.string().optional().describe('Path to a .js/.ts Frida script file'),
        device: z.string().optional().describe('Device ID'),
        session_id: z.string().optional().describe('Reuse an existing session'),
        persistent: z.boolean().optional().default(true).describe('Keep script loaded (default: true). Set false for one-shot scripts.'),
        bridges: z.array(z.enum(['java', 'objc'])).optional().describe('Classic scripts only: bridges to inject, overriding the platform default (android: ["java"], ios/macos: ["objc"]). Use [] for scripts that never touch Java/ObjC.'),
        source_kind: z.enum(['auto', 'classic', 'esm', 'bundle']).default('auto').describe('How to treat the source: "auto" (default) detects a 📦 bundle, then import/export syntax (esm), else classic; "esm" compiles with the Frida Compiler; "bundle" passes frida-compile output through unchanged.'),
        skip_validation: z.boolean().optional().default(false).describe('Skip the pre-load syntax + Frida 17 removed-API check. Validation is on by default and rejects a bad script (with line numbers) before the device is touched; set true only to deliberately run code the linter would flag.'),
        timeout_ms: z.number().int().min(0).optional().describe('Max time for the script\'s initial run in ms. Default: 30000 for one-shot (persistent: false) scripts, 0 (no timeout) for persistent ones. On overrun the script is interrupted, then terminated after 2 s.'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async ({ target, source, file_path, device, session_id, persistent, bridges, source_kind, skip_validation, timeout_ms, response_format }) => {
      const startTime = Date.now();
      try {
        const state = getState();

        // Check if custom scripts are allowed
        if (!state.config.allowCustomScripts) {
          throw new CustomScriptDisabledError();
        }

        const scriptSource = readScriptSource(source, file_path);
        validateScriptSource(scriptSource);
        validateProcessTarget(target);

        // Fail fast, before the device is ever touched: reject syntax errors and APIs
        // removed in Frida 17 (e.g. Module.findExportByName) with line numbers, so the AI
        // sees them as authoring diagnostics rather than a cryptic runtime "not a function".
        if (!skip_validation) {
          await assertScriptPassesLint(scriptSource, detectSourceKind(scriptSource, source_kind));
        }

        rateLimiter.check('script', state.config.rateLimits.scriptsPerMinute);
        rateLimiter.record('script');

        const { sessionEntry: resolvedSession } = await getOrCreateSession(deviceManager, {
          target,
          device,
          sessionId: session_id,
        });
        let sessionEntry = resolvedSession;

        const keepLoaded = persistent ?? true;
        const timeoutMs = resolveTimeoutMs(timeout_ms, keepLoaded);
        const scriptName = `user:${file_path ? basename(file_path) : 'inline'}`;

        // ESM sources are compiled to a bundle first; bundles and classic sources go straight to
        // createAgentScript, which composes preamble + bridges + Script.evaluate for classic code.
        // composeAgentSource throws ScriptError for classic sources that still contain import/export;
        // it is a FridaMcpError and reaches the caller through the catch below unchanged.
        const prepared = await prepareAgentSource(
          scriptSource,
          detectSourceKind(scriptSource, source_kind),
          sessionEntry.platform,
          file_path ? basename(file_path) : 'inline'
        );
        const script = await createAgentScript(sessionEntry.session, {
          sessionEntry: sessionEntry,
          source: prepared.source,
          platform: sessionEntry.platform,
          name: scriptName,
          kind: 'user',
          bridges: bridges as BridgeName[] | undefined,
        });
        const scriptId = state.generateId();
        const messages: Array<Record<string, unknown>> = [];

        const scriptEntry = {
          id: scriptId,
          script,
          messages: [],
          name: scriptName,
          persistent: keepLoaded,
          createdAt: Date.now(),
        };
        sessionEntry.scripts.set(scriptId, scriptEntry);

        // Capture agent console.* into the buffer (never to stdout) and record every
        // send/error message with full error fidelity (stack/file/line/column), while
        // mirroring each entry into the inline `messages` returned from this call.
        attachScriptSinks(script, sessionEntry.id, scriptId, {
          onEntry: (entry) => messages.push({ type: entry.type, payload: entry.payload }),
        });

        try {
          await runGuarded(script, script.load(), timeoutMs, scriptId, messages);

          // For non-persistent scripts, wait briefly and collect output
          if (!keepLoaded) {
            await new Promise((resolve) => setTimeout(resolve, ONESHOT_COLLECT_MS));
            await runGuarded(script, script.unload(), timeoutMs, scriptId, messages);
            sessionEntry.scripts.delete(scriptId);
          }
        } catch (err) {
          // Any load/unload failure (timeout or otherwise) must not leave a dead script
          // entry behind in the session — it would show up forever in get_status/get_messages.
          sessionEntry.scripts.delete(scriptId);
          throw err;
        }

        const scriptHash = createHash('sha256').update(scriptSource).digest('hex').slice(0, 16);

        audit({
          timestamp: new Date().toISOString(),
          sessionId: sessionEntry.id,
          tool: 'execute_script',
          params: { target, file_path, persistent: keepLoaded, bridges, source_kind: prepared.kind, timeout_ms: timeoutMs },
          status: 'success',
          durationMs: Date.now() - startTime,
          scriptHash,
        });

        return formatToolResponse(
          buildResult(
            {
              script_id: scriptId,
              session_id: sessionEntry.id,
              persistent: keepLoaded,
              source_kind: prepared.kind,
              compile_ms: prepared.compileMs,
              timeout_ms: timeoutMs,
              messages_received: messages.length,
              messages: messages.slice(0, 50),
              script_hash: scriptHash,
            },
            keepLoaded
              ? [
                  { tool: 'get_messages', args: { session_id: sessionEntry.id }, reason: 'Retrieve script output' },
                  { tool: 'stop_instrumentation', args: { session_id: sessionEntry.id }, reason: 'Stop and clean up' },
                ]
              : [
                  { tool: 'execute_script', reason: 'Run another script' },
                ]
          ),
          response_format
        );
      } catch (err) {
        const wrapped = wrapFridaError(err);
        return formatToolResponse(wrapped.toErrorResponse(), response_format);
      }
    }
  );
}
