import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../helpers/errors.js';
import { validateProcessTarget } from '../helpers/sanitize.js';
import { log, audit } from '../helpers/logger.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
import { responseFormatSchema } from '../constants.js';
import { createAgentScript } from '../agent/script-factory.js';
import { attachScriptSinks } from '../helpers/script-sink.js';
import { formatModuleOffset, parseTarget, RESOLVE_TARGET_SNIPPET } from '../agent/address.js';
import { JAVA_CLASS_LOOKUP_SNIPPET } from '../agent/java-class-lookup.js';
import { formatJavaSignature, parseJavaSignature } from '../agent/java-signature.js';
import type { HookEntry, HookMissReason } from '../types.js';

/**
 * Frida 17.10+ Interceptor instrumentation options, verified against the "Interceptor"
 * section of https://frida.re/docs/javascript-api/ (read 2026-10-20) and the 17.10.0
 * release notes ("attach(), replace(), and replaceFast() may now take an options object
 * carrying the target"):
 *
 *   "Interceptor.attach(target, callbacks[, data]) ... The target may also be an object
 *    with a target property containing the address, alongside one or more instrumentation
 *    options that control how the inline hook is set up. The same goes for replace() and
 *    replaceFast()."
 *   "Interceptor.defaults: object with default instrumentation options applied to every
 *    subsequent attach(), replace(), and replaceFast() call. Options specified per call
 *    take precedence over these."
 *
 * So the per-call form is `Interceptor.attach({ target: addr, ...options }, callbacks)`;
 * the options ride on the target object, not on a third argument (which stays `data`).
 * The documented instrumentation options are:
 *   scratchRegister    string, e.g. "x16"; "only supported on ... arm64 and mips"
 *   scenario           "online" (default) | "offline"
 *   relocation         "checked" (default) | "unchecked" | "forced"
 *   writeRedirect      callback(details) - a function, not JSON-serialisable, so not exposed
 *   redirectSpaceHint  number of bytes; "Defaults to the size needed for a full redirect,
 *                      e.g. 16 bytes on arm64"
 * Also verified: Interceptor.flush() and Interceptor.detachAll() are process-wide calls;
 * the page documents no per-listener flush(), only listener.detach().
 */
export const interceptorOptionsSchema = z
  .object({
    scenario: z
      .enum(['online', 'offline'])
      .optional()
      .describe('"online" (default): other threads may be mid-call in the target while it is instrumented. "offline": no call can be in flight (e.g. spawned but not yet resumed); lets Frida write past a call-semantics instruction.'),
    relocation: z
      .enum(['checked', 'unchecked', 'forced'])
      .optional()
      .describe('"checked" (default): verify the scratch register is unused in the prologue and nothing branches back into the overwritten instructions. "unchecked": skip those checks. "forced": like unchecked and also allow overwriting past the end of the function (e.g. into alignment padding).'),
    scratchRegister: z
      .string()
      .min(1)
      .optional()
      .describe('Register Interceptor may clobber while building the trampoline, e.g. "x16". Only arm64 and mips expose scratch registers.'),
    redirectSpaceHint: z
      .number()
      .int()
      .positive()
      .optional()
      .describe('Upper bound in bytes on the redirect size Interceptor should plan for. Defaults to a full redirect (16 bytes on arm64); larger values make the safety analysis more expensive.'),
  })
  .strict()
  .optional()
  .describe('Frida 17.10+ Interceptor instrumentation options for native hooks, passed as Interceptor.attach({ target, ...options }, callbacks). Ignored (with a limitations note) for Java and ObjC hooks. Omit to keep Frida defaults / Interceptor.defaults.');

export type InterceptorOptions = z.infer<typeof interceptorOptionsSchema>;

/**
 * Drop unset keys and collapse an empty object to `undefined`, so a script only sees
 * `interceptorOptions` when the caller actually asked for something.
 */
export function normalizeInterceptorOptions(input: InterceptorOptions): Record<string, unknown> | undefined {
  if (!input) return undefined;
  const entries = Object.entries(input).filter(([, value]) => value !== undefined);
  return entries.length > 0 ? Object.fromEntries(entries) : undefined;
}

/** `limitations` entry for hook types that do not go through Interceptor. */
export function interceptorOptionsLimitations(hookType: 'native' | 'java' | 'objc', input: InterceptorOptions): string[] {
  if (hookType === 'native' || normalizeInterceptorOptions(input) === undefined) return [];
  return [`interceptor_options only apply to native Interceptor hooks and were ignored for this ${hookType} hook.`];
}

const unsignedNumberSchema = z.union([z.string().min(1), z.number().int().nonnegative()]);

/**
 * Static-analysis evidence (Ghidra / IDA / jadx / JEB) that names a hook target without
 * rewriting it into hook notation. Flat object (not a union) so every MCP client can
 * render it; the field combination decides the kind:
 *   native  { module, offset }                 offset = image-base-relative RVA
 *           { module, address, image_base }    static address + the image base the tool used
 *   java    { class, signature }               signature may carry the method name
 *           { class, method, signature }       or the name is given separately
 */
export const hookEvidenceSchema = z
  .object({
    module: z.string().min(1).optional().describe('Native: module (library) name as loaded in the process, e.g. "libfoo.so".'),
    offset: unsignedNumberSchema
      .optional()
      .describe('Native: offset of the function relative to the module image base (RVA), hex "0x1234" or decimal. This is the address Ghidra/IDA show minus the image base; it is NOT a raw on-disk file offset.'),
    address: unsignedNumberSchema
      .optional()
      .describe('Native: function address exactly as shown by the static tool (e.g. Ghidra "0x101234"); requires image_base.'),
    image_base: unsignedNumberSchema
      .optional()
      .describe('Native: image base the static tool used for "address" (Ghidra ELF default 0x100000, IDA usually 0x0). offset = address - image_base.'),
    class: z.string().min(1).optional().describe('Java: fully qualified class name, e.g. "com.example.Rc4Client".'),
    method: z.string().min(1).optional().describe('Java: method name; optional when the signature carries it. Constructors: "$init" or "<init>".'),
    signature: z
      .string()
      .min(1)
      .optional()
      .describe('Java: signature selecting ONE overload, in any common form: "encrypt(byte[], java.lang.String)" (jadx / describe_class), "encrypt([B,java.lang.String)", "byte[] encrypt(byte[] data, String key)", or a JVM descriptor "encrypt([BLjava/lang/String;)[B". Unqualified class names ("String") match by simple name.'),
  })
  .strict()
  .describe('Static-analysis evidence instead of a method spec. Native: {module, offset} or {module, address, image_base}. Java: {class, signature} (hooks only the matching overload).');

export type HookEvidence = z.infer<typeof hookEvidenceSchema>;

function invalidEvidence(message: string, evidence: HookEvidence): FridaMcpError {
  return new FridaMcpError('INVALID_ARGUMENT', message, [{ tool: 'frida_help', reason: 'See the evidence / address notation' }], { evidence });
}

function parseUnsigned(value: string | number, field: string, evidence: HookEvidence): bigint {
  const text = String(value).trim();
  if (!/^(0[xX][0-9a-fA-F]+|\d+)$/.test(text)) {
    throw invalidEvidence(`evidence.${field} must be a non-negative hex ("0x1234") or decimal number, got "${text}".`, evidence);
  }
  return BigInt(text);
}

/** `{ module, offset }` / `{ module, address, image_base }` -> `module+0xoff`. */
export function nativeEvidenceToTarget(evidence: HookEvidence): string {
  const { module, offset, address, image_base: imageBase } = evidence;
  if (!module) throw invalidEvidence('Native evidence needs "module".', evidence);
  if (offset !== undefined && (address !== undefined || imageBase !== undefined)) {
    throw invalidEvidence('Pass either evidence.offset or evidence.address + evidence.image_base, not both.', evidence);
  }
  if (offset !== undefined) return formatModuleOffset(module, parseUnsigned(offset, 'offset', evidence));
  if (address === undefined || imageBase === undefined) {
    throw invalidEvidence('Native evidence needs "offset" (image-base-relative) or both "address" and "image_base".', evidence);
  }
  const rva = parseUnsigned(address, 'address', evidence) - parseUnsigned(imageBase, 'image_base', evidence);
  if (rva < 0n) throw invalidEvidence('evidence.address is below evidence.image_base.', evidence);
  return formatModuleOffset(module, rva);
}

/** `{ class, signature }` -> `com.pkg.Class.name(type, type)` (canonical source form). */
export function javaEvidenceToMethod(evidence: HookEvidence): string {
  const { class: className, method, signature } = evidence;
  if (!className) throw invalidEvidence('Java evidence needs "class".', evidence);
  const methodName = method?.replace(/^<init>$/, '$init');
  if (!signature) {
    if (!methodName) throw invalidEvidence('Java evidence needs "signature" (or at least "method").', evidence);
    return `${className}.${methodName}`;
  }
  let parsed;
  try {
    parsed = parseJavaSignature(signature);
  } catch (err) {
    throw invalidEvidence((err as Error).message, evidence);
  }
  if (parsed.name && methodName && parsed.name !== methodName) {
    throw invalidEvidence(`evidence.method "${methodName}" does not match the name in evidence.signature "${parsed.name}".`, evidence);
  }
  const name = parsed.name ?? methodName;
  if (!name) throw invalidEvidence('The signature has no method name; add evidence.method.', evidence);
  return `${className}.${formatJavaSignature(name, parsed.argTypes)}`;
}

/**
 * The method spec a hook installs: `method` as given, or the spec derived from static
 * evidence. Exactly one of the two must be provided.
 */
export function resolveHookMethod(method: string | undefined, evidence: HookEvidence | undefined): string {
  if (method && evidence) {
    throw new FridaMcpError('INVALID_ARGUMENT', 'Pass either "method" or "evidence", not both.', [], { method });
  }
  if (method) return method;
  if (!evidence) {
    throw new FridaMcpError('INVALID_ARGUMENT', 'Provide "method" (hook notation) or "evidence" (static-analysis finding).', [
      { tool: 'frida_help', reason: 'See the hook notation' },
    ]);
  }
  const isNative = evidence.module !== undefined || evidence.offset !== undefined || evidence.address !== undefined || evidence.image_base !== undefined;
  const isJava = evidence.class !== undefined || evidence.signature !== undefined || evidence.method !== undefined;
  if (isNative && isJava) throw invalidEvidence('Evidence mixes native (module/offset) and Java (class/signature) fields.', evidence);
  return isNative ? nativeEvidenceToTarget(evidence) : javaEvidenceToMethod(evidence);
}

/**
 * In-script helper: wraps an address in the Frida 17.10 options form when the caller
 * supplied `interceptorOptions`, and returns the plain address otherwise so the
 * pre-17.10 call shape is unchanged.
 */
export const INTERCEPTOR_TARGET_SNIPPET = `
function interceptorTarget(addr) {
  var io = __FRIDA_MCP__.options.interceptorOptions;
  if (!io) return addr;
  return Object.assign({}, io, { target: addr });
}
`;

export function registerHookTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'hook_method',
    {
      title: 'Hook Method',
      description: 'Hook a method to intercept calls with auto device/session management. Provide the app target (or a session_id of an existing session) and method pattern. Supports Java methods (Android: "com.example.Class.method"), Objective-C methods (iOS: "-[NSURLSession dataTaskWithRequest:]"), and native functions in any notation: "libssl.so!SSL_read" (module export), "libfoo.so+0x1234" or "libfoo.so+4660" (module-relative offset, as shown by Ghidra/IDA), "0x7f1234567890" (absolute address), or "!open" (global export searched across all modules). Native backtraces are reported as "module+0xoff (symbol)". Java overloads: append a signature to hook ONE overload, e.g. "com.pkg.Class.encrypt(byte[], java.lang.String)" (without one, every overload is hooked). Static-analysis findings can be passed as "evidence" instead of "method": {module, offset} (image-base-relative offset from Ghidra/IDA) or {module, address, image_base}, or {class, signature} for Java (jadx/describe_class/JVM descriptor). After hooking, use get_messages to retrieve intercepted calls.',
      inputSchema: z.object({
        target: z.string().optional().describe('App bundle ID, process name, or PID (as string). Optional when session_id is given.'),
        session_id: z.string().optional().describe('Attach the hook to this existing session (from explore_app/hook_method/get_status) instead of looking the app up by target. No new process is spawned.'),
        method: z.string().optional().describe('Method to hook (required unless evidence is given). Java: "com.pkg.Class.method" (all overloads) or "com.pkg.Class.method(byte[], java.lang.String)" (one overload), ObjC: "-[Class method:]", Native: "lib.so!func", "lib.so+0x1234" (or decimal "lib.so+4660"), "0x7f12345678". A bare name like "open" is treated as a Java method; use "!open" or "libc.so!open" for a global native export.'),
        device: z.string().optional().describe('Device ID. Auto-selects if not specified.'),
        log_args: z.boolean().optional().default(true).describe('Log method arguments (default: true)'),
        log_retval: z.boolean().optional().default(true).describe('Log return value (default: true)'),
        log_backtrace: z.boolean().optional().default(false).describe('Log call backtrace (default: false)'),
        spawn: z.boolean().optional().default(false).describe('Spawn the app fresh instead of attaching to running process (default: false)'),
        evidence: hookEvidenceSchema.optional(),
        interceptor_options: interceptorOptionsSchema,
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
    async ({ target, session_id, method: methodInput, evidence, device, log_args, log_retval, log_backtrace, spawn: shouldSpawn, interceptor_options, response_format }) => {
      const startTime = Date.now();
      try {
        const state = getState();
        const method = resolveHookMethod(methodInput, evidence);
        const instrumentation = resolveInstrumentationTarget(target, session_id);

        const { sessionEntry: resolvedSession, fridaDevice, isNew } = await getOrCreateSession(deviceManager, {
          target: instrumentation.target,
          sessionId: instrumentation.sessionId,
          device,
          forceSpawn: shouldSpawn,
        });
        let sessionEntry = resolvedSession;
        if (isNew && shouldSpawn) {
          await fridaDevice.resume(sessionEntry.pid);
        }

        const pid = sessionEntry.pid;

        // Determine hook type; the script body is constant per type and reads its
        // target/flags from __FRIDA_MCP__.options at runtime (no code interpolation).
        const hookType = detectHookType(method);
        const hookOptions = buildHookOptions(
          method,
          hookType,
          {
            logArgs: log_args ?? true,
            logRetval: log_retval ?? true,
            logBacktrace: log_backtrace ?? false,
          },
          interceptor_options
        );

        const script = await createAgentScript(sessionEntry.session, {
          sessionEntry: sessionEntry,
          source: generateHookScript(hookType),
          platform: sessionEntry.platform,
          name: `hook:${method}`,
          kind: 'generated',
          options: { ...hookOptions, platform: sessionEntry.platform },
          // Native hooks never touch Java/ObjC; skip the bridge payload for them.
          bridges: hookType === 'native' ? [] : undefined,
        });
        const scriptId = state.generateId();
        const hookId = state.generateId();

        const scriptEntry = {
          id: scriptId,
          script,
          messages: [],
          name: `hook:${method}`,
          persistent: true,
          createdAt: Date.now(),
        };
        sessionEntry.scripts.set(scriptId, scriptEntry);

        // Register the hook before loading so the agent's install-status message (sent
        // during load) can update its liveness. Cleaned up below if the load fails.
        state.hooks.set(hookId, {
          id: hookId,
          scriptId,
          sessionId: sessionEntry.id,
          target: method,
          type: hookType,
          invocations: [],
          status: 'active',
          createdAt: Date.now(),
          liveness: { installed: false, firstSeenTs: null },
        });

        // Shared sinks capture console.* (never stdout) and record errors with full fidelity.
        // Our onSend handles the hook-specific sends: install-status updates liveness; real
        // invocations are recorded and set firstSeenTs on the first hit.
        attachScriptSinks(script, sessionEntry.id, scriptId, {
          onSend: (rawPayload, data) => {
            const payload = rawPayload as HookAgentPayload | null;
            if (payload && typeof payload.status === 'string') {
              applyHookStatus(state.hooks.get(hookId), payload);
              state.addMessageToScript(sessionEntry!.id, scriptId, { timestamp: Date.now(), type: 'hook_status', payload, data: data ?? null });
              return;
            }

            state.addMessageToScript(sessionEntry!.id, scriptId, { timestamp: Date.now(), type: 'hook_invocation', payload, data: data ?? null });

            const hook = state.hooks.get(hookId);
            if (hook && payload) {
              if (hook.liveness && !hook.liveness.firstSeenTs) hook.liveness.firstSeenTs = Date.now();
              hook.invocations.push({
                timestamp: Date.now(),
                threadId: payload.threadId ?? 0,
                args: payload.args ?? [],
                retval: payload.retval,
                backtrace: payload.backtrace ?? null,
              });
              if (hook.invocations.length > 1000) {
                hook.invocations.splice(0, hook.invocations.length - 1000);
              }
            }
          },
        });

        try {
          await script.load();
        } catch (loadErr) {
          state.hooks.delete(hookId);
          sessionEntry.scripts.delete(scriptId);
          throw loadErr;
        }

        const missReason = state.hooks.get(hookId)?.liveness?.reason;
        log(missReason ? 'warn' : 'info', missReason ? `Hook on ${method} not installed: ${missReason} (hook: ${hookId})` : `Hook installed on ${method} (hook: ${hookId})`);

        audit({
          timestamp: new Date().toISOString(),
          sessionId: sessionEntry.id,
          tool: 'hook_method',
          params: { target, session_id, method, evidence, log_args, log_retval, log_backtrace, interceptor_options },
          status: 'success',
          durationMs: Date.now() - startTime,
        });

        const installedHook = state.hooks.get(hookId);
        return formatToolResponse(
          buildResult(
            {
              hook_id: hookId,
              session_id: sessionEntry.id,
              script_id: scriptId,
              pid,
              method,
              hook_type: hookType,
              status: installedHook?.status ?? 'active',
              ...(evidence ? { evidence } : {}),
              ...(hookOptions.argTypes ? { arg_types: hookOptions.argTypes } : {}),
              ...(installedHook?.liveness?.reason ? { liveness: installedHook.liveness } : {}),
              interceptor_options: hookOptions.interceptorOptions ?? null,
              message: installedHook?.liveness?.reason
                ? `Hook on ${method} did not install (${installedHook.liveness.reason}). See liveness for details.`
                : `Hook installed on ${method}. Use get_messages to retrieve intercepted calls.`,
            },
            [
              { tool: 'get_messages', args: { session_id: sessionEntry.id }, reason: 'Check for intercepted method calls' },
              { tool: 'mobile_action', args: { action: 'mobile_take_screenshot' }, reason: 'See app state before triggering the hooked method' },
              { tool: 'hook_method', reason: 'Hook additional methods' },
              { tool: 'stop_instrumentation', args: { session_id: sessionEntry.id }, reason: 'Remove all hooks when done' },
            ],
            { limitations: interceptorOptionsLimitations(hookType, interceptor_options) }
          ),
          response_format
        );
      } catch (err) {
        const wrapped = wrapFridaError(err);
        audit({
          timestamp: new Date().toISOString(),
          tool: 'hook_method',
          params: { target, session_id, method: methodInput, evidence },
          status: 'error',
          durationMs: Date.now() - startTime,
        });
        return formatToolResponse(wrapped.toErrorResponse(), response_format);
      }
    }
  );
}

/** Shape of the JSON payloads the hook agent scripts send() back to the host. */
interface HookAgentPayload {
  status?: 'hook_installed' | 'hook_error';
  method?: string;
  reason?: HookMissReason;
  classResolved?: boolean;
  overloads?: number;   // java: instrumented overload count
  matches?: number;     // objc: matched class/selector count
  resolved?: string;    // native: resolved address description
  threadId?: number;
  args?: unknown[];
  retval?: unknown;
  backtrace?: string[] | null;
  availableOverloads?: string[]; // java OVERLOAD_MISMATCH: the overloads that do exist
}

/**
 * Fold an agent install/error status message into the hook's liveness record, so the
 * AI can later read whether the hook actually attached and why it did not.
 */
export function applyHookStatus(hook: HookEntry | undefined, payload: HookAgentPayload): void {
  if (!hook || !hook.liveness) return;
  const liveness = hook.liveness;
  if (payload.status === 'hook_installed') {
    liveness.installed = true;
    if (typeof payload.classResolved === 'boolean') liveness.classResolved = payload.classResolved;
    if (typeof payload.overloads === 'number') liveness.overloadsMatched = payload.overloads;
    if (typeof payload.matches === 'number') liveness.matches = payload.matches;
  } else if (payload.status === 'hook_error') {
    liveness.installed = false;
    if (typeof payload.classResolved === 'boolean') liveness.classResolved = payload.classResolved;
    if (payload.reason) liveness.reason = payload.reason;
    if (Array.isArray(payload.availableOverloads)) liveness.availableOverloads = payload.availableOverloads;
    hook.status = 'error';
  }
}

/** What getOrCreateSession needs to find or create the session a hook/trace attaches to. */
export interface InstrumentationTarget {
  target: string;
  sessionId?: string;
}

/**
 * Turn the optional `target` / `session_id` inputs of hook_method and trace_method
 * into session options. A `session_id` must name an existing session (its target
 * fills in a missing `target`); without one, `target` is required and validated.
 */
export function resolveInstrumentationTarget(target: string | undefined, sessionId: string | undefined): InstrumentationTarget {
  if (sessionId) {
    const sessionEntry = getState().getSession(sessionId);
    if (!sessionEntry) {
      throw new FridaMcpError(
        'SESSION_NOT_FOUND',
        `Session "${sessionId}" not found. Omit session_id to attach by target instead.`,
        [{ tool: 'get_status', reason: 'List active sessions' }],
        { session_id: sessionId }
      );
    }
    // Validate an explicitly-passed target even when reusing a session, so the input guard the
    // process-scoped tools relied on is not silently dropped on the session_id path.
    if (target) validateProcessTarget(target);
    return { target: target ?? sessionEntry.target, sessionId };
  }
  if (!target) {
    throw new FridaMcpError(
      'INVALID_ARGUMENT',
      'Provide target (app bundle ID, process name or PID) or session_id of an existing session.',
      [{ tool: 'get_status', reason: 'List active sessions and running apps' }]
    );
  }
  validateProcessTarget(target);
  return { target };
}

export type HookType = 'native' | 'java' | 'objc';

export interface HookFlags {
  logArgs: boolean;
  logRetval: boolean;
  logBacktrace: boolean;
}

/** `module+0xOFF` / `module+1234`: a module-relative offset is always a native target. */
const MODULE_OFFSET_PATTERN = /^.+\+(0[xX][0-9a-fA-F]+|\d+)$/;

/**
 * Classify a method spec. A bare global symbol ("open") cannot be told apart from a
 * Java method name, so it stays 'java'; callers use "!open" or "libc.so!open" instead.
 */
export function detectHookType(method: string): HookType {
  if (method.startsWith('-[') || method.startsWith('+[')) return 'objc';
  if (method.includes('!') || method.startsWith('0x')) return 'native';
  if (MODULE_OFFSET_PATTERN.test(method)) return 'native';
  return 'java'; // Default: assume Java fully qualified method
}

/**
 * Split the user-supplied method spec into the fields the script reads from
 * `__FRIDA_MCP__.options`. Values are serialised as JSON by the preamble, never
 * spliced into code position. `interceptorOptions` is only emitted for native hooks
 * (see interceptorOptionsSchema); Java/ObjC hooks do not go through Interceptor.
 */
export function buildHookOptions(
  method: string,
  hookType: HookType,
  flags: HookFlags,
  interceptorOptions?: InterceptorOptions
): Record<string, unknown> {
  const options: Record<string, unknown> = { method, ...flags };
  const normalized = hookType === 'native' ? normalizeInterceptorOptions(interceptorOptions) : undefined;
  if (normalized) options.interceptorOptions = normalized;
  if (hookType === 'java') {
    Object.assign(options, splitJavaMethod(method));
  } else if (hookType === 'native') {
    // moduleName/funcName/address are kept for backward compatibility; the script
    // resolves the target from the parsed `nativeTarget` (see RESOLVE_TARGET_SNIPPET).
    if (method.includes('!')) {
      const [moduleName, funcName] = method.split('!');
      options.moduleName = moduleName;
      options.funcName = funcName;
    } else {
      options.address = method;
    }
    options.nativeTarget = parseTarget(method);
  }
  return options;
}

export interface JavaMethodSpec {
  className: string;
  methodName: string;
  /** Canonical parameter types selecting one overload; absent = hook every overload. */
  argTypes?: string[];
}

/**
 * `com.pkg.Class.method` or `com.pkg.Class.method(<signature>)` -> class, method and the
 * optional overload selector. The signature accepts every form parseJavaSignature does.
 */
export function splitJavaMethod(method: string): JavaMethodSpec {
  const paren = method.indexOf('(');
  const head = paren < 0 ? method : method.slice(0, paren).trim();
  const lastDot = head.lastIndexOf('.');
  const className = head.substring(0, lastDot);
  const methodName = head.substring(lastDot + 1).replace(/^<init>$/, '$init');
  if (paren < 0) return { className, methodName };
  let parsed;
  try {
    parsed = parseJavaSignature(methodName + method.slice(paren));
  } catch (err) {
    throw new FridaMcpError('INVALID_ARGUMENT', `Invalid Java method signature in "${method}": ${(err as Error).message}`, [
      { tool: 'describe_class', reason: 'List the overloads and their exact signatures' },
    ], { method });
  }
  return { className, methodName, argTypes: parsed.argTypes };
}

const JAVA_HOOK_SCRIPT = `
(function () {
  var o = __FRIDA_MCP__.options;

  function javaBacktrace() {
    try {
      var Log = Java.use('android.util.Log');
      var Exception = Java.use('java.lang.Exception');
      return String(Log.getStackTraceString(Exception.$new()))
        .split('\\n')
        .map(function (l) { return l.trim(); })
        .filter(function (l) { return l.length > 0; });
    } catch (e) {
      return ['<backtrace unavailable: ' + e.message + '>'];
    }
  }

  if (!Java.available) {
    send({ status: 'hook_error', method: o.method, reason: 'NO_RUNTIME', classResolved: false, error: 'Java runtime not available in this process' });
    return;
  }

  // useInAnyLoader(name) comes from JAVA_CLASS_LOOKUP_SNIPPET (cross-class-loader lookup).

  // Canonical type ([B, java.lang.String) -> Java source form (byte[], java.lang.String).
  var PRIMITIVES = { Z: 'boolean', B: 'byte', C: 'char', S: 'short', I: 'int', J: 'long', F: 'float', D: 'double' };
  function arrayDepth(name) {
    var dims = 0;
    while (name.charAt(dims) === '[') dims++;
    return dims;
  }
  // '[Ljava.lang.String;' -> 'java.lang.String', '[B' -> 'B', 'int' -> 'int'
  function elementName(name) {
    var element = name.substring(arrayDepth(name));
    var isClass = element.length > 2 && element.charAt(0) === 'L' && element.charAt(element.length - 1) === ';';
    return isClass ? element.substring(1, element.length - 1) : element;
  }
  function sourceType(name) {
    var dims = arrayDepth(name);
    if (dims === 0) return name;
    var element = name.substring(dims);
    var out = element.charAt(0) === 'L' ? elementName(name) : PRIMITIVES[element];
    for (var i = 0; i < dims; i++) out += '[]';
    return out;
  }
  function simpleName(className) {
    return className.substring(Math.max(className.lastIndexOf('.'), className.lastIndexOf('$')) + 1);
  }
  // A requested type matches exactly, or - when given unqualified ("String", "[LString;") -
  // by simple name with the same array depth.
  function typeMatches(actual, wanted) {
    if (actual === wanted) return true;
    if (wanted.indexOf('.') >= 0) return false;
    if (arrayDepth(actual) !== arrayDepth(wanted)) return false;
    var a = elementName(actual), w = elementName(wanted);
    return simpleName(a) === w || a.substring(a.length - w.length - 1) === '.' + w;
  }
  function overloadMatches(overload, wanted) {
    var types = overload.argumentTypes;
    if (types.length !== wanted.length) return false;
    for (var i = 0; i < types.length; i++) {
      if (!typeMatches(types[i].className, wanted[i])) return false;
    }
    return true;
  }
  function overloadSignature(overload) {
    return o.methodName + '(' + overload.argumentTypes.map(function (t) { return sourceType(t.className); }).join(', ') + ')';
  }

  Java.perform(function () {
    try {
      var cls = useInAnyLoader(o.className);
      if (cls === null) {
        recordHookError(o.method, new Error('class not loaded: ' + o.className));
        send({ status: 'hook_error', method: o.method, reason: 'CLASS_NOT_LOADED', classResolved: false, error: 'Class not loaded in any class loader: ' + o.className });
        return;
      }
      if (typeof cls[o.methodName] === 'undefined' || !cls[o.methodName].overloads) {
        recordHookError(o.method, new Error('no such method: ' + o.method));
        send({ status: 'hook_error', method: o.method, reason: 'NO_SUCH_METHOD', classResolved: true, error: 'Method not found on class: ' + o.method });
        return;
      }
      var overloads = cls[o.methodName].overloads;
      if (Array.isArray(o.argTypes)) {
        var all = overloads;
        overloads = all.filter(function (ov) { return overloadMatches(ov, o.argTypes); });
        if (overloads.length === 0) {
          var available = all.map(overloadSignature);
          recordHookError(o.method, new Error('no overload matches ' + o.method));
          send({ status: 'hook_error', method: o.method, reason: 'OVERLOAD_MISMATCH', classResolved: true, availableOverloads: available, error: 'No overload of ' + o.className + '.' + o.methodName + ' matches the requested signature. Available: ' + available.join('; ') });
          return;
        }
      }
      overloads.forEach(function (overload) {
        overload.implementation = function () {
          var args = [];
          if (o.logArgs) {
            for (var i = 0; i < arguments.length; i++) {
              try { args.push(String(arguments[i])); } catch (e) { args.push('<error>'); }
            }
          }

          var retval = overload.apply(this, arguments);

          var payload = {
            method: o.method,
            type: 'java',
            threadId: Process.getCurrentThreadId(),
          };
          if (o.logArgs) payload.args = args;
          if (o.logRetval) {
            try { payload.retval = String(retval); } catch (e) { payload.retval = '<error>'; }
          }
          if (o.logBacktrace) payload.backtrace = javaBacktrace();

          send(payload);
          return retval;
        };
      });
      send({ status: 'hook_installed', method: o.method, classResolved: true, overloads: overloads.length });
    } catch (e) {
      recordHookError(o.method, e);
      send({ status: 'hook_error', method: o.method, reason: 'NO_SUCH_METHOD', error: e.message });
    }
  });
})();
`;

const OBJC_HOOK_SCRIPT = `
(function () {
  var o = __FRIDA_MCP__.options;

  if (!ObjC.available) {
    send({ status: 'hook_error', method: o.method, reason: 'NO_RUNTIME', classResolved: false, error: 'Objective-C runtime not available in this process' });
    return;
  }

  try {
    var resolver = new ApiResolver('objc');
    var matches = resolver.enumerateMatches(o.method);
    if (matches.length === 0) {
      send({ status: 'hook_error', method: o.method, reason: 'CLASS_NOT_LOADED', classResolved: false, matches: 0, error: 'No matches found for ' + o.method });
      return;
    }
    matches.forEach(function (match) {
      Interceptor.attach(match.address, {
        onEnter: function (args) {
          this.payload = {
            method: o.method,
            type: 'objc',
            threadId: Process.getCurrentThreadId(),
            address: match.address.toString(),
          };
          if (o.logArgs) {
            try {
              this.payload.args = [];
              // First two args are self and _cmd, skip them
              for (var i = 2; i < 10; i++) {
                try {
                  var arg = new ObjC.Object(args[i]);
                  this.payload.args.push(arg.toString());
                } catch (e) { break; }
              }
            } catch (e) {}
          }
          if (o.logBacktrace) {
            this.payload.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
              .map(DebugSymbol.fromAddress)
              .map(function (s) { return s.toString(); });
          }
        },
        onLeave: function (retval) {
          if (o.logRetval) {
            try { this.payload.retval = retval.toString(); } catch (e) { this.payload.retval = retval.toInt32(); }
          }
          send(this.payload);
        }
      });
    });
    send({ status: 'hook_installed', method: o.method, matches: matches.length });
  } catch (e) {
    recordHookError(o.method, e);
    send({ status: 'hook_error', method: o.method, error: e.message });
  }
})();
`;

const NATIVE_HOOK_SCRIPT = `
(function () {
  var o = __FRIDA_MCP__.options;

  try {
    var addr = resolveTarget(o.nativeTarget || o.method);
    if (addr === null) {
      send({ status: 'hook_error', method: o.method, reason: 'NO_EXPORT', error: 'target not found: ' + o.method });
      return;
    }
    // Resolved once at install time; every invocation payload reuses it.
    var resolved = describeAddress(addr);
    var addressText = addr.toString();
    // Frida 17.10 form: { target, ...instrumentation options } when options were given.
    Interceptor.attach(interceptorTarget(addr), {
      onEnter: function (args) {
        this.payload = {
          method: o.method,
          type: 'native',
          threadId: Process.getCurrentThreadId(),
          address: addressText,
          rva: resolved.rva,
        };
        if (o.logArgs) {
          this.payload.args = [];
          for (var i = 0; i < 6; i++) {
            this.payload.args.push(args[i].toString());
          }
        }
        if (o.logBacktrace) {
          this.payload.backtrace = symbolizeBacktrace(this.context);
        }
      },
      onLeave: function (retval) {
        if (o.logRetval) this.payload.retval = retval.toString();
        send(this.payload);
      }
    });
    send({ status: 'hook_installed', method: o.method, resolved: resolved });
  } catch (e) {
    recordHookError(o.method, e);
    send({ status: 'hook_error', method: o.method, error: e.message });
  }
})();
`;

/**
 * Script body for a hook type. The body is constant: the target and logging flags
 * are read at runtime from `__FRIDA_MCP__.options` (see buildHookOptions). The native
 * body is prefixed with the shared target-resolution helpers (resolveTarget,
 * describeAddress, symbolizeBacktrace) and the interceptorTarget() options wrapper.
 */
export function generateHookScript(hookType: HookType): string {
  switch (hookType) {
    case 'java':
      return JAVA_CLASS_LOOKUP_SNIPPET + JAVA_HOOK_SCRIPT;
    case 'objc':
      return OBJC_HOOK_SCRIPT;
    case 'native':
      return RESOLVE_TARGET_SNIPPET + INTERCEPTOR_TARGET_SNIPPET + NATIVE_HOOK_SCRIPT;
  }
}
