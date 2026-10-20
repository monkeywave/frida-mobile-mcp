import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError } from '../helpers/errors.js';
import { log, audit } from '../helpers/logger.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
import { responseFormatSchema } from '../constants.js';
import { createAgentScript } from '../agent/script-factory.js';
import {
  resolveInstrumentationTarget,
  interceptorOptionsSchema,
  interceptorOptionsLimitations,
  normalizeInterceptorOptions,
  INTERCEPTOR_TARGET_SNIPPET,
  type InterceptorOptions,
} from './hook.js';

export function registerTraceTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'trace_method',
    {
      title: 'Trace Method Calls',
      description: 'Trace function calls matching a pattern for a specified duration. Simplified frida-trace equivalent. Supports glob patterns like "com.example.network.*" for Java, "-[NSURL*]" for ObjC, and "libssl.so!SSL_*" for native. Returns all captured invocations after the duration expires.',
      inputSchema: z.object({
        target: z.string().optional().describe('App bundle ID, process name, or PID. Optional when session_id is given.'),
        session_id: z.string().optional().describe('Trace inside this existing session (from explore_app/hook_method/get_status) instead of looking the app up by target. No new process is spawned.'),
        method: z.string().describe('Method pattern to trace. Supports * wildcards.'),
        device: z.string().optional().describe('Device ID'),
        duration_seconds: z.number().optional().default(10).describe('How long to trace (default: 10 seconds)'),
        log_args: z.boolean().optional().default(true).describe('Log arguments'),
        log_retval: z.boolean().optional().default(true).describe('Log return values'),
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
    async ({ target, session_id, method, device, duration_seconds, log_args, log_retval, interceptor_options, response_format }) => {
      const startTime = Date.now();
      try {
        const state = getState();
        const duration = duration_seconds ?? 10;
        const instrumentation = resolveInstrumentationTarget(target, session_id);

        const { sessionEntry: resolvedSession } = await getOrCreateSession(deviceManager, {
          target: instrumentation.target,
          sessionId: instrumentation.sessionId,
          device,
        });
        let sessionEntry = resolvedSession;

        // Build trace script: the body is constant per trace type and reads the
        // pattern/flags from __FRIDA_MCP__.options at runtime (no code interpolation).
        const traceType = detectTraceType(method);
        const traceOptions = buildTraceOptions(
          method,
          traceType,
          {
            logArgs: log_args ?? true,
            logRetval: log_retval ?? true,
          },
          interceptor_options
        );

        const script = await createAgentScript(sessionEntry.session, {
          sessionEntry: sessionEntry,
          source: generateTraceScript(traceType),
          platform: sessionEntry.platform,
          name: `trace:${method}`,
          kind: 'generated',
          options: { ...traceOptions, platform: sessionEntry.platform },
          // Native traces never touch Java/ObjC; skip the bridge payload for them.
          bridges: traceType === 'native' ? [] : undefined,
        });
        const scriptId = state.generateId();
        const traceId = state.generateId();

        const invocations: Array<Record<string, unknown>> = [];

        const scriptEntry = {
          id: scriptId,
          script,
          messages: [],
          name: `trace:${method}`,
          persistent: false,
          createdAt: Date.now(),
        };
        sessionEntry.scripts.set(scriptId, scriptEntry);

        script.message.connect((message, data) => {
          if (message.type === 'send' && message.payload) {
            if (invocations.length < 1000) {
              invocations.push(message.payload);
            }
            state.addMessageToScript(sessionEntry!.id, scriptId, {
              timestamp: Date.now(),
              type: 'trace_hit',
              payload: message.payload,
              data: data ?? null,
            });
          }
        });

        await script.load();

        state.traces.set(traceId, {
          id: traceId,
          scriptId,
          sessionId: sessionEntry.id,
          targets: [method],
          callCount: 0,
          startedAt: Date.now(),
        });

        // Wait for duration
        log('info', `Tracing ${method} for ${duration}s...`);
        await new Promise((resolve) => setTimeout(resolve, duration * 1000));

        // Unload script and collect results
        await script.unload();
        sessionEntry.scripts.delete(scriptId);
        state.traces.delete(traceId);

        audit({
          timestamp: new Date().toISOString(),
          sessionId: sessionEntry.id,
          tool: 'trace_method',
          params: { target, session_id, method, duration_seconds, interceptor_options },
          status: 'success',
          durationMs: Date.now() - startTime,
        });

        return formatToolResponse(
          buildResult(
            {
              trace_id: traceId,
              session_id: sessionEntry.id,
              script_id: scriptId,
              method,
              duration_seconds: duration,
              interceptor_options: traceOptions.interceptorOptions ?? null,
              invocations_count: invocations.length,
              invocations: invocations.slice(0, 100),
              truncated: invocations.length > 100,
            },
            [
              { tool: 'hook_method', args: { session_id: sessionEntry.id, method }, reason: 'Install a persistent hook on this method' },
              { tool: 'trace_method', args: { session_id: sessionEntry.id, method, duration_seconds: duration * 2 }, reason: 'Trace longer for more results' },
              { tool: 'search_classes_and_methods', reason: 'Find related methods to trace' },
            ],
            { limitations: interceptorOptionsLimitations(traceType, interceptor_options) }
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

export type TraceType = 'native' | 'java' | 'objc';

export interface TraceFlags {
  logArgs: boolean;
  logRetval: boolean;
}

export function detectTraceType(pattern: string): TraceType {
  if (pattern.startsWith('-[') || pattern.startsWith('+[')) return 'objc';
  if (pattern.includes('!')) return 'native';
  return 'java'; // Default for Android
}

/**
 * Split the user-supplied pattern into the fields the script reads from
 * `__FRIDA_MCP__.options`. Regexes are compiled inside the script (in try/catch),
 * never built on the host and spliced into code. `interceptorOptions` (Frida 17.10
 * Interceptor instrumentation options) is only emitted for native traces.
 */
export function buildTraceOptions(
  pattern: string,
  traceType: TraceType,
  flags: TraceFlags,
  interceptorOptions?: InterceptorOptions
): Record<string, unknown> {
  const options: Record<string, unknown> = { pattern, ...flags };
  if (traceType === 'native') {
    const [moduleName, funcPattern] = pattern.split('!');
    options.moduleName = moduleName;
    options.funcPattern = funcPattern;
    const normalized = normalizeInterceptorOptions(interceptorOptions);
    if (normalized) options.interceptorOptions = normalized;
  }
  return options;
}

/**
 * Shared in-script helper: converts a glob ("com.example.*", "SSL_*") into an anchored
 * RegExp. `.` is escaped BEFORE `*` is expanded so the expansion is not re-escaped.
 */
const GLOB_HELPER = `
  function globToRegExp(glob) {
    var source = String(glob).replace(/\\./g, '\\\\.').replace(/\\*/g, '.*');
    return new RegExp('^' + source + '$');
  }
`;

const OBJC_TRACE_SCRIPT = `
(function () {
  var o = __FRIDA_MCP__.options;

  if (!ObjC.available) {
    send({ status: 'trace_error', pattern: o.pattern, error: 'Objective-C runtime not available in this process' });
    return;
  }

  var matches;
  try {
    var resolver = new ApiResolver('objc');
    matches = resolver.enumerateMatches(o.pattern);
  } catch (e) {
    send({ status: 'trace_error', pattern: o.pattern, error: e.message });
    return;
  }
  send({ status: 'trace_started', matches: matches.length, pattern: o.pattern });
  matches.forEach(function (match) {
    Interceptor.attach(match.address, {
      onEnter: function (args) {
        this.info = { method: match.name, type: 'objc', threadId: Process.getCurrentThreadId(), timestamp: Date.now() };
        if (o.logArgs) {
          try {
            this.info.args = [];
            for (var i = 2; i < 8; i++) {
              try { this.info.args.push(new ObjC.Object(args[i]).toString()); } catch (e) { break; }
            }
          } catch (e) {}
        }
      },
      onLeave: function (retval) {
        if (o.logRetval) {
          try { this.info.retval = retval.toString(); } catch (e) {}
        }
        send(this.info);
      }
    });
  });
})();
`;

const NATIVE_TRACE_SCRIPT = `
(function () {
  var o = __FRIDA_MCP__.options;
  ${GLOB_HELPER}
  ${INTERCEPTOR_TARGET_SNIPPET}

  var re;
  try {
    re = globToRegExp(o.funcPattern);
  } catch (e) {
    send({ status: 'trace_error', pattern: o.pattern, error: 'invalid pattern: ' + e.message });
    return;
  }

  var m = Process.findModuleByName(o.moduleName);
  if (!m) {
    send({ status: 'trace_error', pattern: o.pattern, error: 'module not found: ' + o.moduleName });
    return;
  }

  var matches = m.enumerateExports()
    .filter(function (e) { return e.type === 'function' && re.test(e.name); });
  send({ status: 'trace_started', matches: matches.length, pattern: o.pattern });
  matches.forEach(function (exp) {
    // Frida 17.10 form: { target, ...instrumentation options } when options were given.
    Interceptor.attach(interceptorTarget(exp.address), {
      onEnter: function (args) {
        this.info = { method: o.moduleName + '!' + exp.name, type: 'native', threadId: Process.getCurrentThreadId(), timestamp: Date.now() };
        if (o.logArgs) {
          this.info.args = [];
          for (var i = 0; i < 4; i++) { this.info.args.push(args[i].toString()); }
        }
      },
      onLeave: function (retval) {
        if (o.logRetval) this.info.retval = retval.toString();
        send(this.info);
      }
    });
  });
})();
`;

const JAVA_TRACE_SCRIPT = `
(function () {
  var o = __FRIDA_MCP__.options;
  ${GLOB_HELPER}

  if (!Java.available) {
    send({ status: 'trace_error', pattern: o.pattern, error: 'Java runtime not available in this process' });
    return;
  }

  var re;
  try {
    re = globToRegExp(o.pattern);
  } catch (e) {
    send({ status: 'trace_error', pattern: o.pattern, error: 'invalid pattern: ' + e.message });
    return;
  }

  Java.perform(function () {
    var matchCount = 0;
    // Collect matching class names first; calling Java.use() from inside the
    // enumerateLoadedClasses callback can deadlock the process.
    var classNames = [];
    Java.enumerateLoadedClasses({
      onMatch: function (className) {
        if (re.test(className)) classNames.push(className);
      },
      onComplete: function () {}
    });
    classNames.forEach(function (className) {
      try {
        var cls = Java.use(className);
        var methods = cls.class.getDeclaredMethods();
        methods.forEach(function (m) {
          var methodName = m.getName();
          try {
            var overloads = cls[methodName].overloads;
            overloads.forEach(function (overload) {
              overload.implementation = function () {
                var info = { method: className + '.' + methodName, type: 'java', threadId: Process.getCurrentThreadId(), timestamp: Date.now() };
                if (o.logArgs) {
                  info.args = [];
                  for (var i = 0; i < arguments.length; i++) {
                    try { info.args.push(String(arguments[i])); } catch (e) { info.args.push('<error>'); }
                  }
                }
                var retval = overload.apply(this, arguments);
                if (o.logRetval) {
                  try { info.retval = String(retval); } catch (e) { info.retval = '<error>'; }
                }
                send(info);
                return retval;
              };
              matchCount++;
            });
          } catch (e) {}
        });
      } catch (e) { recordHookError(className, e); }
    });
    send({ status: 'trace_started', matches: matchCount, classes: classNames.length, pattern: o.pattern });
  });
})();
`;

/**
 * Script body for a trace type. The body is constant: the pattern and logging flags
 * are read at runtime from `__FRIDA_MCP__.options` (see buildTraceOptions).
 */
export function generateTraceScript(traceType: TraceType): string {
  switch (traceType) {
    case 'objc':
      return OBJC_TRACE_SCRIPT;
    case 'native':
      return NATIVE_TRACE_SCRIPT;
    case 'java':
      return JAVA_TRACE_SCRIPT;
  }
}
