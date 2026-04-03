import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError } from '../helpers/errors.js';
import { validateProcessTarget, escapeForScript } from '../helpers/sanitize.js';
import { log, audit } from '../helpers/logger.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
import { responseFormatSchema } from '../constants.js';

export function registerTraceTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'trace_method',
    {
      title: 'Trace Method Calls',
      description: 'Trace function calls matching a pattern for a specified duration. Simplified frida-trace equivalent. Supports glob patterns like "com.example.network.*" for Java, "-[NSURL*]" for ObjC, and "libssl.so!SSL_*" for native. Returns all captured invocations after the duration expires.',
      inputSchema: {
        target: z.string().describe('App bundle ID, process name, or PID'),
        method: z.string().describe('Method pattern to trace. Supports * wildcards.'),
        device: z.string().optional().describe('Device ID'),
        duration_seconds: z.number().optional().default(10).describe('How long to trace (default: 10 seconds)'),
        log_args: z.boolean().optional().default(true).describe('Log arguments'),
        log_retval: z.boolean().optional().default(true).describe('Log return values'),
        response_format: responseFormatSchema,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async ({ target, method, device, duration_seconds, log_args, log_retval, response_format }) => {
      const startTime = Date.now();
      try {
        validateProcessTarget(target);
        const state = getState();
        const duration = duration_seconds ?? 10;

        const { sessionEntry: resolvedSession } = await getOrCreateSession(deviceManager, { target, device });
        let sessionEntry = resolvedSession;

        // Build trace script
        const traceScript = generateTraceScript(method, {
          logArgs: log_args ?? true,
          logRetval: log_retval ?? true,
        });

        const script = await sessionEntry.session.createScript(traceScript);
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
          params: { target, method, duration_seconds },
          status: 'success',
          durationMs: Date.now() - startTime,
        });

        return formatToolResponse(
          buildResult(
            {
              trace_id: traceId,
              session_id: sessionEntry.id,
              method,
              duration_seconds: duration,
              invocations_count: invocations.length,
              invocations: invocations.slice(0, 100),
              truncated: invocations.length > 100,
            },
            [
              { tool: 'hook_method', args: { target, method }, reason: 'Install a persistent hook on this method' },
              { tool: 'trace_method', args: { target, method, duration_seconds: duration * 2 }, reason: 'Trace longer for more results' },
              { tool: 'search_classes_and_methods', reason: 'Find related methods to trace' },
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

function generateTraceScript(
  pattern: string,
  options: { logArgs: boolean; logRetval: boolean }
): string {
  const safePattern = escapeForScript(pattern);

  // Determine if this is a Java, ObjC, or native pattern
  if (pattern.startsWith('-[') || pattern.startsWith('+[')) {
    // ObjC pattern
    return `
      var resolver = new ApiResolver('objc');
      var matches = resolver.enumerateMatches('${safePattern}');
      send({ status: 'trace_started', matches: matches.length, pattern: '${safePattern}' });
      matches.forEach(function(match) {
        Interceptor.attach(match.address, {
          onEnter: function(args) {
            this.info = { method: match.name, type: 'objc', threadId: Process.getCurrentThreadId(), timestamp: Date.now() };
            ${options.logArgs ? `
            try {
              this.info.args = [];
              for (var i = 2; i < 8; i++) {
                try { this.info.args.push(new ObjC.Object(args[i]).toString()); } catch(e) { break; }
              }
            } catch(e) {}` : ''}
          },
          onLeave: function(retval) {
            ${options.logRetval ? `try { this.info.retval = retval.toString(); } catch(e) {}` : ''}
            send(this.info);
          }
        });
      });
    `;
  }

  if (pattern.includes('!')) {
    // Native pattern with module
    const [moduleName, funcPattern] = pattern.split('!');
    const safeModuleName = escapeForScript(moduleName);
    return `
      var matches = Module.enumerateExports('${safeModuleName}')
        .filter(function(e) { return e.type === 'function' && e.name.match(/${funcPattern.replace(/\*/g, '.*')}/); });
      send({ status: 'trace_started', matches: matches.length, pattern: '${safePattern}' });
      matches.forEach(function(exp) {
        Interceptor.attach(exp.address, {
          onEnter: function(args) {
            this.info = { method: '${safeModuleName}!' + exp.name, type: 'native', threadId: Process.getCurrentThreadId(), timestamp: Date.now() };
            ${options.logArgs ? `
            this.info.args = [];
            for (var i = 0; i < 4; i++) { this.info.args.push(args[i].toString()); }` : ''}
          },
          onLeave: function(retval) {
            ${options.logRetval ? `this.info.retval = retval.toString();` : ''}
            send(this.info);
          }
        });
      });
    `;
  }

  // Java pattern (default for Android)
  const javaPattern = pattern.replace(/\*/g, '.*');
  return `
    Java.perform(function() {
      var matchCount = 0;
      Java.enumerateLoadedClasses({
        onMatch: function(className) {
          if (!className.match(/${javaPattern.replace(/\./g, '\\.')}/) ) return;
          try {
            var cls = Java.use(className);
            var methods = cls.class.getDeclaredMethods();
            methods.forEach(function(m) {
              var methodName = m.getName();
              try {
                var overloads = cls[methodName].overloads;
                overloads.forEach(function(overload) {
                  overload.implementation = function() {
                    var info = { method: className + '.' + methodName, type: 'java', threadId: Process.getCurrentThreadId(), timestamp: Date.now() };
                    ${options.logArgs ? `
                    info.args = [];
                    for (var i = 0; i < arguments.length; i++) {
                      try { info.args.push(String(arguments[i])); } catch(e) { info.args.push('<error>'); }
                    }` : ''}
                    var retval = overload.apply(this, arguments);
                    ${options.logRetval ? `try { info.retval = String(retval); } catch(e) { info.retval = '<error>'; }` : ''}
                    send(info);
                    return retval;
                  };
                  matchCount++;
                });
              } catch(e) {}
            });
          } catch(e) {}
        },
        onComplete: function() {
          send({ status: 'trace_started', matches: matchCount, pattern: '${safePattern}' });
        }
      });
    });
  `;
}
