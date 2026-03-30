import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError } from '../helpers/errors.js';
import { validateProcessTarget, escapeForScript } from '../helpers/sanitize.js';
import { log, audit } from '../helpers/logger.js';
import { getOrCreateSession } from '../helpers/session-helper.js';

export function registerHookTool(server: McpServer, deviceManager: DeviceManager): void {
  server.tool(
    'hook_method',
    'Hook a method to intercept calls with auto device/session management. Provide the app target and method pattern. Supports Java methods (Android: "com.example.Class.method"), Objective-C methods (iOS: "-[NSURLSession dataTaskWithRequest:]"), and native functions ("libssl.so!SSL_read"). After hooking, use get_messages to retrieve intercepted calls.',
    {
      target: z.string().describe('App bundle ID, process name, or PID (as string)'),
      method: z.string().describe('Method to hook. Java: "com.pkg.Class.method", ObjC: "-[Class method:]", Native: "lib.so!func"'),
      device: z.string().optional().describe('Device ID. Auto-selects if not specified.'),
      log_args: z.boolean().optional().default(true).describe('Log method arguments (default: true)'),
      log_retval: z.boolean().optional().default(true).describe('Log return value (default: true)'),
      log_backtrace: z.boolean().optional().default(false).describe('Log call backtrace (default: false)'),
      spawn: z.boolean().optional().default(false).describe('Spawn the app fresh instead of attaching to running process (default: false)'),
    },
    async ({ target, method, device, log_args, log_retval, log_backtrace, spawn: shouldSpawn }) => {
      const startTime = Date.now();
      try {
        validateProcessTarget(target);
        const state = getState();

        const { sessionEntry: resolvedSession, fridaDevice, isNew } = await getOrCreateSession(deviceManager, {
          target,
          device,
          forceSpawn: shouldSpawn,
        });
        let sessionEntry = resolvedSession;
        if (isNew && shouldSpawn) {
          await fridaDevice.resume(sessionEntry.pid);
        }

        const pid = sessionEntry.pid;

        // Determine hook type and generate script
        const hookScript = generateHookScript(method, {
          logArgs: log_args ?? true,
          logRetval: log_retval ?? true,
          logBacktrace: log_backtrace ?? false,
        });

        const script = await sessionEntry.session.createScript(hookScript);
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

        // Listen for messages
        script.message.connect((message, data) => {
          if (message.type === 'send') {
            state.addMessageToScript(sessionEntry!.id, scriptId, {
              timestamp: Date.now(),
              type: 'hook_invocation',
              payload: message.payload,
              data: data ?? null,
            });

            // Update hook invocations
            const hook = state.hooks.get(hookId);
            if (hook && message.payload) {
              hook.invocations.push({
                timestamp: Date.now(),
                threadId: message.payload.threadId ?? 0,
                args: message.payload.args ?? [],
                retval: message.payload.retval,
                backtrace: message.payload.backtrace ?? null,
              });
              // Cap invocations to prevent unbounded growth
              if (hook.invocations.length > 1000) {
                hook.invocations.splice(0, hook.invocations.length - 1000);
              }
            }
          } else if (message.type === 'error') {
            state.addMessageToScript(sessionEntry!.id, scriptId, {
              timestamp: Date.now(),
              type: 'error',
              payload: { description: message.description, stack: message.stack, fileName: message.fileName, lineNumber: message.lineNumber },
              data: null,
            });
          }
        });

        await script.load();

        // Register hook
        const hookType = detectHookType(method);
        state.hooks.set(hookId, {
          id: hookId,
          scriptId,
          sessionId: sessionEntry.id,
          target: method,
          type: hookType,
          invocations: [],
          status: 'active',
          createdAt: Date.now(),
        });

        log('info', `Hook installed on ${method} (hook: ${hookId})`);

        audit({
          timestamp: new Date().toISOString(),
          sessionId: sessionEntry.id,
          tool: 'hook_method',
          params: { target, method, log_args, log_retval, log_backtrace },
          status: 'success',
          durationMs: Date.now() - startTime,
        });

        return formatToolResponse(
          buildResult(
            {
              hook_id: hookId,
              session_id: sessionEntry.id,
              script_id: scriptId,
              pid,
              method,
              hook_type: hookType,
              status: 'active',
              message: `Hook installed on ${method}. Use get_messages to retrieve intercepted calls.`,
            },
            [
              { tool: 'get_messages', args: { session_id: sessionEntry.id }, reason: 'Check for intercepted method calls' },
              { tool: 'mobile_action', args: { action: 'mobile_take_screenshot' }, reason: 'See app state before triggering the hooked method' },
              { tool: 'hook_method', reason: 'Hook additional methods' },
              { tool: 'stop_instrumentation', args: { session_id: sessionEntry.id }, reason: 'Remove all hooks when done' },
            ]
          )
        );
      } catch (err) {
        const wrapped = wrapFridaError(err);
        audit({
          timestamp: new Date().toISOString(),
          tool: 'hook_method',
          params: { target, method },
          status: 'error',
          durationMs: Date.now() - startTime,
        });
        return formatToolResponse(wrapped.toErrorResponse());
      }
    }
  );
}

function detectHookType(method: string): 'native' | 'java' | 'objc' {
  if (method.startsWith('-[') || method.startsWith('+[')) return 'objc';
  if (method.includes('!') || method.startsWith('0x')) return 'native';
  return 'java'; // Default: assume Java fully qualified method
}

function generateHookScript(
  method: string,
  options: { logArgs: boolean; logRetval: boolean; logBacktrace: boolean }
): string {
  const hookType = detectHookType(method);
  const safeMethod = escapeForScript(method);

  if (hookType === 'java') {
    const lastDot = method.lastIndexOf('.');
    const safeClassName = escapeForScript(method.substring(0, lastDot));
    const safeMethodName = escapeForScript(method.substring(lastDot + 1));

    return `
      Java.perform(function() {
        try {
          var cls = Java.use('${safeClassName}');
          var overloads = cls['${safeMethodName}'].overloads;
          overloads.forEach(function(overload) {
            overload.implementation = function() {
              var args = [];
              ${options.logArgs ? `
              for (var i = 0; i < arguments.length; i++) {
                try { args.push(String(arguments[i])); } catch(e) { args.push('<error>'); }
              }` : ''}

              var retval = overload.apply(this, arguments);

              var payload = {
                method: '${safeMethod}',
                type: 'java',
                threadId: Process.getCurrentThreadId(),
              };
              ${options.logArgs ? 'payload.args = args;' : ''}
              ${options.logRetval ? `try { payload.retval = String(retval); } catch(e) { payload.retval = '<error>'; }` : ''}
              ${options.logBacktrace ? `
              payload.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress)
                .map(function(s) { return s.toString(); });` : ''}

              send(payload);
              return retval;
            };
          });
          send({ status: 'hook_installed', method: '${safeMethod}', overloads: overloads.length });
        } catch(e) {
          send({ status: 'hook_error', method: '${safeMethod}', error: e.message });
        }
      });
    `;
  }

  if (hookType === 'objc') {
    return `
      try {
        var resolver = new ApiResolver('objc');
        var matches = resolver.enumerateMatches('${safeMethod}');
        if (matches.length === 0) {
          send({ status: 'hook_error', method: '${safeMethod}', error: 'No matches found' });
        }
        matches.forEach(function(match) {
          Interceptor.attach(match.address, {
            onEnter: function(args) {
              this.payload = {
                method: '${safeMethod}',
                type: 'objc',
                threadId: Process.getCurrentThreadId(),
                address: match.address.toString(),
              };
              ${options.logArgs ? `
              try {
                this.payload.args = [];
                // First two args are self and _cmd, skip them
                for (var i = 2; i < 10; i++) {
                  try {
                    var arg = new ObjC.Object(args[i]);
                    this.payload.args.push(arg.toString());
                  } catch(e) { break; }
                }
              } catch(e) {}` : ''}
              ${options.logBacktrace ? `
              this.payload.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress)
                .map(function(s) { return s.toString(); });` : ''}
            },
            onLeave: function(retval) {
              ${options.logRetval ? `
              try { this.payload.retval = retval.toString(); } catch(e) { this.payload.retval = retval.toInt32(); }` : ''}
              send(this.payload);
            }
          });
        });
        send({ status: 'hook_installed', method: '${safeMethod}', matches: matches.length });
      } catch(e) {
        send({ status: 'hook_error', method: '${safeMethod}', error: e.message });
      }
    `;
  }

  // Native hook
  let address: string;
  if (method.includes('!')) {
    const [moduleName, funcName] = method.split('!');
    const safeModuleName = escapeForScript(moduleName);
    const safeFuncName = escapeForScript(funcName);
    address = `Module.findExportByName('${safeModuleName}', '${safeFuncName}')`;
  } else {
    address = `ptr('${safeMethod}')`;
  }

  return `
    try {
      var addr = ${address};
      if (!addr || addr.isNull()) {
        send({ status: 'hook_error', method: '${safeMethod}', error: 'Address not found' });
      } else {
        Interceptor.attach(addr, {
          onEnter: function(args) {
            this.payload = {
              method: '${safeMethod}',
              type: 'native',
              threadId: Process.getCurrentThreadId(),
              address: addr.toString(),
            };
            ${options.logArgs ? `
            this.payload.args = [];
            for (var i = 0; i < 6; i++) {
              this.payload.args.push(args[i].toString());
            }` : ''}
            ${options.logBacktrace ? `
            this.payload.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
              .map(DebugSymbol.fromAddress)
              .map(function(s) { return s.toString(); });` : ''}
          },
          onLeave: function(retval) {
            ${options.logRetval ? `this.payload.retval = retval.toString();` : ''}
            send(this.payload);
          }
        });
        send({ status: 'hook_installed', method: '${safeMethod}' });
      }
    } catch(e) {
      send({ status: 'hook_error', method: '${safeMethod}', error: e.message });
    }
  `;
}
