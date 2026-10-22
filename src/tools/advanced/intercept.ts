import { z } from 'zod';
import { toolOutputSchema } from '../../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import { getState } from '../../state.js';
import { buildResult, formatToolResponse } from '../../helpers/result-builder.js';
import { FridaMcpError, CustomScriptDisabledError, wrapFridaError } from '../../helpers/errors.js';
import { createAgentScript } from '../../agent/script-factory.js';
import { attachScriptSinks } from '../../helpers/script-sink.js';
import { responseFormatSchema } from '../../constants.js';
import { parseTarget, RESOLVE_TARGET_SNIPPET } from '../../agent/address.js';
import {
  interceptorOptionsSchema,
  normalizeInterceptorOptions,
  INTERCEPTOR_TARGET_SNIPPET,
  hookEvidenceSchema,
  resolveHookMethod,
  type HookEvidence,
  type InterceptorOptions,
} from '../hook.js';

/**
 * The hook_function target: `target` as given, or `module+0xoff` from native static
 * evidence. Java evidence is rejected here (hook_function is Interceptor-only).
 */
export function resolveHookFunctionTarget(target: string | undefined, evidence: HookEvidence | undefined): string {
  if (evidence && (evidence.class !== undefined || evidence.signature !== undefined || evidence.method !== undefined)) {
    throw new FridaMcpError('INVALID_ARGUMENT', 'hook_function only takes native evidence ({module, offset} or {module, address, image_base}); use hook_method for Java {class, signature}.', [
      { tool: 'hook_method', reason: 'Hook a Java overload by signature' },
    ], { evidence });
  }
  return resolveHookMethod(target, evidence);
}

function isObjCSelector(target: string): boolean {
  return target.startsWith('-[') || target.startsWith('+[');
}

/**
 * Split the target spec into the fields the script reads from `__FRIDA_MCP__.options`.
 * Values are serialised as JSON by the preamble, never spliced into code position.
 * moduleName/funcName/address are kept for backward compatibility; native targets are
 * resolved from the parsed `nativeTarget` (see RESOLVE_TARGET_SNIPPET). Every
 * hook_function target (ObjC selectors included) is attached with Interceptor, so the
 * Frida 17.10 `interceptorOptions` apply to all of them.
 */
export function buildHookFunctionOptions(target: string, interceptorOptions?: InterceptorOptions): Record<string, unknown> {
  const options: Record<string, unknown> = { target };
  const normalized = normalizeInterceptorOptions(interceptorOptions);
  if (normalized) options.interceptorOptions = normalized;
  if (target.includes('!')) {
    const [moduleName, funcName] = target.split('!');
    options.moduleName = moduleName;
    options.funcName = funcName;
  } else if (isObjCSelector(target)) {
    options.selector = target;
  } else {
    options.address = target;
  }
  if (!isObjCSelector(target)) {
    options.nativeTarget = parseTarget(target);
  }
  return options;
}

/**
 * Constant script body for hook_function. Custom on_enter/on_leave bodies are compiled
 * with `new Function(...)` from the options object, so they are never in code position;
 * they are invoked with the Interceptor invocation context as `this`.
 */
export const HOOK_FUNCTION_SCRIPT = `
(function () {
  var o = __FRIDA_MCP__.options;

  function compileHandler(body, argName) {
    if (typeof body !== 'string' || body.length === 0) return null;
    return new Function(argName, body);
  }

  var onEnterBody, onLeaveBody;
  try {
    onEnterBody = compileHandler(o.on_enter, 'args');
    onLeaveBody = compileHandler(o.on_leave, 'retval');
  } catch (e) {
    send({ status: 'error', target: o.target, error: 'invalid handler: ' + e.message });
    return;
  }

  var addr = null;
  try {
    if (o.selector) {
      var matches = new ApiResolver('objc').enumerateMatches(o.selector);
      addr = matches.length > 0 ? matches[0].address : null;
    } else {
      addr = resolveTarget(o.nativeTarget || o.target);
    }
  } catch (e) {
    send({ status: 'error', target: o.target, error: e.message });
    return;
  }

  if (addr === null || addr.isNull()) {
    send({ status: 'error', target: o.target, error: 'target not found: ' + o.target });
    return;
  }

  // Frida 17.10 form: { target, ...instrumentation options } when options were given.
  Interceptor.attach(interceptorTarget(addr), {
    onEnter: function (args) {
      if (onEnterBody) onEnterBody.call(this, args);
      else send({ event: 'enter', threadId: Process.getCurrentThreadId() });
    },
    onLeave: function (retval) {
      if (onLeaveBody) onLeaveBody.call(this, retval);
      else send({ event: 'leave', retval: retval.toString() });
    }
  });
  send({ status: 'hooked', target: o.target, address: addr.toString(), resolved: describeAddress(addr) });
})();
`;

export function registerAdvancedInterceptTools(server: McpServer): void {
  server.registerTool(
    'hook_function',
    {
      title: 'Hook Function (Low-Level)',
      description: 'Low-level hook with custom onEnter/onLeave JavaScript handlers. For advanced use when hook_method does not provide enough control. Custom handler bodies require allowCustomScripts: true in config; without them the hook sends default enter/leave events. Handler bodies are compiled as functions (new Function) inside the agent: `this` is the Interceptor invocation context (this.context, this.returnAddress, this.threadId, and any fields you set in on_enter are visible in on_leave). Java/ObjC globals are available (auto-injected by platform). A static-analysis finding can be passed as evidence {module, offset} or {module, address, image_base} instead of target.',
      inputSchema: z.object({
        session_id: z.string().describe('Session ID'),
        target: z.string().optional().describe('Required unless evidence is given. Function target: "module!func" (module export), "module+0x1234" or "module+4660" (module-relative offset, as shown by Ghidra/IDA), "0x7f12345678" (absolute address), "func" or "!func" (global export searched across all modules), or an ObjC selector "-[Class method:]"'),
        evidence: hookEvidenceSchema
          .optional()
          .describe('Native static-analysis evidence instead of target: {module, offset} (offset relative to the image base, as Ghidra/IDA show it minus the base) or {module, address, image_base}. Resolved to "module+0xoff".'),
        on_enter: z.string().optional().describe('JavaScript function body for onEnter. Receives `args` (NativePointer[]); `this` is the invocation context. Requires allowCustomScripts.'),
        on_leave: z.string().optional().describe('JavaScript function body for onLeave. Receives `retval` (InvocationReturnValue); `this` is the invocation context. Requires allowCustomScripts.'),
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
    async ({ session_id, target: targetInput, evidence, on_enter, on_leave, interceptor_options, response_format }) => {
      try {
        const state = getState();
        const target = resolveHookFunctionTarget(targetInput, evidence);
        const session = state.getSession(session_id);
        if (!session) throw new FridaMcpError('SESSION_NOT_FOUND', `Session not found.`, []);

        // Custom handler bodies are arbitrary JavaScript: gate them like execute_script.
        if ((on_enter || on_leave) && !state.config.allowCustomScripts) {
          throw new CustomScriptDisabledError();
        }

        const hookOptions = buildHookFunctionOptions(target, interceptor_options);
        const script = await createAgentScript(session.session, {
          sessionEntry: session,
          // The resolution helpers are harmless for ObjC selectors, so always prepend them.
          source: RESOLVE_TARGET_SNIPPET + INTERCEPTOR_TARGET_SNIPPET + HOOK_FUNCTION_SCRIPT,
          platform: session.platform,
          name: `hook:${target}`,
          kind: 'generated',
          options: { ...hookOptions, on_enter, on_leave, platform: session.platform },
        });
        const scriptId = state.generateId();
        const hookId = state.generateId();

        session.scripts.set(scriptId, {
          id: scriptId,
          script,
          messages: [],
          name: `hook:${target}`,
          persistent: true,
          createdAt: Date.now(),
        });

        attachScriptSinks(script, session_id, scriptId, {
          onSend: (payload, data) => {
            state.addMessageToScript(session_id, scriptId, { timestamp: Date.now(), type: 'hook', payload, data: data ?? null });
          },
        });

        await script.load();

        state.hooks.set(hookId, {
          id: hookId,
          scriptId,
          sessionId: session_id,
          target,
          type: target.startsWith('-[') || target.startsWith('+[') ? 'objc' : target.includes('!') ? 'native' : 'native',
          invocations: [],
          status: 'active',
          createdAt: Date.now(),
        });

        return formatToolResponse(buildResult({
          hook_id: hookId,
          script_id: scriptId,
          target,
          ...(evidence ? { evidence } : {}),
          status: 'active',
          interceptor_options: hookOptions.interceptorOptions ?? null,
        }, [
          { tool: 'get_messages', args: { session_id }, reason: 'Check hook output' },
          { tool: 'unhook_function', args: { hook_id: hookId }, reason: 'Remove this hook' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );

  server.registerTool(
    'unhook_function',
    {
      title: 'Unhook Function',
      description: 'Remove a specific hook by its hook ID.',
      inputSchema: z.object({
        hook_id: z.string().describe('Hook ID to remove'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ hook_id, response_format }) => {
      try {
        const state = getState();
        const hook = state.hooks.get(hook_id);
        if (!hook) throw new FridaMcpError('HOOK_NOT_FOUND', `Hook "${hook_id}" not found.`, [{ tool: 'get_status', reason: 'List active hooks' }]);

        const session = state.getSession(hook.sessionId);
        if (session) {
          const scriptEntry = session.scripts.get(hook.scriptId);
          if (scriptEntry) {
            try { await scriptEntry.script.unload(); } catch {}
            session.scripts.delete(hook.scriptId);
          }
        }
        state.hooks.delete(hook_id);

        return formatToolResponse(buildResult({
          hook_id,
          target: hook.target,
          status: 'removed',
        }, [{ tool: 'get_status', reason: 'Check remaining hooks' }]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}
