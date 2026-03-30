import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getState } from '../../state.js';
import { buildResult, formatToolResponse } from '../../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../../helpers/errors.js';

export function registerAdvancedInterceptTools(server: McpServer): void {
  server.tool(
    'hook_function',
    'Low-level hook with custom onEnter/onLeave JavaScript handlers. For advanced use when hook_method does not provide enough control.',
    {
      session_id: z.string().describe('Session ID'),
      target: z.string().describe('Function target: "module!func", ObjC selector, or hex address'),
      on_enter: z.string().optional().describe('JavaScript code for onEnter handler. Has access to args[] array.'),
      on_leave: z.string().optional().describe('JavaScript code for onLeave handler. Has access to retval.'),
    },
    async ({ session_id, target, on_enter, on_leave }) => {
      try {
        const state = getState();
        const session = state.getSession(session_id);
        if (!session) throw new FridaMcpError('SESSION_NOT_FOUND', `Session not found.`, []);

        let resolveAddr: string;
        if (target.includes('!')) {
          const [mod, func] = target.split('!');
          resolveAddr = `Module.findExportByName('${mod}', '${func}')`;
        } else if (target.startsWith('-[') || target.startsWith('+[')) {
          resolveAddr = `new ApiResolver('objc').enumerateMatches('${target}')[0].address`;
        } else {
          resolveAddr = `ptr('${target}')`;
        }

        const scriptSource = `
          var addr = ${resolveAddr};
          if (!addr || addr.isNull()) {
            send({ status: 'error', message: 'Target not found: ${target}' });
          } else {
            Interceptor.attach(addr, {
              onEnter: function(args) {
                ${on_enter || 'send({ event: "enter", threadId: Process.getCurrentThreadId() });'}
              },
              onLeave: function(retval) {
                ${on_leave || 'send({ event: "leave", retval: retval.toString() });'}
              }
            });
            send({ status: 'hooked', target: '${target}', address: addr.toString() });
          }
        `;

        const script = await session.session.createScript(scriptSource);
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

        script.message.connect((message, data) => {
          if (message.type === 'send') {
            state.addMessageToScript(session_id, scriptId, {
              timestamp: Date.now(),
              type: 'hook',
              payload: message.payload,
              data: data ?? null,
            });
          }
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
          status: 'active',
        }, [
          { tool: 'get_messages', args: { session_id }, reason: 'Check hook output' },
          { tool: 'unhook_function', args: { hook_id: hookId }, reason: 'Remove this hook' },
        ]));
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse());
      }
    }
  );

  server.tool(
    'unhook_function',
    'Remove a specific hook by its hook ID.',
    {
      hook_id: z.string().describe('Hook ID to remove'),
    },
    async ({ hook_id }) => {
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
        }, [{ tool: 'get_status', reason: 'Check remaining hooks' }]));
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse());
      }
    }
  );
}
