import { z } from 'zod';
import { readFileSync } from 'node:fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError, CustomScriptDisabledError, ScriptError } from '../helpers/errors.js';
import { validateProcessTarget, validateScriptSource, validateFilePath } from '../helpers/sanitize.js';
import { log, audit } from '../helpers/logger.js';
import { rateLimiter } from '../helpers/rate-limiter.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
import { createHash } from 'node:crypto';

export function registerScriptTool(server: McpServer, deviceManager: DeviceManager): void {
  server.tool(
    'execute_script',
    'Execute a custom Frida JavaScript script in a target process. Provide either inline source code or a file path. Scripts can use the full Frida JavaScript API including Java.perform(), ObjC, Interceptor, Memory, Module, etc. Results are sent via send() and retrieved with get_messages. Note: custom scripts must be explicitly enabled in config (allowCustomScripts: true).',
    {
      target: z.string().describe('App bundle ID, process name, or PID'),
      source: z.string().optional().describe('Inline JavaScript source code'),
      file_path: z.string().optional().describe('Path to a .js Frida script file'),
      device: z.string().optional().describe('Device ID'),
      session_id: z.string().optional().describe('Reuse an existing session'),
      persistent: z.boolean().optional().default(true).describe('Keep script loaded (default: true). Set false for one-shot scripts.'),
    },
    async ({ target, source, file_path, device, session_id, persistent }) => {
      const startTime = Date.now();
      try {
        const state = getState();

        // Check if custom scripts are allowed
        if (!state.config.allowCustomScripts) {
          throw new CustomScriptDisabledError();
        }

        // Get script source
        let scriptSource: string;
        if (source) {
          scriptSource = source;
        } else if (file_path) {
          validateFilePath(file_path);
          try {
            scriptSource = readFileSync(file_path, 'utf-8');
          } catch (err) {
            throw new ScriptError(`Cannot read file: ${file_path}`);
          }
        } else {
          throw new ScriptError('Either source or file_path must be provided');
        }

        validateScriptSource(scriptSource);
        validateProcessTarget(target);

        rateLimiter.check('script', state.config.rateLimits.scriptsPerMinute);
        rateLimiter.record('script');

        const { sessionEntry: resolvedSession } = await getOrCreateSession(deviceManager, {
          target,
          device,
          sessionId: session_id,
        });
        let sessionEntry = resolvedSession;

        // Create and load script
        const script = await sessionEntry.session.createScript(scriptSource);
        const scriptId = state.generateId();
        const messages: Array<Record<string, unknown>> = [];

        const scriptEntry = {
          id: scriptId,
          script,
          messages: [],
          name: file_path || 'inline_script',
          persistent: persistent ?? true,
          createdAt: Date.now(),
        };
        sessionEntry.scripts.set(scriptId, scriptEntry);

        script.message.connect((message, data) => {
          const entry = {
            timestamp: Date.now(),
            type: message.type,
            payload: message.type === 'send' ? message.payload : { description: (message as any).description },
            data: data ?? null,
          };
          state.addMessageToScript(sessionEntry!.id, scriptId, entry);
          messages.push({ type: message.type, payload: entry.payload });
        });

        await script.load();

        // For non-persistent scripts, wait briefly and collect output
        if (!persistent) {
          await new Promise((resolve) => setTimeout(resolve, 2000));
          await script.unload();
          sessionEntry.scripts.delete(scriptId);
        }

        const scriptHash = createHash('sha256').update(scriptSource).digest('hex').slice(0, 16);

        audit({
          timestamp: new Date().toISOString(),
          sessionId: sessionEntry.id,
          tool: 'execute_script',
          params: { target, file_path, persistent },
          status: 'success',
          durationMs: Date.now() - startTime,
          scriptHash,
        });

        return formatToolResponse(
          buildResult(
            {
              script_id: scriptId,
              session_id: sessionEntry.id,
              persistent: persistent ?? true,
              messages_received: messages.length,
              messages: messages.slice(0, 50),
              script_hash: scriptHash,
            },
            persistent
              ? [
                  { tool: 'get_messages', args: { session_id: sessionEntry.id }, reason: 'Retrieve script output' },
                  { tool: 'stop_instrumentation', args: { session_id: sessionEntry.id }, reason: 'Stop and clean up' },
                ]
              : [
                  { tool: 'execute_script', reason: 'Run another script' },
                ]
          )
        );
      } catch (err) {
        const wrapped = wrapFridaError(err);
        return formatToolResponse(wrapped.toErrorResponse());
      }
    }
  );
}
