import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getState } from '../../state.js';
import { buildResult, formatToolResponse } from '../../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../../helpers/errors.js';
import { responseFormatSchema } from '../../constants.js';

export function registerAdvancedModuleTools(server: McpServer): void {
  server.registerTool(
    'enumerate_modules',
    {
      title: 'Enumerate Modules',
      description: 'List loaded modules (shared libraries) in the target process.',
      inputSchema: {
        session_id: z.string().describe('Session ID'),
        response_format: responseFormatSchema,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ session_id, response_format }) => {
      try {
        const state = getState();
        const session = state.getSession(session_id);
        if (!session) throw new FridaMcpError('SESSION_NOT_FOUND', `Session not found.`, []);

        const script = await session.session.createScript(`
          rpc.exports.run = function() {
            return Process.enumerateModules().map(function(m) {
              return { name: m.name, base: m.base.toString(), size: m.size, path: m.path };
            });
          };
        `);
        await script.load();
        const modules = await script.exports.run();
        await script.unload();

        return formatToolResponse(buildResult({ session_id, modules }, [
          { tool: 'enumerate_exports', reason: 'List exports of a module' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );

  server.registerTool(
    'enumerate_exports',
    {
      title: 'Enumerate Module Exports',
      description: 'List exports (functions and variables) of a specific module.',
      inputSchema: {
        session_id: z.string().describe('Session ID'),
        module_name: z.string().describe('Module name (e.g., "libssl.so")'),
        response_format: responseFormatSchema,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ session_id, module_name, response_format }) => {
      try {
        const state = getState();
        const session = state.getSession(session_id);
        if (!session) throw new FridaMcpError('SESSION_NOT_FOUND', `Session not found.`, []);

        const script = await session.session.createScript(`
          rpc.exports.run = function(name) {
            return Module.enumerateExports(name).map(function(e) {
              return { type: e.type, name: e.name, address: e.address.toString() };
            });
          };
        `);
        await script.load();
        const exports = await script.exports.run(module_name) as Array<{ type: string; name: string; address: string }>;
        await script.unload();

        return formatToolResponse(buildResult({
          session_id,
          module: module_name,
          export_count: exports.length,
          exports: exports.slice(0, 200),
          truncated: exports.length > 200,
        }, [
          { tool: 'hook_method', args: { method: `${module_name}!${exports[0]?.name}` }, reason: 'Hook an export' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}
