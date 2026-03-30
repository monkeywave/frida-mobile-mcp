import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getState } from '../../state.js';
import { buildResult, formatToolResponse } from '../../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../../helpers/errors.js';

export function registerAdvancedModuleTools(server: McpServer): void {
  server.tool(
    'enumerate_modules',
    'List loaded modules (shared libraries) in the target process.',
    {
      session_id: z.string().describe('Session ID'),
    },
    async ({ session_id }) => {
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
        ]));
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse());
      }
    }
  );

  server.tool(
    'enumerate_exports',
    'List exports (functions and variables) of a specific module.',
    {
      session_id: z.string().describe('Session ID'),
      module_name: z.string().describe('Module name (e.g., "libssl.so")'),
    },
    async ({ session_id, module_name }) => {
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
        ]));
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse());
      }
    }
  );
}
