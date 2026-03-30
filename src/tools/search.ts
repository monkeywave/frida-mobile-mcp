import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError } from '../helpers/errors.js';
import { validateProcessTarget } from '../helpers/sanitize.js';
import { log } from '../helpers/logger.js';
import { getOrCreateSession } from '../helpers/session-helper.js';

export function registerSearchTool(server: McpServer, deviceManager: DeviceManager): void {
  server.tool(
    'search_classes_and_methods',
    'Search for classes and their methods by pattern in a running app. Combines class enumeration and method listing. Use regex patterns like "Login", "com\\.example\\.auth.*", or "NSURLSession". Returns matching classes with their methods when include_methods is true.',
    {
      target: z.string().describe('App bundle ID, process name, or PID'),
      pattern: z.string().describe('Regex pattern to match class names'),
      device: z.string().optional().describe('Device ID'),
      include_methods: z.boolean().optional().default(false).describe('Also enumerate methods of matched classes (default: false)'),
      limit: z.number().optional().default(50).describe('Max classes to return (default: 50)'),
    },
    async ({ target, pattern, device, include_methods, limit }) => {
      try {
        validateProcessTarget(target);
        const state = getState();
        const maxResults = limit ?? 50;

        const { sessionEntry: resolvedSession } = await getOrCreateSession(deviceManager, { target, device });
        let sessionEntry = resolvedSession;

        const platform = sessionEntry.platform;
        let scriptSource: string;

        if (platform === 'android') {
          scriptSource = `
            rpc.exports.search = function(pattern, includeMethods, maxResults) {
              var re = new RegExp(pattern);
              var results = [];
              Java.perform(function() {
                Java.enumerateLoadedClasses({
                  onMatch: function(name) {
                    if (results.length >= maxResults) return;
                    if (!re.test(name)) return;
                    var entry = { name: name };
                    if (includeMethods) {
                      try {
                        var cls = Java.use(name);
                        var methods = cls.class.getDeclaredMethods();
                        entry.methods = methods.map(function(m) { return m.getName(); });
                        entry.methods = entry.methods.filter(function(v, i, a) { return a.indexOf(v) === i; });
                      } catch(e) { entry.methods = []; }
                    }
                    results.push(entry);
                  },
                  onComplete: function() {}
                });
              });
              return results;
            };
          `;
        } else if (platform === 'ios') {
          scriptSource = `
            rpc.exports.search = function(pattern, includeMethods, maxResults) {
              var re = new RegExp(pattern);
              var results = [];
              var classes = ObjC.enumerateLoadedClassesSync();
              for (var name in classes) {
                if (results.length >= maxResults) break;
                if (!re.test(name)) continue;
                var entry = { name: name };
                if (includeMethods) {
                  try {
                    var cls = ObjC.classes[name];
                    entry.methods = cls.$ownMethods || [];
                  } catch(e) { entry.methods = []; }
                }
                results.push(entry);
              }
              return results;
            };
          `;
        } else {
          // Generic: enumerate modules and exports
          scriptSource = `
            rpc.exports.search = function(pattern, includeMethods, maxResults) {
              var re = new RegExp(pattern);
              var results = [];
              var modules = Process.enumerateModules();
              modules.forEach(function(m) {
                if (results.length >= maxResults) return;
                if (!re.test(m.name)) return;
                var entry = { name: m.name, path: m.path };
                if (includeMethods) {
                  entry.methods = Module.enumerateExports(m.name)
                    .filter(function(e) { return e.type === 'function'; })
                    .map(function(e) { return e.name; })
                    .slice(0, 100);
                }
                results.push(entry);
              });
              return results;
            };
          `;
        }

        const script = await sessionEntry.session.createScript(scriptSource);
        await script.load();
        const results = await script.exports.search(pattern, include_methods ?? false, maxResults) as Array<{ name: string; methods?: string[] }>;
        await script.unload();

        return formatToolResponse(
          buildResult(
            {
              session_id: sessionEntry.id,
              platform,
              pattern,
              total_matches: results.length,
              classes: results,
              truncated: results.length >= maxResults,
            },
            [
              ...(results.length > 0
                ? [{ tool: 'hook_method', args: { target, method: results[0].name }, reason: `Hook methods in ${results[0].name}` }]
                : []),
              { tool: 'search_classes_and_methods', args: { target, pattern, include_methods: true }, reason: 'Search again with methods included' },
            ]
          )
        );
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse());
      }
    }
  );
}
