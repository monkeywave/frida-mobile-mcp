import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError, FridaMcpError } from '../helpers/errors.js';
import { resolveInstrumentationTarget } from './hook.js';
import { log } from '../helpers/logger.js';
import { responseFormatSchema } from '../constants.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
import { createAgentScript } from '../agent/script-factory.js';
import type { BridgeName } from '../agent/bridges.js';
import { callRpcWithTimeout } from '../helpers/rpc-timeout.js';

export function registerSearchTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'search_classes_and_methods',
    {
      title: 'Search Classes and Methods',
      description: 'Search for classes and their methods by pattern in a running app. Combines class enumeration and method listing. Use regex patterns like "Login", "com\\.example\\.auth.*", or "NSURLSession". Returns matching classes with their methods when include_methods is true.',
      inputSchema: z.object({
        target: z.string().optional().describe('App bundle ID, process name, or PID. Optional when session_id is given.'),
        session_id: z.string().optional().describe('Reuse an existing session (from explore_app/get_status) instead of re-attaching by target.'),
        pattern: z.string().describe('Regex pattern to match class names'),
        device: z.string().optional().describe('Device ID'),
        include_methods: z.boolean().optional().default(false).describe('Also enumerate methods of matched classes (default: false)'),
        limit: z.number().optional().default(50).describe('Max classes to return (default: 50)'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ target, session_id, pattern, device, include_methods, limit, response_format }) => {
      try {
        const resolved = resolveInstrumentationTarget(target, session_id);
        const state = getState();
        const maxResults = limit ?? 50;

        const { sessionEntry: resolvedSession } = await getOrCreateSession(deviceManager, { target: resolved.target, device, sessionId: resolved.sessionId });
        let sessionEntry = resolvedSession;

        const platform = sessionEntry.platform;
        const { source, bridges } = selectSearchSource(platform);

        const script = await createAgentScript(sessionEntry.session, {
          sessionEntry: sessionEntry,
          source,
          platform,
          name: 'search_classes_and_methods:' + platform,
          kind: 'generated',
          options: { pattern, includeMethods: include_methods ?? false, maxResults },
          ...(bridges ? { bridges } : {}),
        });
        await script.load();
        let results: SearchEntry[];
        try {
          const raw = await callRpcWithTimeout(script.exports.search() as Promise<SearchResult>, 'Class search');
          if (!Array.isArray(raw)) {
            throw new FridaMcpError('INVALID_PATTERN', `Invalid pattern regex: ${raw.message}`, [
              { tool: 'search_classes_and_methods', args: { target }, reason: 'Retry with a valid regex pattern' },
            ]);
          }
          results = raw;
        } finally {
          await script.unload();
        }

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
          ),
          response_format
        );
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}

interface SearchEntry {
  name: string;
  path?: string;
  methods?: string[];
}

type SearchResult = SearchEntry[] | { error: string; message: string };

/** Shared by all three variants: compiles the user regex inside the agent, never in code position. */
const COMPILE_PATTERN_SNIPPET = `
  function compilePattern() {
    try {
      return { re: new RegExp(__FRIDA_MCP__.options.pattern) };
    } catch (e) {
      return { error: { error: 'invalid_pattern', message: String(e && e.message ? e.message : e) } };
    }
  }
`;

const ANDROID_SEARCH_SOURCE = COMPILE_PATTERN_SNIPPET + `
  rpc.exports.search = function() {
    var o = __FRIDA_MCP__.options;
    var compiled = compilePattern();
    if (compiled.error) return compiled.error;
    var re = compiled.re;
    return javaPerform(function() {
      var results = [];
      // Collect names first: calling Java.use() from inside the enumerateLoadedClasses
      // callback can deadlock the process (class-linker lock held during enumeration).
      Java.enumerateLoadedClasses({
        onMatch: function(name) {
          if (results.length >= o.maxResults) return;
          if (re.test(name)) results.push({ name: name });
        },
        onComplete: function() {}
      });
      if (o.includeMethods) {
        for (var i = 0; i < results.length; i++) {
          var entry = results[i];
          try {
            var cls = Java.use(entry.name);
            var methods = cls.class.getDeclaredMethods();
            entry.methods = methods.map(function(m) { return m.getName(); });
            entry.methods = entry.methods.filter(function(v, idx, a) { return a.indexOf(v) === idx; });
          } catch(e) { entry.methods = []; entry.methods_error = String(e && e.message ? e.message : e); }
        }
      }
      return results;
    });
  };
`;

const IOS_SEARCH_SOURCE = COMPILE_PATTERN_SNIPPET + `
  rpc.exports.search = function() {
    var o = __FRIDA_MCP__.options;
    var compiled = compilePattern();
    if (compiled.error) return compiled.error;
    var re = compiled.re;
    var results = [];
    var names = objcClassNames();
    for (var i = 0; i < names.length; i++) {
      if (results.length >= o.maxResults) break;
      var name = names[i];
      if (!re.test(name)) continue;
      var entry = { name: name };
      if (o.includeMethods) {
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

const NATIVE_SEARCH_SOURCE = COMPILE_PATTERN_SNIPPET + `
  rpc.exports.search = function() {
    var o = __FRIDA_MCP__.options;
    var compiled = compilePattern();
    if (compiled.error) return compiled.error;
    var re = compiled.re;
    var results = [];
    Process.enumerateModules().forEach(function(m) {
      if (results.length >= o.maxResults) return;
      if (!re.test(m.name)) return;
      var entry = { name: m.name, path: m.path };
      if (o.includeMethods) {
        entry.methods = m.enumerateExports()
          .filter(function(e) { return e.type === 'function'; })
          .map(function(e) { return e.name; })
          .slice(0, 100);
      }
      results.push(entry);
    });
    return results;
  };
`;

function selectSearchSource(platform: string): { source: string; bridges?: BridgeName[] } {
  if (platform === 'android') return { source: ANDROID_SEARCH_SOURCE };
  if (platform === 'ios') return { source: IOS_SEARCH_SOURCE };
  // Generic: enumerate modules and exports — no bridge needed
  return { source: NATIVE_SEARCH_SOURCE, bridges: [] };
}
