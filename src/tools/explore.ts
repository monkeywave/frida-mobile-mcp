import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError, FridaMcpError } from '../helpers/errors.js';
import { validateProcessTarget } from '../helpers/sanitize.js';
import { log, audit } from '../helpers/logger.js';
import { rateLimiter } from '../helpers/rate-limiter.js';
import { responseFormatSchema } from '../constants.js';
import { createAgentScript } from '../agent/script-factory.js';
import { callRpcWithTimeout } from '../helpers/rpc-timeout.js';
import type { SessionEntry } from '../types.js';
import { getOrCreateSession } from '../helpers/session-helper.js';

export function registerExploreTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'explore_app',
    {
      title: 'Explore Mobile App',
      description: 'Launch a mobile app and gather comprehensive initial context including loaded classes, modules, and libraries. This is the recommended starting point for any app analysis. The app will be spawned in suspended mode, instrumented, then resumed. Returns: pid, platform, loaded modules, and filtered class list.',
      inputSchema: z.object({
        target: z.string().describe('App bundle ID (e.g., "com.example.app") or process name'),
        device: z.string().optional().describe('Device ID. Auto-selects USB device if not specified.'),
        class_filter: z.string().optional().describe('Regex filter for class enumeration (e.g., "com\\.example\\..*"). Defaults to app package pattern.'),
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
    async ({ target, device, class_filter, response_format }) => {
      const startTime = Date.now();
      try {
        validateProcessTarget(target);
        const state = getState();

        rateLimiter.check('session', state.config.rateLimits.sessionsPerMinute);
        rateLimiter.record('session');

        // Attach to a running instance, otherwise spawn suspended (resume: false) so that
        // module enumeration can see the pristine process. Class enumeration happens AFTER
        // resume: Java.perform() needs the app's class loader, and Android kills a spawned app
        // that stays suspended for more than ~10 s (launch timeout; Frida >= 17.6 cannot disable it).
        const { sessionEntry, fridaDevice, needsResume } = await getOrCreateSession(deviceManager, {
          target,
          device,
          resume: false,
        });
        const { id: sessionId, pid, platform } = sessionEntry;
        const spawned = needsResume;

        const filter = class_filter || (platform === 'android' ? target.replace(/\./g, '\\.') : '.*');
        let modules: ModuleInfo[] = [];
        let classes: string[] = [];
        try {
          modules = await enumerateModules(sessionEntry);
        } finally {
          if (needsResume) {
            await fridaDevice.resume(pid);
            log('info', `App ${target} launched and resumed (PID: ${pid})`);
          }
        }
        classes = await enumerateClasses(sessionEntry, filter);

        audit({
          timestamp: new Date().toISOString(),
          sessionId,
          tool: 'explore_app',
          params: { target, device, class_filter },
          status: 'success',
          durationMs: Date.now() - startTime,
        });

        return formatToolResponse(
          buildResult(
            {
              session_id: sessionId,
              pid,
              platform,
              spawned,
              device: { id: fridaDevice.id, name: fridaDevice.name, type: fridaDevice.type },
              modules_count: modules.length,
              modules: modules.slice(0, 50).map((m) => ({ name: m.name, path: m.path })),
              classes_count: classes.length,
              classes: classes.slice(0, 100),
              truncated: {
                modules: modules.length > 50,
                classes: classes.length > 100,
              },
            },
            [
              { tool: 'search_classes_and_methods', args: { target, pattern: target.split('.').pop() }, reason: 'Search for app-specific classes and methods' },
              { tool: 'hook_method', reason: 'Hook a method of interest' },
              { tool: 'bypass_ssl_pinning', args: { target }, reason: 'Bypass SSL pinning for network analysis' },
              { tool: 'mobile_action', args: { action: 'mobile_take_screenshot' }, reason: 'Take a screenshot to see the app state' },
            ]
          ),
          response_format
        );
      } catch (err) {
        const wrapped = wrapFridaError(err);
        audit({
          timestamp: new Date().toISOString(),
          tool: 'explore_app',
          params: { target, device },
          status: 'error',
          durationMs: Date.now() - startTime,
        });
        return formatToolResponse(wrapped.toErrorResponse(), response_format);
      }
    }
  );
}

interface ModuleInfo {
  name: string;
  base: string;
  size: number;
  path: string;
}


async function enumerateModules(sessionEntry: SessionEntry): Promise<ModuleInfo[]> {
  const script = await createAgentScript(sessionEntry.session, {
    sessionEntry: sessionEntry,
    source: `
      rpc.exports.run = function() {
        return Process.enumerateModules().map(function(m) {
          return { name: m.name, base: m.base.toString(), size: m.size, path: m.path };
        });
      };
    `,
    platform: sessionEntry.platform,
    name: 'explore_app:modules',
    kind: 'generated',
    bridges: [],
  });
  await script.load();
  try {
    return await callRpcWithTimeout(script.exports.run() as Promise<ModuleInfo[]>, 'Module enumeration');
  } finally {
    await script.unload();
  }
}

type ClassEnumerationResult = string[] | { error: string; message: string };

const CLASS_ENUMERATION_SOURCE = `
  function compileFilter() {
    try {
      return { re: new RegExp(__FRIDA_MCP__.options.filter) };
    } catch (e) {
      return { error: { error: 'invalid_pattern', message: String(e && e.message ? e.message : e) } };
    }
  }

  function enumerateJavaClasses(re) {
    return javaPerform(function() {
      var result = [];
      Java.enumerateLoadedClasses({
        onMatch: function(name) {
          if (re.test(name)) result.push(name);
        },
        onComplete: function() {}
      });
      return result;
    });
  }

  function enumerateObjcClasses(re) {
    var names = objcClassNames();
    var result = [];
    for (var i = 0; i < names.length && result.length < 500; i++) {
      if (re.test(names[i])) result.push(names[i]);
    }
    return result;
  }

  rpc.exports.run = function() {
    var compiled = compileFilter();
    if (compiled.error) return compiled.error;
    if (Java.available) return enumerateJavaClasses(compiled.re);
    if (ObjC.available) return enumerateObjcClasses(compiled.re);
    return [];
  };
`;

async function enumerateClasses(sessionEntry: SessionEntry, filter: string): Promise<string[]> {
  if (sessionEntry.platform !== 'android' && sessionEntry.platform !== 'ios') return [];

  const script = await createAgentScript(sessionEntry.session, {
    sessionEntry: sessionEntry,
    source: CLASS_ENUMERATION_SOURCE,
    platform: sessionEntry.platform,
    name: 'explore_app:classes',
    kind: 'generated',
    options: { filter },
  });
  await script.load();
  try {
    const result = await callRpcWithTimeout(script.exports.run() as Promise<ClassEnumerationResult>, 'Class enumeration');
    if (!Array.isArray(result)) {
      throw new FridaMcpError('INVALID_PATTERN', `Invalid class_filter regex: ${result.message}`, [
        { tool: 'explore_app', args: { target: sessionEntry.target }, reason: 'Retry with a valid class_filter regex' },
      ]);
    }
    return result;
  } catch (err) {
    if (err instanceof FridaMcpError && err.code === 'INVALID_PATTERN') throw err;
    log('debug', `Class enumeration failed: ${err}`);
    return [];
  } finally {
    await script.unload();
  }
}
