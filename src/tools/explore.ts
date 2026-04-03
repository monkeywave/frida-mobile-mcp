import frida from 'frida';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError } from '../helpers/errors.js';
import { validateProcessTarget } from '../helpers/sanitize.js';
import { log, audit } from '../helpers/logger.js';
import { rateLimiter } from '../helpers/rate-limiter.js';
import { responseFormatSchema } from '../constants.js';

export function registerExploreTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'explore_app',
    {
      title: 'Explore Mobile App',
      description: 'Launch a mobile app and gather comprehensive initial context including loaded classes, modules, and libraries. This is the recommended starting point for any app analysis. The app will be spawned in suspended mode, instrumented, then resumed. Returns: pid, platform, loaded modules, and filtered class list.',
      inputSchema: {
        target: z.string().describe('App bundle ID (e.g., "com.example.app") or process name'),
        device: z.string().optional().describe('Device ID. Auto-selects USB device if not specified.'),
        class_filter: z.string().optional().describe('Regex filter for class enumeration (e.g., "com\\.example\\..*"). Defaults to app package pattern.'),
        response_format: responseFormatSchema,
      },
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

        // Resolve device
        const fridaDevice = device
          ? await deviceManager.resolve({ deviceId: device })
          : await deviceManager.resolve();
        state.selectedDevice = fridaDevice;

        // Detect platform
        const platform = await deviceManager.detectPlatform(fridaDevice);

        // Spawn the app
        log('info', `Spawning ${target} on ${fridaDevice.name}`);
        const pid = await fridaDevice.spawn(target);

        // Attach session
        const session = await fridaDevice.attach(pid);
        const sessionId = state.generateId();

        const sessionEntry = {
          id: sessionId,
          session,
          pid,
          deviceId: fridaDevice.id,
          target,
          platform,
          scripts: new Map(),
          createdAt: Date.now(),
        };
        state.addSession(sessionEntry);

        // Set up detach handler
        session.detached.connect((reason) => {
          log('info', `Session ${sessionId} detached: ${reason}`);
          state.removeSession(sessionId);
        });

        // Run module and class enumeration concurrently
        const filter = class_filter || (platform === 'android' ? target.replace(/\./g, '\\.') : '.*');
        const [modules, classes] = await Promise.all([
          enumerateModules(session),
          enumerateClasses(session, platform, filter),
        ]);

        // Resume the process
        await fridaDevice.resume(pid);
        log('info', `App ${target} launched and resumed (PID: ${pid})`);

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

async function enumerateModules(session: frida.Session): Promise<Array<{ name: string; base: string; size: number; path: string }>> {
  const script = await session.createScript(`
    rpc.exports.run = function() {
      var modules = Process.enumerateModules();
      return modules.map(function(m) {
        return { name: m.name, base: m.base.toString(), size: m.size, path: m.path };
      });
    };
  `);
  await script.load();
  const result = await script.exports.run() as Array<{ name: string; base: string; size: number; path: string }>;
  await script.unload();
  return result;
}

async function enumerateClasses(session: frida.Session, platform: string, filter: string): Promise<string[]> {
  if (platform === 'android') {
    const classScript = await session.createScript(`
      rpc.exports.run = function(filter) {
        var re = new RegExp(filter);
        var result = [];
        Java.perform(function() {
          Java.enumerateLoadedClasses({
            onMatch: function(name) {
              if (re.test(name)) result.push(name);
            },
            onComplete: function() {}
          });
        });
        return result;
      };
    `);
    await classScript.load();
    try {
      const classes = await classScript.exports.run(filter) as string[];
      await classScript.unload();
      return classes;
    } catch (err) {
      log('debug', `Class enumeration failed: ${err}`);
      await classScript.unload();
      return [];
    }
  } else if (platform === 'ios') {
    const classScript = await session.createScript(`
      rpc.exports.run = function(filter) {
        var re = new RegExp(filter);
        var result = [];
        var classes = ObjC.enumerateLoadedClassesSync();
        for (var name in classes) {
          if (re.test(name)) result.push(name);
        }
        return result.slice(0, 500);
      };
    `);
    await classScript.load();
    try {
      const classes = await classScript.exports.run(filter) as string[];
      await classScript.unload();
      return classes;
    } catch (err) {
      log('debug', `Class enumeration failed: ${err}`);
      await classScript.unload();
      return [];
    }
  }
  return [];
}
