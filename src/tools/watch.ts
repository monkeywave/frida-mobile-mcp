import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError } from '../helpers/errors.js';
import { resolveInstrumentationTarget } from './hook.js';
import { log } from '../helpers/logger.js';
import { responseFormatSchema } from '../constants.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
import { createAgentScript } from '../agent/script-factory.js';
import type { BridgeName } from '../agent/bridges.js';
import { attachScriptSinks } from '../helpers/script-sink.js';

const NO_BRIDGES: BridgeName[] = [];

export function registerWatchTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'watch_loads',
    {
      title: 'Watch Late Loads and Anti-Instrumentation Signals',
      description:
        'Install a persistent watcher that reports what the app does AFTER attach, straight into the session message buffer. Three signal families, each toggleable: (1) native libraries (.so) loaded late via dlopen/android_dlopen_ext — so a target that only appears after a UI action is still seen; (2) Java classes loaded late via ClassLoader.loadClass (Android only; the Java.available guard makes it a no-op elsewhere); (3) anti-instrumentation / anti-debug reads of canonical /proc locations (maps, status, task) via open/fopen. The watcher stays loaded and keeps emitting: drive the app (e.g. mobile_action), then call get_messages to read the watch_event entries. Pair with discover_crypto / hook_method once a late-loaded target shows up.',
      inputSchema: z.object({
        target: z.string().optional().describe('App bundle ID, process name, or PID. Optional when session_id is given.'),
        session_id: z.string().optional().describe('Reuse an existing session from explore_app/get_status.'),
        device: z.string().optional().describe('Device ID'),
        watch_native: z.boolean().optional().default(true).describe('Report native libraries (.so) loaded after attach via dlopen/android_dlopen_ext (default: true).'),
        watch_classes: z.boolean().optional().default(true).describe('Report Java classes loaded after attach via ClassLoader.loadClass (Android only; default: true).'),
        watch_tamper: z.boolean().optional().default(true).describe('Report anti-instrumentation / anti-debug reads of /proc maps|status|task via open/fopen (default: true).'),
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
    async ({ target, session_id, device, watch_native, watch_classes, watch_tamper, response_format }) => {
      try {
        const resolved = resolveInstrumentationTarget(target, session_id);
        const state = getState();

        const { sessionEntry } = await getOrCreateSession(deviceManager, { target: resolved.target, device, sessionId: resolved.sessionId });
        const platform = sessionEntry.platform;

        const watchNative = watch_native ?? true;
        const watchClasses = watch_classes ?? true;
        const watchTamper = watch_tamper ?? true;

        const script = await createAgentScript(sessionEntry.session, {
          sessionEntry,
          source: WATCH_SOURCE,
          platform,
          name: 'watch_loads:' + platform,
          kind: 'generated',
          options: { watchNative, watchClasses, watchTamper },
          // Android/iOS get their default bridge (Java/ObjC); everything else is bridge-free.
          ...(platform === 'android' || platform === 'ios' ? {} : { bridges: NO_BRIDGES }),
        });

        const scriptId = state.generateId();
        const scriptEntry = {
          id: scriptId,
          script,
          messages: [],
          name: 'watch_loads:' + platform,
          persistent: true,
          createdAt: Date.now(),
        };
        sessionEntry.scripts.set(scriptId, scriptEntry);

        // Shared sinks capture console.* (never stdout) and record errors with full fidelity;
        // our onSend turns every watcher send(...) into a watch_event entry.
        attachScriptSinks(script, sessionEntry.id, scriptId, {
          onSend: (payload, data) => {
            state.addMessageToScript(sessionEntry.id, scriptId, { timestamp: Date.now(), type: 'watch_event', payload, data: data ?? null });
          },
        });

        // Persistent: load and leave it running — do NOT unload.
        try {
          await script.load();
        } catch (loadErr) {
          sessionEntry.scripts.delete(scriptId);
          throw loadErr;
        }

        log('info', `Watcher installed on session ${sessionEntry.id} (script: ${scriptId})`);

        return formatToolResponse(
          buildResult(
            {
              session_id: sessionEntry.id,
              script_id: scriptId,
              watching: { native: watchNative, classes: watchClasses, tamper: watchTamper },
              message: 'Watcher installed. Drive the app, then call get_messages to see watch_event entries.',
            },
            [
              { tool: 'mobile_action', args: { action: 'mobile_list_elements_on_screen', session_id: sessionEntry.id }, reason: 'Drive the app so late loads and tamper checks happen' },
              { tool: 'get_messages', args: { session_id: sessionEntry.id }, reason: 'Read the watch_event entries (module_loaded / class_loaded / tamper_signal)' },
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

/**
 * Persistent watcher agent (classic JS). Reads its toggles from __FRIDA_MCP__.options and
 * never splices user input into code. Each signal is emitted with send() so the host records
 * it as a watch_event. The Java.available guard makes class watching a no-op off Android.
 */
const WATCH_SOURCE = `
(function () {
  var o = __FRIDA_MCP__.options;
  function emit(ev) { send(ev); }

  if (o.watchNative) {
    ['android_dlopen_ext', 'dlopen'].forEach(function (name) {
      hookNative(null, name, {
        onEnter: function (args) { try { this.path = args[0].readCString(); } catch (e) { this.path = null; } },
        onLeave: function () { if (this.path) emit({ event: 'module_loaded', path: this.path, ts: Date.now() }); }
      });
    });
  }

  if (o.watchTamper) {
    // Report when the app reads the canonical anti-Frida/anti-debug locations.
    ['open', 'fopen'].forEach(function (name) {
      hookNative(null, name, {
        onEnter: function (args) {
          try {
            var p = args[0].readCString();
            if (p && (p.indexOf('/proc/') === 0) && (p.indexOf('maps') !== -1 || p.indexOf('status') !== -1 || p.indexOf('task') !== -1)) {
              emit({ event: 'tamper_signal', kind: 'proc_read', path: p, ts: Date.now() });
            }
          } catch (e) {}
        }
      });
    });
  }

  if (o.watchClasses && typeof Java !== 'undefined' && Java.available) {
    javaPerform(function () {
      try {
        var CL = Java.use('java.lang.ClassLoader');
        var m = CL.loadClass.overload('java.lang.String');
        m.implementation = function (name) {
          try { emit({ event: 'class_loaded', name: name, ts: Date.now() }); } catch (e) {}
          return m.call(this, name);
        };
      } catch (e) { emit({ event: 'watch_error', detail: 'classloader hook failed: ' + e.message }); }
    });
  }

  emit({ event: 'watch_installed', native: !!o.watchNative, classes: !!o.watchClasses, tamper: !!o.watchTamper });
})();
`;
