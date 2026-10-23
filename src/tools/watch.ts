import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { MemoryWriteDisabledError, wrapFridaError } from '../helpers/errors.js';
import { EVASION_SCRUB_SNIPPET } from '../scripts/evasion-scrub.js';
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
        'Install a persistent watcher that reports what the app does AFTER attach, straight into the session message buffer. Three signal families, each toggleable: (1) native libraries (.so) loaded late (dlopen/android_dlopen_ext), observed via Frida\'s loader module-load notifications — no dlopen hook, so it will not destabilize the target — meaning a library that only appears after a UI action is still seen; (2) Java classes loaded late via ClassLoader.loadClass (Android only; the Java.available guard makes it a no-op elsewhere); (3) anti-instrumentation / anti-debug reads of canonical /proc locations (maps, status, task) via open/fopen. The watcher stays loaded and keeps emitting: drive the app (e.g. mobile_action), then call get_messages to read the watch_event entries. Pair with discover_crypto / hook_method once a late-loaded target shows up. Set spoof=true (needs memoryWriteEnabled) to go beyond reporting and actively scrub Frida signatures / zero TracerPid from those /proc reads; for a fuller stealth set use the anti_frida_evasion prebuilt script.',
      inputSchema: z.object({
        target: z.string().optional().describe('App bundle ID, process name, or PID. Optional when session_id is given.'),
        session_id: z.string().optional().describe('Reuse an existing session from explore_app/get_status.'),
        device: z.string().optional().describe('Device ID'),
        watch_native: z.boolean().optional().default(true).describe('Report native libraries (.so) loaded after attach (dlopen/android_dlopen_ext), via Frida\'s loader module-load notifications rather than a dlopen hook, so it is safe on loader-sensitive targets (default: true).'),
        watch_classes: z.boolean().optional().default(true).describe('Report Java classes loaded after attach via ClassLoader.loadClass (Android only; default: true).'),
        watch_tamper: z.boolean().optional().default(true).describe('Report anti-instrumentation / anti-debug reads of /proc maps|status|task via open/fopen (default: true).'),
        spoof: z.boolean().optional().default(false).describe('Actively scrub Frida signatures and zero TracerPid from the /proc reads detected by watch_tamper (and make strstr "frida" miss), instead of only reporting them. Writes target memory, so it requires memoryWriteEnabled. For a fuller stealth set (thread names, dlopen, iOS dyld) use the anti_frida_evasion prebuilt script.'),
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
    async ({ target, session_id, device, watch_native, watch_classes, watch_tamper, spoof, response_format }) => {
      try {
        const resolved = resolveInstrumentationTarget(target, session_id);
        const state = getState();

        const watchNative = watch_native ?? true;
        const watchClasses = watch_classes ?? true;
        const watchTamper = watch_tamper ?? true;
        const spoofTamper = spoof ?? false;

        // Spoofing rewrites the target's /proc buffers, so it is gated like write_memory.
        if (spoofTamper && !state.config.memoryWriteEnabled) {
          throw new MemoryWriteDisabledError(
            'watch_loads spoof=true writes to target memory. Enable it with memoryWriteEnabled: true in config or FRIDA_MCP_MEMORY_WRITE=1, or leave spoof=false to only report tamper signals.',
          );
        }

        const { sessionEntry } = await getOrCreateSession(deviceManager, { target: resolved.target, device, sessionId: resolved.sessionId });
        const platform = sessionEntry.platform;

        const script = await createAgentScript(sessionEntry.session, {
          sessionEntry,
          source: WATCH_SOURCE,
          platform,
          name: 'watch_loads:' + platform,
          kind: 'generated',
          options: { watchNative, watchClasses, watchTamper, spoofTamper },
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
              watching: { native: watchNative, classes: watchClasses, tamper: watchTamper, spoof: spoofTamper },
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
  ${EVASION_SCRUB_SNIPPET}
  var o = __FRIDA_MCP__.options;
  function emit(ev) { send(ev); }
  // When spoof is on, the shared evasion handle scrubs the /proc reads that watch_tamper detects.
  var ev = o.spoofTamper ? installEvasion({ mode: 'spoof' }) : null;

  if (o.watchNative) {
    // Observe late native-library loads through the loader's own notification API rather than
    // Interceptor-hooking dlopen. Hooking dlopen rewrites its prologue, and bionic derives the
    // calling linker namespace from the return address, so a trampoline there makes the loader
    // mis-resolve the namespace and abort the target (~800ms after resume on sensitive apps;
    // see issue #19). attachModuleObserver carries no such hazard — it fires on the modules the
    // loader actually maps, dlopen/android_dlopen_ext alike. Present since Frida 16.2 (always
    // true on the pinned 17.x); guarded so an older runtime degrades to a clear message.
    if (typeof Process.attachModuleObserver === 'function') {
      Process.attachModuleObserver({
        onAdded: function (m) {
          try { emit({ event: 'module_loaded', path: m.path, name: m.name, ts: Date.now() }); } catch (e) {}
        }
      });
    } else {
      emit({ event: 'watch_error', detail: 'native load watching needs Frida >= 16.2 (Process.attachModuleObserver)' });
    }
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

  // Scrubbing is independent of tamper reporting: spoof=true must scrub even with watch_tamper=false.
  // Scrub the bytes the app reads back from /proc via the stable fgets/fread layer (the common
  // fopen()+fgets() maps-parsing idiom) rather than hooking the very hot read(), which can
  // destabilize a busy process. Same shared wiring as the anti_frida_evasion script; for raw
  // open()+read() scrubbing and strstr greps use that script with aggressive=true.
  if (ev) {
    ev.installBufferScrubHooks('spoof');
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

  emit({ event: 'watch_installed', native: !!o.watchNative, classes: !!o.watchClasses, tamper: !!o.watchTamper, spoof: !!o.spoofTamper });
})();
`;
