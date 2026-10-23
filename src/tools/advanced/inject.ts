import { z } from 'zod';
import { toolOutputSchema } from '../../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../../device/manager.js';
import { getState } from '../../state.js';
import { buildResult, formatToolResponse } from '../../helpers/result-builder.js';
import { NativeInjectionDisabledError, wrapFridaError } from '../../helpers/errors.js';
import { log } from '../../helpers/logger.js';
import { responseFormatSchema } from '../../constants.js';

/**
 * inject_library — load a native agent library (.so / .dylib) into a target process using
 * Frida's own injector (device.injectLibraryFile), independent of the GumJS script engine.
 *
 * This runs arbitrary native code the caller supplies in the target, so it is gated on its own
 * allowNativeInjection capability (separate from allowCustomScripts, which gates JS agents). The
 * library must be built for the device's architecture; its `entrypoint` export (if any) is called
 * with the `data` string.
 */
export function registerInjectTools(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'inject_library',
    {
      title: 'Inject Native Library',
      description: "Inject a native agent library (.so/.dylib) from the host into a target process via Frida's injector, independent of the JS engine — the parity path for a prebuilt Frida gadget/agent or a custom .so. Runs arbitrary native code in the target, so it needs allowNativeInjection (a capability separate from allowCustomScripts). The library must match the device architecture (arm64-v8a etc.); its optional exported entrypoint is called with the data string. Returns the frida injectee id.",
      inputSchema: z.object({
        target: z.union([z.string(), z.number()]).describe('Target process: PID (number) or process/app name (string).'),
        library_path: z.string().describe('Host path to the native library (.so/.dylib) to inject; Frida reads and transfers it to the device.'),
        entrypoint: z.string().optional().default('').describe("Exported function in the library to call after load (empty = rely on the library's own constructors)."),
        data: z.string().optional().default('').describe('String passed to the entrypoint.'),
        device: z.string().optional().describe('Device ID. Uses the selected/default device when omitted.'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    async ({ target, library_path, entrypoint, data, device: deviceId, response_format }) => {
      try {
        const state = getState();
        if (!state.config.allowNativeInjection) {
          throw new NativeInjectionDisabledError(
            'inject_library runs arbitrary native code in the target. Enable it with allowNativeInjection: true in config or FRIDA_MCP_ALLOW_NATIVE_INJECTION=1.',
          );
        }

        const device = deviceId
          ? await deviceManager.resolve({ deviceId })
          : state.selectedDevice || await deviceManager.resolve();
        state.selectedDevice = device;

        const injecteeId = await device.injectLibraryFile(target, library_path, entrypoint ?? '', data ?? '');
        log('info', `Injected library ${library_path} into ${String(target)} (injectee ${injecteeId})`);

        return formatToolResponse(buildResult({
          target: String(target),
          library_path,
          entrypoint: entrypoint || null,
          injectee_id: injecteeId,
          status: 'injected',
          message: 'Library injected. It runs independently of the JS engine; there is no message channel back from an injected library.',
        }, [
          { tool: 'list_processes', reason: 'Confirm the target is still alive' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}
