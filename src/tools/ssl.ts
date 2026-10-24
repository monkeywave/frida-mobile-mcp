import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { attachScriptSinks } from '../helpers/script-sink.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError } from '../helpers/errors.js';
import { resolveInstrumentationTarget } from './hook.js';
import { log } from '../helpers/logger.js';
import { rateLimiter } from '../helpers/rate-limiter.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
import { getScriptRegistry } from '../scripts/registry.js';
import { responseFormatSchema } from '../constants.js';
import { createAgentScript } from '../agent/script-factory.js';
import type { PlatformContext } from '../types.js';

export function registerSslTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'bypass_ssl_pinning',
    {
      title: 'Bypass SSL Pinning',
      description: 'One-click SSL certificate pinning bypass for the target app. Auto-detects platform (Android/iOS) and applies the appropriate bypass techniques. On Android: hooks TrustManager, OkHttp CertificatePinner, and Conscrypt. On iOS: hooks SecTrust, ATS, and BoringSSL verification. Returns which bypass methods were successfully installed.',
      inputSchema: z.object({
        target: z.string().optional().describe('App bundle ID or process name. Optional when session_id is given.'),
        session_id: z.string().optional().describe('Reuse an existing session (from explore_app/get_status) instead of re-attaching by target.'),
        device: z.string().optional().describe('Device ID'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ target, session_id, device, response_format }) => {
      try {
        const resolved = resolveInstrumentationTarget(target, session_id);
        const state = getState();

        rateLimiter.check('script', state.config.rateLimits.scriptsPerMinute);
        rateLimiter.record('script');

        const { sessionEntry: resolvedSession } = await getOrCreateSession(deviceManager, { target: resolved.target, device, sessionId: resolved.sessionId });
        let sessionEntry = resolvedSession;

        const platform = sessionEntry.platform;

        const registry = getScriptRegistry();
        const template = registry.get('ssl_pinning_bypass');
        if (!template) {
          throw new Error('SSL pinning bypass script not found in registry');
        }

        const context: PlatformContext = { platform: platform === 'android' || platform === 'ios' ? platform : 'unknown' };
        const script = await createAgentScript(sessionEntry.session, {
          sessionEntry: sessionEntry,
          source: template.generate({ platform }, context),
          platform,
          name: `prebuilt:${template.name}`,
          kind: 'generated',
          options: { platform },
        });
        const scriptId = state.generateId();
        const results: Array<Record<string, unknown>> = [];

        sessionEntry.scripts.set(scriptId, {
          id: scriptId,
          script,
          messages: [],
          name: 'ssl_pinning_bypass',
          persistent: true,
          createdAt: Date.now(),
        });

        attachScriptSinks(script, sessionEntry.id, scriptId, {
          onSend: (payload, data) => {
            results.push(payload as Record<string, unknown>);
            state.addMessageToScript(sessionEntry!.id, scriptId, { timestamp: Date.now(), type: 'ssl_bypass', payload, data: data ?? null });
          },
        });

        await script.load();
        await new Promise((resolve) => setTimeout(resolve, 2000));

        const bypassed = results.filter((r: any) => r.status === 'bypassed').map((r: any) => r.method);
        const failed = results.filter((r: any) => r.status === 'failed').map((r: any) => r.method);

        return formatToolResponse(
          buildResult(
            {
              session_id: sessionEntry.id,
              script_id: scriptId,
              platform,
              bypassed_methods: bypassed,
              failed_methods: failed,
              all_results: results,
              message: bypassed.length > 0
                ? `SSL pinning bypassed via: ${bypassed.join(', ')}`
                : 'SSL pinning bypass scripts loaded. Bypass will activate on next network request.',
            },
            [
              { tool: 'run_prebuilt_script', args: { script_name: 'network_inspector', target }, reason: 'Monitor network traffic now that SSL pinning is bypassed' },
              { tool: 'mobile_action', args: { action: 'mobile_take_screenshot' }, reason: 'Navigate the app to trigger network requests' },
              { tool: 'get_messages', args: { session_id: sessionEntry.id }, reason: 'Check bypass status messages' },
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
