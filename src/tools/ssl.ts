import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError } from '../helpers/errors.js';
import { validateProcessTarget } from '../helpers/sanitize.js';
import { log, audit } from '../helpers/logger.js';
import { rateLimiter } from '../helpers/rate-limiter.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
import { getScriptRegistry } from '../scripts/registry.js';
import { responseFormatSchema } from '../constants.js';

export function registerSslTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'bypass_ssl_pinning',
    {
      title: 'Bypass SSL Pinning',
      description: 'One-click SSL certificate pinning bypass for the target app. Auto-detects platform (Android/iOS) and applies the appropriate bypass techniques. On Android: hooks TrustManager, OkHttp CertificatePinner, and Conscrypt. On iOS: hooks SecTrust, ATS, and BoringSSL verification. Returns which bypass methods were successfully installed.',
      inputSchema: {
        target: z.string().describe('App bundle ID or process name'),
        device: z.string().optional().describe('Device ID'),
        response_format: responseFormatSchema,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ target, device, response_format }) => {
      const startTime = Date.now();
      try {
        validateProcessTarget(target);
        const state = getState();

        rateLimiter.check('script', state.config.rateLimits.scriptsPerMinute);
        rateLimiter.record('script');

        const { sessionEntry: resolvedSession } = await getOrCreateSession(deviceManager, { target, device });
        let sessionEntry = resolvedSession;

        const platform = sessionEntry.platform;

        const registry = getScriptRegistry();
        const template = registry.get('ssl_pinning_bypass');
        if (!template) {
          throw new Error('SSL pinning bypass script not found in registry');
        }

        const scriptSource = template.generate({ platform });
        const script = await sessionEntry.session.createScript(scriptSource);
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

        script.message.connect((message, data) => {
          if (message.type === 'send') {
            results.push(message.payload);
            state.addMessageToScript(sessionEntry!.id, scriptId, {
              timestamp: Date.now(),
              type: 'ssl_bypass',
              payload: message.payload,
              data: data ?? null,
            });
          }
        });

        await script.load();
        await new Promise((resolve) => setTimeout(resolve, 2000));

        const bypassed = results.filter((r: any) => r.status === 'bypassed').map((r: any) => r.method);
        const failed = results.filter((r: any) => r.status === 'failed').map((r: any) => r.method);

        audit({
          timestamp: new Date().toISOString(),
          sessionId: sessionEntry.id,
          tool: 'bypass_ssl_pinning',
          params: { target, device },
          status: 'success',
          durationMs: Date.now() - startTime,
        });

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
