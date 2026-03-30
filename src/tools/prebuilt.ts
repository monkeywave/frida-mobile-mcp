import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError, FridaMcpError } from '../helpers/errors.js';
import { validateProcessTarget } from '../helpers/sanitize.js';
import { log, audit } from '../helpers/logger.js';
import { rateLimiter } from '../helpers/rate-limiter.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
import { getScriptRegistry } from '../scripts/registry.js';

export function registerPrebuiltTool(server: McpServer, deviceManager: DeviceManager): void {
  server.tool(
    'run_prebuilt_script',
    'Run a pre-built Frida script from the built-in library. Call without script_name to list all available scripts. Available scripts include: ssl_pinning_bypass, root_jailbreak_bypass, class_enumeration, method_hook, crypto_monitor, network_inspector, keychain_prefs, filesystem_monitor.',
    {
      script_name: z.string().optional().describe('Script name. Omit to list all available scripts.'),
      target: z.string().optional().describe('App bundle ID, process name, or PID (required when running a script)'),
      device: z.string().optional().describe('Device ID'),
      options: z.record(z.unknown()).optional().describe('Script-specific options'),
    },
    async ({ script_name, target, device, options }) => {
      try {
        const registry = getScriptRegistry();

        // If no script name, list all available scripts
        if (!script_name) {
          const scripts = registry.listAll();
          return formatToolResponse(
            buildResult(
              {
                available_scripts: scripts.map((s) => ({
                  name: s.name,
                  description: s.description,
                  platforms: s.platforms,
                  category: s.category,
                  risk_tier: s.riskTier,
                  options: s.options ? Object.entries(s.options).map(([k, v]) => ({
                    name: k,
                    type: v.type,
                    description: v.description,
                    default: v.default,
                  })) : [],
                })),
              },
              [
                { tool: 'run_prebuilt_script', args: { script_name: 'ssl_pinning_bypass' }, reason: 'Most commonly used script' },
                { tool: 'run_prebuilt_script', args: { script_name: 'class_enumeration' }, reason: 'Start exploring app classes' },
              ]
            )
          );
        }

        // Run a specific script
        if (!target) {
          throw new FridaMcpError(
            'INVALID_ARGUMENT',
            'target is required when running a script',
            [{ tool: 'run_prebuilt_script', reason: 'List available scripts first' }]
          );
        }

        validateProcessTarget(target);
        const state = getState();

        rateLimiter.check('script', state.config.rateLimits.scriptsPerMinute);
        rateLimiter.record('script');

        const template = registry.get(script_name);
        if (!template) {
          throw new FridaMcpError(
            'SCRIPT_NOT_FOUND',
            `Script "${script_name}" not found.`,
            [{ tool: 'run_prebuilt_script', reason: 'List available scripts' }]
          );
        }

        // Generate script source
        const scriptSource = template.generate(options || {});

        const { sessionEntry: resolvedSession } = await getOrCreateSession(deviceManager, { target, device });
        let sessionEntry = resolvedSession;

        // Load and run
        const script = await sessionEntry.session.createScript(scriptSource);
        const scriptId = state.generateId();
        const messages: Array<Record<string, unknown>> = [];

        sessionEntry.scripts.set(scriptId, {
          id: scriptId,
          script,
          messages: [],
          name: `prebuilt:${script_name}`,
          persistent: true,
          createdAt: Date.now(),
        });

        script.message.connect((message, data) => {
          if (message.type === 'send') {
            messages.push(message.payload);
            state.addMessageToScript(sessionEntry!.id, scriptId, {
              timestamp: Date.now(),
              type: 'prebuilt_output',
              payload: message.payload,
              data: data ?? null,
            });
          }
        });

        await script.load();

        // Wait briefly to collect initial output
        await new Promise((resolve) => setTimeout(resolve, 2000));

        audit({
          timestamp: new Date().toISOString(),
          sessionId: sessionEntry.id,
          tool: 'run_prebuilt_script',
          params: { script_name, target, options },
          status: 'success',
        });

        return formatToolResponse(
          buildResult(
            {
              script_name,
              script_id: scriptId,
              session_id: sessionEntry.id,
              description: template.description,
              initial_messages: messages.slice(0, 20),
              message: `Script "${script_name}" loaded and running. Use get_messages for ongoing output.`,
            },
            [
              { tool: 'get_messages', args: { session_id: sessionEntry.id }, reason: 'Check script output' },
              { tool: 'mobile_action', args: { action: 'mobile_take_screenshot' }, reason: 'See app state' },
            ]
          )
        );
      } catch (err) {
        if (err instanceof FridaMcpError) return formatToolResponse(err.toErrorResponse());
        return formatToolResponse(wrapFridaError(err).toErrorResponse());
      }
    }
  );
}
