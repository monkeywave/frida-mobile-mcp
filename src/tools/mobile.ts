import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { MobileMcpUnavailableError, FridaMcpError } from '../helpers/errors.js';
import { responseFormatSchema } from '../constants.js';
import { log, audit } from '../helpers/logger.js';

// Available mobile-mcp actions for reference
const MOBILE_ACTIONS = [
  'mobile_take_screenshot',
  'mobile_list_elements_on_screen',
  'mobile_click_on_screen_at_coordinates',
  'mobile_double_tap_on_screen',
  'mobile_long_press_on_screen_at_coordinates',
  'mobile_swipe_on_screen',
  'mobile_type_keys',
  'mobile_press_button',
  'mobile_launch_app',
  'mobile_terminate_app',
  'mobile_list_apps',
  'mobile_install_app',
  'mobile_uninstall_app',
  'mobile_open_url',
  'mobile_get_screen_size',
  'mobile_get_orientation',
  'mobile_set_orientation',
  'mobile_save_screenshot',
  'mobile_start_screen_recording',
  'mobile_stop_screen_recording',
  'mobile_list_available_devices',
];

export function registerMobileTool(server: McpServer): void {
  server.registerTool(
    'mobile_action',
    {
      title: 'Mobile UI Action',
      description: `Gateway to mobile-mcp UI automation tools. Perform screenshots, taps, swipes, text input, app management and more. Common actions: mobile_take_screenshot, mobile_list_elements_on_screen, mobile_click_on_screen_at_coordinates (params: {x, y}), mobile_swipe_on_screen (params: {direction}), mobile_type_keys (params: {text}), mobile_launch_app (params: {appId}), mobile_list_apps. Call without action to see all available actions.`,
      inputSchema: z.object({
        action: z.string().optional().describe('mobile-mcp action name (e.g., "mobile_take_screenshot"). Omit to list available actions.'),
        params: z.record(z.string(), z.unknown()).optional().describe('Parameters for the action'),
        session_id: z.string().optional().describe('Resolve the mobile device from this session (falls back to the selected device). Needed so UI actions target the right device when several are attached.'),
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
    async ({ action, params, session_id, response_format }) => {
      try {
        const state = getState();

        if (!state.config.mobileMcp.enabled) {
          throw new MobileMcpUnavailableError('mobile-mcp integration is disabled in config');
        }

        // List actions if none specified
        if (!action) {
          let actions: string[] = MOBILE_ACTIONS; // fallback
          try {
            const { getMobileMcpProxy } = await import('../mobile-mcp/proxy.js');
            const proxy = await getMobileMcpProxy();
            const tools = await proxy.listTools();
            if (tools.length > 0) {
              actions = tools.map((t) => t.name);
            }
          } catch {
            // Use fallback hardcoded list
          }

          return formatToolResponse(
            buildResult(
              {
                available_actions: actions,
                usage: 'Call mobile_action with an action name and params. Example: mobile_action({ action: "mobile_click_on_screen_at_coordinates", params: { x: 100, y: 200 } })',
              },
              [
                { tool: 'mobile_action', args: { action: 'mobile_take_screenshot' }, reason: 'Take a screenshot' },
                { tool: 'mobile_action', args: { action: 'mobile_list_apps' }, reason: 'List installed apps' },
              ]
            ),
            response_format
          );
        }

        // Resolve the device so UI actions target the right one when several are attached.
        const fridaDeviceId = session_id
          ? state.getSession(session_id)?.deviceId
          : state.selectedDevice?.id;

        // Try to use mobile-mcp proxy (shared helper resolves + injects the device).
        try {
          const { callMobileAction } = await import('../mobile-mcp/call.js');
          const result = await callMobileAction(action, params, fridaDeviceId);

          audit({
            timestamp: new Date().toISOString(),
            tool: 'mobile_action',
            params: { action, params },
            status: 'success',
          });

          return formatToolResponse(
            buildResult(
              {
                action,
                result: result,
              },
              [
                { tool: 'mobile_action', args: { action: 'mobile_list_elements_on_screen' }, reason: 'List UI elements' },
                { tool: 'hook_method', reason: 'Hook a method to trace what happens after this action' },
              ]
            ),
            response_format
          );
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          if (message.includes('MODULE_NOT_FOUND') || message.includes('Cannot find') || message.includes('ENOENT')) {
            throw new MobileMcpUnavailableError('mobile-mcp not installed. Install with: npm install -g @mobilenext/mobile-mcp');
          }
          throw err;
        }
      } catch (err) {
        if (err instanceof FridaMcpError) return formatToolResponse(err.toErrorResponse(), response_format);
        return formatToolResponse(
          new FridaMcpError('MOBILE_ERROR', err instanceof Error ? err.message : String(err), [
            { tool: 'mobile_action', reason: 'List available actions' },
          ]).toErrorResponse(),
          response_format
        );
      }
    }
  );
}
