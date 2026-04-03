import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError } from '../helpers/errors.js';
import { log } from '../helpers/logger.js';
import { responseFormatSchema } from '../constants.js';

export function registerStatusTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'get_status',
    {
      title: 'Get Frida Status',
      description: 'Get an overview of connected devices, active sessions, and hooks. Use this first to understand what is available before starting any instrumentation work.',
      inputSchema: {
        response_format: responseFormatSchema,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ response_format }) => {
      try {
        const state = getState();

        // List devices
        let devices: Awaited<ReturnType<typeof deviceManager.listDevices>> = [];
        try {
          devices = await deviceManager.listDevices();
        } catch {
          devices = [];
        }

        // Current device info
        let currentDevice = null;
        if (state.selectedDevice) {
          try {
            currentDevice = await deviceManager.getDeviceInfo(state.selectedDevice.id);
          } catch {
            currentDevice = { id: state.selectedDevice.id, name: state.selectedDevice.name, type: state.selectedDevice.type };
          }
        }

        // Sessions
        const sessions = Array.from(state.sessions.values()).map((s) => ({
          id: s.id,
          target: s.target,
          pid: s.pid,
          platform: s.platform,
          device: s.deviceId,
          scripts: s.scripts.size,
          created: new Date(s.createdAt).toISOString(),
        }));

        // Hooks
        const hooks = Array.from(state.hooks.values()).map((h) => ({
          id: h.id,
          target: h.target,
          type: h.type,
          status: h.status,
          invocations: h.invocations.length,
        }));

        // Traces
        const traces = Array.from(state.traces.values()).map((t) => ({
          id: t.id,
          targets: t.targets,
          calls: t.callCount,
        }));

        const result = buildResult(
          {
            devices,
            current_device: currentDevice,
            sessions,
            hooks,
            traces,
            config: {
              custom_scripts_enabled: state.config.allowCustomScripts,
              memory_write_enabled: state.config.memoryWriteEnabled,
              mobile_mcp_enabled: state.config.mobileMcp.enabled,
              max_sessions: state.config.maxSessions,
            },
          },
          [
            ...(devices.length > 0 && !currentDevice
              ? [{ tool: 'explore_app', reason: 'Start exploring an app on a connected device' }]
              : []),
            ...(sessions.length > 0
              ? [{ tool: 'get_messages', reason: 'Check output from active scripts/hooks' }]
              : []),
            ...(devices.length === 0
              ? [{
                  tool: 'frida_help',
                  args: { topic: 'overview' },
                  reason: 'No devices found - get help on setup',
                }]
              : []),
          ]
        );

        return formatToolResponse(result, response_format);
      } catch (err) {
        const wrapped = wrapFridaError(err);
        return formatToolResponse(wrapped.toErrorResponse(), response_format);
      }
    }
  );
}
