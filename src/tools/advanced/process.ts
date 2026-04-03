import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { DeviceManager } from '../../device/manager.js';
import { getState } from '../../state.js';
import { buildResult, formatToolResponse } from '../../helpers/result-builder.js';
import { wrapFridaError } from '../../helpers/errors.js';
import { responseFormatSchema } from '../../constants.js';

export function registerAdvancedProcessTools(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'list_processes',
    {
      title: 'List Processes',
      description: 'List running processes on the target device. Equivalent to frida-ps CLI command.',
      inputSchema: {
        device_id: z.string().optional().describe('Device ID'),
        response_format: responseFormatSchema,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ device_id, response_format }) => {
      try {
        const state = getState();
        const device = device_id
          ? await deviceManager.getDevice(device_id)
          : state.selectedDevice || await deviceManager.resolve();
        state.selectedDevice = device;

        const processes = await device.enumerateProcesses();
        const processList = processes.map((p) => ({ pid: p.pid, name: p.name }));

        return formatToolResponse(buildResult({
          device: device.name,
          process_count: processList.length,
          processes: processList.slice(0, 200),
          truncated: processList.length > 200,
        }, [
          { tool: 'attach_process', reason: 'Attach to a specific process' },
          { tool: 'list_applications', reason: 'List installed applications instead' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );

  server.registerTool(
    'list_applications',
    {
      title: 'List Applications',
      description: 'List installed and running applications on the target device.',
      inputSchema: {
        device_id: z.string().optional().describe('Device ID'),
        response_format: responseFormatSchema,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ device_id, response_format }) => {
      try {
        const state = getState();
        const device = device_id
          ? await deviceManager.getDevice(device_id)
          : state.selectedDevice || await deviceManager.resolve();
        state.selectedDevice = device;

        const apps = await device.enumerateApplications();
        const appList = apps.map((a) => ({
          identifier: a.identifier,
          name: a.name,
          pid: a.pid,
        }));

        return formatToolResponse(buildResult({
          device: device.name,
          app_count: appList.length,
          applications: appList,
        }, [
          { tool: 'explore_app', reason: 'Explore a specific app' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );

  server.registerTool(
    'get_frontmost_application',
    {
      title: 'Get Frontmost Application',
      description: 'Get the currently foreground application on the device.',
      inputSchema: {
        device_id: z.string().optional().describe('Device ID'),
        response_format: responseFormatSchema,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ device_id, response_format }) => {
      try {
        const state = getState();
        const device = device_id
          ? await deviceManager.getDevice(device_id)
          : state.selectedDevice || await deviceManager.resolve();
        state.selectedDevice = device;

        const app = await device.getFrontmostApplication();
        if (!app) {
          return formatToolResponse(buildResult({ frontmost_app: null, message: 'No foreground app detected.' }, []), response_format);
        }

        return formatToolResponse(buildResult({
          frontmost_app: { identifier: app.identifier, name: app.name, pid: app.pid },
        }, [
          { tool: 'explore_app', args: { target: app.identifier }, reason: 'Explore this app' },
          { tool: 'hook_method', args: { target: app.identifier }, reason: 'Hook methods in this app' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}
