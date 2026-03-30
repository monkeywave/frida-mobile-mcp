import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { DeviceManager } from '../../device/manager.js';
import { getState } from '../../state.js';
import { buildResult, formatToolResponse } from '../../helpers/result-builder.js';
import { wrapFridaError } from '../../helpers/errors.js';

export function registerAdvancedDeviceTools(server: McpServer, deviceManager: DeviceManager): void {
  server.tool(
    'list_devices',
    'Enumerate all Frida-visible devices including local, USB, and remote devices. Equivalent to frida-ls-devices CLI command.',
    {},
    async () => {
      try {
        const devices = await deviceManager.listDevices();
        return formatToolResponse(buildResult({ devices }, [
          { tool: 'select_device', reason: 'Select a specific device' },
          { tool: 'explore_app', reason: 'Start exploring an app' },
        ]));
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse());
      }
    }
  );

  server.tool(
    'select_device',
    'Explicitly select the active Frida device for subsequent operations.',
    {
      device_id: z.string().optional().describe('Device ID from list_devices'),
      type: z.enum(['usb', 'local', 'remote']).optional().describe('Device type'),
      host: z.string().optional().describe('Remote host:port for remote devices'),
    },
    async ({ device_id, type, host }) => {
      try {
        const state = getState();
        const device = await deviceManager.resolve({ deviceId: device_id, type: type as any, host });
        state.selectedDevice = device;
        const info = await deviceManager.getDeviceInfo(device.id);
        return formatToolResponse(buildResult({
          selected_device: info,
          message: `Device selected: ${device.name} (${device.id})`,
        }, [
          { tool: 'explore_app', reason: 'Start exploring an app on this device' },
          { tool: 'list_processes', reason: 'List running processes' },
        ]));
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse());
      }
    }
  );

  server.tool(
    'get_device_info',
    'Get detailed information about a device including OS version, architecture, and system parameters.',
    {
      device_id: z.string().optional().describe('Device ID. Uses selected device if not specified.'),
    },
    async ({ device_id }) => {
      try {
        const state = getState();
        const id = device_id || state.selectedDevice?.id;
        if (!id) {
          return formatToolResponse(buildResult({ error: 'No device selected. Use select_device or provide device_id.' }, [
            { tool: 'list_devices', reason: 'List available devices' },
          ]));
        }
        const info = await deviceManager.getDeviceInfo(id);
        return formatToolResponse(buildResult({ device: info }, []));
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse());
      }
    }
  );
}
