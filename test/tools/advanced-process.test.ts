import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('frida', () => ({
  default: {
    getDeviceManager: () => ({}),
    Cancellable: { withTimeout: vi.fn(() => ({ isCancelled: false })) },
  },
}));

import { registerAdvancedProcessTools } from '../../src/tools/advanced/process.js';
import { initState, getState } from '../../src/state.js';
import { DeviceNotFoundError } from '../../src/helpers/errors.js';
import {
  makeMcpHarness,
  callJson,
  makeDevice,
  makeDeviceManager,
  TEST_CONFIG,
  type McpHarness,
  type FakeDevice,
} from '../helpers/mock-fixtures.js';

describe('advanced process tools', () => {
  let device: FakeDevice;
  let deviceManager: any;
  let harness: McpHarness;

  beforeEach(async () => {
    initState({ ...TEST_CONFIG });
    device = makeDevice();
    deviceManager = makeDeviceManager(device);
    harness = await makeMcpHarness((server) => registerAdvancedProcessTools(server, deviceManager));
  });

  afterEach(async () => {
    await harness.close();
    getState().stopCleanupTimer();
    vi.restoreAllMocks();
  });

  describe('list_processes', () => {
    it('lists processes via the resolved device and records it as selected', async () => {
      device.enumerateProcesses.mockResolvedValue([
        { pid: 1, name: 'init' },
        { pid: 42, name: 'com.example.app' },
      ]);

      const body = await callJson(harness.client, 'list_processes', {});

      expect(deviceManager.resolve).toHaveBeenCalledTimes(1);
      expect(getState().selectedDevice).toBe(device);
      expect(body.result.device).toBe('Dev');
      expect(body.result.process_count).toBe(2);
      expect(body.result.truncated).toBe(false);
      expect(body.result.processes).toEqual([
        { pid: 1, name: 'init' },
        { pid: 42, name: 'com.example.app' },
      ]);
    });

    it('caps the process list at 200 and flags truncation', async () => {
      const many = Array.from({ length: 250 }, (_, i) => ({ pid: i + 1, name: `p${i}` }));
      device.enumerateProcesses.mockResolvedValue(many);

      const body = await callJson(harness.client, 'list_processes', {});

      expect(body.result.process_count).toBe(250);
      expect(body.result.processes).toHaveLength(200);
      expect(body.result.truncated).toBe(true);
    });

    it('targets a device by id via getDevice', async () => {
      const body = await callJson(harness.client, 'list_processes', { device_id: 'dev1' });

      expect(deviceManager.getDevice).toHaveBeenCalledWith('dev1');
      expect(deviceManager.resolve).not.toHaveBeenCalled();
      expect(body.result.process_count).toBe(0);
    });

    it('propagates a disallowed target device as an error', async () => {
      deviceManager.getDevice.mockRejectedValue(new DeviceNotFoundError('devX', ['dev1']));

      const body = await callJson(harness.client, 'list_processes', { device_id: 'devX' });

      expect(body.error.code).toBe('DEVICE_NOT_FOUND');
    });
  });

  describe('list_applications', () => {
    it('maps installed applications', async () => {
      device.enumerateApplications.mockResolvedValue([
        { identifier: 'com.example.app', name: 'Example', pid: 42 },
        { identifier: 'com.other.app', name: 'Other', pid: 0 },
      ]);

      const body = await callJson(harness.client, 'list_applications', {});

      expect(body.result.app_count).toBe(2);
      expect(body.result.applications).toEqual([
        { identifier: 'com.example.app', name: 'Example', pid: 42 },
        { identifier: 'com.other.app', name: 'Other', pid: 0 },
      ]);
    });
  });

  describe('get_frontmost_application', () => {
    // Swap the frontmost-app stub onto the device the beforeEach harness already resolves,
    // so these cases reuse that harness instead of building (and leaking) a second one.
    function stubFrontmostApp(result: unknown): void {
      device.getFrontmostApplication = vi.fn().mockResolvedValue(result);
    }

    it('returns the foreground app with explore/hook suggestions', async () => {
      stubFrontmostApp({ identifier: 'com.example.app', name: 'Example', pid: 42 });

      const body = await callJson(harness.client, 'get_frontmost_application', {});

      expect(body.result.frontmost_app).toEqual({ identifier: 'com.example.app', name: 'Example', pid: 42 });
      expect(body.suggested_next.map((a: any) => a.tool)).toContain('explore_app');
    });

    it('reports when no foreground app is detected', async () => {
      stubFrontmostApp(null);

      const body = await callJson(harness.client, 'get_frontmost_application', {});

      expect(body.result.frontmost_app).toBeNull();
      expect(body.result.message).toContain('No foreground app');
    });
  });
});
