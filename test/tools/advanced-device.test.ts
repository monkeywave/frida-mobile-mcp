import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('frida', () => ({
  default: {
    getDeviceManager: () => ({}),
    Cancellable: { withTimeout: vi.fn(() => ({ isCancelled: false })) },
  },
}));

import { registerAdvancedDeviceTools } from '../../src/tools/advanced/device.js';
import { DeviceManager } from '../../src/device/manager.js';
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

const DEVICE_INFO = { id: 'dev1', name: 'Dev', type: 'usb', platform: 'linux', os: '{"id":"android"}', arch: 'arm64' };

describe('advanced device tools', () => {
  let device: FakeDevice;
  let deviceManager: any;
  let harness: McpHarness;

  beforeEach(async () => {
    initState({ ...TEST_CONFIG });
    device = makeDevice();
    deviceManager = makeDeviceManager(device);
    deviceManager.listDevices = vi.fn().mockResolvedValue([DEVICE_INFO]);
    deviceManager.getDeviceInfo = vi.fn().mockResolvedValue(DEVICE_INFO);
    harness = await makeMcpHarness((server) => registerAdvancedDeviceTools(server, deviceManager));
  });

  afterEach(async () => {
    await harness.close();
    getState().stopCleanupTimer();
    vi.restoreAllMocks();
  });

  describe('list_devices', () => {
    it('returns the enumerated devices with follow-up suggestions', async () => {
      const body = await callJson(harness.client, 'list_devices', {});

      expect(deviceManager.listDevices).toHaveBeenCalledTimes(1);
      expect(body.result.devices).toEqual([DEVICE_INFO]);
      expect(body.suggested_next.map((a: any) => a.tool)).toContain('select_device');
      expect(body.evidence_id).toBeTypeOf('string');
    });

    it('surfaces enumeration failures through the error envelope', async () => {
      deviceManager.listDevices.mockRejectedValue(new Error('unable to find device'));

      const body = await callJson(harness.client, 'list_devices', {});

      expect(body.error.code).toBe('DEVICE_NOT_FOUND');
      expect(body.error.category).toBe('capability');
    });
  });

  describe('select_device', () => {
    it('resolves, selects and reports the device', async () => {
      const body = await callJson(harness.client, 'select_device', { device_id: 'dev1' });

      expect(deviceManager.resolve).toHaveBeenCalledWith({ deviceId: 'dev1', type: undefined, host: undefined });
      expect(getState().selectedDevice).toBe(device);
      expect(body.result.selected_device).toEqual(DEVICE_INFO);
      expect(body.result.message).toContain('Dev');
    });

    it('propagates a disallowed device as DEVICE_NOT_FOUND', async () => {
      deviceManager.resolve.mockRejectedValue(new DeviceNotFoundError('dev9', ['dev1']));

      const body = await callJson(harness.client, 'select_device', { device_id: 'dev9' });

      expect(body.error.code).toBe('DEVICE_NOT_FOUND');
      expect(body.error.context.requested_device).toBe('dev9');
    });
  });

  describe('get_device_info', () => {
    it('uses the explicit device_id', async () => {
      const body = await callJson(harness.client, 'get_device_info', { device_id: 'dev1' });

      expect(deviceManager.getDeviceInfo).toHaveBeenCalledWith('dev1');
      expect(body.result.device).toEqual(DEVICE_INFO);
    });

    it('falls back to the selected device', async () => {
      getState().selectedDevice = device as any;

      const body = await callJson(harness.client, 'get_device_info', {});

      expect(deviceManager.getDeviceInfo).toHaveBeenCalledWith('dev1');
      expect(body.result.device).toEqual(DEVICE_INFO);
    });

    it('reports when no device is selected or provided', async () => {
      const body = await callJson(harness.client, 'get_device_info', {});

      expect(deviceManager.getDeviceInfo).not.toHaveBeenCalled();
      expect(body.result.error).toContain('No device selected');
      expect(body.suggested_next.map((a: any) => a.tool)).toContain('list_devices');
    });
  });
});

// The allowedDevices allowlist lives in DeviceManager, which the device tools delegate to.
describe('allowedDevices guardrail (DeviceManager)', () => {
  beforeEach(() => initState({ ...TEST_CONFIG }));
  afterEach(() => {
    getState().stopCleanupTimer();
    vi.restoreAllMocks();
  });

  it('rejects a device that is not on the allowlist before any lookup', async () => {
    const fakeFrida = { getDeviceById: vi.fn(), enumerateDevices: vi.fn() } as any;
    const manager = new DeviceManager(fakeFrida, { ...TEST_CONFIG, allowedDevices: ['dev1'] });

    await expect(manager.getDevice('dev9')).rejects.toMatchObject({ code: 'DEVICE_NOT_FOUND', category: 'capability' });
    expect(fakeFrida.getDeviceById).not.toHaveBeenCalled();
  });

  it('allows a device that is on the allowlist', async () => {
    const allowed = makeDevice({ id: 'dev1' });
    const fakeFrida = { getDeviceById: vi.fn().mockResolvedValue(allowed), enumerateDevices: vi.fn() } as any;
    const manager = new DeviceManager(fakeFrida, { ...TEST_CONFIG, allowedDevices: ['dev1'] });

    await expect(manager.getDevice('dev1')).resolves.toBe(allowed);
    expect(fakeFrida.getDeviceById).toHaveBeenCalledTimes(1);
  });
});
