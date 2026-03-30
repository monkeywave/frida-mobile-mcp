import frida from 'frida';
import type { DeviceInfo, FridaMcpConfig } from '../types.js';
import { resolveDevice, deviceToInfo, deviceToDetailedInfo } from './resolver.js';
import { DeviceNotFoundError } from '../helpers/errors.js';
import { log } from '../helpers/logger.js';

export class DeviceManager {
  private fridaManager: frida.DeviceManager;
  private config: FridaMcpConfig;
  private deviceCache: Map<string, frida.Device> = new Map();

  constructor(fridaManager: frida.DeviceManager, config: FridaMcpConfig) {
    this.fridaManager = fridaManager;
    this.config = config;
  }

  async resolve(options?: { deviceId?: string; type?: 'usb' | 'local' | 'remote'; host?: string }): Promise<frida.Device> {
    const device = await resolveDevice(this.fridaManager, options);

    // Check allowlist
    if (this.config.allowedDevices.length > 0 && !this.config.allowedDevices.includes(device.id)) {
      throw new DeviceNotFoundError(
        device.id,
        this.config.allowedDevices
      );
    }

    this.deviceCache.set(device.id, device);
    return device;
  }

  async listDevices(): Promise<DeviceInfo[]> {
    const devices = await this.fridaManager.enumerateDevices();
    const infos: DeviceInfo[] = [];

    for (const device of devices) {
      // Skip the 'local' system device type entry that is just the socket pipe
      if (device.type === 'local' && device.id === 'local') {
        infos.push(deviceToInfo(device));
        continue;
      }
      this.deviceCache.set(device.id, device);
      infos.push(deviceToInfo(device));
    }

    return infos;
  }

  async getDeviceInfo(deviceId: string): Promise<DeviceInfo> {
    let device = this.deviceCache.get(deviceId);
    if (!device) {
      device = await this.fridaManager.getDeviceById(deviceId, 5000);
      this.deviceCache.set(device.id, device);
    }
    return await deviceToDetailedInfo(device);
  }

  async getDevice(deviceId: string): Promise<frida.Device> {
    let device = this.deviceCache.get(deviceId);
    if (!device) {
      device = await this.fridaManager.getDeviceById(deviceId, 5000);
      this.deviceCache.set(device.id, device);
    }
    return device;
  }

  async detectPlatform(device: frida.Device): Promise<'android' | 'ios' | 'linux' | 'macos' | 'windows' | 'unknown'> {
    try {
      const params = await device.querySystemParameters();
      const platform = params.platform as string;
      if (['android', 'ios', 'linux', 'macos', 'windows'].includes(platform)) {
        return platform as 'android' | 'ios' | 'linux' | 'macos' | 'windows';
      }
    } catch {
      log('debug', 'Could not detect platform from system parameters');
    }
    return 'unknown';
  }
}
