import frida from 'frida';
import type { DeviceInfo } from '../types.js';
import { DeviceNotFoundError } from '../helpers/errors.js';
import { log } from '../helpers/logger.js';

export interface ResolveOptions {
  deviceId?: string;
  type?: 'usb' | 'local' | 'remote';
  host?: string;
}

export async function resolveDevice(
  deviceManager: frida.DeviceManager,
  options: ResolveOptions = {}
): Promise<frida.Device> {
  // 1. Explicit device ID
  if (options.deviceId) {
    log('debug', `Resolving device by ID: ${options.deviceId}`);
    try {
      return await deviceManager.getDeviceById(options.deviceId, 5000);
    } catch {
      const devices = await deviceManager.enumerateDevices();
      throw new DeviceNotFoundError(
        options.deviceId,
        devices.map((d) => d.id)
      );
    }
  }

  // 2. Explicit type
  if (options.type === 'local') {
    return await frida.getLocalDevice();
  }
  if (options.type === 'remote' && options.host) {
    log('debug', `Resolving remote device: ${options.host}`);
    return await deviceManager.addRemoteDevice(options.host);
  }
  if (options.type === 'usb') {
    return await getUsbDevice(deviceManager);
  }

  // 3. Environment variable
  const envDeviceId = process.env.FRIDA_DEVICE_ID;
  if (envDeviceId) {
    log('debug', `Resolving device from FRIDA_DEVICE_ID: ${envDeviceId}`);
    try {
      return await deviceManager.getDeviceById(envDeviceId, 5000);
    } catch {
      log('warn', `Device from FRIDA_DEVICE_ID not found: ${envDeviceId}`);
    }
  }

  // 4. USB device (most common for mobile)
  try {
    return await getUsbDevice(deviceManager);
  } catch {
    log('debug', 'No USB device found, falling back to local');
  }

  // 5. Local device
  return await frida.getLocalDevice();
}

async function getUsbDevice(deviceManager: frida.DeviceManager): Promise<frida.Device> {
  try {
    return await frida.getUsbDevice({ timeout: 5000 });
  } catch {
    const devices = await deviceManager.enumerateDevices();
    const usbDevices = devices.filter((d) => d.type === 'usb');
    if (usbDevices.length > 0) {
      return usbDevices[0];
    }
    throw new DeviceNotFoundError('usb', devices.map((d) => d.id));
  }
}

export function deviceToInfo(device: frida.Device): DeviceInfo {
  return {
    id: device.id,
    name: device.name,
    type: device.type,
  };
}

export async function deviceToDetailedInfo(device: frida.Device): Promise<DeviceInfo> {
  const info = deviceToInfo(device);
  try {
    const params = await device.querySystemParameters();
    info.platform = params.platform as string | undefined;
    info.os = params.os ? JSON.stringify(params.os) : undefined;
    info.arch = params.arch as string | undefined;
  } catch {
    // System params not available for all device types
  }
  return info;
}
