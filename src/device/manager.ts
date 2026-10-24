import frida from 'frida';
import { readFileSync } from 'node:fs';
import type { DeviceInfo, FridaMcpConfig } from '../types.js';
import {
  resolveDevice,
  deviceToInfo,
  deviceToDetailedInfo,
  toRemoteDeviceOptions,
  type RemoteAuthOptions,
  type ResolveOptions,
} from './resolver.js';
import { DeviceNotFoundError, FridaMcpError } from '../helpers/errors.js';
import { log } from '../helpers/logger.js';
import { getState } from '../state.js';

const DEVICE_LOOKUP_TIMEOUT_MS = 5000;

export class DeviceManager {
  private fridaManager: frida.DeviceManager;
  private config: FridaMcpConfig;
  private deviceCache: Map<string, frida.Device> = new Map();

  constructor(fridaManager: frida.DeviceManager, config: FridaMcpConfig) {
    this.fridaManager = fridaManager;
    this.config = config;
  }

  async resolve(options?: ResolveOptions): Promise<frida.Device> {
    const device = await resolveDevice(this.fridaManager, withLoadedCertificate(options));
    this.assertAllowed(device.id);
    return this.remember(device);
  }

  /**
   * Register a remote frida-server (`host[:port]`), optionally with its auth token and TLS
   * certificate (a PEM file path), then apply the same allowlist check as `resolve()`.
   */
  async addRemoteDevice(address: string, options: RemoteAuthOptions = {}): Promise<frida.Device> {
    const device = await this.fridaManager.addRemoteDevice(address, toRemoteDeviceOptions(withLoadedCertificate(options)));
    this.assertAllowed(device.id);
    return this.remember(device);
  }

  /** Throws when an allowlist is configured and the device is not on it. */
  private assertAllowed(deviceId: string): void {
    if (this.config.allowedDevices.length > 0 && !this.config.allowedDevices.includes(deviceId)) {
      throw new DeviceNotFoundError(deviceId, this.config.allowedDevices);
    }
  }

  private remember(device: frida.Device): frida.Device {
    this.deviceCache.set(device.id, device);
    watchCrashes(device);
    return device;
  }

  /** Look a device up by id with a bounded wait; a timeout surfaces as DeviceNotFoundError. */
  private async lookupDevice(deviceId: string): Promise<frida.Device> {
    try {
      return await this.fridaManager.getDeviceById(deviceId, DEVICE_LOOKUP_TIMEOUT_MS);
    } catch (err) {
      log('debug', `getDeviceById(${deviceId}) failed: ${String(err)}`);
      throw new DeviceNotFoundError(deviceId, await this.listKnownDeviceIds());
    }
  }

  private async listKnownDeviceIds(): Promise<string[]> {
    try {
      const devices = await this.fridaManager.enumerateDevices();
      return devices.map((d) => d.id);
    } catch {
      return Array.from(this.deviceCache.keys());
    }
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
    const device = await this.getDevice(deviceId);
    return await deviceToDetailedInfo(device);
  }

  async getDevice(deviceId: string): Promise<frida.Device> {
    this.assertAllowed(deviceId);
    const cached = this.deviceCache.get(deviceId);
    if (cached) return cached;
    return this.remember(await this.lookupDevice(deviceId));
  }

  async detectPlatform(device: frida.Device): Promise<'android' | 'ios' | 'linux' | 'macos' | 'windows' | 'unknown'> {
    const cached = platformCache.get(device.id);
    if (cached) return cached;
    let platform: 'android' | 'ios' | 'linux' | 'macos' | 'windows' | 'unknown' = 'unknown';
    try {
      const params = await device.querySystemParameters();
      platform = platformFromSystemParameters(params);
    } catch {
      log('debug', 'Could not detect platform from system parameters');
    }
    if (platform !== 'unknown') {
      platformCache.set(device.id, platform);
      try { getState().setDevicePlatform(device.id, platform); } catch { /* state not initialised */ }
    }
    return platform;
  }
}

/**
 * Register a remote frida-server for the running server (startup `--remote` / FRIDA_MCP_REMOTE).
 * `state.deviceManager` is the raw frida manager, so this goes through the wrapper to get the
 * certificate loading and the `allowedDevices` check that the tools apply.
 */
export function addRemoteDeviceForState(
  state: { deviceManager: frida.DeviceManager; config: FridaMcpConfig },
  address: string,
  auth: RemoteAuthOptions = {}
): Promise<frida.Device> {
  return new DeviceManager(state.deviceManager, state.config).addRemoteDevice(address, auth);
}

/**
 * Read a certificate given as a file path into PEM text. frida accepts either, but reading it
 * here turns a missing/unreadable file into a clear INVALID_ARGUMENT instead of a TLS error.
 * Values that already contain a newline are treated as PEM text and passed through.
 */
export function loadRemoteCertificate(certificate: string | undefined): string | undefined {
  if (!certificate || certificate.includes('\n')) return certificate;
  try {
    return readFileSync(certificate, 'utf-8');
  } catch (err) {
    throw new FridaMcpError(
      'INVALID_ARGUMENT',
      `Cannot read remote frida-server certificate "${certificate}": ${(err as Error).message}`,
      [],
      { certificate },
      { remediation: 'Pass the path of the PEM certificate frida-server was started with (--certificate).' }
    );
  }
}

function withLoadedCertificate<T extends { certificate?: string }>(options: T | undefined): T | undefined {
  if (!options?.certificate) return options;
  return { ...options, certificate: loadRemoteCertificate(options.certificate) };
}

const platformCache = new Map<string, 'android' | 'ios' | 'linux' | 'macos' | 'windows'>();

/**
 * Frida reports Android as `platform: "linux"` with `os.id: "android"`, and iOS as
 * `platform: "darwin"` with `os.id: "ios"`, so the OS id must win over the kernel platform.
 */
export function platformFromSystemParameters(params: Record<string, unknown>): 'android' | 'ios' | 'linux' | 'macos' | 'windows' | 'unknown' {
  const os = params.os as { id?: string } | undefined;
  const osId = typeof os?.id === 'string' ? os.id.toLowerCase() : '';
  if (osId === 'android') return 'android';
  if (osId === 'ios' || osId === 'ipados' || osId === 'tvos' || osId === 'watchos') return 'ios';
  if (osId === 'macos') return 'macos';
  if (osId === 'windows') return 'windows';
  if (osId === 'linux') return 'linux';
  const platform = typeof params.platform === 'string' ? params.platform : '';
  if (platform === 'darwin') return 'macos';
  if (['android', 'ios', 'linux', 'macos', 'windows'].includes(platform)) {
    return platform as 'android' | 'ios' | 'linux' | 'macos' | 'windows';
  }
  return 'unknown';
}

/** Subscribe to crash events for the device (state de-duplicates per device id). */
function watchCrashes(device: frida.Device): void {
  try {
    getState().watchDeviceCrashes(device);
  } catch {
    // State is not initialised in some unit tests; crash tracking is optional there.
  }
}
