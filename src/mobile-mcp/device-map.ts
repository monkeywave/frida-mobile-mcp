import frida from 'frida';
import { log } from '../helpers/logger.js';

interface DeviceMapping {
  fridaId: string;
  mobileMcpId: string;
  platform: 'android' | 'ios';
  lastUpdated: number;
}

const deviceMappings: Map<string, DeviceMapping> = new Map();
const CACHE_TTL_MS = 30_000; // 30 seconds

export async function resolveMobileDeviceId(fridaDevice: frida.Device): Promise<string | null> {
  // Check cache
  const cached = deviceMappings.get(fridaDevice.id);
  if (cached && Date.now() - cached.lastUpdated < CACHE_TTL_MS) {
    return cached.mobileMcpId;
  }

  // For USB and remote devices, the Frida ID typically matches the ADB serial / iOS UDID
  // which is also what mobile-mcp uses
  try {
    const params = await fridaDevice.querySystemParameters();
    const platform = params.platform as string;

    let mobileMcpId: string;

    if (platform === 'android') {
      // Android: Frida device ID = ADB serial
      mobileMcpId = fridaDevice.id;
    } else if (platform === 'ios') {
      // iOS: Use UDID from system parameters or device ID
      mobileMcpId = (params.udid as string) || fridaDevice.id;
    } else {
      // Non-mobile device - no mobile-mcp equivalent
      return null;
    }

    const mapping: DeviceMapping = {
      fridaId: fridaDevice.id,
      mobileMcpId,
      platform: platform as 'android' | 'ios',
      lastUpdated: Date.now(),
    };
    deviceMappings.set(fridaDevice.id, mapping);

    log('debug', `Device mapping: Frida ${fridaDevice.id} -> mobile-mcp ${mobileMcpId}`);
    return mobileMcpId;
  } catch (err) {
    log('debug', `Could not resolve mobile device ID for ${fridaDevice.id}: ${err}`);
    // Fallback: assume IDs match
    return fridaDevice.id;
  }
}

export function clearDeviceCache(): void {
  deviceMappings.clear();
}
