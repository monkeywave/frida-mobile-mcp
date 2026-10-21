import { getMobileMcpProxy } from './proxy.js';
import { resolveMobileDeviceId } from './device-resolve.js';

/**
 * Call a mobile-mcp action, resolving and injecting the device so UI actions target the right
 * one. mobile-mcp names emulators by AVD, not adb serial, so the frida device id is translated
 * via device-resolve. An explicit `params.device` always wins; the gap is only filled in. Shared
 * by mobile_action and trigger_and_wait so the resolve→merge→call sequence lives in one place.
 */
export async function callMobileAction(
  action: string,
  params: Record<string, unknown> | undefined,
  fridaDeviceId: string | undefined,
): Promise<unknown> {
  const proxy = await getMobileMcpProxy();
  const deviceId = await resolveMobileDeviceId(fridaDeviceId);
  const merged: Record<string, unknown> = { ...(params ?? {}) };
  if (deviceId && merged.device === undefined) merged.device = deviceId;
  return proxy.callTool(action, merged);
}
