import { execFile } from 'node:child_process';

/**
 * mobile-mcp identifies Android emulators by their AVD name (e.g. "Pixel_9_Pro_-root"), while
 * frida — and this server's sessions — use the adb serial ("emulator-5556"). Passing the serial
 * to a mobile-mcp tool fails with "Device ... not found". Map the serial to the AVD name via
 * `adb -s <serial> emu avd name`. Physical-device serials and anything we cannot map are returned
 * unchanged (mobile-mcp uses the adb serial directly for physical devices).
 */
const avdNameCache = new Map<string, string>();

export async function resolveMobileDeviceId(fridaDeviceId: string | undefined): Promise<string | undefined> {
  if (!fridaDeviceId) return undefined;
  // Only emulator serials need translating; a physical serial or an already-resolved name passes through.
  if (!/^emulator-\d+$/.test(fridaDeviceId)) return fridaDeviceId;

  const cached = avdNameCache.get(fridaDeviceId);
  if (cached) return cached;

  const name = await adbAvdName(fridaDeviceId);
  const resolved = name ?? fridaDeviceId;
  avdNameCache.set(fridaDeviceId, resolved);
  return resolved;
}

/** Clear the serial→AVD-name cache (tests; also if emulators are recreated). */
export function clearMobileDeviceCache(): void {
  avdNameCache.clear();
}

function adbAvdName(serial: string): Promise<string | null> {
  return new Promise((resolve) => {
    execFile('adb', ['-s', serial, 'emu', 'avd', 'name'], { timeout: 4000, windowsHide: true }, (err, stdout) => {
      if (err || !stdout) {
        resolve(null);
        return;
      }
      // `emu avd name` prints the AVD name on the first line, followed by an "OK" status line.
      const first = stdout
        .split(/\r?\n/)
        .map((line) => line.trim())
        .find((line) => line.length > 0 && line !== 'OK');
      resolve(first ?? null);
    });
  });
}
