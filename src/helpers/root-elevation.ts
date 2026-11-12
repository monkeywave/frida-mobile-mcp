/**
 * Root elevation for device-side adb shell commands.
 *
 * Android devices expose root in incompatible ways, so a hard-coded `su -c '<cmd>'` only works on
 * Magisk/SuperSU. Ported from fkie-cad/AndroidFridaManager (`ADB.find` + RootADB/MagiskADB/SuADB):
 *
 * - `none`   — adbd already runs as root (`adb root` on userdebug/emulator images): no wrapping.
 * - `magisk` — Magisk/SuperSU `su`: `su -c '<cmd>'`.
 * - `legacy` — AOSP/emulator `su` (takes a uid, not `-c`): `su 0 sh -c '<cmd>'`.
 */
import { runAdb, type AdbContext } from './adb.js';

export type SuStyle = 'none' | 'magisk' | 'legacy';

/** Each probe is a quick one-liner; a hanging `su` (e.g. waiting on a grant prompt) must not stall the tool. */
const PROBE_TIMEOUT_MS = 5_000;

/** Detected styles per device serial. Only successful detections are cached, so `adb root` later is picked up. */
const suStyleCache = new Map<string, SuStyle>();

/** Quote `value` as one single-quoted POSIX shell word (`'` becomes `'\''`). */
export function shellSingleQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** Wrap a device-side command so it runs as root using the given su style. */
export function wrapWithSu(cmd: string, style: SuStyle): string {
  switch (style) {
    case 'none':
      return cmd;
    case 'magisk':
      return `su -c ${shellSingleQuote(cmd)}`;
    case 'legacy':
      return `su 0 sh -c ${shellSingleQuote(cmd)}`;
  }
}

/** Run one probe; any failure (non-zero exit, timeout, exec error) counts as "no". */
async function probe(ctx: AdbContext, command: string): Promise<string | null> {
  try {
    const out = await runAdb(ctx.deps, ctx.adbPath, ['shell', command], { serial: ctx.serial, timeoutMs: PROBE_TIMEOUT_MS });
    return out.code === 0 ? out.stdout.trim() : null;
  } catch {
    return null;
  }
}

/** Probe the device in AndroidFridaManager order: adbd root, Magisk `su -v`, legacy `su 0`. */
async function probeSuStyle(ctx: AdbContext): Promise<SuStyle | null> {
  if ((await probe(ctx, 'id -u')) === '0') return 'none';
  if (await probe(ctx, 'su -v')) return 'magisk';
  if ((await probe(ctx, 'su 0 id -u')) === '0') return 'legacy';
  return null;
}

/** Detect (and cache per serial) how to obtain root on the device; null when the device is not rooted. */
export async function detectSuStyle(ctx: AdbContext): Promise<SuStyle | null> {
  const cached = suStyleCache.get(ctx.serial);
  if (cached) return cached;
  const style = await probeSuStyle(ctx);
  if (style) suStyleCache.set(ctx.serial, style);
  return style;
}

/** Forget cached detections (all devices, or one serial). Used by tests and after a device re-roots. */
export function clearSuStyleCache(serial?: string): void {
  if (serial === undefined) suStyleCache.clear();
  else suStyleCache.delete(serial);
}
