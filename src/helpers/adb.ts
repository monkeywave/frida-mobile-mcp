/**
 * Shared ADB / process-exec primitives.
 *
 * These are the never-throwing `execFile` wrapper, the dependency-free `which`, and the
 * `adb devices` parser. They originated in `src/cli/doctor.ts`; they live here so every
 * consumer (doctor, the frida-server lifecycle tools, the raw adb tools) shares one
 * implementation. Every function is pure or side-effect-isolated so callers can inject a
 * fake `exec`/`which` in unit tests without a device.
 */
import { execFile } from 'node:child_process';
import { statSync } from 'node:fs';
import path from 'node:path';
import { FridaMcpError } from './errors.js';

/** Result of running a child process. Resolves on every outcome; `code` is null when unknown. */
export interface ExecResult {
  stdout: string;
  stderr: string;
  code: number | null;
}

/** A single entry from `adb devices`. */
export interface AdbDevice {
  id: string;
  state: string;
}

/** Shape of the two injectable primitives the adb-backed tools depend on. */
export interface AdbExecDeps {
  which: (bin: string) => Promise<string | null>;
  exec: (cmd: string, args: string[], timeoutMs: number) => Promise<ExecResult>;
}

/** Default adb command timeout (ms). `logcat` and other streaming calls override this. */
export const DEFAULT_ADB_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------
// Process execution
// ---------------------------------------------------------------------------

/** `execFile` wrapper that resolves on every outcome (never throws). */
export function exec(cmd: string, args: string[], timeoutMs: number): Promise<ExecResult> {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: timeoutMs, windowsHide: true, maxBuffer: 64 * 1024 * 1024 }, (error, stdout, stderr) => {
      const code = error ? extractExitCode(error) : 0;
      const errorText = error && !stderr ? error.message : '';
      resolve({ stdout: String(stdout), stderr: String(stderr) || errorText, code });
    });
  });
}

function extractExitCode(error: unknown): number | null {
  const code = (error as { code?: unknown }).code;
  return typeof code === 'number' ? code : null;
}

// ---------------------------------------------------------------------------
// PATH lookup
// ---------------------------------------------------------------------------

/** Locate an executable on PATH without external dependencies. */
export async function which(bin: string): Promise<string | null> {
  const dirs = (process.env.PATH ?? '').split(path.delimiter).filter(Boolean);
  for (const dir of dirs) {
    for (const candidate of candidateNames(bin)) {
      const full = path.join(dir, candidate);
      if (isExecutableFile(full)) return full;
    }
  }
  return null;
}

function candidateNames(bin: string): string[] {
  if (process.platform !== 'win32') return [bin];
  const extensions = (process.env.PATHEXT ?? '.EXE;.CMD;.BAT;.COM').split(';').filter(Boolean);
  const hasExtension = extensions.some((ext) => bin.toLowerCase().endsWith(ext.toLowerCase()));
  return hasExtension ? [bin] : [bin, ...extensions.map((ext) => bin + ext)];
}

function isExecutableFile(filePath: string): boolean {
  try {
    return statSync(filePath).isFile();
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// adb devices parsing
// ---------------------------------------------------------------------------

/** Parse `adb devices` output into `{ id, state }` entries, skipping the header line. */
export function parseAdbDevices(stdout: string): AdbDevice[] {
  return stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('List of devices') && !line.startsWith('*'))
    .map(parseAdbDeviceLine)
    .filter((device): device is AdbDevice => device !== null);
}

function parseAdbDeviceLine(line: string): AdbDevice | null {
  const [id, state] = line.split(/\s+/);
  if (!id || !state) return null;
  return { id, state };
}

// ---------------------------------------------------------------------------
// adb invocation convenience
// ---------------------------------------------------------------------------

/**
 * Run an adb subcommand, optionally scoped to a device serial via `-s`. Resolves on every
 * outcome (never throws); inspect `result.code`. Serial validation against an allowlist is
 * the caller's responsibility (`resolveAllowedSerial`).
 */
export async function runAdb(
  deps: AdbExecDeps,
  adbPath: string,
  args: string[],
  options: { serial?: string; timeoutMs?: number } = {},
): Promise<ExecResult> {
  const prefix = options.serial ? ['-s', options.serial] : [];
  return deps.exec(adbPath, [...prefix, ...args], options.timeoutMs ?? DEFAULT_ADB_TIMEOUT_MS);
}

/** Locate adb or throw a DEVICE_NOT_FOUND FridaMcpError with an actionable hint. */
export async function requireAdbPath(deps: AdbExecDeps): Promise<string> {
  const adbPath = await deps.which('adb');
  if (!adbPath) {
    throw new FridaMcpError('DEVICE_NOT_FOUND', 'adb was not found on PATH; install the Android platform-tools and ensure `adb` is runnable.');
  }
  return adbPath;
}

/**
 * Resolve the adb device serial to act on and enforce the `allowedDevices` allowlist.
 *
 * - When `requested` is given it must be a connected, healthy (`device` state) serial.
 * - When omitted, resolves to the sole healthy device, or errors if zero/many are attached.
 * - When `allowedDevices` is non-empty the resolved serial must appear in it, otherwise a
 *   `DEVICE_NOT_ALLOWED` error is thrown (mirrors the frida-side allowlist guardrail).
 */
export async function resolveAllowedSerial(
  deps: AdbExecDeps,
  adbPath: string,
  requested: string | undefined,
  allowedDevices: string[],
): Promise<string> {
  const listing = await runAdb(deps, adbPath, ['devices']);
  if (listing.code !== 0) {
    throw new FridaMcpError('DEVICE_NOT_FOUND', `\`adb devices\` failed: ${listing.stderr.trim() || 'unknown error'}`);
  }
  const devices = parseAdbDevices(listing.stdout);
  const healthy = devices.filter((d) => d.state === 'device');

  let serial: string;
  if (requested) {
    const match = devices.find((d) => d.id === requested);
    if (!match) {
      throw new FridaMcpError('DEVICE_NOT_FOUND', `adb device "${requested}" is not connected. Attached: ${describeDevices(devices)}.`);
    }
    if (match.state !== 'device') {
      throw new FridaMcpError('DEVICE_NOT_FOUND', `adb device "${requested}" is in state "${match.state}", not ready. Accept the USB debugging prompt or reconnect.`);
    }
    serial = requested;
  } else if (healthy.length === 1) {
    serial = healthy[0].id;
  } else if (healthy.length === 0) {
    throw new FridaMcpError('DEVICE_NOT_FOUND', 'no ready adb device is attached. Connect a device and accept the USB debugging prompt.');
  } else {
    throw new FridaMcpError('INVALID_ARGUMENT', `multiple adb devices attached (${describeDevices(healthy)}); specify which with the device parameter.`);
  }

  if (allowedDevices.length > 0 && !allowedDevices.includes(serial)) {
    throw new FridaMcpError('DEVICE_NOT_ALLOWED', `adb device "${serial}" is not in the configured allowedDevices allowlist (${allowedDevices.join(', ')}).`);
  }
  return serial;
}

/** Default adb primitives (real `which`/`exec`); tool modules inject fakes in tests. */
export function defaultAdbDeps(): AdbExecDeps {
  return { which, exec };
}

/** Resolved context an adb-backed tool operates in: the deps, the adb binary, and the serial. */
export interface AdbContext {
  deps: AdbExecDeps;
  adbPath: string;
  serial: string;
}

/**
 * Resolve the adb binary and the (allowlist-checked) device serial for a tool call. Shared by
 * every adb-backed tool so locating adb and enforcing `allowedDevices` happen in exactly one place.
 */
export async function createAdbContext(
  deps: AdbExecDeps,
  requested: string | undefined,
  allowedDevices: string[],
): Promise<AdbContext> {
  const adbPath = await requireAdbPath(deps);
  const serial = await resolveAllowedSerial(deps, adbPath, requested, allowedDevices);
  return { deps, adbPath, serial };
}

function describeDevices(devices: AdbDevice[]): string {
  return devices.length > 0 ? devices.map((d) => `${d.id} (${d.state})`).join(', ') : 'none';
}
