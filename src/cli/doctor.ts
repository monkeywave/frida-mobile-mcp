/**
 * `frida-mobile-mcp doctor` - environment diagnostics.
 *
 * Every external effect (frida binding, child processes, filesystem, config) is injected
 * through `DoctorDeps` so the checks can be unit-tested without a device. Only `runDoctor`
 * writes to stdout; everything else returns data.
 */
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import path from 'node:path';
import { areBridgesBuilt } from '../agent/bridges.js';
import { loadConfig } from '../config.js';
import { exec, parseAdbDevices, which, type AdbDevice, type ExecResult } from '../helpers/adb.js';

// Re-exported so existing importers of these from `./doctor.js` keep working; the single
// implementation now lives in `src/helpers/adb.ts`.
export { exec, parseAdbDevices, which };
export type { AdbDevice, ExecResult };

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type CheckStatus = 'ok' | 'warn' | 'fail' | 'skip';

export interface CheckResult {
  name: string;
  status: CheckStatus;
  detail: string;
  required: boolean;
}

export interface DoctorConfigSummary {
  allowCustomScripts: boolean;
  memoryWriteEnabled: boolean;
  allowedDevices: string[];
}

export interface DoctorDeps {
  nodeVersion: string;
  platform: NodeJS.Platform;
  loadFrida: () => Promise<typeof import('frida')>;
  fridaNodeVersion: () => string | null;
  which: (bin: string) => Promise<string | null>;
  exec: (cmd: string, args: string[], timeoutMs: number) => Promise<ExecResult>;
  areBridgesBuilt: () => boolean;
  configPath: string;
  configExists: (p: string) => boolean;
  loadConfig: () => DoctorConfigSummary;
  timeoutMs: number;
}

/** Minimal structural view of a frida device; `typeof import('frida')` satisfies it. */
export interface DoctorDevice {
  id: string;
  name: string;
  type: string;
  querySystemParameters(): Promise<DoctorSystemParameters>;
  enumerateProcesses(): Promise<unknown[]>;
}

export interface DoctorSystemParameters {
  os: { id: string; version?: string };
  arch: string;
}

interface DoctorFrida {
  getDeviceManager(): unknown;
  enumerateDevices(): Promise<DoctorDevice[]>;
}

const DEFAULT_TIMEOUT_MS = 5000;
/** Oldest supported Node.js release (keep in step with `engines.node` in package.json). */
const MIN_NODE_VERSION = '22.12';

// ---------------------------------------------------------------------------
// Default dependencies (real side effects live here only)
// ---------------------------------------------------------------------------

export function defaultDoctorDeps(): DoctorDeps {
  return {
    nodeVersion: process.version,
    platform: process.platform,
    loadFrida: () => import('frida'),
    fridaNodeVersion: readFridaNodeVersion,
    which,
    exec,
    areBridgesBuilt,
    configPath: path.join(homedir(), '.config', 'frida-mobile-mcp', 'config.json'),
    configExists: existsSync,
    loadConfig: summarizeConfig,
    timeoutMs: DEFAULT_TIMEOUT_MS,
  };
}

/**
 * `frida/package.json` is not in the package exports map, so resolve the entry point
 * (`build/src/frida.js`) and walk up to the package root instead.
 */
export function readFridaNodeVersion(): string | null {
  try {
    const require = createRequire(import.meta.url);
    const entry = require.resolve('frida');
    const manifestPath = path.join(path.dirname(entry), '..', '..', 'package.json');
    const manifest = require(manifestPath) as { version?: string };
    return manifest.version ?? null;
  } catch {
    return null;
  }
}

function summarizeConfig(): DoctorConfigSummary {
  const config = loadConfig();
  return {
    allowCustomScripts: config.allowCustomScripts,
    memoryWriteEnabled: config.memoryWriteEnabled,
    allowedDevices: config.allowedDevices,
  };
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

export function parseNodeMajor(version: string): number {
  const match = /^v?(\d+)/.exec(version.trim());
  return match ? Number(match[1]) : NaN;
}

/** Parse `vMAJOR.MINOR.PATCH` (or a `MAJOR[.MINOR]` minimum) into `[major, minor]`; NaN when unparsable. */
export function parseNodeMajorMinor(version: string): [number, number] {
  const match = /^v?(\d+)(?:\.(\d+))?/.exec(version.trim());
  return match ? [Number(match[1]), Number(match[2] ?? 0)] : [NaN, NaN];
}

function isAtLeast(version: string, minimum: string): boolean {
  const [major, minor] = parseNodeMajorMinor(version);
  const [minMajor, minMinor] = parseNodeMajorMinor(minimum);
  if (!Number.isFinite(major)) return false;
  return major > minMajor || (major === minMajor && minor >= minMinor);
}

export function checkNodeVersion(version: string, minimum = MIN_NODE_VERSION): CheckResult {
  const ok = isAtLeast(version, minimum);
  return {
    name: 'Node.js version',
    status: ok ? 'ok' : 'fail',
    detail: ok ? `${version} (>= ${minimum} required)` : `${version} is too old, Node.js >= ${minimum} is required`,
    required: true,
  };
}

/** Translate a raw frida error into an actionable hint. */
export function classifyFridaError(message: string, fridaNodeVersion: string | null): string {
  const text = message.toLowerCase();
  const serverVersion = fridaNodeVersion ?? 'the same version as frida-node';
  const majorHint = fridaNodeVersion ? `major version ${parseNodeMajor(fridaNodeVersion)}` : 'the same major version';

  if (text.includes('unable to connect to remote frida-server') || text.includes('connection refused')) {
    return `frida-server is not running or not forwarded. Start it via \`adb shell\` using ${majorHint} (frida-node is ${serverVersion}).`;
  }
  if (text.includes('version mismatch') || text.includes('incompatible') || text.includes('protocol') || text.includes('unexpected')) {
    return `frida-server version must match frida-node ${serverVersion}. (${message})`;
  }
  if (text.includes('timed out') || text.includes('timeout')) {
    return `Device did not answer in time; it may be busy or the USB connection is unstable. (${message})`;
  }
  if (text.includes('permission denied')) {
    return `Permission denied; run frida-server as root on the device. (${message})`;
  }
  return message;
}

/** Reject with a labelled error when `promise` does not settle within `ms`. */
export function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms} ms`)), ms);
    timer.unref?.();
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

export async function checkNativeBinding(deps: DoctorDeps): Promise<{ result: CheckResult; frida: DoctorFrida | null }> {
  const name = 'frida native binding';
  const version = deps.fridaNodeVersion() ?? 'unknown version';
  try {
    const frida = (await deps.loadFrida()) as unknown as DoctorFrida;
    if (!frida.getDeviceManager()) throw new Error('getDeviceManager() returned nothing');
    return { result: { name, status: 'ok', detail: `frida-node ${version} loaded`, required: true }, frida };
  } catch (error) {
    const detail = `frida-node ${version} failed to load: ${errorMessage(error)}. Try \`npm rebuild frida\`.`;
    return { result: { name, status: 'fail', detail, required: true }, frida: null };
  }
}

export async function checkAdb(deps: DoctorDeps): Promise<CheckResult> {
  const name = 'adb';
  const adbPath = await deps.which('adb');
  if (!adbPath) {
    return { name, status: 'warn', detail: 'not found on PATH - Android device checks unavailable', required: false };
  }
  const output = await deps.exec(adbPath, ['devices'], deps.timeoutMs);
  if (output.code !== 0) {
    return { name, status: 'warn', detail: `${adbPath}: \`adb devices\` failed: ${output.stderr.trim() || 'unknown error'}`, required: false };
  }
  return describeAdbDevices(name, adbPath, parseAdbDevices(output.stdout));
}

function describeAdbDevices(name: string, adbPath: string, devices: AdbDevice[]): CheckResult {
  if (devices.length === 0) {
    return { name, status: 'warn', detail: `${adbPath}: no devices listed by \`adb devices\``, required: false };
  }
  const unhealthy = devices.filter((device) => device.state !== 'device');
  const listing = devices.map((device) => `${device.id} (${device.state})`).join(', ');
  const hint = unhealthy.length > 0 ? ' - accept the USB debugging prompt or reconnect the device' : '';
  return { name, status: unhealthy.length > 0 ? 'warn' : 'ok', detail: `${listing}${hint}`, required: false };
}

export async function checkFridaDevices(
  frida: DoctorFrida | null,
  deps: DoctorDeps,
): Promise<{ result: CheckResult; devices: DoctorDevice[] }> {
  const name = 'Frida devices';
  if (!frida) {
    return { result: { name, status: 'skip', detail: 'skipped - frida native binding unavailable', required: true }, devices: [] };
  }
  try {
    const devices = await withTimeout(frida.enumerateDevices(), deps.timeoutMs, 'enumerateDevices');
    return { result: { name, status: 'ok', detail: describeDeviceList(devices), required: true }, devices };
  } catch (error) {
    return { result: { name, status: 'fail', detail: errorMessage(error), required: true }, devices: [] };
  }
}

function describeDeviceList(devices: DoctorDevice[]): string {
  const remote = devices.filter((device) => device.type !== 'local');
  const hasLocal = devices.some((device) => device.type === 'local');
  const listing = remote.length > 0 ? remote.map((device) => `${device.id} [${device.type}]`).join(', ') : 'no remote or USB devices';
  return hasLocal ? `${listing} (plus local system)` : listing;
}

export async function checkUsbDevices(devices: DoctorDevice[], deps: DoctorDeps): Promise<CheckResult[]> {
  const usbDevices = devices.filter((device) => device.type === 'usb');
  if (usbDevices.length === 0) {
    return [{ name: 'USB device', status: 'warn', detail: 'no USB device attached', required: false }];
  }
  return Promise.all(usbDevices.map((device) => checkUsbDevice(device, deps)));
}

export async function checkUsbDevice(device: DoctorDevice, deps: DoctorDeps): Promise<CheckResult> {
  const name = `USB device ${device.id}`;
  try {
    const params = await withTimeout(device.querySystemParameters(), deps.timeoutMs, `${device.id} querySystemParameters`);
    const processes = await withTimeout(device.enumerateProcesses(), deps.timeoutMs, `${device.id} enumerateProcesses`);
    const detail = `${params.os.id} ${params.os.version ?? ''} ${params.arch}, ${processes.length} processes`.replace(/\s+/g, ' ');
    return { name, status: 'ok', detail, required: false };
  } catch (error) {
    return { name, status: 'warn', detail: classifyFridaError(errorMessage(error), deps.fridaNodeVersion()), required: false };
  }
}

export function checkBridges(deps: DoctorDeps): CheckResult {
  const built = deps.areBridgesBuilt();
  return {
    name: 'Bridge bundles',
    status: built ? 'ok' : 'fail',
    detail: built ? 'java and objc bridges built' : 'missing - run `npm run build:bridges`',
    required: true,
  };
}

export async function checkFritap(deps: DoctorDeps): Promise<CheckResult> {
  const fritapPath = await deps.which('fritap');
  return {
    name: 'fritap',
    status: fritapPath ? 'ok' : 'warn',
    detail: fritapPath ?? 'not found - fritap tools unavailable',
    required: false,
  };
}

export function checkConfig(deps: DoctorDeps): CheckResult {
  const source = deps.configExists(deps.configPath) ? deps.configPath : `defaults (no file at ${deps.configPath})`;
  const config = deps.loadConfig();
  const devices = config.allowedDevices.length > 0 ? config.allowedDevices.join(', ') : 'any';
  return {
    name: 'Config',
    status: 'ok',
    detail: `${source}; allowCustomScripts=${config.allowCustomScripts} memoryWriteEnabled=${config.memoryWriteEnabled} allowedDevices=${devices}`,
    required: false,
  };
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/** Run a check so that a thrown error becomes a 'fail' result instead of aborting the run. */
async function guarded<T>(name: string, required: boolean, run: () => Promise<T> | T, onError: (result: CheckResult) => T): Promise<T> {
  try {
    return await run();
  } catch (error) {
    return onError({ name, status: 'fail', detail: errorMessage(error), required });
  }
}

function guardedResult(name: string, required: boolean, run: () => Promise<CheckResult> | CheckResult): Promise<CheckResult> {
  return guarded(name, required, run, (result) => result);
}

export async function runDoctorChecks(overrides: Partial<DoctorDeps> = {}): Promise<CheckResult[]> {
  const deps: DoctorDeps = { ...defaultDoctorDeps(), ...overrides };
  const results: CheckResult[] = [];

  results.push(await guardedResult('Node.js version', true, () => checkNodeVersion(deps.nodeVersion)));

  const binding = await guarded('frida native binding', true, () => checkNativeBinding(deps), (result) => ({ result, frida: null }));
  results.push(binding.result);

  results.push(await guardedResult('adb', false, () => checkAdb(deps)));

  const enumeration = await guarded('Frida devices', true, () => checkFridaDevices(binding.frida, deps), (result) => ({ result, devices: [] }));
  results.push(enumeration.result);

  results.push(...(await guarded('USB device', false, () => checkUsbDevices(enumeration.devices, deps), (result) => [result])));
  results.push(await guardedResult('Bridge bundles', true, () => checkBridges(deps)));
  results.push(await guardedResult('fritap', false, () => checkFritap(deps)));
  results.push(await guardedResult('Config', false, () => checkConfig(deps)));

  return results;
}

// ---------------------------------------------------------------------------
// Presentation
// ---------------------------------------------------------------------------

const STATUS_LABELS: Record<CheckStatus, string> = { ok: 'OK', warn: 'WARN', fail: 'FAIL', skip: 'SKIP' };

export function formatDoctorTable(results: CheckResult[]): string {
  const statusWidth = Math.max('STATUS'.length, ...Object.values(STATUS_LABELS).map((label) => label.length));
  const nameWidth = Math.max('CHECK'.length, ...results.map((result) => result.name.length));
  const header = `${'STATUS'.padEnd(statusWidth)} | ${'CHECK'.padEnd(nameWidth)} | DETAIL`;
  const separator = `${'-'.repeat(statusWidth)}-+-${'-'.repeat(nameWidth)}-+-${'-'.repeat('DETAIL'.length)}`;
  const rows = results.map(
    (result) => `${STATUS_LABELS[result.status].padEnd(statusWidth)} | ${result.name.padEnd(nameWidth)} | ${result.detail}`,
  );
  return [header, separator, ...rows, '', summarizeResults(results)].join('\n');
}

function summarizeResults(results: CheckResult[]): string {
  const count = (status: CheckStatus) => results.filter((result) => result.status === status).length;
  const counts = `${count('ok')} ok, ${count('warn')} warn, ${count('fail')} fail, ${count('skip')} skip`;
  const verdict = doctorExitCode(results) === 0 ? 'ready' : 'required checks failed';
  return `Summary: ${counts} - ${verdict}`;
}

export function doctorExitCode(results: CheckResult[]): number {
  return results.some((result) => result.required && result.status === 'fail') ? 1 : 0;
}

export async function runDoctor(deps: Partial<DoctorDeps> = {}): Promise<number> {
  const results = await runDoctorChecks(deps);
  console.log(formatDoctorTable(results));
  return doctorExitCode(results);
}
