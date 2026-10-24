/**
 * `get_app_info`: identify the exact installed artifact of an app.
 *
 * Gives an agent the APK paths, sizes and sha256 of what is actually installed (and, with
 * `pull_to`, verified host copies), so a static tool such as REA `inspect_android_package`
 * analyses the same APK that is running and an evidence report can state what was analysed.
 *
 * Frida's `enumerateApplications({ scope: 'full' })` works on Android and iOS. On Android the
 * tool additionally runs a FIXED set of adb commands (`pm path`, `dumpsys package`,
 * `sha256sum`, `stat`); no user-controlled shell string reaches the device: the package name
 * is regex-validated and the APK paths from `pm path` are allow-list validated before reuse.
 * The parsers are pure and exported so they are unit-tested without a device.
 */
import { createHash } from 'node:crypto';
import { createReadStream, promises as fs } from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import type frida from 'frida';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { toolOutputSchema } from '../helpers/output-schema.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../helpers/errors.js';
import { responseFormatSchema } from '../constants.js';
import { getState } from '../state.js';
import { createAdbContext, defaultAdbDeps, isSafeShellWord, runAdb, type AdbContext, type AdbExecDeps } from '../helpers/adb.js';
import { adbPull } from './advanced/adb.js';
import { resolveDumpOutputPath } from './advanced/native.js';
import type { SuggestedAction } from '../types.js';

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/** Android package / iOS bundle id: dot-separated identifiers, at least two segments. */
export const PACKAGE_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/;

export function assertPackageName(target: string): string {
  if (!PACKAGE_NAME_PATTERN.test(target)) {
    throw new FridaMcpError(
      'INVALID_ARGUMENT',
      `target "${target}" is not a valid package name / bundle id (expected e.g. "com.example.app").`,
      [{ tool: 'list_applications', reason: 'List installed applications and their identifiers' }],
      { target },
    );
  }
  return target;
}

/**
 * Device paths from `pm path` are re-used in device-side commands, so they must be absolute
 * shell-safe words (`/data/app/~~x==/pkg-y==/base.apk`) without traversal. Android 11+ APK
 * directories start with `~~`; a `~` directly after a `/` is never tilde-expanded (only a
 * word-leading one is), so those runs are allowed here while isSafeShellWord rejects `~`.
 */
export function isSafeDevicePath(devicePath: string): boolean {
  if (!devicePath.startsWith('/') || devicePath.includes('..')) return false;
  return isSafeShellWord(devicePath.replace(/\/~+/g, '/'));
}

// ---------------------------------------------------------------------------
// Pure parsers
// ---------------------------------------------------------------------------

/** `pm path <pkg>` -> APK paths (base + splits), `package:` prefix stripped. */
export function parsePmPath(out: string): string[] {
  return out
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith('package:'))
    .map((line) => line.slice('package:'.length).trim())
    .filter((p) => p.length > 0);
}

export interface DumpsysPackageInfo {
  version_name?: string;
  version_code?: number;
  target_sdk?: number;
  min_sdk?: number;
  debuggable?: boolean;
  primary_cpu_abi?: string;
  native_lib_dir?: string;
  data_dir?: string;
  installer?: string;
  last_update_time?: string;
}

/** `dumpsys package <pkg>` -> the fields of the first `Package [..]` block (all optional). */
export function parseDumpsysPackage(out: string): DumpsysPackageInfo {
  const block = firstPackageBlock(out);
  const info: DumpsysPackageInfo = {
    version_name: matchValue(block, /^\s*versionName=(.+)$/m),
    version_code: matchNumber(block, /\bversionCode=(\d+)/),
    target_sdk: matchNumber(block, /\btargetSdk=(\d+)/),
    min_sdk: matchNumber(block, /\bminSdk=(\d+)/),
    debuggable: parseDebuggable(block),
    primary_cpu_abi: matchValue(block, /\bprimaryCpuAbi=(\S+)/),
    native_lib_dir: matchValue(block, /\b(?:legacyNativeLibraryDir|nativeLibraryDir|nativeLibraryPath)=(\S+)/),
    data_dir: matchValue(block, /\bdataDir=(\S+)/),
    installer: matchValue(block, /\binstallerPackageName=(\S+)/),
    last_update_time: matchValue(block, /\blastUpdateTime=(.+)$/m),
  };
  return dropUndefined(info);
}

/** `sha256sum <paths>` -> path -> lowercase hex digest. */
export function parseSha256sum(out: string): Record<string, string> {
  const hashes: Record<string, string> = {};
  for (const line of out.split(/\r?\n/)) {
    const match = /^([0-9a-fA-F]{64})\s+\*?(\S.*)$/.exec(line.trim());
    if (match) hashes[match[2].trim()] = match[1].toLowerCase();
  }
  return hashes;
}

/** `stat -c '%s %n' <paths>` -> path -> size in bytes. */
export function parseStatSizes(out: string): Record<string, number> {
  const sizes: Record<string, number> = {};
  for (const line of out.split(/\r?\n/)) {
    const match = /^(\d+)\s+(\S.*)$/.exec(line.trim());
    if (match) sizes[match[2].trim()] = Number.parseInt(match[1], 10);
  }
  return sizes;
}

function firstPackageBlock(out: string): string {
  const lines = out.split(/\r?\n/);
  const start = lines.findIndex((line) => /^\s*Package \[/.test(line));
  if (start < 0) return out;
  const indent = lines[start].search(/\S/);
  const end = lines.findIndex((line, i) => i > start && line.trim().length > 0 && line.search(/\S/) <= indent);
  return lines.slice(start, end < 0 ? undefined : end).join('\n');
}

function parseDebuggable(block: string): boolean | undefined {
  const flagLists = [...block.matchAll(/\b(?:flags|pkgFlags)=\[([^\]]*)\]/g)].map((m) => m[1]);
  if (flagLists.length === 0) return undefined;
  return flagLists.some((flags) => /\bDEBUGGABLE\b/.test(flags));
}

function matchValue(text: string, pattern: RegExp): string | undefined {
  const value = pattern.exec(text)?.[1]?.trim();
  return value && value !== 'null' ? value : undefined;
}

function matchNumber(text: string, pattern: RegExp): number | undefined {
  const value = matchValue(text, pattern);
  return value === undefined ? undefined : Number.parseInt(value, 10);
}

function dropUndefined<T extends object>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as T;
}

// ---------------------------------------------------------------------------
// Frida side
// ---------------------------------------------------------------------------

/** Frida's full-scope parameters minus the icon blobs, as plain JSON (BigInt -> number/string). */
export function sanitizeFridaParameters(params: Record<string, unknown> | undefined): Record<string, unknown> {
  if (!params) return {};
  const { icons: _icons, ...rest } = params;
  return JSON.parse(JSON.stringify(rest, jsonSafeValue)) as Record<string, unknown>;
}

function jsonSafeValue(_key: string, value: unknown): unknown {
  if (Buffer.isBuffer(value)) return undefined;
  if (typeof value === 'bigint') return Number.isSafeInteger(Number(value)) ? Number(value) : value.toString();
  return value;
}

async function queryFridaApplication(device: frida.Device, target: string): Promise<frida.Application | undefined> {
  const apps = await device.enumerateApplications({ identifiers: [target], scope: 'full' as frida.Scope });
  return apps.find((app) => app.identifier === target) ?? apps[0];
}

/** Artifact paths Frida reports when no on-device shell is available. */
function fridaArtifactPaths(params: Record<string, unknown>): string[] {
  const sources = params.sources;
  if (Array.isArray(sources) && sources.every((s) => typeof s === 'string')) return sources as string[];
  return typeof params.path === 'string' ? [params.path] : [];
}

// ---------------------------------------------------------------------------
// Android (adb) side
// ---------------------------------------------------------------------------

export interface Artifact {
  path: string;
  sha256?: string;
  size?: number;
}

export interface AndroidPackageFacts {
  artifacts: Artifact[];
  dumpsys: DumpsysPackageInfo;
  limitations: string[];
}

async function shell(ctx: AdbContext, args: string[]): Promise<string> {
  const result = await runAdb(ctx.deps, ctx.adbPath, ['shell', ...args], { serial: ctx.serial, timeoutMs: 30_000 });
  return result.stdout;
}

/** Run the fixed adb command set (independent queries in parallel) and combine paths, hashes and sizes. */
export async function collectAndroidFacts(ctx: AdbContext, pkg: string): Promise<AndroidPackageFacts> {
  const limitations: string[] = [];
  const [pmPathOut, dumpsysOut] = await Promise.all([shell(ctx, ['pm', 'path', pkg]), shell(ctx, ['dumpsys', 'package', pkg])]);
  const listed = parsePmPath(pmPathOut);
  const paths = listed.filter(isSafeDevicePath);
  const rejected = listed.filter((p) => !isSafeDevicePath(p));
  if (rejected.length > 0) {
    limitations.push(`Ignored ${rejected.length} APK path(s) from pm path with unexpected characters: ${rejected.map((p) => JSON.stringify(p)).join(', ')}`);
  }
  const dumpsys = parseDumpsysPackage(dumpsysOut);
  if (paths.length === 0) return { artifacts: [], dumpsys, limitations };
  const [sha256Out, statOut] = await Promise.all([shell(ctx, ['sha256sum', ...paths]), shell(ctx, ['stat', '-c', "'%s %n'", ...paths])]);
  const hashes = parseSha256sum(sha256Out);
  const sizes = parseStatSizes(statOut);
  const artifacts = paths.map((p) => dropUndefined({ path: p, sha256: hashes[p], size: sizes[p] }));
  return { artifacts, dumpsys, limitations };
}

// ---------------------------------------------------------------------------
// Pull + host-side verification
// ---------------------------------------------------------------------------

export interface PulledArtifact {
  device_path: string;
  host_path: string;
  sha256: string;
  verified: boolean;
}

function sha256File(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    createReadStream(filePath)
      .on('data', (chunk) => hash.update(chunk))
      .on('error', reject)
      .on('end', () => resolve(hash.digest('hex')));
  });
}

/**
 * Pull every artifact into `<dir>/<identifier>/` (sequentially, adb serialises transfers anyway)
 * and cross-check host vs device sha256; the host hashes run while the next pull is in flight.
 */
export async function pullArtifacts(
  ctx: AdbContext,
  artifacts: Artifact[],
  dir: string,
  identifier: string,
): Promise<{ pulled: PulledArtifact[]; limitations: string[] }> {
  const targetDir = path.join(dir, identifier);
  await fs.mkdir(targetDir, { recursive: true });
  const hashing: Array<Promise<PulledArtifact>> = [];
  const limitations: string[] = [];
  for (const artifact of artifacts) {
    const hostPath = path.join(targetDir, path.posix.basename(artifact.path));
    const result = await adbPull(ctx, artifact.path, hostPath);
    if (result.code !== 0) {
      limitations.push(`adb pull of ${artifact.path} failed: ${result.stderr.trim() || 'unknown error'}`);
      continue;
    }
    hashing.push(verifyPulled(artifact, hostPath, limitations));
  }
  return { pulled: await Promise.all(hashing), limitations };
}

async function verifyPulled(artifact: Artifact, hostPath: string, limitations: string[]): Promise<PulledArtifact> {
  const sha256 = await sha256File(hostPath);
  const verified = artifact.sha256 !== undefined && artifact.sha256 === sha256;
  if (!verified) limitations.push(verificationLimitation(artifact, sha256));
  return { device_path: artifact.path, host_path: hostPath, sha256, verified };
}

function verificationLimitation(artifact: Artifact, hostSha256: string): string {
  return artifact.sha256
    ? `sha256 mismatch for ${artifact.path}: device ${artifact.sha256}, host ${hostSha256}`
    : `${artifact.path} could not be verified: no device-side sha256`;
}

// ---------------------------------------------------------------------------
// Result assembly
// ---------------------------------------------------------------------------

export interface AppInfoResult extends Omit<DumpsysPackageInfo, 'version_code'> {
  identifier: string;
  name?: string;
  platform: string;
  version_name?: string;
  version_code?: number | string;
  artifacts: Artifact[];
  pulled?: PulledArtifact[];
  frida_parameters: Record<string, unknown>;
}

const STATIC_HANDOFF_REASON =
  'feed the pulled base.apk to a static tool such as REA inspect_android_package or jadx; hashes let a report state which artifact was analysed';

function suggestNext(info: AppInfoResult, device: string | undefined): SuggestedAction[] {
  const base = info.artifacts.find((a) => a.path.endsWith('/base.apk')) ?? info.artifacts[0];
  if (info.platform !== 'android' || !base) return [];
  const pulledBase = info.pulled?.find((p) => p.device_path === base.path);
  if (pulledBase) {
    return [{ tool: 'inspect_android_package', args: { path: pulledBase.host_path }, reason: STATIC_HANDOFF_REASON, condition: 'a static-analysis MCP server such as REA is connected', priority: 'optional' }];
  }
  return [
    { tool: 'get_app_info', args: { target: info.identifier, ...(device ? { device } : {}), pull_to: '<host directory>' }, reason: `Pull and hash-verify the installed APKs, then ${STATIC_HANDOFF_REASON}` },
    { tool: 'adb_pull', args: { remote_path: base.path, local_path: '<host path>/base.apk' }, reason: STATIC_HANDOFF_REASON },
  ];
}

function isComplete(info: AppInfoResult, limitations: string[]): boolean {
  return limitations.length === 0
    && info.artifacts.length > 0
    && info.artifacts.every((a) => a.sha256 !== undefined && a.size !== undefined);
}

// ---------------------------------------------------------------------------
// Tool
// ---------------------------------------------------------------------------

interface GatherInput {
  target: string;
  device?: string;
  pull_to?: string;
}

async function resolveFridaDevice(deviceManager: DeviceManager, requested: string | undefined): Promise<frida.Device> {
  if (requested) return deviceManager.resolve({ deviceId: requested });
  return getState().selectedDevice ?? deviceManager.resolve();
}

/** The adb serial for a Frida device: the USB Frida id equals the adb serial. */
async function adbContextFor(deps: AdbExecDeps, device: frida.Device): Promise<AdbContext> {
  if (device.type !== 'usb') {
    throw new FridaMcpError('PLATFORM_UNSUPPORTED', `Frida device "${device.id}" is not a USB device, so it has no matching adb serial`);
  }
  return createAdbContext(deps, device.id, getState().config.allowedDevices);
}

async function gatherAppInfo(
  deviceManager: DeviceManager,
  deps: AdbExecDeps,
  input: GatherInput,
): Promise<{ info: AppInfoResult; limitations: string[] }> {
  const target = assertPackageName(input.target);
  const pullDir = input.pull_to !== undefined ? resolveDumpOutputPath(input.pull_to) : undefined;
  const device = await resolveFridaDevice(deviceManager, input.device);
  const platform = await deviceManager.detectPlatform(device);
  const app = await queryFridaApplication(device, target);
  const fridaParameters = sanitizeFridaParameters(app?.parameters);
  const limitations: string[] = [];

  let android: AndroidPackageFacts | undefined;
  let ctx: AdbContext | undefined;
  if (platform === 'android') {
    try {
      ctx = await adbContextFor(deps, device);
      android = await collectAndroidFacts(ctx, target);
      limitations.push(...android.limitations);
    } catch (err) {
      if (err instanceof FridaMcpError && err.code === 'DEVICE_NOT_ALLOWED') throw err;
      limitations.push(`sha256/size unavailable: adb query failed (${err instanceof Error ? err.message : String(err)})`);
    }
  } else {
    limitations.push('sha256/size unavailable: no on-device shell for this platform');
  }

  const artifacts = android && android.artifacts.length > 0
    ? android.artifacts
    : fridaArtifactPaths(fridaParameters).map((p) => ({ path: p }));
  if (!app && artifacts.length === 0) {
    throw new FridaMcpError('PROCESS_NOT_FOUND', `App "${target}" is not installed on device "${device.id}".`, [
      { tool: 'list_applications', reason: 'List installed applications and their identifiers' },
    ], { target });
  }

  const dumpsys = android?.dumpsys ?? {};
  const info: AppInfoResult = dropUndefined({
    identifier: target,
    name: app?.name,
    platform,
    ...dumpsys,
    version_name: dumpsys.version_name ?? stringParam(fridaParameters.version),
    version_code: dumpsys.version_code ?? stringParam(fridaParameters.build),
    artifacts,
    frida_parameters: fridaParameters,
  }) as AppInfoResult;

  if (pullDir !== undefined) {
    if (!ctx) {
      limitations.push('pull_to ignored: pulling artifacts needs adb (Android USB device)');
    } else {
      const pulled = await pullArtifacts(ctx, artifacts, pullDir, target);
      info.pulled = pulled.pulled;
      limitations.push(...pulled.limitations);
    }
  }
  return { info, limitations };
}

function stringParam(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

export function registerAppInfoTool(server: McpServer, deviceManager: DeviceManager, deps: AdbExecDeps = defaultAdbDeps()): void {
  server.registerTool(
    'get_app_info',
    {
      title: 'Get App Info',
      description:
        'Identify the exact installed artifact of an app: version, SDK levels, debuggable flag, installer, data/native-lib dirs and every APK (base + splits) with on-device sha256 and size (Android via fixed adb queries: pm path, dumpsys package, sha256sum, stat). With pull_to, pulls the APKs to the host and verifies their sha256 against the device. Use it to hand the same APK that runs to a static tool (REA inspect_android_package, jadx) and to record in a report which artifact was analysed. iOS returns the Frida application parameters without hashes.',
      inputSchema: z.object({
        target: z.string().describe('Package name / bundle id, e.g. "com.example.app"'),
        device: z.string().optional().describe('Device ID'),
        pull_to: z.string().optional().describe('Absolute host directory to pull the APKs into (under cwd, the temp dir or ~/.config/frida-mobile-mcp/dumps); files land in <pull_to>/<target>/'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ target, device, pull_to, response_format }) => {
      try {
        const { info, limitations } = await gatherAppInfo(deviceManager, deps, { target, device, pull_to });
        const coverage = isComplete(info, limitations) ? { status: 'complete' as const } : { status: 'unknown' as const };
        return formatToolResponse(buildResult(info, suggestNext(info, device), { limitations, coverage }), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    },
  );
}
