/**
 * frida-server lifecycle tools (Android, via adb): status / install / start / stop.
 *
 * These complement `doctor` (which only *detects* frida-server) so an agent can provision and
 * control the device-side server without dropping to a shell. All device effects go through the
 * injectable adb primitives in `src/helpers/adb.ts`, and the command-planning functions are pure
 * and exported so the behaviour is unit-tested without a device.
 *
 * Deliberately dependency-free: frida-server release assets are `.xz` and Node has no xz
 * decoder, so `install` pushes a binary the user already fetched/decompressed, and `status`
 * reports the device ABI plus the exact GitHub asset URL to download for that ABI/version.
 */
import { existsSync } from 'node:fs';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/server';
import { toolOutputSchema } from '../../helpers/output-schema.js';
import { buildResult, formatToolResponse } from '../../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../../helpers/errors.js';
import { responseFormatSchema } from '../../constants.js';
import { getState } from '../../state.js';
import { readFridaNodeVersion } from '../../cli/doctor.js';
import {
  assertSafeShellWord,
  isSafeShellWord,
  createAdbContext,
  defaultAdbDeps,
  runAdb,
  type AdbContext,
  type AdbExecDeps,
  type ExecResult,
} from '../../helpers/adb.js';

const DEFAULT_REMOTE_PATH = '/data/local/tmp/frida-server';
const DEFAULT_PROCESS_NAME = 'frida-server';
const DEFAULT_PORT = 27042;
const DEFAULT_LISTEN = '127.0.0.1';
/** frida-server can take a moment to daemonize; give the follow-up status check headroom. */
const START_SETTLE_MS = 1500;

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested without a device)
// ---------------------------------------------------------------------------

/**
 * Shell-safe token guard for non-secret values (remote path, process name, listen address,
 * extra arg): device-side commands are joined into one `sh -c` string by adb, so they must be
 * free of shell metacharacters. The error echoes the value; use `assertSafeShellWord` for secrets.
 */
export function assertSafeToken(value: string, label: string): string {
  if (!isSafeShellWord(value)) {
    throw new FridaMcpError('INVALID_ARGUMENT', `${label} "${value}" contains characters that are not allowed in a device-side command.`);
  }
  return value;
}

/** Replace the value after `--token` so a start command can be reported without the secret. */
export function redactTokenArg(command: string, token: string | undefined): string {
  return token ? command.split(`--token ${token}`).join('--token ***') : command;
}

/** Map an Android `ro.product.cpu.abi` value to the frida-server release arch suffix. */
export function abiToFridaArch(abi: string): string | null {
  switch (abi.trim()) {
    case 'arm64-v8a':
      return 'arm64';
    case 'armeabi-v7a':
    case 'armeabi':
      return 'arm';
    case 'x86_64':
      return 'x86_64';
    case 'x86':
      return 'x86';
    default:
      return null;
  }
}

/** GitHub release asset URL for a given frida version + frida arch (e.g. v17.2.1, arm64). */
export function fridaServerAssetUrl(version: string, arch: string): string {
  const tag = version.startsWith('v') ? version : `v${version}`;
  const bare = tag.slice(1);
  return `https://github.com/frida/frida/releases/download/${tag}/frida-server-${bare}-android-${arch}.xz`;
}

/** Build the device-side command that launches frida-server detached (`-D` daemonizes). */
export function buildStartCommand(opts: {
  remotePath: string;
  listenAddress: string;
  port: number;
  extraArgs: string[];
  useSu: boolean;
  /** Auth token clients must present (`frida-server --token`). */
  token?: string;
}): string {
  assertSafeToken(opts.remotePath, 'remote_path');
  assertSafeToken(opts.listenAddress, 'listen_address');
  for (const arg of opts.extraArgs) assertSafeToken(arg, 'extra_args entry');
  const tokenArgs = opts.token ? ['--token', assertSafeShellWord(opts.token, 'token')] : [];
  const argv = [opts.remotePath, '-l', `${opts.listenAddress}:${opts.port}`, '-D', ...tokenArgs, ...opts.extraArgs].join(' ');
  return opts.useSu ? `su -c '${argv}'` : argv;
}

/** Build the device-side command that stops frida-server by name. */
export function buildStopCommand(opts: { processName: string; signal: string; useSu: boolean }): string {
  assertSafeToken(opts.processName, 'process_name');
  assertSafeToken(opts.signal, 'signal');
  const kill = `pkill -${opts.signal} -f ${selfExcludingPattern(opts.processName)}`;
  return opts.useSu ? `su -c '${kill}'` : kill;
}

/**
 * Turn a process name into a `pgrep -f`/`pkill -f` regex that cannot match the matcher's own
 * `sh -c '... <name> ...'` wrapper: wrapping the first character in a one-char class means the
 * literal pattern text (which appears verbatim in the wrapper's cmdline) no longer matches the
 * regex, while a real `<name>` process still does. The classic `grep [f]oo` self-exclusion trick.
 * `name` is assumed already validated by `assertSafeToken` (its first char is a safe token char).
 */
export function selfExcludingPattern(name: string): string {
  return `[${name[0]}]${name.slice(1)}`;
}

/** Parse whitespace/newline-separated PIDs from `pgrep`/`pidof` output. */
export function parsePids(stdout: string): number[] {
  return stdout
    .split(/\s+/)
    .map((token) => Number.parseInt(token, 10))
    .filter((pid) => Number.isInteger(pid) && pid > 0);
}

// ---------------------------------------------------------------------------
// Device operations (take resolved deps + serial; never throw for exec failures)
// ---------------------------------------------------------------------------

/** @deprecated alias kept for callers/tests; the shared shape lives in helpers/adb.ts. */
export type ServerOpContext = AdbContext;

async function shell(ctx: ServerOpContext, command: string, timeoutMs?: number): Promise<ExecResult> {
  return runAdb(ctx.deps, ctx.adbPath, ['shell', command], { serial: ctx.serial, timeoutMs });
}

export async function readDeviceAbi(ctx: ServerOpContext): Promise<string> {
  const out = await shell(ctx, 'getprop ro.product.cpu.abi');
  return out.stdout.trim();
}

export async function findServerPids(ctx: ServerOpContext, processName: string): Promise<number[]> {
  assertSafeToken(processName, 'process_name');
  const out = await shell(ctx, `pgrep -f ${selfExcludingPattern(processName)}`);
  return parsePids(out.stdout);
}

export interface ServerStatus {
  running: boolean;
  pids: number[];
  processName: string;
  port: number;
  deviceAbi: string;
  fridaArch: string | null;
  fridaNodeVersion: string | null;
  suggestedAssetUrl: string | null;
}

export async function fridaServerStatus(
  ctx: ServerOpContext,
  params: { processName: string; port: number },
): Promise<ServerStatus> {
  // The pid scan and the ABI read are independent adb round-trips; run them together.
  const [pids, deviceAbi] = await Promise.all([findServerPids(ctx, params.processName), readDeviceAbi(ctx)]);
  const fridaArch = abiToFridaArch(deviceAbi);
  const fridaNodeVersion = readFridaNodeVersion();
  const suggestedAssetUrl =
    fridaArch && fridaNodeVersion ? fridaServerAssetUrl(fridaNodeVersion, fridaArch) : null;
  return {
    running: pids.length > 0,
    pids,
    processName: params.processName,
    port: params.port,
    deviceAbi,
    fridaArch,
    fridaNodeVersion,
    suggestedAssetUrl,
  };
}

export async function fridaServerInstall(
  ctx: ServerOpContext,
  params: { binaryPath: string; remotePath: string; overwrite: boolean },
): Promise<{ remotePath: string; pushed: boolean }> {
  assertSafeToken(params.remotePath, 'remote_path');
  if (!existsSync(params.binaryPath)) {
    throw new FridaMcpError('INVALID_ARGUMENT', `binary_path "${params.binaryPath}" does not exist. Download and decompress the frida-server .xz for the device ABI first (see frida_server_status).`);
  }
  if (!params.overwrite) {
    const existing = await shell(ctx, `[ -e ${params.remotePath} ] && echo EXISTS || true`);
    if (existing.stdout.includes('EXISTS')) {
      throw new FridaMcpError('INVALID_ARGUMENT', `${params.remotePath} already exists on the device. Pass overwrite=true to replace it.`);
    }
  }
  const push = await runAdb(ctx.deps, ctx.adbPath, ['push', params.binaryPath, params.remotePath], {
    serial: ctx.serial,
    timeoutMs: 60_000,
  });
  if (push.code !== 0) {
    throw new FridaMcpError('FRIDA_ERROR', `adb push failed: ${push.stderr.trim() || 'unknown error'}`);
  }
  const chmod = await shell(ctx, `chmod 755 ${params.remotePath}`);
  if (chmod.code !== 0) {
    throw new FridaMcpError('FRIDA_ERROR', `chmod of ${params.remotePath} failed: ${chmod.stderr.trim() || 'unknown error'}`);
  }
  return { remotePath: params.remotePath, pushed: true };
}

export async function fridaServerStart(
  ctx: ServerOpContext,
  params: { remotePath: string; listenAddress: string; port: number; extraArgs: string[]; useSu: boolean; processName: string; token?: string },
  sleep: (ms: number) => Promise<void> = defaultSleep,
): Promise<{ started: boolean; pids: number[]; command: string }> {
  const command = buildStartCommand(params);
  // Launch in the background so the blocking daemon does not hold the adb shell open.
  await shell(ctx, `${command} >/dev/null 2>&1 &`, 10_000);
  await sleep(START_SETTLE_MS);
  const pids = await findServerPids(ctx, params.processName);
  if (pids.length === 0) {
    throw new FridaMcpError('FRIDA_ERROR', `frida-server did not come up after start. Check that ${params.remotePath} exists and the device is rooted (useSu=${params.useSu}).`);
  }
  return { started: true, pids, command: redactTokenArg(command, params.token) };
}

export async function fridaServerStop(
  ctx: ServerOpContext,
  params: { processName: string; signal: string; useSu: boolean },
): Promise<{ stopped: boolean; remaining: number[] }> {
  const command = buildStopCommand(params);
  await shell(ctx, command);
  const remaining = await findServerPids(ctx, params.processName);
  return { stopped: remaining.length === 0, remaining };
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

const deviceParam = z.string().optional().describe('adb device serial (as in `adb devices`). Uses the sole attached device when omitted.');

export function registerFridaServerTools(server: McpServer, deps: AdbExecDeps = defaultAdbDeps()): void {
  const context = (requested: string | undefined): Promise<ServerOpContext> =>
    createAdbContext(deps, requested, getState().config.allowedDevices);

  server.registerTool(
    'frida_server_status',
    {
      title: 'frida-server Status',
      description: 'Report whether frida-server is running on an Android device (via adb): its PIDs, the device CPU ABI, the matching frida release arch, and the exact GitHub .xz asset URL to download for the installed frida-node version.',
      inputSchema: z.object({
        device: deviceParam,
        process_name: z.string().default(DEFAULT_PROCESS_NAME).describe('frida-server process name to look for.'),
        port: z.number().int().default(DEFAULT_PORT).describe('Port frida-server is expected to listen on (informational).'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ device, process_name, port, response_format }) => {
      try {
        const status = await fridaServerStatus(await context(device), { processName: process_name, port });
        return formatToolResponse(buildResult({ status }, status.running
          ? [{ tool: 'explore_app', reason: 'frida-server is up; start analysing an app' }]
          : [{ tool: 'frida_server_start', reason: 'Start frida-server on the device' }]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    },
  );

  server.registerTool(
    'frida_server_install',
    {
      title: 'Install frida-server',
      description: 'Push a local frida-server binary to an Android device and make it executable (adb push + chmod 755). Download and decompress the correct .xz for the device ABI first (frida_server_status gives the asset URL).',
      inputSchema: z.object({
        binary_path: z.string().describe('Path on this host to the decompressed frida-server binary to push.'),
        device: deviceParam,
        remote_path: z.string().default(DEFAULT_REMOTE_PATH).describe('Destination path on the device.'),
        overwrite: z.boolean().default(false).describe('Replace an existing file at remote_path.'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    async ({ binary_path, device, remote_path, overwrite, response_format }) => {
      try {
        const result = await fridaServerInstall(await context(device), { binaryPath: binary_path, remotePath: remote_path, overwrite });
        return formatToolResponse(buildResult({ install: result }, [
          { tool: 'frida_server_start', reason: 'Start the server you just installed' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    },
  );

  server.registerTool(
    'frida_server_start',
    {
      title: 'Start frida-server',
      description: 'Start frida-server detached on an Android device (adb shell, daemonized with -D), optionally via su. Supports a custom listen address/port and a renamed binary path for stealth setups, then confirms the server came up.',
      inputSchema: z.object({
        device: deviceParam,
        remote_path: z.string().default(DEFAULT_REMOTE_PATH).describe('Path to the frida-server binary on the device.'),
        process_name: z.string().default(DEFAULT_PROCESS_NAME).describe('Process name to confirm after start (match the binary name for renamed servers).'),
        listen_address: z.string().default(DEFAULT_LISTEN).describe('Address to bind. 127.0.0.1 keeps it off the network; 0.0.0.0 exposes it.'),
        port: z.number().int().default(DEFAULT_PORT).describe('Port to listen on (use a non-default port to evade :27042 scans).'),
        use_su: z.boolean().default(true).describe('Launch via `su -c` (needed on production-rooted devices; set false on userdebug/emulator adb-root).'),
        extra_args: z.array(z.string()).default([]).describe('Additional frida-server CLI arguments.'),
        token: z.string().optional().describe('Require this auth token from clients (frida-server --token). Recommended with listen_address 0.0.0.0; connect with select_device token / FRIDA_MCP_REMOTE_TOKEN. Redacted in the result.'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    async ({ device, remote_path, process_name, listen_address, port, use_su, extra_args, token, response_format }) => {
      try {
        const result = await fridaServerStart(await context(device), {
          remotePath: remote_path,
          listenAddress: listen_address,
          port,
          extraArgs: extra_args,
          useSu: use_su,
          processName: process_name,
          token,
        });
        return formatToolResponse(buildResult({ start: result }, [
          { tool: 'list_devices', reason: 'Confirm Frida now sees the device' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    },
  );

  server.registerTool(
    'frida_server_stop',
    {
      title: 'Stop frida-server',
      description: 'Stop frida-server on an Android device by sending a signal to the matching process (adb shell pkill, optionally via su), then report any remaining PIDs.',
      inputSchema: z.object({
        device: deviceParam,
        process_name: z.string().default(DEFAULT_PROCESS_NAME).describe('Process name to stop.'),
        signal: z.string().default('TERM').describe('Signal to send (e.g. TERM, KILL).'),
        use_su: z.boolean().default(true).describe('Send the signal via `su -c`.'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    async ({ device, process_name, signal, use_su, response_format }) => {
      try {
        const result = await fridaServerStop(await context(device), { processName: process_name, signal, useSu: use_su });
        return formatToolResponse(buildResult({ stop: result }, []), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    },
  );
}
