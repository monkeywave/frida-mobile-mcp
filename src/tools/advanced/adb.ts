/**
 * Raw ADB convenience tools (Android): shell / logcat / pull / push / forward.
 *
 * These let an agent correlate instrumentation with device state (logcat), move files, and set
 * up port forwards without leaving the MCP surface. All device effects go through the injectable
 * adb primitives in `src/helpers/adb.ts`; `adb_shell` is arbitrary command execution and is gated
 * behind the `allowAdbShell` config flag (default false). Every call enforces `allowedDevices`.
 */
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/server';
import { toolOutputSchema } from '../../helpers/output-schema.js';
import { buildResult, formatToolResponse } from '../../helpers/result-builder.js';
import { AdbShellDisabledError, FridaMcpError, wrapFridaError } from '../../helpers/errors.js';
import { responseFormatSchema } from '../../constants.js';
import { getState } from '../../state.js';
import {
  createAdbContext,
  defaultAdbDeps,
  runAdb,
  DEFAULT_ADB_TIMEOUT_MS,
  type AdbContext,
  type AdbExecDeps,
  type ExecResult,
} from '../../helpers/adb.js';

const LOGCAT_TIMEOUT_MS = 20_000;
const DEFAULT_LOGCAT_LINES = 200;

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/** Build the `adb logcat` argv for a bounded, one-shot dump. */
export function buildLogcatArgs(opts: { lines: number; filters: string[]; clear: boolean }): string[] {
  if (opts.clear) return ['logcat', '-c'];
  // `-d` dumps and exits; `-t N` limits to the last N lines (implies -d).
  return ['logcat', '-t', String(opts.lines), ...opts.filters];
}

// ---------------------------------------------------------------------------
// Device operations
// ---------------------------------------------------------------------------

/** @deprecated alias kept for callers/tests; the shared shape lives in helpers/adb.ts. */
export type AdbOpContext = AdbContext;

export async function adbShell(ctx: AdbOpContext, command: string, timeoutMs: number): Promise<ExecResult> {
  return runAdb(ctx.deps, ctx.adbPath, ['shell', command], { serial: ctx.serial, timeoutMs });
}

export async function adbLogcat(ctx: AdbOpContext, opts: { lines: number; filters: string[]; clear: boolean }): Promise<ExecResult> {
  return runAdb(ctx.deps, ctx.adbPath, buildLogcatArgs(opts), { serial: ctx.serial, timeoutMs: LOGCAT_TIMEOUT_MS });
}

export async function adbPull(ctx: AdbOpContext, remotePath: string, localPath: string): Promise<ExecResult> {
  return runAdb(ctx.deps, ctx.adbPath, ['pull', remotePath, localPath], { serial: ctx.serial, timeoutMs: 60_000 });
}

export async function adbPush(ctx: AdbOpContext, localPath: string, remotePath: string): Promise<ExecResult> {
  return runAdb(ctx.deps, ctx.adbPath, ['push', localPath, remotePath], { serial: ctx.serial, timeoutMs: 60_000 });
}

export async function adbForward(ctx: AdbOpContext, opts: { local?: string; remote?: string; remove?: string; list?: boolean }): Promise<ExecResult> {
  if (opts.list) return runAdb(ctx.deps, ctx.adbPath, ['forward', '--list'], { serial: ctx.serial });
  if (opts.remove) return runAdb(ctx.deps, ctx.adbPath, ['forward', '--remove', opts.remove], { serial: ctx.serial });
  if (!opts.local || !opts.remote) {
    throw new FridaMcpError('INVALID_ARGUMENT', 'adb_forward needs both local and remote (e.g. local="tcp:27042", remote="tcp:27042"), or list=true / remove="tcp:27042".');
  }
  return runAdb(ctx.deps, ctx.adbPath, ['forward', opts.local, opts.remote], { serial: ctx.serial });
}

function envelope(result: ExecResult): { stdout: string; stderr: string; code: number | null; ok: boolean } {
  return { stdout: result.stdout, stderr: result.stderr, code: result.code, ok: result.code === 0 };
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

const deviceParam = z.string().optional().describe('adb device serial (as in `adb devices`). Uses the sole attached device when omitted.');

export function registerAdbTools(server: McpServer, deps: AdbExecDeps = defaultAdbDeps()): void {
  const context = (requested: string | undefined): Promise<AdbOpContext> =>
    createAdbContext(deps, requested, getState().config.allowedDevices);

  server.registerTool(
    'adb_shell',
    {
      title: 'adb shell',
      description: 'Run an arbitrary shell command on an Android device via `adb shell`. DISABLED by default: arbitrary command execution must be enabled with allowAdbShell (config) or FRIDA_MCP_ALLOW_ADB_SHELL=1. Enforces allowedDevices.',
      inputSchema: z.object({
        command: z.string().describe('Shell command to run on the device.'),
        device: deviceParam,
        timeout_ms: z.number().int().positive().default(DEFAULT_ADB_TIMEOUT_MS).describe('Per-command timeout in milliseconds.'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    async ({ command, device, timeout_ms, response_format }) => {
      try {
        if (!getState().config.allowAdbShell) {
          throw new AdbShellDisabledError(
            'adb_shell is disabled. Enable it with allowAdbShell: true in config or FRIDA_MCP_ALLOW_ADB_SHELL=1 (it runs arbitrary commands on the device).',
          );
        }
        const result = await adbShell(await context(device), command, timeout_ms);
        return formatToolResponse(buildResult({ result: envelope(result) }, []), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    },
  );

  server.registerTool(
    'adb_logcat',
    {
      title: 'adb logcat',
      description: 'Dump the last N lines of the Android logcat (one-shot, `adb logcat -t N`), optionally filtered by tag:priority specs, or clear the buffer. Useful for correlating app log output with instrumentation events.',
      inputSchema: z.object({
        device: deviceParam,
        lines: z.number().int().positive().max(5000).default(DEFAULT_LOGCAT_LINES).describe('Number of recent lines to dump.'),
        filters: z.array(z.string()).default([]).describe('logcat filter specs, e.g. ["MyTag:D", "*:S"].'),
        clear: z.boolean().default(false).describe('Clear (flush) the logcat buffer instead of dumping.'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    async ({ device, lines, filters, clear, response_format }) => {
      try {
        const result = await adbLogcat(await context(device), { lines, filters, clear });
        return formatToolResponse(buildResult({ cleared: clear, result: envelope(result) }, []), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    },
  );

  server.registerTool(
    'adb_pull',
    {
      title: 'adb pull',
      description: 'Pull a file from an Android device to the host (`adb pull`). Enforces allowedDevices.',
      inputSchema: z.object({
        remote_path: z.string().describe('Path on the device to pull.'),
        local_path: z.string().describe('Destination path on this host.'),
        device: deviceParam,
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    async ({ remote_path, local_path, device, response_format }) => {
      try {
        const result = await adbPull(await context(device), remote_path, local_path);
        return formatToolResponse(buildResult({ local_path, result: envelope(result) }, []), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    },
  );

  server.registerTool(
    'adb_push',
    {
      title: 'adb push',
      description: 'Push a file from the host to an Android device (`adb push`). Enforces allowedDevices.',
      inputSchema: z.object({
        local_path: z.string().describe('Path on this host to push.'),
        remote_path: z.string().describe('Destination path on the device.'),
        device: deviceParam,
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    async ({ local_path, remote_path, device, response_format }) => {
      try {
        const result = await adbPush(await context(device), local_path, remote_path);
        return formatToolResponse(buildResult({ remote_path, result: envelope(result) }, []), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    },
  );

  server.registerTool(
    'adb_forward',
    {
      title: 'adb forward',
      description: 'Manage adb port forwards (`adb forward`): add a local->remote forward, remove one, or list them. Use it to reach a frida-server on a non-default device port (e.g. local "tcp:27042" -> remote "tcp:12345").',
      inputSchema: z.object({
        local: z.string().optional().describe('Local endpoint, e.g. "tcp:27042".'),
        remote: z.string().optional().describe('Device endpoint, e.g. "tcp:27042".'),
        remove: z.string().optional().describe('Remove the forward with this local endpoint.'),
        list: z.boolean().default(false).describe('List current forwards instead of adding one.'),
        device: deviceParam,
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ local, remote, remove, list, device, response_format }) => {
      try {
        const result = await adbForward(await context(device), { local, remote, remove, list });
        return formatToolResponse(buildResult({ result: envelope(result) }, []), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    },
  );
}
