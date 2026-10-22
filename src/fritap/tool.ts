/**
 * capture_tls: run the friTap agent inside the target and collect TLS key material and
 * decrypted plaintext without the friTap Python CLI.
 *
 * Flow: locate bundle -> spawn suspended (or attach) -> createAgentScript (passthrough)
 * -> configureFritapAgent (answers the agent's config handshake during load) -> load
 * -> resume -> buffer keylog/datalog records on the session for get_messages.
 */
import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type frida from 'frida';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../helpers/errors.js';
import { validateFilePath, validateProcessTarget } from '../helpers/sanitize.js';
import { audit, log } from '../helpers/logger.js';
import { rateLimiter } from '../helpers/rate-limiter.js';
import { getOrCreateSession, withTimeout } from '../helpers/session-helper.js';
import { responseFormatSchema } from '../constants.js';
import { createAgentScript } from '../agent/script-factory.js';
import { attachScriptLogHandler } from '../helpers/script-sink.js';
import type { SessionEntry } from '../types.js';
import {
  configureFritapAgent,
  gracefulDetachFritap,
  locateFritapAgent,
  readFritapAbiVersion,
  FRITAP_AGENT_ABI_VERSION,
  type LocatedFritapAgent,
} from './agent-loader.js';
import { FritapCapture, type FritapRecord } from './capture.js';

export const FRITAP_SCRIPT_NAME = 'fritap';
const INITIAL_OUTPUT_WAIT_MS = 2_000;
const MAX_INITIAL_MESSAGES = 20;
const MAX_DURATION_SECONDS = 600;

interface ActiveCapture {
  sessionId: string;
  scriptId: string;
  script: frida.Script;
  capture: FritapCapture;
  timer?: NodeJS.Timeout;
}

const activeCaptures = new Map<string, ActiveCapture>();

/** Captures currently running (script id -> capture), for tests and diagnostics. */
export function getActiveFritapCaptures(): ReadonlyMap<string, ActiveCapture> {
  return activeCaptures;
}

export function registerFritapTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'capture_tls',
    {
      title: 'Capture TLS (friTap)',
      description:
        'Capture TLS session keys (NSS key log format) and decrypted plaintext from the target using the friTap agent (OpenSSL/BoringSSL, Conscrypt, NSS, GnuTLS, wolfSSL, mbedTLS, Secure Transport, ...). ' +
        'By default the app is spawned suspended, friTap is loaded, then the app is resumed so early handshakes are caught. ' +
        'Key log lines are written to keylog_path (usable with Wireshark tls.keylog_file) and plaintext records are buffered as fritap_datalog messages for get_messages (requires full_capture). ' +
        'Needs the friTap agent bundle: pip install friTap, FRITAP_AGENT_PATH, or allow_download.',
      inputSchema: z.object({
        target: z.string().describe('App bundle ID, process name, or PID'),
        device: z.string().optional().describe('Device ID'),
        keylog_path: z.string().optional().describe('File to append NSS key log lines to (CLIENT_RANDOM ...). Omitted: keys are only buffered as messages.'),
        pcap_path: z.string().optional().describe('Write decrypted records as a synthetic TCP pcap (implies full_capture). Full pcap of real traffic needs the friTap Python CLI.'),
        spawn: z.boolean().default(true).describe('Spawn the app suspended and resume after friTap is loaded (early hooks). false: attach to the running process.'),
        anti_root: z.boolean().default(false).describe('Install friTap anti-root hooks (Android)'),
        full_capture: z.boolean().default(false).describe('Also capture decrypted plaintext records (fritap_datalog messages), not only keys'),
        duration_seconds: z.number().int().min(0).max(MAX_DURATION_SECONDS).default(0).describe('Stop the capture automatically after N seconds (0 = keep running until stop_instrumentation)'),
        allow_download: z.boolean().default(true).describe('Download the pinned friTap agent from GitHub when it is not installed locally'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async (args) => {
      const { response_format } = args;
      try {
        const result = await runCaptureTls(deviceManager, args);
        return formatToolResponse(result, response_format);
      } catch (err) {
        if (err instanceof FridaMcpError) return formatToolResponse(err.toErrorResponse(), response_format);
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}

interface CaptureTlsArgs {
  target: string;
  device?: string;
  keylog_path?: string;
  pcap_path?: string;
  spawn: boolean;
  anti_root: boolean;
  full_capture: boolean;
  duration_seconds: number;
  allow_download: boolean;
}

async function runCaptureTls(deviceManager: DeviceManager, args: CaptureTlsArgs) {
  validateProcessTarget(args.target);
  if (args.keylog_path) validateFilePath(args.keylog_path);
  if (args.pcap_path) validateFilePath(args.pcap_path);
  const state = getState();
  rateLimiter.check('script', state.config.rateLimits.scriptsPerMinute);
  rateLimiter.record('script');

  const agent = await locateFritapAgent({ allowDownload: args.allow_download });
  const fullCapture = args.full_capture || Boolean(args.pcap_path);

  const resolution = await getOrCreateSession(deviceManager, {
    target: args.target,
    device: args.device,
    forceSpawn: args.spawn,
    resume: false,
  });
  const { sessionEntry, fridaDevice, needsResume } = resolution;

  const capture = new FritapCapture({ keylogPath: args.keylog_path, pcapPath: args.pcap_path });
  const initial: FritapRecord[] = [];
  let script: frida.Script;
  let scriptId: string;
  try {
    script = await createAgentScript(sessionEntry.session, {
      sessionEntry: sessionEntry,
      source: agent.source,
      platform: sessionEntry.platform,
      name: `${FRITAP_SCRIPT_NAME}:${agent.version}`,
      kind: 'generated',
    });
    scriptId = state.generateId();
    registerScript(sessionEntry, scriptId, script);
    const handshake = configureFritapAgent(script, {
      antiRoot: args.anti_root,
      fullCapture,
      keylog: true,
      spawned: needsResume,
    });
    connectMessageSink(sessionEntry, scriptId, script, capture, initial);
    // Keep agent console.* out of stdout (the stdio JSON-RPC channel); the bespoke
    // capture/handshake message protocol above stays as-is.
    attachScriptLogHandler(script, sessionEntry.id, scriptId);
    await script.load();
    log('info', `friTap agent ${agent.version} loaded (handshake: ${handshake.answered.join(',') || 'none'})`);
  } catch (err) {
    capture.close();
    await abortSpawn(fridaDevice, sessionEntry, needsResume);
    throw err;
  }

  const abi = await readFritapAbiVersion(script);
  if (needsResume) {
    await withTimeout((c) => fridaDevice.resume(sessionEntry.pid, c), `resume(${sessionEntry.pid})`);
  }
  trackCapture(sessionEntry.id, scriptId, script, capture, args.duration_seconds);
  await new Promise((resolve) => setTimeout(resolve, INITIAL_OUTPUT_WAIT_MS));

  audit({
    timestamp: new Date().toISOString(),
    sessionId: sessionEntry.id,
    tool: 'capture_tls',
    params: { target: args.target, spawn: args.spawn, anti_root: args.anti_root, full_capture: fullCapture, keylog_path: args.keylog_path, pcap_path: args.pcap_path },
    status: 'success',
  });

  return buildCaptureResult(sessionEntry, scriptId, agent, abi, capture, initial, args, fullCapture);
}

function registerScript(sessionEntry: SessionEntry, scriptId: string, script: frida.Script): void {
  sessionEntry.scripts.set(scriptId, {
    id: scriptId,
    script,
    messages: [],
    name: FRITAP_SCRIPT_NAME,
    persistent: true,
    createdAt: Date.now(),
  });
}

/** Route agent messages into the capture sinks and the session message buffer. */
function connectMessageSink(
  sessionEntry: SessionEntry,
  scriptId: string,
  script: frida.Script,
  capture: FritapCapture,
  initial: FritapRecord[]
): void {
  const state = getState();
  const push = (record: FritapRecord | null): void => {
    if (!record) return;
    if (initial.length < MAX_INITIAL_MESSAGES) initial.push(record);
    state.addMessageToScript(sessionEntry.id, scriptId, {
      timestamp: Date.now(),
      type: record.type,
      payload: record.payload,
      data: null,
    });
  };
  script.message.connect((message: frida.Message, data: Buffer | null) => {
    if (message.type === 'send') {
      push(capture.handleSend(message.payload, data));
    } else if (message.type === 'error') {
      push(capture.handleError(message.description, message.stack));
    }
  });
  script.destroyed.connect(() => finishCapture(scriptId));
}

function trackCapture(sessionId: string, scriptId: string, script: frida.Script, capture: FritapCapture, durationSeconds: number): void {
  const entry: ActiveCapture = { sessionId, scriptId, script, capture };
  if (durationSeconds > 0) {
    entry.timer = setTimeout(() => { void stopFritapCapture(scriptId); }, durationSeconds * 1000);
    entry.timer.unref?.();
  }
  activeCaptures.set(scriptId, entry);
}

/** Release friTap's hooks, unload the script and close the files; safe to call twice. */
export async function stopFritapCapture(scriptId: string): Promise<void> {
  const entry = activeCaptures.get(scriptId);
  if (!entry) return;
  finishCapture(scriptId);
  await gracefulDetachFritap(entry.script);
  try { await entry.script.unload(); } catch { /* already unloaded */ }
  getState().getSession(entry.sessionId)?.scripts.delete(scriptId);
}

function finishCapture(scriptId: string): void {
  const entry = activeCaptures.get(scriptId);
  if (!entry) return;
  if (entry.timer) clearTimeout(entry.timer);
  entry.capture.close();
  activeCaptures.delete(scriptId);
}

/** Never leave a suspended process behind when the agent failed to load. */
async function abortSpawn(device: frida.Device, sessionEntry: SessionEntry, spawned: boolean): Promise<void> {
  try { await getState().removeSession(sessionEntry.id); } catch { /* best-effort */ }
  if (!spawned) return;
  try { await device.kill(sessionEntry.pid); } catch { /* best-effort */ }
}

function buildCaptureResult(
  sessionEntry: SessionEntry,
  scriptId: string,
  agent: LocatedFritapAgent,
  abi: number | null,
  capture: FritapCapture,
  initial: FritapRecord[],
  args: CaptureTlsArgs,
  fullCapture: boolean
) {
  const limitations = describeLimitations(capture, abi, args, fullCapture);
  const hooks = initial
    .filter((r) => r.type === 'fritap_console' || r.type === 'fritap_event')
    .map((r) => (r.type === 'fritap_console' ? String(r.payload.message) : JSON.stringify(r.payload)));

  return buildResult(
    {
      session_id: sessionEntry.id,
      script_id: scriptId,
      target: sessionEntry.target,
      pid: sessionEntry.pid,
      platform: sessionEntry.platform,
      agent_version: agent.version,
      agent_origin: agent.origin,
      agent_abi: abi,
      keylog_path: capture.keylogPath,
      pcap_path: capture.pcapPath,
      full_capture: fullCapture,
      duration_seconds: args.duration_seconds,
      hooks,
      stats: capture.stats,
      initial_messages: initial,
      message: `friTap ${agent.version} is running in ${sessionEntry.target} (pid ${sessionEntry.pid}). ` +
        'Key log lines arrive as fritap_keylog messages' + (capture.keylogPath ? ` and in ${capture.keylogPath}` : '') +
        (fullCapture ? '; plaintext records as fritap_datalog messages' : '') +
        '. Exercise the app, then call get_messages.',
    },
    [
      { tool: 'get_messages', args: { session_id: sessionEntry.id, script_id: scriptId }, reason: 'Read key log lines and plaintext records' },
      { tool: 'mobile_action', args: { action: 'mobile_take_screenshot' }, reason: 'Drive the app to trigger TLS traffic' },
      { tool: 'stop_instrumentation', args: { session_id: sessionEntry.id }, reason: 'Stop the capture and detach' },
    ],
    { limitations, coverage: { status: 'unknown', note: 'live capture; coverage depends on which TLS library the app uses and the traffic triggered' } }
  );
}

function describeLimitations(capture: FritapCapture, abi: number | null, args: CaptureTlsArgs, fullCapture: boolean): string[] {
  const limitations: string[] = [];
  if (!fullCapture) limitations.push('Only key material is captured (full_capture=false); plaintext records are not buffered.');
  if (!capture.keylogPath) limitations.push('No keylog_path given: key log lines are only kept in the session message buffer (bounded).');
  if (capture.pcapPath) limitations.push('pcap contains synthetic TCP/UDP packets of decrypted records, not the real wire traffic; use the friTap CLI (fritap -p) for full captures.');
  if (abi !== null && abi !== FRITAP_AGENT_ABI_VERSION) limitations.push(`friTap agent ABI ${abi} differs from the expected ${FRITAP_AGENT_ABI_VERSION}; message shapes may differ.`);
  if (!args.spawn) limitations.push('Attached to a running process: TLS sessions established before the hooks were installed are not covered.');
  return limitations;
}
