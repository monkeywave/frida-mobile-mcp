/**
 * capture_tls: run the friTap agent inside the target and collect TLS key material and
 * decrypted plaintext without the friTap Python CLI.
 *
 * Flow: locate bundle -> spawn suspended (or attach) -> createAgentScript (passthrough)
 * -> configureFritapAgent (answers the agent's config handshake during load) -> load
 * -> resume -> buffer keylog/datalog records on the session for get_messages.
 * spawn_mode 'early_resume' (or the automatic one-time retry after an OS start-timeout kill)
 * resumes right after the attach and loads the agent into the running app instead.
 * A spawned target is checked for liveness after the start (start-recovery.ts): an app killed
 * during or right after the resume is never reported as a running capture.
 */
import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type frida from 'frida';
import type { DeviceManager } from '../device/manager.js';
import { getState, type ScriptUnloader } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../helpers/errors.js';
import { validateFilePath, validateProcessTarget } from '../helpers/sanitize.js';
import { log } from '../helpers/logger.js';
import { rateLimiter } from '../helpers/rate-limiter.js';
import { getOrCreateSession, withTimeout } from '../helpers/session-helper.js';
import { responseFormatSchema } from '../constants.js';
import { createAgentScript } from '../agent/script-factory.js';
import { attachScriptLogHandler } from '../helpers/script-sink.js';
import type { SessionEntry } from '../types.js';
import {
  configureFritapAgent,
  type FritapAgentOptions,
  gracefulDetachFritap,
  locateFritapAgent,
  readFritapAbiVersion,
  type LocatedFritapAgent,
  validateFritapHookJson,
} from './agent-loader.js';
import { FritapCapture, type FritapCaptureStats, type FritapRecord } from './capture.js';
import { isSupportedFritapAbi, SUPPORTED_FRITAP_AGENT_ABI_VERSIONS } from './compat.js';
import { FRITAP_PROTOCOL_CHOICES, validateFritapProtocols } from './protocols.js';
import {
  isTargetDead,
  observeSpawnedTarget,
  processTerminatedError,
  shouldRetrySuspendedStart,
  type TargetObservation,
} from './start-recovery.js';

export const FRITAP_SCRIPT_NAME = 'fritap';
const INITIAL_OUTPUT_WAIT_MS = 2_000;
const MAX_INITIAL_MESSAGES = 20;
const MAX_DURATION_SECONDS = 600;
/** How long a spawned target must survive the start (and how long a failed start waits for the detach signal). */
const LIVENESS_GRACE_MS = 1_000;

/** How a spawned target is started: resumed after friTap is loaded, or right after the attach. */
export const FRITAP_SPAWN_MODES = ['suspended', 'early_resume'] as const;
export type FritapSpawnMode = (typeof FRITAP_SPAWN_MODES)[number];
/** The start mode of one capture attempt; 'attach' means spawn=false. */
export type CaptureStartMode = FritapSpawnMode | 'attach';

export const EARLY_RESUME_LIMITATION =
  'friTap agent loaded after app start (spawn_mode=early_resume): TLS handshakes during the first seconds may be missed.';
export const START_TIMEOUT_RETRY_NOTE =
  'The suspended app was killed during spawn/load (Android start timeout: not resumed within ~10 s); capture_tls retried once with spawn_mode=early_resume.';

interface ActiveCapture {
  sessionId: string;
  scriptId: string;
  script: frida.Script;
  capture: FritapCapture;
  timer?: NodeJS.Timeout;
}

const activeCaptures = new Map<string, ActiveCapture>();

/**
 * Final totals of a capture that has ended (stop_instrumentation, unload_script, duration end, process exit).
 * They are kept in memory (last MAX_FINISHED_CAPTURES) until returned once as fritap_captures[]: by
 * stop_instrumentation/detach_session/unload_script while the session lives, and by
 * unload_script(session_id, script_id) or stop_instrumentation(session_id) even after the script
 * (duration_seconds expiry) or the whole session (app exit) is already gone.
 */
export interface FinalFritapCapture {
  session_id: string;
  script_id: string;
  ended_at: string;
  stats: FritapCaptureStats;
}

/** Ended captures whose final stats were not yet returned to the caller (oldest first, bounded). */
const finishedCaptures = new Map<string, FinalFritapCapture>();
const MAX_FINISHED_CAPTURES = 50;

export const FRITAP_STATS_NOTE =
  'Snapshot taken when capture_tls returned; per_library and record counts keep growing while the capture runs. ' +
  'The final totals (including per_library) are returned once, as fritap_captures[], by stop_instrumentation for this session_id or unload_script for this script_id. ' +
  'Both also work after the capture ended on its own (duration_seconds expired: script already removed; app exited: session already gone); ' +
  `the server keeps the totals of the last ${MAX_FINISHED_CAPTURES} ended captures in memory until they are retrieved.`;

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
        'By default the app is spawned suspended, friTap is loaded, then the app is resumed so early handshakes are caught ' +
        '(retried once with spawn_mode=early_resume when Android kills the suspended app for a start timeout). ' +
        'Key log lines are written to keylog_path (usable with Wireshark tls.keylog_file) and plaintext records are buffered as fritap_datalog messages for get_messages (requires full_capture). ' +
        'protocols widens hooking beyond TLS (e.g. rc4); probe, pairip_safe and no_loader_hook help when instrumentation crashes anti-tamper apps; attribute_sdk adds per-connection caller stacks. ' +
        'Needs the friTap agent bundle: pip install friTap, FRITAP_AGENT_PATH, or allow_download.',
      inputSchema: z.object({
        target: z.string().describe('App bundle ID, process name, or PID'),
        device: z.string().optional().describe('Device ID'),
        keylog_path: z.string().optional().describe('File to append NSS key log lines to (CLIENT_RANDOM ...). Omitted: keys are only buffered as messages.'),
        pcap_path: z.string().optional().describe('Write decrypted records as a synthetic TCP pcap (implies full_capture). Full pcap of real traffic needs the friTap Python CLI.'),
        spawn: z.boolean().default(true).describe('Spawn the app suspended and resume after friTap is loaded (early hooks). false: attach to the running process.'),
        spawn_mode: z.enum(FRITAP_SPAWN_MODES).default('suspended').describe('With spawn=true: "suspended" (default) loads friTap before resuming; if the OS kills the app for a start timeout it is retried once as "early_resume". "early_resume" resumes right after the attach and loads friTap into the running app (slow devices; first handshakes may be missed).'),
        anti_root: z.boolean().default(false).describe('Install friTap anti-root hooks (Android)'),
        full_capture: z.boolean().default(false).describe('Also capture decrypted plaintext records (fritap_datalog messages), not only keys'),
        duration_seconds: z.number().int().min(0).max(MAX_DURATION_SECONDS).default(0).describe('Stop the capture automatically after N seconds (0 = keep running until stop_instrumentation)'),
        allow_download: z.boolean().default(true).describe('Download the pinned friTap agent from GitHub when it is not installed locally'),
        patterns: z.unknown().optional().describe('Custom byte patterns for friTap pattern-based hooking (friTap pattern.json contents, as an object or JSON string). Pair with generate_memory_pattern output.'),
        offsets: z.unknown().optional().describe('Custom offsets for friTap offset-based hooking (friTap offsets JSON, as an object or JSON string). Pair with generate_memory_pattern output.'),
        protocols: z.array(z.enum(FRITAP_PROTOCOL_CHOICES)).min(1).optional().describe('Protocols to hook (default ["tls"]). Combine concrete ones, e.g. ["tls","rc4"]; "auto" (hook what is detected) and "all" (install every hook) must be passed alone.'),
        pairip_safe: z.boolean().default(false).describe('PairIP/anti-tamper apps: minimal symbol-only keylog on system BoringSSL libs (no loader hook, pattern scan, Java or OHTTP hooks). Prefer spawn=false.'),
        no_loader_hook: z.boolean().default(false).describe('Skip the Android dynamic-loader hook (avoids anti-tamper crashes); TLS libraries loaded later are not hooked.'),
        probe: z.boolean().default(false).describe('Dry run: report the detected platform branch as a fritap_platform_report message and install no hooks. Use to diagnose crashes during instrumentation.'),
        attribute_sdk: z.boolean().default(false).describe('Emit one fritap_caller_stack backtrace per TLS connection to attribute traffic to the SDK/app code that produced it.'),
        default_fd: z.boolean().default(false).describe('Keep plaintext records whose socket cannot be resolved, using placeholder addresses (127.0.0.1) instead of dropping them.'),
        library_scan: z.boolean().default(false).describe('Scan loaded modules for an SSL key-log callback and hook TLS libraries friTap does not know by name.'),
        experimental: z.boolean().default(false).describe('Enable friTap experimental hooks (may be unstable).'),
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

export interface CaptureTlsArgs {
  target: string;
  device?: string;
  keylog_path?: string;
  pcap_path?: string;
  spawn: boolean;
  spawn_mode?: FritapSpawnMode;
  anti_root: boolean;
  full_capture: boolean;
  duration_seconds: number;
  allow_download: boolean;
  patterns?: unknown;
  offsets?: unknown;
  protocols?: string[];
  pairip_safe?: boolean;
  no_loader_hook?: boolean;
  probe?: boolean;
  attribute_sdk?: boolean;
  default_fd?: boolean;
  library_scan?: boolean;
  experimental?: boolean;
}

/** friTap agent options selected by the capture_tls arguments (besides the spawn/attach state). */
export function agentOptionsFromArgs(args: CaptureTlsArgs, fullCapture: boolean, spawned: boolean): FritapAgentOptions {
  return {
    antiRoot: args.anti_root,
    fullCapture,
    keylog: true,
    spawned,
    patterns: args.patterns,
    offsets: args.offsets,
    protocols: args.protocols,
    pairipSafe: args.pairip_safe ?? false,
    noLoaderHook: args.no_loader_hook ?? false,
    probe: args.probe ?? false,
    attributeSdk: args.attribute_sdk ?? false,
    defaultFd: args.default_fd ?? false,
    libraryScan: args.library_scan ?? false,
    experimental: args.experimental ?? false,
  };
}

/** Map spawn/spawn_mode to the start mode of the first attempt. */
export function resolveCaptureStartMode(args: Pick<CaptureTlsArgs, 'spawn' | 'spawn_mode'>): CaptureStartMode {
  return args.spawn ? (args.spawn_mode ?? 'suspended') : 'attach';
}

/** How the returned capture was started; drives limitations and the result fields. */
export interface CaptureStartInfo {
  mode: CaptureStartMode;
  retriedAfterStartTimeout: boolean;
}

interface StartedCapture {
  sessionEntry: SessionEntry;
  scriptId: string;
  script: frida.Script;
  abi: number | null;
  capture: FritapCapture;
  initial: FritapRecord[];
}

interface CaptureContext {
  deviceManager: DeviceManager;
  args: CaptureTlsArgs;
  agent: LocatedFritapAgent;
  fullCapture: boolean;
  livenessGraceMs: number;
}

/** Test seams: how long to wait for the first agent messages, and the start liveness grace. */
export interface CaptureTlsRunOptions {
  initialOutputWaitMs?: number;
  livenessGraceMs?: number;
}

/** State of one capture attempt, kept for the retry decision and the cleanup after a failure. */
interface StartAttempt {
  sessionEntry?: SessionEntry;
  observation?: TargetObservation;
  /** The friTap script this attempt registered on the session (if it got that far). */
  scriptId?: string;
  script?: frida.Script;
}

/** What one capture attempt created and therefore may tear down when it fails. */
export interface CaptureOwnership {
  /** The session was created by this attempt (not a reused, possibly shared, session). */
  createdSession: boolean;
  /** The process was spawned by this attempt. */
  spawnedProcess: boolean;
}

/** Exported for tests. */
export async function runCaptureTls(deviceManager: DeviceManager, args: CaptureTlsArgs, runOptions: CaptureTlsRunOptions = {}) {
  validateProcessTarget(args.target);
  validateFritapProtocols(args.protocols);
  validateFritapHookJson('patterns', args.patterns);
  validateFritapHookJson('offsets', args.offsets);
  if (args.keylog_path) validateFilePath(args.keylog_path);
  if (args.pcap_path) validateFilePath(args.pcap_path);
  const state = getState();
  rateLimiter.check('script', state.config.rateLimits.scriptsPerMinute);
  rateLimiter.record('script');

  const agent = await locateFritapAgent({ allowDownload: args.allow_download });
  const fullCapture = args.full_capture || Boolean(args.pcap_path);
  const context: CaptureContext = { deviceManager, args, agent, fullCapture, livenessGraceMs: runOptions.livenessGraceMs ?? LIVENESS_GRACE_MS };

  const { started, start } = await startCaptureWithRetry(context, resolveCaptureStartMode(args));
  const { sessionEntry, scriptId, script, abi, capture, initial } = started;
  trackCapture(sessionEntry.id, scriptId, script, capture, args.duration_seconds);
  await new Promise((resolve) => setTimeout(resolve, runOptions.initialOutputWaitMs ?? INITIAL_OUTPUT_WAIT_MS));

  return buildCaptureResult(sessionEntry, scriptId, agent, abi, capture, initial, args, fullCapture, start);
}

/**
 * Start in `mode`; a suspended start whose app died (or failed the way an OS start-timeout kill
 * fails) is retried once in early-resume mode.
 */
async function startCaptureWithRetry(context: CaptureContext, mode: CaptureStartMode): Promise<{ started: StartedCapture; start: CaptureStartInfo }> {
  const attempt: StartAttempt = {};
  try {
    return { started: await startCapture(context, mode, attempt), start: { mode, retriedAfterStartTimeout: false } };
  } catch (err) {
    if (mode !== 'suspended' || !shouldRetrySuspendedStart(err, attemptObservation(attempt))) throw err;
    log('warn', `capture_tls: ${context.args.target} died or stalled during the suspended start (${String(err)}); retrying once with spawn_mode=early_resume`);
    const started = await startCapture(context, 'early_resume', {});
    return { started, start: { mode: 'early_resume', retriedAfterStartTimeout: true } };
  }
}

/** The attempt's observation, or the session's detach reason when no observation was taken. */
function attemptObservation(attempt: StartAttempt): TargetObservation {
  return attempt.observation ?? { detachReason: attempt.sessionEntry?.detachReason ?? null };
}

/**
 * One capture attempt. suspended: spawn -> attach -> load -> resume. early_resume: spawn -> attach
 * -> resume -> load. attach: attach (a not-running target is spawned and resumed after the load).
 * A target we spawned must still be alive LIVENESS_GRACE_MS after the start (PROCESS_TERMINATED
 * otherwise). On failure the target is observed (for the retry decision) and only what this attempt
 * created is torn down (see abortStart): a reused session keeps its other scripts.
 */
async function startCapture(context: CaptureContext, mode: CaptureStartMode, attempt: StartAttempt): Promise<StartedCapture> {
  const { deviceManager, args, agent, fullCapture } = context;
  const { sessionEntry, fridaDevice, needsResume, isNew } = await getOrCreateSession(deviceManager, {
    target: args.target,
    device: args.device,
    forceSpawn: mode !== 'attach',
    resume: false,
  });
  attempt.sessionEntry = sessionEntry;
  const resumeBeforeLoad = needsResume && mode === 'early_resume';

  const initial: FritapRecord[] = [];
  let capture: FritapCapture | undefined;
  try {
    assertNoActiveCaptureInProcess(sessionEntry);
    capture = new FritapCapture({ keylogPath: args.keylog_path, pcapPath: args.pcap_path });
    if (resumeBeforeLoad) await resumeTarget(fridaDevice, sessionEntry.pid);
    // friTap's `spawned` flag (v2.6.5: "friTap spawned the target rather than attaching") only gates
    // startup-window behaviour: the anti-tamper auto-skip of the Android loader hook (PairIP's
    // spawn-time integrity scan) and the pairip_safe hook delay (8 s after load vs 1.5 s on attach).
    // early_resume still spawned the app and loads friTap within its first moments, inside that
    // window, so it stays true; only an attach to an already-running process passes false.
    const options = agentOptionsFromArgs(args, fullCapture, needsResume);
    const { script, scriptId } = await loadFritapScript(sessionEntry, agent, options, capture, initial, attempt);
    const abi = await readFritapAbiVersion(script);
    if (needsResume && !resumeBeforeLoad) await resumeTarget(fridaDevice, sessionEntry.pid);
    if (needsResume) await assertSpawnedTargetAlive(context, fridaDevice, sessionEntry, attempt);
    return { sessionEntry, scriptId, script, abi, capture, initial };
  } catch (err) {
    capture?.close();
    if (needsResume && !attempt.observation) attempt.observation = await observeSpawnedTarget(fridaDevice, sessionEntry, context.livenessGraceMs);
    await abortStart(fridaDevice, sessionEntry, attempt, { createdSession: isNew, spawnedProcess: needsResume });
    throw err;
  }
}

/**
 * The running capture already instrumenting this session's process (same session, or another
 * session on the same device and pid), if any.
 */
export function findActiveCaptureInProcess(sessionEntry: SessionEntry): ActiveCapture | undefined {
  const state = getState();
  for (const active of activeCaptures.values()) {
    if (active.sessionId === sessionEntry.id) return active;
    const other = state.getSession(active.sessionId);
    if (other && other.pid === sessionEntry.pid && other.deviceId === sessionEntry.deviceId) return active;
  }
  return undefined;
}

/**
 * Refuse a second friTap agent in one process: two concurrent agents crash the app (CheckJNI abort
 * in frida-agent on the next hooked call, seen on device). Throws FRITAP_CAPTURE_ACTIVE.
 */
function assertNoActiveCaptureInProcess(sessionEntry: SessionEntry): void {
  const active = findActiveCaptureInProcess(sessionEntry);
  if (!active) return;
  throw new FridaMcpError(
    'FRITAP_CAPTURE_ACTIVE',
    `A friTap capture is already running in process ${sessionEntry.pid} (session_id ${active.sessionId}, script_id ${active.scriptId}); ` +
      'a second friTap agent in the same process crashes the app. Keep using it (get_messages), or stop it first.',
    [
      { tool: 'get_messages', args: { session_id: active.sessionId, script_id: active.scriptId }, reason: 'Read the running capture' },
      { tool: 'unload_script', args: { session_id: active.sessionId, script_id: active.scriptId }, reason: 'Stop the running capture, then call capture_tls again' },
      { tool: 'stop_instrumentation', args: { session_id: active.sessionId }, reason: 'Stop all instrumentation of the session, then call capture_tls again' },
    ],
    { session_id: active.sessionId, script_id: active.scriptId, pid: sessionEntry.pid },
    { category: 'request', retryable: false }
  );
}

/** Throw PROCESS_TERMINATED when the spawned target died during or right after the start. */
async function assertSpawnedTargetAlive(context: CaptureContext, device: frida.Device, sessionEntry: SessionEntry, attempt: StartAttempt): Promise<void> {
  const observation = await observeSpawnedTarget(device, sessionEntry, context.livenessGraceMs);
  if (!isTargetDead(observation)) return;
  attempt.observation = observation;
  throw processTerminatedError(context.args.target, sessionEntry.pid, observation);
}

async function resumeTarget(device: frida.Device, pid: number): Promise<void> {
  await withTimeout((c) => device.resume(pid, c), `resume(${pid})`);
}

/** Create, register, configure and load the friTap agent script. */
async function loadFritapScript(
  sessionEntry: SessionEntry,
  agent: LocatedFritapAgent,
  options: FritapAgentOptions,
  capture: FritapCapture,
  initial: FritapRecord[],
  attempt: StartAttempt = {}
): Promise<{ script: frida.Script; scriptId: string }> {
  const script = await createAgentScript(sessionEntry.session, {
    sessionEntry: sessionEntry,
    source: agent.source,
    platform: sessionEntry.platform,
    name: `${FRITAP_SCRIPT_NAME}:${agent.version}`,
    kind: 'generated',
    usesJavaBridge: agent.usesJavaBridge ?? true,
  });
  const scriptId = getState().generateId();
  registerScript(sessionEntry, scriptId, script);
  attempt.scriptId = scriptId;
  attempt.script = script;
  const handshake = configureFritapAgent(script, options);
  connectMessageSink(sessionEntry, scriptId, script, capture, initial);
  // Keep agent console.* out of stdout (the stdio JSON-RPC channel); the bespoke
  // capture/handshake message protocol above stays as-is.
  attachScriptLogHandler(script, sessionEntry.id, scriptId);
  await script.load();
  log('info', `friTap agent ${agent.version} loaded (handshake: ${handshake.answered.join(',') || 'none'})`);
  return { script, scriptId };
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

/** Exported for tests. */
export function trackCapture(sessionId: string, scriptId: string, script: frida.Script, capture: FritapCapture, durationSeconds: number): void {
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
  rememberFinalStats(entry);
}

function rememberFinalStats(entry: ActiveCapture): void {
  finishedCaptures.set(entry.scriptId, {
    session_id: entry.sessionId,
    script_id: entry.scriptId,
    ended_at: new Date().toISOString(),
    stats: structuredClone(entry.capture.stats),
  });
  while (finishedCaptures.size > MAX_FINISHED_CAPTURES) {
    finishedCaptures.delete(finishedCaptures.keys().next().value as string);
  }
}

/**
 * Final stats of the ended captures of a session (optionally only `scriptIds`), removed from the
 * pending set so each is reported once. stop_instrumentation and unload_script return these as
 * `fritap_captures`.
 */
export function takeFinalFritapStats(sessionId: string, scriptIds?: readonly string[]): FinalFritapCapture[] {
  const taken: FinalFritapCapture[] = [];
  for (const [scriptId, final] of finishedCaptures) {
    if (final.session_id !== sessionId || (scriptIds && !scriptIds.includes(scriptId))) continue;
    taken.push(final);
    finishedCaptures.delete(scriptId);
  }
  return taken;
}

/**
 * Teardown unloader for unloadScriptsNewestFirst: a running friTap capture is stopped through
 * stopFritapCapture (graceful detach, files closed, final stats recorded); any other script is
 * just unloaded.
 */
export const unloadScriptForTeardown: ScriptUnloader = async (scriptEntry) => {
  if (activeCaptures.has(scriptEntry.id)) {
    await stopFritapCapture(scriptEntry.id);
    return;
  }
  await scriptEntry.script.unload();
};

/**
 * Undo a failed start without touching what it did not create: a session this attempt created is
 * removed (and a process it spawned killed, never leaving a suspended app behind); a reused session
 * only loses the friTap script this attempt registered, so the user's other hooks stay intact.
 */
async function abortStart(device: frida.Device, sessionEntry: SessionEntry, attempt: StartAttempt, ownership: CaptureOwnership): Promise<void> {
  if (ownership.createdSession) {
    try { await getState().removeSession(sessionEntry.id); } catch { /* best-effort */ }
  } else {
    await unloadAttemptScript(sessionEntry, attempt);
  }
  if (!ownership.spawnedProcess) return;
  try { await device.kill(sessionEntry.pid); } catch { /* best-effort */ }
}

async function unloadAttemptScript(sessionEntry: SessionEntry, attempt: StartAttempt): Promise<void> {
  if (!attempt.scriptId || !attempt.script) return;
  sessionEntry.scripts.delete(attempt.scriptId);
  try { await attempt.script.unload(); } catch { /* never loaded or already gone */ }
}

/** Exported for tests. */
export function buildCaptureResult(
  sessionEntry: SessionEntry,
  scriptId: string,
  agent: LocatedFritapAgent,
  abi: number | null,
  capture: FritapCapture,
  initial: FritapRecord[],
  args: CaptureTlsArgs,
  fullCapture: boolean,
  start: CaptureStartInfo = { mode: resolveCaptureStartMode(args), retriedAfterStartTimeout: false }
) {
  const limitations = [...describeLimitations(capture, abi, args, fullCapture, start), ...(agent.warnings ?? [])];
  const hooks = initial
    .filter((r) => r.type === 'fritap_console' || r.type === 'fritap_event' || r.type === 'fritap_platform_report')
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
      spawn_mode: start.mode === 'attach' ? null : start.mode,
      start_retried: start.retriedAfterStartTimeout,
      hooks,
      stats: capture.stats,
      stats_note: FRITAP_STATS_NOTE,
      java_bridge_patch: agent.javaBridgePatch ?? null,
      warnings: agent.warnings ?? [],
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

function describeLimitations(capture: FritapCapture, abi: number | null, args: CaptureTlsArgs, fullCapture: boolean, start: CaptureStartInfo): string[] {
  const limitations: string[] = [];
  if (!fullCapture) limitations.push('Only key material is captured (full_capture=false); plaintext records are not buffered.');
  if (!capture.keylogPath) limitations.push('No keylog_path given: key log lines are only kept in the session message buffer (bounded).');
  if (capture.pcapPath) limitations.push('pcap contains synthetic TCP/UDP packets of decrypted records, not the real wire traffic; use the friTap CLI (fritap -p) for full captures.');
  const abiWarning = describeAbiMismatch(abi);
  if (abiWarning) limitations.push(abiWarning);
  if (args.probe) limitations.push('probe=true: friTap only reported the platform (fritap_platform_report) and installed no hooks; nothing is captured.');
  if (!args.spawn) limitations.push('Attached to a running process: TLS sessions established before the hooks were installed are not covered.');
  if (start.retriedAfterStartTimeout) limitations.push(START_TIMEOUT_RETRY_NOTE);
  if (start.mode === 'early_resume') limitations.push(EARLY_RESUME_LIMITATION);
  return limitations;
}

/** Limitation text for an agent ABI outside the supported set; null when supported or unknown. */
export function describeAbiMismatch(abi: number | null): string | null {
  if (abi === null || isSupportedFritapAbi(abi)) return null;
  return `friTap agent ABI ${abi} is outside the supported set (${SUPPORTED_FRITAP_AGENT_ABI_VERSIONS.join(', ')}); message shapes may differ.`;
}
