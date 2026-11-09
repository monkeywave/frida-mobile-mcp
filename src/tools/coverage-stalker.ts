/**
 * Stalker engine for trace_coverage: follow thread(s) for a bounded window and record every
 * basic block compiled inside one module (or an offset range of it) as `module+0xoffset`.
 *
 * Unlike the entry-hook engine (persistent, function granularity) this is a time-boxed,
 * basic-block-granular snapshot. Stalker re-compiles every block the followed thread runs,
 * so it is CPU heavy; the window is capped by duration and by a block budget.
 */
import { z } from 'zod';
import type frida from 'frida';
import type { DeviceManager } from '../device/manager.js';
import type { SessionEntry, SessionRealm, EvidenceCoverage, RecoveryAction, SuggestedAction } from '../types.js';
import type { BridgeName } from '../agent/bridges.js';
import { getState } from '../state.js';
import { attachScriptSinks } from '../helpers/script-sink.js';
import { buildResult } from '../helpers/result-builder.js';
import { FridaMcpError } from '../helpers/errors.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
import { createAgentScript } from '../agent/script-factory.js';
import { callRpcWithTimeout } from '../helpers/rpc-timeout.js';
import { formatModuleOffset, normaliseOffset } from '../agent/address.js';
import { log } from '../helpers/logger.js';

const NO_BRIDGES: BridgeName[] = [];

export const DEFAULT_STALKER_DURATION_SECONDS = 10;
export const MAX_STALKER_DURATION_SECONDS = 120;
export const DEFAULT_STALKER_MAX_BLOCKS = 5000;
export const MAX_STALKER_MAX_BLOCKS = 100_000;
/** Blocks listed in the response; the full count is always reported. */
export const MAX_STALKER_BLOCKS_IN_RESPONSE = 1000;
const STALKER_RPC_TIMEOUT_MS = 30_000;

export const coverageEngineSchema = z
  .enum(['hooks', 'stalker'])
  .optional()
  .describe("Coverage engine (default 'hooks'): 'hooks' arms persistent entry-hooks over `scope`; 'stalker' follows thread(s) with Stalker for a bounded window and returns every basic block executed inside `module` (block granularity, CPU heavy).");

export const stalkerModuleSchema = z
  .string()
  .optional()
  .describe("engine='stalker' only (required): module name whose basic blocks are recorded, e.g. \"libfoo.so\".");

export const stalkerOffsetRangeSchema = z
  .object({
    start: z.union([z.string(), z.number().int().nonnegative()]).describe('Module-relative start offset (hex "0x1234" or decimal).'),
    size: z.number().int().positive().describe('Range size in bytes.'),
  })
  .optional()
  .describe("engine='stalker' only: restrict recording to [module+start, module+start+size). Default: the whole module.");

export const stalkerThreadSchema = z
  .union([z.literal('main'), z.number().int().positive()])
  .optional()
  .describe("engine='stalker' only: which thread(s) to follow — 'main' (default, the UI/main thread) or a numeric thread id. Native work often runs on worker threads, so main may yield 0 blocks: call list_threads and pass the worker thread id.");

export const stalkerDurationSchema = z
  .number()
  .positive()
  .max(MAX_STALKER_DURATION_SECONDS)
  .optional()
  .describe(`engine='stalker' only: recording window in seconds (default ${DEFAULT_STALKER_DURATION_SECONDS}, max ${MAX_STALKER_DURATION_SECONDS}). Drive the app meanwhile.`);

export const stalkerMaxBlocksSchema = z
  .number()
  .int()
  .positive()
  .max(MAX_STALKER_MAX_BLOCKS)
  .optional()
  .describe(`engine='stalker' only: stop early once this many unique blocks were recorded (default ${DEFAULT_STALKER_MAX_BLOCKS}).`);

export type StalkerThreadChoice = 'main' | number;

export interface StalkerParams {
  module?: string;
  offset_range?: { start: string | number; size: number };
  thread?: StalkerThreadChoice;
  duration_seconds?: number;
  max_blocks?: number;
}

/** Options the agent reads from __FRIDA_MCP__.options (never spliced into code). */
export interface StalkerAgentOptions {
  moduleName: string;
  rangeStart: string;
  rangeSize: number | null;
  thread: StalkerThreadChoice;
  maxBlocks: number;
}

export interface StalkerPlan {
  agentOptions: StalkerAgentOptions;
  durationSeconds: number;
}

interface StalkerStartResult {
  error?: string;
  module?: string;
  base?: string;
  range_start?: string;
  range_size?: number;
  threads?: number[];
}

interface StalkerStopResult {
  offsets?: string[];
  cap_hit?: boolean;
  errors?: string[];
}

export interface StalkerBlocks {
  blocks: string[];
  capHit: boolean;
}

/** Validate the stalker-only parameters and turn them into the agent options and window length. */
export function planStalkerCoverage(params: StalkerParams): StalkerPlan {
  const moduleName = params.module?.trim();
  if (!moduleName) {
    throw new FridaMcpError('INVALID_ARGUMENT', "module is required for engine='stalker' (e.g. \"libfoo.so\").", [
      { tool: 'enumerate_modules', reason: 'Find the module name to record' },
    ]);
  }
  return {
    agentOptions: {
      moduleName,
      rangeStart: normaliseRangeStart(params.offset_range?.start),
      rangeSize: params.offset_range?.size ?? null,
      thread: params.thread ?? 'main',
      maxBlocks: params.max_blocks ?? DEFAULT_STALKER_MAX_BLOCKS,
    },
    durationSeconds: params.duration_seconds ?? DEFAULT_STALKER_DURATION_SECONDS,
  };
}

function normaliseRangeStart(start: string | number | undefined): string {
  if (start === undefined) return '0x0';
  try {
    return normaliseOffset(start);
  } catch {
    throw new FridaMcpError('INVALID_ARGUMENT', `offset_range.start must be a hex ("0x1234") or decimal offset, got "${String(start).trim()}".`, []);
  }
}

/** Dedupe, sort by offset and cap the agent's module-relative block offsets, formatted as `module+0xoff`. */
export function toModuleBlocks(moduleName: string, offsets: readonly string[], maxBlocks: number): StalkerBlocks {
  const unique = Array.from(new Set(offsets.map((o) => BigInt(o)))).sort(compareBigInt);
  const capHit = unique.length >= maxBlocks;
  const blocks = unique.slice(0, maxBlocks).map((offset) => formatModuleOffset(moduleName, offset));
  return { blocks, capHit };
}

function compareBigInt(a: bigint, b: bigint): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** 'complete' only when the window ran to its end without the block cap stopping it early. */
export function stalkerCoverageStatus(windowCompleted: boolean, capHit: boolean): EvidenceCoverage['status'] {
  return windowCompleted && !capHit ? 'complete' : 'unknown';
}

export interface StalkerLimitationInput {
  realm?: SessionRealm;
  capHit: boolean;
  thread: StalkerThreadChoice;
  agentErrors?: readonly string[];
  blocksCount?: number;
}

export function stalkerLimitations({ realm, capHit, thread, agentErrors = [], blocksCount }: StalkerLimitationInput): string[] {
  const limitations = [
    'Stalker is CPU heavy: the followed thread(s) run much slower while recording, which can trigger ANRs or timing-based anti-instrumentation.',
    'Only blocks executed during the window on the followed thread(s) are recorded; this is a snapshot, not a persistent reachability map.',
  ];
  if (thread === 'main') limitations.push("Only the main thread was followed; code running on worker threads is missed (call list_threads and pass a worker thread id).");
  if (blocksCount === 0) limitations.push('0 blocks recorded: native work often runs on worker threads. Call list_threads and re-run with thread set to the worker thread id.');
  if (realm === 'emulated') limitations.push('Emulated realm is not supported for Stalker: results under native-bridge translation are unreliable.');
  if (capHit) limitations.push('Block cap (max_blocks) was hit: recording stopped early and later blocks are missing.');
  for (const error of agentErrors) limitations.push(`Agent reported: ${error}`);
  return limitations;
}

/**
 * Agent body. Follows the chosen thread(s) with compile events only, keeps the blocks whose
 * start lies in [lo, hi), dedupes them and stops itself at the block cap. Every exit path
 * (stop rpc, cap, error, script unload via rpc.exports.dispose) runs stopFollowing():
 * Stalker.unfollow + Stalker.flush + Stalker.garbageCollect.
 */
export const STALKER_COVERAGE_SCRIPT = `
(function () {
  var o = __FRIDA_MCP__.options;
  var followed = [];
  var seen = {};
  var offsets = [];
  var errors = [];
  var capHit = false;
  var lo = null, hi = null, base = null;

  function unfollowAll() {
    for (var i = 0; i < followed.length; i++) {
      try { Stalker.unfollow(followed[i]); } catch (e) { errors.push('unfollow ' + followed[i] + ': ' + e.message); }
    }
    followed = [];
  }

  function stopFollowing() {
    unfollowAll();
    try { Stalker.flush(); } catch (e) {}
    try { Stalker.garbageCollect(); } catch (e) {}
  }

  function recordBlock(start) {
    if (capHit || start.compare(lo) < 0 || start.compare(hi) >= 0) return;
    var off = '0x' + start.sub(base).toString(16);
    if (seen[off]) return;
    seen[off] = 1;
    offsets.push(off);
    if (offsets.length >= o.maxBlocks) {
      capHit = true;
      // Inside onReceive: only unfollow here; flush/garbageCollect run in stop() / dispose().
      unfollowAll();
      send({ stalker_cap: true, blocks: offsets.length });
    }
  }

  function onReceive(events) {
    if (capHit) return;
    try {
      var parsed = Stalker.parse(events, { annotate: true, stringify: false });
      for (var i = 0; i < parsed.length && !capHit; i++) {
        if (parsed[i][0] === 'compile') recordBlock(parsed[i][1]);
      }
    } catch (e) { errors.push('parse: ' + e.message); }
  }

  function selectThreads() {
    var self = Process.getCurrentThreadId();
    var threads = Process.enumerateThreads().filter(function (t) { return t.id !== self; });
    if (o.thread === 'main') {
      var main = threads.filter(function (t) { return t.id === Process.id; })[0] || threads[0];
      return main ? [main.id] : [];
    }
    return threads.some(function (t) { return t.id === o.thread; }) ? [o.thread] : [];
  }

  function resolveRange() {
    var m = Process.findModuleByName(o.moduleName);
    if (!m) return 'module_not_found: ' + o.moduleName;
    var start = m.base.add(ptr(o.rangeStart));
    var end = o.rangeSize === null ? m.base.add(m.size) : start.add(o.rangeSize);
    var moduleEnd = m.base.add(m.size);
    if (start.compare(moduleEnd) >= 0) return 'offset_out_of_range: ' + o.rangeStart;
    base = m.base; lo = start; hi = end.compare(moduleEnd) > 0 ? moduleEnd : end;
    return null;
  }

  rpc.exports.start = function () {
    var rangeError = resolveRange();
    if (rangeError) return { error: rangeError };
    var tids = selectThreads();
    if (tids.length === 0) return { error: 'thread_not_found: ' + o.thread };
    try {
      for (var i = 0; i < tids.length; i++) {
        Stalker.follow(tids[i], { events: { compile: true }, onReceive: onReceive });
        followed.push(tids[i]);
      }
    } catch (e) {
      stopFollowing();
      return { error: 'follow_failed: ' + e.message };
    }
    return { module: o.moduleName, base: base.toString(), range_start: '0x' + lo.sub(base).toString(16), range_size: hi.sub(lo).toInt32(), threads: tids };
  };

  rpc.exports.stop = function () {
    stopFollowing();
    // Let the flushed event batches reach onReceive before reporting.
    return new Promise(function (resolve) {
      setTimeout(function () {
        try { Stalker.garbageCollect(); } catch (e) {}
        resolve({ offsets: offsets, cap_hit: capHit, errors: errors });
      }, 100);
    });
  };

  rpc.exports.dispose = function () { stopFollowing(); };
})();
`;

/** Recovery hint for a failed Stalker start: a missing thread needs list_threads, anything else (module/range) enumerate_modules. */
export function stalkerArmFailureHint(agentError: string, sessionId: string): RecoveryAction {
  if (agentError.startsWith('thread_not_found')) {
    return { tool: 'list_threads', args: { session_id: sessionId }, reason: 'The requested thread is not running; list threads and pick a live thread id (or use "main")' };
  }
  return { tool: 'enumerate_modules', args: { session_id: sessionId }, reason: 'Check the module name and that it is loaded' };
}

export interface RecordingWindow {
  /** Resolves true when the window elapsed, false when stopped early (block cap hit). */
  done: Promise<boolean>;
  /** Start the timer; call only once the agent is actually recording. Idempotent. */
  start: () => void;
  stopEarly: () => void;
  /** Clear a pending timer without resolving (failure paths). */
  cancel: () => void;
}

/**
 * A recording window of `durationMs` whose timer starts only on `start()`, so time spent creating
 * and loading the script and arming Stalker is not deducted from the window.
 */
export function recordingWindow(durationMs: number): RecordingWindow {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let settled = false;
  let resolveDone: (completed: boolean) => void = () => {};
  const done = new Promise<boolean>((resolve) => { resolveDone = resolve; });
  const cancel = () => { if (timer !== undefined) clearTimeout(timer); timer = undefined; };
  const finish = (completed: boolean) => {
    if (settled) return;
    settled = true;
    cancel();
    resolveDone(completed);
  };
  const start = () => {
    if (settled || timer !== undefined) return;
    timer = setTimeout(() => finish(true), durationMs);
  };
  return { done, start, stopEarly: () => finish(false), cancel };
}

export interface StalkerRunInput extends StalkerParams {
  target: string;
  sessionId?: string;
  device?: string;
}

/** Run one Stalker coverage window end to end and build the evidence envelope. */
export async function runStalkerCoverage(deviceManager: DeviceManager, input: StalkerRunInput) {
  const plan = planStalkerCoverage(input);
  const { sessionEntry } = await getOrCreateSession(deviceManager, { target: input.target, device: input.device, sessionId: input.sessionId });
  const window = recordingWindow(plan.durationSeconds * 1000);
  const { script, scriptId } = await loadStalkerScript(sessionEntry, plan, window.stopEarly);

  try {
    const started = await callRpcWithTimeout(script.exports.start() as Promise<StalkerStartResult>, 'Stalker coverage start', STALKER_RPC_TIMEOUT_MS);
    if (started.error) {
      throw new FridaMcpError('COVERAGE_ARM_FAILED', `Could not start Stalker coverage: ${started.error}`, [stalkerArmFailureHint(started.error, sessionEntry.id)]);
    }
    // The window counts from the moment Stalker is armed, not from session/script setup.
    window.start();
    log('info', `Stalker coverage on ${plan.agentOptions.moduleName} for ${plan.durationSeconds}s...`);
    const windowCompleted = await window.done;
    const stopped = await callRpcWithTimeout(script.exports.stop() as Promise<StalkerStopResult>, 'Stalker coverage stop', STALKER_RPC_TIMEOUT_MS);
    return shapeStalkerResult(sessionEntry, plan, started, stopped, windowCompleted);
  } finally {
    window.cancel();
    await unloadQuietly(script);
    sessionEntry.scripts.delete(scriptId);
  }
}

async function loadStalkerScript(sessionEntry: SessionEntry, plan: StalkerPlan, onCapHit: () => void) {
  const state = getState();
  const name = `coverage:stalker:${plan.agentOptions.moduleName}`;
  const script = await createAgentScript(sessionEntry.session, {
    sessionEntry,
    source: STALKER_COVERAGE_SCRIPT,
    platform: sessionEntry.platform,
    name,
    kind: 'generated',
    options: { ...plan.agentOptions, platform: sessionEntry.platform },
    bridges: NO_BRIDGES,
  });
  const scriptId = state.generateId();
  const scriptEntry = { id: scriptId, script, messages: [], name, persistent: false, createdAt: Date.now() };
  attachScriptSinks(script, sessionEntry.id, scriptId, {
    onSend: (payload) => {
      if ((payload as { stalker_cap?: boolean } | null)?.stalker_cap) onCapHit();
    },
  });
  await script.load();
  sessionEntry.scripts.set(scriptId, scriptEntry);
  return { script, scriptId };
}

/** Unloading triggers rpc.exports.dispose (unfollow/flush/gc) even when stop() never ran. */
async function unloadQuietly(script: frida.Script): Promise<void> {
  try { await script.unload(); } catch (err) { log('debug', `Stalker coverage unload failed: ${String(err)}`); }
}

function shapeStalkerResult(
  sessionEntry: SessionEntry,
  plan: StalkerPlan,
  started: StalkerStartResult,
  stopped: StalkerStopResult,
  windowCompleted: boolean,
) {
  const { moduleName, maxBlocks, thread } = plan.agentOptions;
  const { blocks, capHit: hostCapHit } = toModuleBlocks(moduleName, stopped.offsets ?? [], maxBlocks);
  const capHit = hostCapHit || stopped.cap_hit === true;
  const listed = blocks.slice(0, MAX_STALKER_BLOCKS_IN_RESPONSE);
  const listTruncated = listed.length < blocks.length;
  return buildResult(
    {
      session_id: sessionEntry.id,
      engine: 'stalker',
      module: moduleName,
      range: { start: started.range_start, size: started.range_size },
      threads: started.threads ?? [],
      duration_seconds: plan.durationSeconds,
      window_completed: windowCompleted,
      cap_hit: capHit,
      blocks_count: blocks.length,
      blocks: listed,
      truncated: listTruncated,
    },
    stalkerNextActions(sessionEntry.id, moduleName, plan.durationSeconds, blocks.length === 0),
    {
      limitations: stalkerLimitations({ realm: sessionEntry.realm, capHit, thread, agentErrors: stopped.errors ?? [], blocksCount: blocks.length }),
      coverage: {
        status: stalkerCoverageStatus(windowCompleted, capHit),
        scope: `stalker basic blocks of ${moduleName}`,
        truncated: listTruncated,
      },
    },
  );
}

function stalkerNextActions(sessionId: string, moduleName: string, durationSeconds: number, noBlocks: boolean): SuggestedAction[] {
  return [
    { tool: 'trace_coverage', args: { session_id: sessionId, engine: 'stalker', module: moduleName, duration_seconds: durationSeconds }, reason: 'Record another window while driving a different flow' },
    { tool: 'hook_method', args: { session_id: sessionId }, reason: 'Hook an interesting block (pass module+0xoffset as the target)' },
    ...(noBlocks ? [{ tool: 'list_threads', args: { session_id: sessionId }, reason: "0 blocks recorded: native work often runs on worker threads; list threads and re-run with thread set to a worker thread id" }] : []),
  ];
}
