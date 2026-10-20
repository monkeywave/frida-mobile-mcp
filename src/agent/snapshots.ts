/**
 * Optional per-session script-runtime snapshots (opt-in: config `snapshots` / `FRIDA_MCP_SNAPSHOTS=1`).
 *
 * A snapshot (`session.snapshotScript`) captures a heap that already contains the static half of
 * the agent preamble (bridge stubs + helpers) and the bridge bundles, so the ~300 KB Java bridge
 * does not have to be re-sent and re-parsed for every script of a session. Scripts created from it
 * only carry the per-script `__FRIDA_MCP__` context literal, a one-line bridge-installer call and
 * the body (see composeSnapshotLiveSource in script-factory.ts).
 *
 * Two facts, verified on device, shape the design:
 *   1. The embed script runs in a bare JavaScript context: `Process`, `Memory`, `Script` and the
 *      other Frida globals do NOT exist while the snapshot is taken. The bridge IIFEs read
 *      `Process.pageSize` at top level, so they cannot execute at snapshot time. They are therefore
 *      embedded as a *deferred installer* (`globalThis.__FRIDA_MCP_INSTALL_BRIDGES__ = function
 *      () { ...IIFEs... }`) that the live script calls once the Frida runtime is present.
 *   2. Only V8 can snapshot: QuickJS (Frida's default runtime) answers
 *      "not supported by the QuickJS runtime". The failure is remembered per session and the
 *      plain path is used, so the feature is a no-op unless `FRIDA_MCP_RUNTIME=v8`.
 *
 * Measurements (frida-server 17.24.3, Android 16 emulator-5556, com.example.rc4demo, V8 runtime,
 * preamble + frida-java-bridge 7.0.13 embed = 294 KB source -> 775 KB snapshot, taken in ~50-75 ms;
 * create+load of a Java-touching rpc script, 10 interleaved iterations each, median):
 *   plain (full source every script):   35.9 ms   (first Java.perform rpc: 18.9 ms)
 *   snapshot (inline transport):        35.4 ms   (first Java.perform rpc: 18.9 ms)
 *   QuickJS plain, for reference:       ~150-200 ms create+load, snapshot unsupported
 *   (test/e2e/snapshots.test.ts, 5 interleaved iterations: plain 38.7 ms vs snapshot 37.7 ms median)
 * The snapshot is larger than the source it replaces and is shipped inline with every
 * createScript (shared-memory transport is local-only and takes the remote connection down),
 * so there is no measurable win on a remote device; hence the feature defaults to off.
 * Correctness from a snapshot was verified: Java.available === true, Java.perform / Java.use work
 * after resume, Interceptor + Java scripts work, a second script on the same session reuses the
 * cached Buffer (host-side cache hit) and `Script.evaluate`-wrapped user scripts see the bridge.
 */
import type frida from 'frida';
import { loadBridgeSource, type BridgeName } from './bridges.js';
import { buildPreamble, type PreambleContext } from './preamble.js';
import { log } from '../helpers/logger.js';
import type { SessionEntry } from '../types.js';

/** Runtime names as accepted by `createScript` / `snapshotScript`; 'default' lets frida-server choose. */
export type SnapshotRuntime = 'default' | 'qjs' | 'v8';

export interface SessionSnapshotOptions {
  platform: string;
  bridges: readonly BridgeName[];
  runtime: SnapshotRuntime;
}

/** The slice of a SessionEntry the snapshot cache needs; tests pass a fake session. */
export type SnapshotHost = Pick<SessionEntry, 'id' | 'session' | 'snapshots' | 'snapshotFailures'>;

/** Global installed by the embed script; the live script calls it to install the bridges. */
export const BRIDGE_INSTALLER_GLOBAL = '__FRIDA_MCP_INSTALL_BRIDGES__';

const CONTEXT_LINE_PREFIX = 'globalThis.__FRIDA_MCP__ = ';

function isContextLine(line: string): boolean {
  return line.startsWith(CONTEXT_LINE_PREFIX);
}

/**
 * Split `buildPreamble` output into the context-independent part (stubs + helpers), which can live
 * in a snapshot, and the per-script `globalThis.__FRIDA_MCP__ = {...};` line, which cannot.
 * The context literal is a single line: JSON.stringify never emits a raw LF.
 */
function splitPreamble(ctx: PreambleContext): { staticPart: string; dynamicPart: string } {
  const lines = buildPreamble(ctx).split('\n');
  return {
    staticPart: lines.filter((line) => !isContextLine(line)).join('\n'),
    dynamicPart: lines.filter(isContextLine).join('\n'),
  };
}

/** Preamble half that does not depend on the script: bridge stubs + helpers. */
export function buildStaticPreamble(platform: string, bridges: readonly BridgeName[]): string {
  return splitPreamble({ name: '', platform, options: {}, injectedBridges: bridges }).staticPart;
}

/** Preamble half that changes per script: the `__FRIDA_MCP__` context literal. */
export function buildDynamicPreamble(ctx: PreambleContext): string {
  return splitPreamble(ctx).dynamicPart;
}

/**
 * Bridge bundles wrapped in a deferred installer. Nothing runs at definition time, so the source
 * can be embedded in a snapshot context that has no Frida runtime yet.
 */
export function buildBridgeInstaller(bridges: readonly BridgeName[]): string {
  const body = bridges.map((bridge) => loadBridgeSource(bridge)).join('\n');
  return `globalThis.${BRIDGE_INSTALLER_GLOBAL} = function () {\n${body}\n};`;
}

/** Statement the live script runs to install the bridges that the snapshot carries. */
export function bridgeInstallerCall(): string {
  return `${BRIDGE_INSTALLER_GLOBAL}();`;
}

/** Everything that goes into the snapshot heap for (platform, bridges). */
export function composeSnapshotEmbedSource(platform: string, bridges: readonly BridgeName[]): string {
  return [buildStaticPreamble(platform, bridges), buildBridgeInstaller(bridges)].join('\n');
}

/** Cache key: snapshots are runtime-specific and must contain exactly the requested bridges. */
export function snapshotCacheKey(bridges: readonly BridgeName[], runtime: SnapshotRuntime): string {
  return `${runtime}:${[...bridges].sort().join('+')}`;
}

/** In-flight creations per host, so concurrent scripts on one session share a single round trip. */
const pending = new WeakMap<SnapshotHost, Map<string, Promise<Buffer | null>>>();

/**
 * Return the session's snapshot for the given bridge set and runtime, creating it on first use.
 * Returns null (and remembers that) when there is nothing worth snapshotting (no bridges) or the
 * runtime/server cannot snapshot, so callers fall back to sending the full source.
 */
export async function getOrCreateSessionSnapshot(
  host: SnapshotHost,
  opts: SessionSnapshotOptions
): Promise<Buffer | null> {
  if (opts.bridges.length === 0) return null;

  const key = snapshotCacheKey(opts.bridges, opts.runtime);
  const cached = host.snapshots?.get(key);
  if (cached) return cached;
  if (host.snapshotFailures?.has(key)) return null;

  let inFlight = pending.get(host);
  if (!inFlight) {
    inFlight = new Map();
    pending.set(host, inFlight);
  }
  let creation = inFlight.get(key);
  if (!creation) {
    creation = createSnapshot(host, opts, key).finally(() => inFlight!.delete(key));
    inFlight.set(key, creation);
  }
  return creation;
}

async function createSnapshot(host: SnapshotHost, opts: SessionSnapshotOptions, key: string): Promise<Buffer | null> {
  const embed = composeSnapshotEmbedSource(opts.platform, opts.bridges);
  const snapshotOptions: frida.SnapshotOptions = {};
  if (opts.runtime !== 'default') {
    snapshotOptions.runtime = opts.runtime as frida.ScriptRuntime;
  }
  const startedAt = Date.now();
  try {
    const snapshot = await host.session.snapshotScript(embed, snapshotOptions);
    (host.snapshots ??= new Map()).set(key, snapshot);
    log('debug', `Session ${host.id}: created ${key} snapshot (${snapshot.length} bytes from ${embed.length} chars) in ${Date.now() - startedAt} ms`);
    return snapshot;
  } catch (err) {
    (host.snapshotFailures ??= new Set()).add(key);
    log('debug', `Session ${host.id}: snapshot ${key} unavailable, using plain scripts: ${String(err instanceof Error ? err.message : err)}`);
    return null;
  }
}
