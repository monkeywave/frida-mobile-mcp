/**
 * Composes and creates Frida scripts that run on Frida 17.x.
 *
 * Layout of a composed script:
 *   preamble (JSON context, bridge stubs, helpers)
 *   bridge IIFE(s) selected by platform (java on Android, objc on iOS/macOS)
 *   body:
 *     kind 'generated' -> template / tool code appended verbatim
 *     kind 'user'      -> Script.evaluate(name, source) so a legacy classic script keeps its own
 *                         file name and line numbers in error messages
 *
 * Sources starting with the frida-compile bundle marker (📦) are passed through untouched:
 * they already contain everything they need (this is how friTap's agent or any
 * frida-compile output can be loaded). ES module sources must be compiled first;
 * execute_script does that through src/agent/compiler.ts (frida.Compiler) before calling here.
 *
 * Snapshot layout (opt-in, see src/agent/snapshots.ts): when the session has a runtime snapshot
 * holding the static preamble + bridges, the live source shrinks to
 *   dynamic preamble (`__FRIDA_MCP__` context) + bridge installer call + body
 * and the snapshot is passed to createScript. Passthrough bundles never use a snapshot.
 */
import type frida from 'frida';
import { loadBridgeSource, type BridgeName } from './bridges.js';
import { buildPreamble } from './preamble.js';
import { ScriptError } from '../helpers/errors.js';
import { getActiveConfig, parseBooleanFlag } from '../config.js';
import {
  bridgeInstallerCall,
  buildDynamicPreamble,
  getOrCreateSessionSnapshot,
  type SnapshotHost,
} from './snapshots.js';

export {
  buildStaticPreamble,
  buildDynamicPreamble,
  buildBridgeInstaller,
  composeSnapshotEmbedSource,
  BRIDGE_INSTALLER_GLOBAL,
} from './snapshots.js';

export const FRIDA_COMPILE_BUNDLE_MARKER = '📦\n';

export type AgentPlatform = 'android' | 'ios' | 'linux' | 'macos' | 'windows' | 'unknown';
export type ScriptKind = 'generated' | 'user';
export type ScriptRuntime = 'default' | 'qjs' | 'v8';

export interface AgentScriptOptions {
  /** Template output or user-supplied classic JavaScript. */
  source: string;
  platform: AgentPlatform;
  /** Script name, e.g. 'prebuilt:ssl_pinning_bypass' or 'user:execute_script'. */
  name: string;
  kind: ScriptKind;
  /** Exposed to the script as `__FRIDA_MCP__.options`. */
  options?: Record<string, unknown>;
  /** Override the platform default (e.g. [] for rpc-only scripts that never touch Java/ObjC). */
  bridges?: BridgeName[];
  runtime?: ScriptRuntime;
  /**
   * Session entry that owns the snapshot cache. Without it (or with `useSnapshot: false`) the
   * full source is sent, exactly as before snapshots existed.
   */
  sessionEntry?: SnapshotHost;
  /** Defaults to `FRIDA_MCP_SNAPSHOTS` / config `snapshots` (off). */
  useSnapshot?: boolean;
}

export interface ComposedAgentSource {
  source: string;
  name: string;
  bridges: BridgeName[];
  passthrough: boolean;
}

export function defaultBridgesFor(platform: AgentPlatform): BridgeName[] {
  switch (platform) {
    case 'android':
      return ['java'];
    case 'ios':
    case 'macos':
      return ['objc'];
    default:
      return [];
  }
}

export function isFridaCompileBundle(source: string): boolean {
  return source.startsWith(FRIDA_COMPILE_BUNDLE_MARKER);
}

const ESM_PATTERN = /^\s*(import\s+[\w{}*\s,]+\s+from\s+['"]|import\s*['"]|export\s+(default|const|function|class|let|var|\{))/m;

export function looksLikeEsModule(source: string): boolean {
  return ESM_PATTERN.test(source);
}

interface ClassicParts {
  bridges: BridgeName[];
  body: string;
}

/** Validate a non-passthrough source and resolve its bridge set and body statement. */
function classicPartsOf(opts: AgentScriptOptions): ClassicParts {
  if (opts.kind === 'user' && looksLikeEsModule(opts.source)) {
    throw new ScriptError(
      'ES module syntax (import/export) must be compiled first (execute_script does this automatically via source_kind "esm"), ' +
        'or provide a classic script (Java/ObjC globals are available) or a frida-compile bundle (starts with the 📦 marker).',
      opts.source
    );
  }
  const bridges = opts.bridges ?? defaultBridgesFor(opts.platform);
  const body =
    opts.kind === 'user'
      ? `Script.evaluate(${JSON.stringify(opts.name)}, ${JSON.stringify(opts.source)});`
      : opts.source;
  return { bridges, body };
}

function passthroughOf(opts: AgentScriptOptions): ComposedAgentSource {
  return { source: opts.source, name: opts.name, bridges: [], passthrough: true };
}

/** Pure composition step; unit-testable without Frida. */
export function composeAgentSource(opts: AgentScriptOptions): ComposedAgentSource {
  if (isFridaCompileBundle(opts.source)) {
    return passthroughOf(opts);
  }
  const { bridges, body } = classicPartsOf(opts);
  const parts: string[] = [
    buildPreamble({ name: opts.name, platform: opts.platform, options: opts.options ?? {}, injectedBridges: bridges }),
  ];
  for (const bridge of bridges) {
    parts.push(loadBridgeSource(bridge));
  }
  parts.push(body);
  return { source: parts.join('\n'), name: opts.name, bridges, passthrough: false };
}

/**
 * Live source for a script created from a session snapshot that already holds the static
 * preamble and the bridges for `bridges`: context literal + installer call + body.
 */
export function composeSnapshotLiveSource(opts: AgentScriptOptions): ComposedAgentSource {
  if (isFridaCompileBundle(opts.source)) {
    return passthroughOf(opts);
  }
  const { bridges, body } = classicPartsOf(opts);
  const parts: string[] = [
    buildDynamicPreamble({ name: opts.name, platform: opts.platform, options: opts.options ?? {}, injectedBridges: bridges }),
  ];
  if (bridges.length > 0) {
    parts.push(bridgeInstallerCall());
  }
  parts.push(body);
  return { source: parts.join('\n'), name: opts.name, bridges, passthrough: false };
}

/** Per-script runtime override, then `FRIDA_MCP_RUNTIME`, else the server default. */
export function resolveScriptRuntime(requested?: ScriptRuntime): ScriptRuntime {
  if (requested && requested !== 'default') return requested;
  const fromEnv = process.env.FRIDA_MCP_RUNTIME;
  if (fromEnv === 'v8' || fromEnv === 'qjs') return fromEnv;
  return 'default';
}

/** Explicit option, then `FRIDA_MCP_SNAPSHOTS`, then config `snapshots`; off by default. */
export function snapshotsEnabled(explicit?: boolean): boolean {
  if (explicit !== undefined) return explicit;
  return parseBooleanFlag(process.env.FRIDA_MCP_SNAPSHOTS) ?? getActiveConfig()?.snapshots ?? false;
}

async function snapshotFor(opts: AgentScriptOptions, bridges: BridgeName[], runtime: ScriptRuntime): Promise<Buffer | null> {
  if (!opts.sessionEntry || !snapshotsEnabled(opts.useSnapshot)) return null;
  return getOrCreateSessionSnapshot(opts.sessionEntry, { platform: opts.platform, bridges, runtime });
}

/** Compose and create (but do not load) a script on the given session. */
export async function createAgentScript(session: frida.Session, opts: AgentScriptOptions): Promise<frida.Script> {
  const composed = composeAgentSource(opts);
  const runtime = resolveScriptRuntime(opts.runtime);
  const scriptOptions: frida.ScriptOptions = { name: composed.name };
  if (runtime !== 'default') {
    scriptOptions.runtime = runtime as frida.ScriptRuntime;
  }
  const snapshot = composed.passthrough ? null : await snapshotFor(opts, composed.bridges, runtime);
  if (!snapshot) {
    return session.createScript(composed.source, scriptOptions);
  }
  scriptOptions.snapshot = snapshot;
  return session.createScript(composeSnapshotLiveSource(opts).source, scriptOptions);
}
