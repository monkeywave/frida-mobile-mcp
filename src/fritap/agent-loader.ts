/**
 * Locates, validates and configures the friTap Frida agent.
 *
 * friTap (https://github.com/fkie-cad/friTap) ships its agent as a frida-compile bundle
 * (`friTap/fritap_agent.js`, starts with the 📦 marker). The bundle is self-contained
 * (it embeds frida-java-bridge / frida-objc-bridge) and is loaded through
 * createAgentScript's passthrough path.
 *
 * Discovery order:
 *   1. FRITAP_AGENT_PATH env
 *   2. the installed Python package (python3 -c "import friTap, os; print(...)")
 *   3. ~/.config/frida-mobile-mcp/fritap/<version>/fritap_agent.js (cache)
 *   4. download from GitHub (only when allowDownload is true)
 *
 * Integrity: when a sha256 pin exists for the tag (built-in PINNED_AGENT_SHA256 or
 * FRITAP_AGENT_SHA256), both the cached bundle (3) and a download (4) are verified against it;
 * a mismatching cache entry is ignored and re-downloaded. FRITAP_AGENT_PATH (1) and the pip
 * package (2) are local, user-chosen sources and are trusted as-is (not verified).
 *
 * Handshake (what friTap's Python side does, see ssl_logger_core / legacy/message_handler):
 * the agent drives the configuration itself during script.load(). It calls
 * `send("config_batch")` and blocks in `recv("config_batch").wait()`, then `send("anti")`
 * and waits for a message of type `antiroot`. Older bundles ask per field
 * (`experimental`, `defaultFD`, `socket_tracing`, `pattern_hooking`, `offset_hooking`, ...)
 * and expect a reply with the same type name. Hooks are installed automatically at the
 * end of the bundle; nothing has to be called via rpc after load. `rpc.exports` offers
 * `agentAbiVersion()` (currently 2) and `gracefulDetach()`.
 */
import { execFile } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import type frida from 'frida';
import { FRIDA_COMPILE_BUNDLE_MARKER } from '../agent/script-factory.js';
import { sha256Hex } from '../helpers/sanitize.js';
import { FritapAgentUnavailableError } from '../helpers/errors.js';
import { log } from '../helpers/logger.js';
import { PINNED_AGENT_SHA256 } from './constants.js';

export const DEFAULT_FRITAP_VERSION = 'v2.5.2';
export const FRITAP_AGENT_FILENAME = 'fritap_agent.js';
export const FRITAP_AGENT_ABI_VERSION = 2;
const PYTHON_PROBE_TIMEOUT_MS = 5_000;
const DOWNLOAD_TIMEOUT_MS = 60_000;
const PYTHON_CANDIDATES = ['python3', 'python'];

export type FritapAgentOrigin = 'env' | 'python' | 'cache' | 'download';

export interface LocatedFritapAgent {
  path: string;
  source: string;
  /** Version string: friTap.__version__ for the Python package, the git tag for downloads, 'unknown' for env paths. */
  version: string;
  origin: FritapAgentOrigin;
}

export interface LocateOptions {
  allowDownload?: boolean;
  /** Git tag to download / cache key. Defaults to FRITAP_VERSION or DEFAULT_FRITAP_VERSION. */
  version?: string;
  env?: NodeJS.ProcessEnv;
  cacheDir?: string;
  fetchImpl?: typeof fetch;
  /** Skip the Python package probe (tests). */
  skipPython?: boolean;
}

export function fritapCacheDir(version: string, env: NodeJS.ProcessEnv = process.env): string {
  const base = env.XDG_CONFIG_HOME || path.join(homedir(), '.config');
  return path.join(base, 'frida-mobile-mcp', 'fritap', version);
}

export function fritapDownloadUrl(version: string): string {
  return `https://raw.githubusercontent.com/fkie-cad/friTap/${version}/friTap/${FRITAP_AGENT_FILENAME}`;
}

/** Normalise a version to a git tag: '2.5.2' -> 'v2.5.2', 'main' stays 'main'. */
export function toFritapTag(version: string): string {
  return /^\d+\.\d+/.test(version) ? `v${version}` : version;
}

export function isValidFritapBundle(source: string): boolean {
  return source.startsWith(FRIDA_COMPILE_BUNDLE_MARKER);
}

/** Find the friTap agent bundle, trying env, Python package, cache and (optionally) download. */
export async function locateFritapAgent(options: LocateOptions = {}): Promise<LocatedFritapAgent> {
  const env = options.env ?? process.env;
  const version = toFritapTag(options.version ?? env.FRITAP_VERSION ?? DEFAULT_FRITAP_VERSION);
  const searched: string[] = [];

  const fromEnv = loadFromEnv(env, searched);
  if (fromEnv) return fromEnv;

  if (!options.skipPython) {
    const fromPython = await loadFromPythonPackage(searched);
    if (fromPython) return fromPython;
  }

  const cacheDir = options.cacheDir ?? fritapCacheDir(version, env);
  const cachedPath = path.join(cacheDir, FRITAP_AGENT_FILENAME);
  const fromCache = loadFromCache(cachedPath, version, env, searched);
  if (fromCache) return fromCache;

  if (!options.allowDownload) {
    throw new FritapAgentUnavailableError(
      'no bundle found via FRITAP_AGENT_PATH, the friTap Python package or the download cache (allow_download is false)',
      searched
    );
  }
  return downloadBundle(version, cachedPath, options.fetchImpl ?? fetch, searched, env);
}

function loadFromEnv(env: NodeJS.ProcessEnv, searched: string[]): LocatedFritapAgent | null {
  const envPath = env.FRITAP_AGENT_PATH;
  if (!envPath) return null;
  const bundle = readBundle(envPath, 'unknown', 'env', searched);
  if (!bundle) {
    throw new FritapAgentUnavailableError(
      `FRITAP_AGENT_PATH=${envPath} does not point to a readable frida-compile bundle (expected the 📦 marker)`,
      searched
    );
  }
  return bundle;
}

async function loadFromPythonPackage(searched: string[]): Promise<LocatedFritapAgent | null> {
  const packageDir = await findFritapPackageDir();
  if (!packageDir) {
    searched.push('python package friTap (not importable)');
    return null;
  }
  const bundlePath = path.join(packageDir, FRITAP_AGENT_FILENAME);
  const version = (await readFritapPythonVersion()) ?? 'unknown';
  return readBundle(bundlePath, version, 'python', searched);
}

function readBundle(file: string, version: string, origin: FritapAgentOrigin, searched: string[]): LocatedFritapAgent | null {
  searched.push(file);
  if (!existsSync(file)) return null;
  let source: string;
  try {
    source = readFileSync(file, 'utf8');
  } catch (err) {
    log('warn', `friTap agent at ${file} could not be read: ${String(err)}`);
    return null;
  }
  if (!isValidFritapBundle(source)) {
    log('warn', `friTap agent at ${file} is not a frida-compile bundle (missing 📦 marker)`);
    return null;
  }
  return { path: file, source, version, origin };
}

/** The cached bundle, or null when absent or when it does not match the tag's sha256 pin. */
function loadFromCache(cachedPath: string, version: string, env: NodeJS.ProcessEnv, searched: string[]): LocatedFritapAgent | null {
  const bundle = readBundle(cachedPath, version, 'cache', searched);
  if (!bundle) return null;
  const expected = expectedAgentSha256(version, env);
  if (!expected) return bundle;
  const actual = sha256Hex(bundle.source);
  if (actual === expected) return bundle;
  log('warn', `Ignoring cached friTap agent ${cachedPath}: sha256 ${actual} does not match the pin ${expected}`);
  return null;
}

async function downloadBundle(
  version: string,
  cachedPath: string,
  fetchImpl: typeof fetch,
  searched: string[],
  env: NodeJS.ProcessEnv = process.env
): Promise<LocatedFritapAgent> {
  const url = fritapDownloadUrl(version);
  log('info', `Downloading friTap agent ${version} from ${url}`);
  let source: string;
  try {
    const response = await fetchImpl(url, { signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS) });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }
    source = await response.text();
  } catch (err) {
    throw new FritapAgentUnavailableError(`download of ${url} failed: ${err instanceof Error ? err.message : String(err)}`, searched);
  }
  if (!isValidFritapBundle(source)) {
    throw new FritapAgentUnavailableError(`downloaded file from ${url} is not a frida-compile bundle`, searched);
  }
  verifyDownloadedBundle(source, version, url, env, searched);
  mkdirSync(path.dirname(cachedPath), { recursive: true });
  writeFileSync(cachedPath, source, 'utf8');
  return { path: cachedPath, source, version, origin: 'download' };
}

/**
 * Expected sha256 for a tag: a bare `FRITAP_AGENT_SHA256` hash applies to the selected
 * `FRITAP_VERSION` tag and overrides the built-in PINNED_AGENT_SHA256 map. Null when nothing is pinned.
 */
export function expectedAgentSha256(version: string, env: NodeJS.ProcessEnv = process.env): string | null {
  const override = env.FRITAP_AGENT_SHA256?.trim().toLowerCase();
  if (override) return override;
  return PINNED_AGENT_SHA256[version]?.toLowerCase() ?? null;
}

/** Reject a downloaded bundle whose sha256 differs from the pin; warn when no pin exists. Nothing is cached on rejection. */
function verifyDownloadedBundle(source: string, version: string, url: string, env: NodeJS.ProcessEnv, searched: string[]): void {
  const expected = expectedAgentSha256(version, env);
  if (!expected) {
    log('warn', `No sha256 pin for friTap agent ${version}; accepting the download unverified. Set FRITAP_AGENT_SHA256 to pin it.`);
    return;
  }
  const actual = sha256Hex(source);
  if (actual === expected) return;
  throw new FritapAgentUnavailableError(
    `sha256 mismatch for ${url}: expected ${expected}, got ${actual}. The download was discarded. ` +
      'If you trust this build, set FRITAP_AGENT_SHA256 to the new hash; otherwise use FRITAP_AGENT_PATH or pip install friTap.',
    searched
  );
}

/** Directory of the installed friTap Python package, or null when it cannot be imported. */
export async function findFritapPackageDir(): Promise<string | null> {
  const output = await runPython('import friTap, os; print(os.path.dirname(friTap.__file__))');
  return output ? output.trim() : null;
}

export async function readFritapPythonVersion(): Promise<string | null> {
  const output = await runPython(
    'import friTap\n' +
    'v = getattr(friTap, "__version__", None)\n' +
    'if not v:\n' +
    '    from importlib.metadata import version\n' +
    '    v = version("friTap")\n' +
    'print(v)'
  );
  return output ? output.trim() : null;
}

async function runPython(code: string): Promise<string | null> {
  for (const python of PYTHON_CANDIDATES) {
    const output = await execFileWithTimeout(python, ['-c', code]);
    if (output !== null) return output;
  }
  return null;
}

function execFileWithTimeout(command: string, args: string[]): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(command, args, { timeout: PYTHON_PROBE_TIMEOUT_MS, encoding: 'utf8' }, (err, stdout) => {
      if (err) {
        log('debug', `${command} probe failed: ${err.message}`);
        resolve(null);
        return;
      }
      resolve(stdout);
    });
  });
}

// ---------------------------------------------------------------------------
// Agent configuration handshake
// ---------------------------------------------------------------------------

export interface FritapAgentOptions {
  /** Install friTap's Android anti-root hooks. */
  antiRoot?: boolean;
  /** Also capture plaintext records (friTap's "pcap" channel, datalog messages). */
  fullCapture?: boolean;
  /** Emit NSS key log lines (default true). */
  keylog?: boolean;
  /** Whether the target was spawned (lets the agent skip the loader hook under anti-tamper). */
  spawned?: boolean;
  /** Enable friTap's experimental hooks. */
  experimental?: boolean;
  /** Custom byte patterns, as friTap's pattern.json contents (object or JSON string). */
  patterns?: unknown;
  /** Custom offsets, as friTap's offsets JSON (object or JSON string). */
  offsets?: unknown;
  /** Verbose agent debugging output. */
  debugOutput?: boolean;
}

/** Fields friTap's Python side sends in the `config_batch` reply (ssl_logger_core.py). */
export function buildFritapConfigBatch(options: FritapAgentOptions): Record<string, unknown> {
  return {
    offsets: options.offsets === undefined ? null : asJsonString(options.offsets),
    patterns: options.patterns === undefined ? null : asJsonString(options.patterns),
    socket_tracing: false,
    defaultFD: false,
    experimental: options.experimental ?? false,
    protocol_select: 'tls',
    install_lsass_hook: true,
    use_modern: false,
    library_scan: null,
    library_scan_enabled: false,
    ohttp_enabled: true,
    quic_capture_mode: 'stream',
    quic_only: false,
    no_loader_hook: false,
    spawned: options.spawned ?? false,
    stealth_loader: false,
    pairip_safe: false,
    probe: false,
    force_anchor_locator: false,
    quic_egress_headers_layer: 'auto',
    debug_output: options.debugOutput ?? false,
    pcap_enabled: options.fullCapture ?? false,
    keylog_enabled: options.keylog ?? true,
    extensions: {},
  };
}

function asJsonString(value: unknown): string {
  return typeof value === 'string' ? value : JSON.stringify(value);
}

/**
 * Legacy per-field handshake channels (older friTap bundles). The agent sends the
 * channel name as a bare string and waits for a message of the same type.
 */
const LEGACY_CHANNEL_REPLIES: Record<string, (o: FritapAgentOptions) => unknown> = {
  experimental: (o) => o.experimental ?? false,
  defaultFD: () => false,
  socket_tracing: () => false,
  pattern_hooking: (o) => (o.patterns === undefined ? null : asJsonString(o.patterns)),
  offset_hooking: (o) => (o.offsets === undefined ? null : asJsonString(o.offsets)),
  install_lsass_hook: () => true,
  protocol_select: () => 'tls',
  library_scan: () => null,
  use_modern: () => false,
};

export interface HandshakeReply {
  type: string;
  payload: unknown;
}

/** True when a `send()` payload is one of the agent's bare-string handshake requests. */
export function isFritapHandshakeRequest(payload: unknown): payload is string {
  return typeof payload === 'string' && (payload === 'config_batch' || payload === 'anti' || payload in LEGACY_CHANNEL_REPLIES);
}

/** Compute the reply the agent expects for a handshake request, or null if it is not one. */
export function fritapHandshakeReply(payload: unknown, options: FritapAgentOptions): HandshakeReply | null {
  if (typeof payload !== 'string') return null;
  if (payload === 'config_batch') return { type: 'config_batch', payload: buildFritapConfigBatch(options) };
  if (payload === 'anti') return { type: 'antiroot', payload: options.antiRoot ?? false };
  const legacy = Object.prototype.hasOwnProperty.call(LEGACY_CHANNEL_REPLIES, payload) ? LEGACY_CHANNEL_REPLIES[payload] : undefined;
  if (legacy) return { type: payload, payload: legacy(options) };
  return null;
}

export interface FritapHandshakeState {
  /** Channels the agent asked for, in order. */
  answered: string[];
  /** Resolves once the agent requested and received its configuration. */
  configured: Promise<void>;
}

/**
 * Install the configuration handshake on a freshly created (not yet loaded) friTap script.
 * Must be called before `script.load()`; the agent blocks in `recv().wait()` until answered.
 * The returned promise resolves after the `config_batch` reply (or the first legacy reply)
 * has been posted, so callers can detect a bundle that never asked for configuration.
 */
export function configureFritapAgent(script: frida.Script, options: FritapAgentOptions): FritapHandshakeState {
  const answered: string[] = [];
  let resolveConfigured: () => void = () => {};
  const configured = new Promise<void>((resolve) => { resolveConfigured = resolve; });

  script.message.connect((message: frida.Message) => {
    if (message.type !== 'send') return;
    const reply = fritapHandshakeReply(message.payload, options);
    if (!reply) return;
    answered.push(message.payload as string);
    script.post(reply);
    log('debug', `friTap handshake: answered ${message.payload} with type=${reply.type}`);
    if (reply.type !== 'antiroot') resolveConfigured();
  });

  return { answered, configured };
}

type RpcExports = Record<string, (() => Promise<unknown>) | undefined>;

/** Read the agent ABI version through rpc; returns null when the bundle has no such export. */
export async function readFritapAbiVersion(script: frida.Script, timeoutMs = 5_000): Promise<number | null> {
  const result = await callOptionalRpc(script, 'agentAbiVersion', timeoutMs);
  return typeof result === 'number' ? result : null;
}

/** Ask the agent to release its hooks before unloading (best effort). */
export async function gracefulDetachFritap(script: frida.Script, timeoutMs = 5_000): Promise<void> {
  await callOptionalRpc(script, 'gracefulDetach', timeoutMs);
}

async function callOptionalRpc(script: frida.Script, name: string, timeoutMs: number): Promise<unknown> {
  try {
    const fn = (script.exports as unknown as RpcExports)[name];
    if (typeof fn !== 'function') return null;
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<null>((resolve) => { timer = setTimeout(() => resolve(null), timeoutMs); });
    return await Promise.race([fn(), timeout]).finally(() => { if (timer) clearTimeout(timer); });
  } catch (err) {
    log('debug', `${name} rpc failed: ${String(err)}`);
    return null;
  }
}
