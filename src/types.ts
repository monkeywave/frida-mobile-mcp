import type frida from 'frida';

// Session entry stored in state
export interface SessionEntry {
  id: string;               // UUID
  session: frida.Session;
  pid: number;
  deviceId: string;
  target: string;           // app bundle ID or process name
  platform: 'android' | 'ios' | 'linux' | 'macos' | 'windows' | 'unknown';
  scripts: Map<string, ScriptEntry>;
  createdAt: number;
  lastActivityAt?: number;  // updated on message receipt and on every tool use (state.touchSession)
  device?: frida.Device;    // cached frida.Device the session lives on
  detachReason?: string;    // set by the detach handler right before removal
  crash?: CrashSummary;     // set by the detach handler when frida reports a crash
  /** Script-runtime snapshots keyed by snapshotCacheKey() (src/agent/snapshots.ts); never retried once created. */
  snapshots?: Map<string, Buffer>;
  /** Snapshot cache keys whose creation failed on this session (unsupported runtime etc.); not retried. */
  snapshotFailures?: Set<string>;
}

export interface ScriptEntry {
  id: string;               // UUID
  script: frida.Script;
  messages: MessageEntry[];
  name?: string;
  persistent: boolean;      // whether script stays loaded
  createdAt: number;
  nextMessageIndex?: number; // monotonic per-script counter (survives buffer trimming)
  eternalized?: boolean;    // script.eternalize() was called: it survives detach but can no longer be messaged or unloaded
}

// Crash information as reported by frida (device.processCrashed / session.detached)
export interface CrashSummary {
  pid: number;
  processName: string;
  summary: string;
  report?: string;
}

// Record of a session detach or a process crash, kept in state.recentDetaches
export interface DetachRecord {
  sessionId: string | null;  // null for crashes not tied to a known session
  target: string;
  pid: number;
  deviceId: string;
  reason: string;            // SessionDetachReason string or 'process-crashed'
  crash: CrashSummary | null;
  timestamp: number;
}

export interface MessageEntry {
  /** Per-script counter (survives buffer trimming); kept for display/back-compat. */
  index: number;
  /**
   * Session-global monotonic sequence number across all scripts. Pagination cursors use
   * this so merging messages from several scripts can neither skip nor duplicate entries
   * (per-script `index` values collide across scripts and cannot order a merged stream).
   */
  seq: number;
  timestamp: number;
  type: string;
  payload: unknown;
  data: Buffer | null;
}

export interface HookEntry {
  id: string;
  scriptId: string;
  sessionId: string;
  target: string;
  type: 'native' | 'java' | 'objc';
  invocations: HookInvocation[];
  status: 'active' | 'completed' | 'error';
  createdAt: number;
  liveness?: HookLiveness;
}

/**
 * Whether a hook actually attached, and whether it has ever fired. The point is to
 * turn a silent miss — a hook that installs but never runs because the hypothesis was
 * wrong (wrong class, wrong overload, class not loaded) — into first-class feedback the
 * AI can read, instead of leaving it to infer failure from `invocations: 0`.
 */
export interface HookLiveness {
  installed: boolean;           // did the agent attach the interceptor / implementation
  classResolved?: boolean;      // java/objc: was the target class found (in any loader)
  overloadsMatched?: number;    // java: how many method overloads were instrumented
  availableOverloads?: string[]; // java OVERLOAD_MISMATCH: signatures of the overloads that exist
  matches?: number;             // objc: how many classes/selectors matched
  firstSeenTs?: number | null;  // when the hook first fired; null = installed but never hit
  reason?: HookMissReason;      // populated when installed === false
}

export type HookMissReason =
  | 'CLASS_NOT_LOADED'   // java/objc: class is not present in any loaded class loader (yet)
  | 'NO_SUCH_METHOD'     // java/objc: class found, but the method/selector does not exist
  | 'OVERLOAD_MISMATCH'  // java: method found, but no overload matched the requested signature
  | 'NO_EXPORT'          // native: the module!symbol / address could not be resolved
  | 'NO_RUNTIME';        // the Java/ObjC runtime is not available in this process

export interface HookInvocation {
  timestamp: number;
  threadId: number;
  args: unknown[];
  retval: unknown;
  backtrace: string[] | null;
}

export interface TraceEntry {
  id: string;
  scriptId: string;
  sessionId: string;
  targets: string[];
  callCount: number;
  startedAt: number;
}

/**
 * A persistent coverage run (trace_coverage): a broad set of cheap entry-hooks whose purpose is
 * not to log calls but to answer "which of these targets have I reached, and which are still
 * COLD?" — the reachability signal for a drive loop. `allTargets` is the full installed set
 * captured when the run is armed; a target is added to `hits` the first time it fires (the agent
 * dedupes, so `hits.hits` is always 1 — a "reached" marker, not a call count) and accumulates
 * across `trigger_and_wait` drives. Cold = `allTargets` minus `hits.keys()`. `firstSeenTs` mirrors
 * HookLiveness's "fired" convention.
 */
export interface CoverageEntry {
  id: string;
  scriptId: string;
  sessionId: string;
  scope: string;
  allTargets: string[];
  hits: Map<string, { hits: number; firstSeenTs: number }>;
  createdAt: number;
}

/**
 * A persistent crypto oracle (monitor_crypto): a wide net of crypto-sink hooks that streams
 * `crypto_event` messages as the app encrypts/decrypts. Tracked like the other persistent
 * instruments so an agent can resolve the `oracle_id` it was handed, see how many events it has
 * captured via get_status, and have it torn down on unload_script / session stop. `eventCount`
 * counts only `crypto_event` messages (init/status messages are excluded).
 */
export interface OracleEntry {
  id: string;
  scriptId: string;
  sessionId: string;
  pattern: string;
  eventCount: number;
  lastEventTs?: number;
  createdAt: number;
}

// Tool return value structure.
// evidence_id / limitations / coverage follow the REA/ReVa evidence conventions so that
// results from this server can be cited next to static-analysis findings.
export interface ToolResult<T = unknown> {
  result: T;
  session_context: SessionContext;
  suggested_next: SuggestedAction[];
  /** Unique id (uuid) for this tool invocation's evidence; always set by buildResult. */
  evidence_id?: string;
  /** Known gaps of this result (truncation, filtered output, unsupported platform ...). */
  limitations?: string[];
  /** Whether the result is known to be complete or coverage is unknown. */
  coverage?: EvidenceCoverage;
  /** Optional raw provider output when the caller wants to keep the unprocessed data. */
  raw_result?: unknown;
}

export interface EvidenceCoverage {
  status: 'complete' | 'unknown';
  note?: string;
}

/** Options accepted by buildResult's third argument. */
export interface EvidenceMeta {
  limitations?: string[];
  coverage?: EvidenceCoverage;
  raw_result?: unknown;
}

export interface SessionContext {
  device: string | null;
  platform: string | null;
  active_sessions: Array<{
    id: string;
    target: string;
    pid: number;
  }>;
  active_hooks: number;
  active_oracles: number;
  active_scripts: number;
  last_detach?: {
    target: string;
    reason: string;
    crash_summary: string | null;
    timestamp: number;
  } | null;
}

export interface SuggestedAction {
  tool: string;
  args?: Record<string, unknown>;
  reason: string;
  condition?: string;
  priority?: 'required' | 'recommended' | 'optional';
}

// Error types
export type ErrorCategory = 'request' | 'authorization' | 'capability' | 'timeout' | 'resource' | 'provider';

export interface ErrorResponse {
  error: {
    code: string;
    category: ErrorCategory;
    message: string;
    retryable: boolean;
    remediation?: string;
    recovery_actions: RecoveryAction[];
    context?: Record<string, unknown>;
  };
}

export interface RecoveryAction {
  tool?: string;
  args?: Record<string, unknown>;
  action?: string;
  reason?: string;
  message?: string;
}

export type ScriptCategory = 'bypass' | 'enumeration' | 'security' | 'network' | 'crypto' | 'filesystem' | 'detection';

// Script template
export interface ScriptTemplate {
  name: string;
  description: string;
  platforms: Array<'android' | 'ios'>;
  category: ScriptCategory;
  riskTier: 1 | 2 | 3;
  options?: Record<string, ScriptOption>;
  /**
   * Whether this template, given these options, writes to the target's memory and must therefore
   * be gated on `memoryWriteEnabled`. Returns the reason (used verbatim as the refusal detail)
   * when a write is required, or null when the invocation is observe-only. Observe-only templates
   * omit this entirely. Keeps the "which options write memory" policy with the template that
   * owns those options, instead of a magic option check in the run_prebuilt_script tool.
   */
  requiresMemoryWrite?: (options: Record<string, unknown>) => string | null;
  generate: (options: Record<string, unknown>, context?: PlatformContext) => string;
}

export interface ScriptOption {
  type: 'string' | 'boolean' | 'number' | 'array';
  description: string;
  default?: unknown;
  required?: boolean;
}

export interface PlatformContext {
  platform: 'android' | 'ios' | 'unknown';
  apiLevel?: number;
  osVersion?: string;
  arch?: string;
}

// Device info
export interface DeviceInfo {
  id: string;
  name: string;
  type: string;
  platform?: string;
  os?: string;
  arch?: string;
}

// Config types
export interface FridaMcpConfig {
  allowCustomScripts: boolean;
  memoryWriteEnabled: boolean;
  /**
   * Allow the `adb_shell` tool to run arbitrary shell commands on a device. DISABLED by
   * default: it is arbitrary command execution. Env: `FRIDA_MCP_ALLOW_ADB_SHELL=0|1`.
   */
  allowAdbShell: boolean;
  /**
   * Allow the `inject_library` tool to load a native library (.so/.dylib) into a target via
   * Frida's injector. DISABLED by default: it runs arbitrary native code in the target. Kept
   * separate from `allowCustomScripts` (which gates JS agents) so native injection can be
   * granted or withheld independently. Env: `FRIDA_MCP_ALLOW_NATIVE_INJECTION=0|1`.
   */
  allowNativeInjection: boolean;
  allowedDevices: string[];
  maxSessions: number;
  sessionTimeoutMinutes: number;
  maxMessageBuffer: number;
  auditLogPath: string;
  mobileMcp: MobileMcpConfig;
  rateLimits: RateLimitConfig;
  /**
   * Pre-warm a script-runtime snapshot of the preamble + bridges per session so the ~300 KB
   * Java/ObjC bridge is not re-sent and re-evaluated for every script. Requires the V8 runtime
   * (`FRIDA_MCP_RUNTIME=v8`); QuickJS cannot snapshot. Env: `FRIDA_MCP_SNAPSHOTS=0|1`.
   */
  snapshots?: boolean;
}

export interface MobileMcpConfig {
  enabled: boolean;
  command: string;
  args: string[];
}

export interface RateLimitConfig {
  scriptsPerMinute: number;
  memoryReadsPerMinute: number;
  sessionsPerMinute: number;
}
