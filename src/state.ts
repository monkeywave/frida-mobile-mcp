import frida from 'frida';
import { randomUUID } from 'node:crypto';
import { log } from './helpers/logger.js';
import type {
  FridaMcpConfig,
  SessionEntry,
  HookEntry,
  TraceEntry,
  CoverageEntry,
  OracleEntry,
  ScriptEntry,
  MessageEntry,
  SessionContext,
  DetachRecord,
  CrashSummary,
} from './types.js';

const MAX_RECENT_DETACHES = 20;
const CLEANUP_INTERVAL_MS = 60_000;

class ServerState {
  /** Platform per device id, filled by DeviceManager.detectPlatform(). */
  readonly devicePlatforms = new Map<string, string>();

  setDevicePlatform(deviceId: string, platform: string): void {
    this.devicePlatforms.set(deviceId, platform);
  }

  deviceManager: frida.DeviceManager;
  selectedDevice: frida.Device | null = null;
  sessions: Map<string, SessionEntry> = new Map();
  hooks: Map<string, HookEntry> = new Map();
  traces: Map<string, TraceEntry> = new Map();
  coverage: Map<string, CoverageEntry> = new Map();
  oracles: Map<string, OracleEntry> = new Map();
  config: FridaMcpConfig;
  /** Ring buffer (newest last) of recent session detaches and process crashes. */
  recentDetaches: DetachRecord[] = [];
  private lastCleanupAt: number = 0;
  private cleanupTimer: NodeJS.Timeout | null = null;
  private crashWatchedDevices: Set<string> = new Set();
  /** Session-global monotonic message counter; see MessageEntry.seq. */
  private messageSeq: number = 0;
  /** Pending waiters resolved as messages arrive; see waitForNewMessages. */
  private messageWaiters: Set<MessageWaiter> = new Set();

  constructor(config: FridaMcpConfig) {
    this.deviceManager = frida.getDeviceManager();
    this.config = config;
  }

  generateId(): string {
    return randomUUID();
  }

  /** Throws when no further session can be created. Call BEFORE spawning/attaching. */
  ensureSessionCapacity(): void {
    if (this.sessions.size >= this.config.maxSessions) {
      throw new Error(
        `Maximum session limit reached (${this.config.maxSessions}). ` +
        `Use stop_instrumentation to clean up existing sessions.`
      );
    }
  }

  addSession(entry: SessionEntry): void {
    this.ensureSessionCapacity();
    if (entry.lastActivityAt === undefined) {
      entry.lastActivityAt = entry.createdAt;
    }
    this.sessions.set(entry.id, entry);
  }

  getSession(sessionId: string): SessionEntry | undefined {
    return this.sessions.get(sessionId);
  }

  /** Mark a session as recently used so idle expiry is based on real activity. */
  touchSession(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.lastActivityAt = Date.now();
    }
  }

  /**
   * Remove a session and everything that belongs to it.
   * The session, its hooks and traces are dropped from the maps synchronously so
   * callers that do not await see a consistent state; the scripts are unloaded
   * best-effort and the returned promise resolves once that has been attempted.
   */
  removeSession(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return Promise.resolve();

    this.sessions.delete(sessionId);
    this.dropHooksForSession(sessionId);
    this.dropTracesForSession(sessionId);
    this.dropCoverageForSession(sessionId);
    this.dropOraclesForSession(sessionId);

    return unloadScripts(session);
  }

  private dropHooksForSession(sessionId: string): void {
    for (const [hookId, hook] of this.hooks) {
      if (hook.sessionId === sessionId) {
        this.hooks.delete(hookId);
      }
    }
  }

  private dropTracesForSession(sessionId: string): void {
    for (const [traceId, trace] of this.traces) {
      if (trace.sessionId === sessionId) {
        this.traces.delete(traceId);
      }
    }
  }

  private dropCoverageForSession(sessionId: string): void {
    for (const [coverageId, entry] of this.coverage) {
      if (entry.sessionId === sessionId) {
        this.coverage.delete(coverageId);
      }
    }
  }

  private dropOraclesForSession(sessionId: string): void {
    for (const [oracleId, entry] of this.oracles) {
      if (entry.sessionId === sessionId) {
        this.oracles.delete(oracleId);
      }
    }
  }

  addMessageToScript(sessionId: string, scriptId: string, message: Omit<MessageEntry, 'index' | 'seq'>): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    const script = session.scripts.get(scriptId);
    if (!script) return;

    const index = nextMessageIndex(script);
    const seq = ++this.messageSeq;
    script.messages.push({ ...message, index, seq });
    session.lastActivityAt = Date.now();

    // Batch eviction: trim when 10% over limit to avoid splice on every message
    const evictionThreshold = Math.floor(this.config.maxMessageBuffer * 1.1);
    if (script.messages.length > evictionThreshold) {
      script.messages = script.messages.slice(-this.config.maxMessageBuffer);
    }

    this.notifyMessageWaiters();
  }

  /** The current global message cursor; pass to waitForNewMessages as the "after" point. */
  currentMessageSeq(): number {
    return this.messageSeq;
  }

  /** Count messages in a session whose global seq is strictly greater than `afterSeq`. */
  countMessagesSince(sessionId: string, afterSeq: number): number {
    const session = this.sessions.get(sessionId);
    if (!session) return 0;
    let count = 0;
    for (const script of session.scripts.values()) {
      for (const m of script.messages) if (m.seq > afterSeq) count++;
    }
    return count;
  }

  /**
   * Resolve once a session has at least `minCount` messages with seq > `afterSeq`, or after
   * `timeoutMs`. This is the event-driven half of trigger_and_wait: perform a UI action, then
   * wait to learn whether it actually drove any instrumented code (a hook firing) — turning
   * "tap and poll blindly" into a single correlated round-trip. Resolves `true` if the count
   * was reached, `false` on timeout.
   */
  waitForNewMessages(sessionId: string, afterSeq: number, minCount: number, timeoutMs: number): Promise<boolean> {
    if (this.countMessagesSince(sessionId, afterSeq) >= minCount) return Promise.resolve(true);
    return new Promise<boolean>((resolve) => {
      const waiter: MessageWaiter = {
        check: () => this.countMessagesSince(sessionId, afterSeq) >= minCount,
        settle: (reached: boolean) => {
          if (waiter.done) return;
          waiter.done = true;
          clearTimeout(timer);
          this.messageWaiters.delete(waiter);
          resolve(reached);
        },
        done: false,
      };
      const timer = setTimeout(() => waiter.settle(false), timeoutMs);
      timer.unref?.();
      this.messageWaiters.add(waiter);
    });
  }

  private notifyMessageWaiters(): void {
    if (this.messageWaiters.size === 0) return;
    for (const waiter of [...this.messageWaiters]) {
      if (waiter.check()) waiter.settle(true);
    }
  }

  findSessionByTarget(target: string): SessionEntry | undefined {
    for (const session of this.sessions.values()) {
      if (session.target === target || session.pid.toString() === target) {
        return session;
      }
    }
    return undefined;
  }

  findSessionByPid(deviceId: string, pid: number): SessionEntry | undefined {
    for (const session of this.sessions.values()) {
      if (session.deviceId === deviceId && session.pid === pid) {
        return session;
      }
    }
    return undefined;
  }

  /** Append a detach/crash record to the bounded ring buffer. */
  recordDetach(record: DetachRecord): void {
    this.recentDetaches.push(record);
    if (this.recentDetaches.length > MAX_RECENT_DETACHES) {
      this.recentDetaches.splice(0, this.recentDetaches.length - MAX_RECENT_DETACHES);
    }
  }

  /** Record a crash reported by `device.processCrashed` and annotate the matching session. */
  recordCrash(deviceId: string, crash: CrashSummary): void {
    const session = this.findSessionByPid(deviceId, crash.pid);
    if (session) {
      session.crash = crash;
    }
    this.recordDetach({
      sessionId: session?.id ?? null,
      target: session?.target ?? crash.processName,
      pid: crash.pid,
      deviceId,
      reason: 'process-crashed',
      crash,
      timestamp: Date.now(),
    });
    log('warn', `Process ${crash.processName} (PID ${crash.pid}) crashed on ${deviceId}: ${crash.summary}`);
  }

  /** Subscribe to `processCrashed` exactly once per device. */
  watchDeviceCrashes(device: frida.Device): void {
    if (this.crashWatchedDevices.has(device.id)) return;
    this.crashWatchedDevices.add(device.id);
    try {
      device.processCrashed.connect((crash: frida.Crash) => {
        const summary = toCrashSummary(crash);
        if (summary) this.recordCrash(device.id, summary);
      });
    } catch (err) {
      this.crashWatchedDevices.delete(device.id);
      log('debug', `Could not subscribe to crash events on ${device.id}: ${String(err)}`);
    }
  }

  getSessionContext(): SessionContext {
    this.cleanupExpiredSessions().catch(() => { /* best-effort */ });
    const lastDetach = this.recentDetaches[this.recentDetaches.length - 1];
    return {
      device: this.selectedDevice
        ? `${this.selectedDevice.name} (${this.selectedDevice.type}:${this.selectedDevice.id})`
        : null,
      platform: this.selectedDevice
        ? (this.devicePlatforms.get(this.selectedDevice.id) ?? detectPlatform(this.selectedDevice))
        : null,
      active_sessions: Array.from(this.sessions.values()).map((s) => ({
        id: s.id,
        target: s.target,
        pid: s.pid,
      })),
      active_hooks: this.hooks.size,
      active_oracles: this.oracles.size,
      active_scripts: Array.from(this.sessions.values()).reduce(
        (count, s) => count + s.scripts.size,
        0
      ),
      last_detach: lastDetach
        ? {
            target: lastDetach.target,
            reason: lastDetach.reason,
            crash_summary: lastDetach.crash?.summary ?? null,
            timestamp: lastDetach.timestamp,
          }
        : null,
    };
  }

  /** Start the periodic expiry sweep (idempotent; the timer never keeps the process alive). */
  startCleanupTimer(): void {
    if (this.cleanupTimer) return;
    this.cleanupTimer = setInterval(() => {
      this.cleanupExpiredSessions().catch((err) => {
        log('debug', `Session expiry sweep failed: ${String(err)}`);
      });
    }, CLEANUP_INTERVAL_MS);
    this.cleanupTimer.unref();
  }

  stopCleanupTimer(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  /**
   * Detach sessions that have been idle longer than `sessionTimeoutMinutes`.
   * Throttled to at most once per minute; pass `force` to bypass the throttle.
   */
  async cleanupExpiredSessions(force = false): Promise<void> {
    const now = Date.now();
    if (!force && now - this.lastCleanupAt < CLEANUP_INTERVAL_MS) return;
    this.lastCleanupAt = now;

    const timeoutMs = this.config.sessionTimeoutMinutes * 60 * 1000;
    if (timeoutMs <= 0) return;

    for (const [id, entry] of this.sessions) {
      const lastActivity = entry.lastActivityAt ?? entry.createdAt;
      if (now - lastActivity <= timeoutMs) continue;

      log('info', `Session ${id} expired (target: ${entry.target})`);
      try {
        await this.removeSession(id);
        await entry.session.detach();
      } catch (err) {
        log('debug', `Error while expiring session ${id}: ${String(err)}`);
      }
    }
  }

  async cleanup(): Promise<void> {
    this.stopCleanupTimer();

    for (const [sessionId, entry] of this.sessions) {
      try {
        await unloadScripts(entry);
        await entry.session.detach();
      } catch { /* ignore */ }
      this.sessions.delete(sessionId);
    }
    this.hooks.clear();
    this.traces.clear();
    this.coverage.clear();
    this.oracles.clear();

    try {
      const { disconnectMobileMcp } = await import('./mobile-mcp/client.js');
      await disconnectMobileMcp();
    } catch { /* mobile-mcp may never have been started */ }
  }
}

/** A pending waiter registered by waitForNewMessages. */
interface MessageWaiter {
  check: () => boolean;
  settle: (reached: boolean) => void;
  done: boolean;
}

/** Monotonic per-script message index that survives buffer trimming. */
function nextMessageIndex(script: ScriptEntry): number {
  const index = script.nextMessageIndex ?? script.messages.length;
  script.nextMessageIndex = index + 1;
  return index;
}

async function unloadScripts(entry: SessionEntry): Promise<void> {
  for (const scriptEntry of entry.scripts.values()) {
    try {
      // Eternalized scripts are deliberately pinned in the target and must outlive the session
      // (that is the point of eternalize_script), so never unload them here either.
      if (scriptEntry.eternalized || scriptEntry.script.isDestroyed) continue;
      await scriptEntry.script.unload();
    } catch { /* script may already be unloaded or the process may be gone */ }
  }
}

export function toCrashSummary(crash: frida.Crash | null | undefined): CrashSummary | null {
  if (!crash) return null;
  return {
    pid: crash.pid,
    processName: crash.processName,
    summary: crash.summary,
    report: crash.report,
  };
}

function detectPlatform(device: frida.Device): string | null {
  // Best-effort platform detection from device type
  const type = device.type;
  if (type === 'local') return process.platform === 'darwin' ? 'macos' : process.platform;
  // For USB/remote devices, we'll detect platform when we query system params
  return null;
}

let stateInstance: ServerState | null = null;

export function initState(config: FridaMcpConfig): ServerState {
  if (stateInstance) {
    stateInstance.stopCleanupTimer();
  }
  stateInstance = new ServerState(config);
  stateInstance.startCleanupTimer();
  return stateInstance;
}

export function getState(): ServerState {
  if (!stateInstance) {
    throw new Error('Server state not initialized. Call initState() first.');
  }
  return stateInstance;
}

export { ServerState };
