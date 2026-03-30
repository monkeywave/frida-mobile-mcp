import frida from 'frida';
import { randomUUID } from 'node:crypto';
import { log } from './helpers/logger.js';
import type {
  FridaMcpConfig,
  SessionEntry,
  HookEntry,
  TraceEntry,
  ScriptEntry,
  MessageEntry,
  SessionContext,
} from './types.js';

class ServerState {
  deviceManager: frida.DeviceManager;
  selectedDevice: frida.Device | null = null;
  sessions: Map<string, SessionEntry> = new Map();
  hooks: Map<string, HookEntry> = new Map();
  traces: Map<string, TraceEntry> = new Map();
  config: FridaMcpConfig;
  private lastCleanupAt: number = 0;

  constructor(config: FridaMcpConfig) {
    this.deviceManager = frida.getDeviceManager();
    this.config = config;
  }

  generateId(): string {
    return randomUUID();
  }

  addSession(entry: SessionEntry): void {
    if (this.sessions.size >= this.config.maxSessions) {
      throw new Error(
        `Maximum session limit reached (${this.config.maxSessions}). ` +
        `Use stop_instrumentation to clean up existing sessions.`
      );
    }
    this.sessions.set(entry.id, entry);
  }

  getSession(sessionId: string): SessionEntry | undefined {
    return this.sessions.get(sessionId);
  }

  removeSession(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      // Clean up associated hooks
      for (const [hookId, hook] of this.hooks) {
        if (hook.sessionId === sessionId) {
          this.hooks.delete(hookId);
        }
      }
      // Clean up associated traces
      for (const [traceId, trace] of this.traces) {
        if (trace.sessionId === sessionId) {
          this.traces.delete(traceId);
        }
      }
      this.sessions.delete(sessionId);
    }
  }

  addMessageToScript(sessionId: string, scriptId: string, message: Omit<MessageEntry, 'index'>): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    const script = session.scripts.get(scriptId);
    if (!script) return;

    const index = script.messages.length;
    script.messages.push({ ...message, index });

    // Batch eviction: trim when 10% over limit to avoid splice on every message
    const evictionThreshold = Math.floor(this.config.maxMessageBuffer * 1.1);
    if (script.messages.length > evictionThreshold) {
      script.messages = script.messages.slice(-this.config.maxMessageBuffer);
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

  getSessionContext(): SessionContext {
    this.cleanupExpiredSessions();
    return {
      device: this.selectedDevice
        ? `${this.selectedDevice.name} (${this.selectedDevice.type}:${this.selectedDevice.id})`
        : null,
      platform: this.selectedDevice
        ? detectPlatform(this.selectedDevice)
        : null,
      active_sessions: Array.from(this.sessions.values()).map((s) => ({
        id: s.id,
        target: s.target,
        pid: s.pid,
      })),
      active_hooks: this.hooks.size,
      active_scripts: Array.from(this.sessions.values()).reduce(
        (count, s) => count + s.scripts.size,
        0
      ),
    };
  }

  cleanupExpiredSessions(): void {
    const now = Date.now();
    if (now - this.lastCleanupAt < 60_000) return; // At most once per minute
    this.lastCleanupAt = now;

    const timeoutMs = this.config.sessionTimeoutMinutes * 60 * 1000;
    if (timeoutMs <= 0) return;

    for (const [id, entry] of this.sessions) {
      if (now - entry.createdAt > timeoutMs) {
        log('info', `Session ${id} expired (target: ${entry.target})`);
        // Best-effort cleanup
        for (const scriptEntry of entry.scripts.values()) {
          try { scriptEntry.script.unload(); } catch { /* ignore */ }
        }
        try { entry.session.detach(); } catch { /* ignore */ }
        this.removeSession(id);
      }
    }
  }

  async cleanup(): Promise<void> {
    for (const [sessionId, entry] of this.sessions) {
      try {
        for (const scriptEntry of entry.scripts.values()) {
          try {
            await scriptEntry.script.unload();
          } catch { /* ignore */ }
        }
        await entry.session.detach();
      } catch { /* ignore */ }
      this.sessions.delete(sessionId);
    }
    this.hooks.clear();
    this.traces.clear();
  }
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
  stateInstance = new ServerState(config);
  return stateInstance;
}

export function getState(): ServerState {
  if (!stateInstance) {
    throw new Error('Server state not initialized. Call initState() first.');
  }
  return stateInstance;
}

export { ServerState };
