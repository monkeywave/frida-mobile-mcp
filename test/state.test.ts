import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('frida', () => ({
  default: {
    getDeviceManager: () => ({}),
    Cancellable: { withTimeout: () => ({ isCancelled: false }) },
  },
}));

vi.mock('../src/helpers/logger.js', () => ({
  log: vi.fn(),
  initLogger: vi.fn(),
}));

vi.mock('../src/mobile-mcp/client.js', () => ({
  disconnectMobileMcp: vi.fn().mockResolvedValue(undefined),
}));

import { ServerState, initState, getState } from '../src/state.js';
import { disconnectMobileMcp } from '../src/mobile-mcp/client.js';
import type {
  FridaMcpConfig,
  SessionEntry,
  ScriptEntry,
  HookEntry,
  TraceEntry,
  DetachRecord,
} from '../src/types.js';

const MINUTE_MS = 60_000;

function makeConfig(overrides: Partial<FridaMcpConfig> = {}): FridaMcpConfig {
  return {
    allowCustomScripts: false,
    memoryWriteEnabled: false,
    allowedDevices: [],
    maxSessions: 2,
    sessionTimeoutMinutes: 1,
    maxMessageBuffer: 10,
    auditLogPath: '',
    mobileMcp: { enabled: false, command: '', args: [] },
    rateLimits: { scriptsPerMinute: 10, memoryReadsPerMinute: 10, sessionsPerMinute: 10 },
    ...overrides,
  };
}

function makeSession(id: string, pid: number, overrides: Partial<SessionEntry> = {}): SessionEntry {
  return {
    id,
    session: { detach: vi.fn().mockResolvedValue(undefined) } as any,
    pid,
    deviceId: 'dev1',
    target: 'com.example',
    platform: 'android',
    scripts: new Map(),
    createdAt: Date.now(),
    ...overrides,
  };
}

function makeScript(id: string, isDestroyed = false): ScriptEntry {
  return {
    id,
    script: { unload: vi.fn().mockResolvedValue(undefined), isDestroyed } as any,
    messages: [],
    persistent: false,
    createdAt: Date.now(),
  };
}

function makeHook(id: string, sessionId: string): HookEntry {
  return {
    id,
    scriptId: 'script-' + id,
    sessionId,
    target: 'fn',
    type: 'native',
    invocations: [],
    status: 'active',
    createdAt: Date.now(),
  };
}

function makeTrace(id: string, sessionId: string): TraceEntry {
  return {
    id,
    scriptId: 'script-' + id,
    sessionId,
    targets: ['fn'],
    callCount: 0,
    startedAt: Date.now(),
  };
}

function makeDetach(n: number): DetachRecord {
  return {
    sessionId: `s${n}`,
    target: `target-${n}`,
    pid: n,
    deviceId: 'dev1',
    reason: 'application-requested',
    crash: null,
    timestamp: n,
  };
}

function makeMessage(n: number) {
  return { timestamp: n, type: 'send', payload: { n }, data: null };
}

describe('ServerState', () => {
  let state: ServerState;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    state = new ServerState(makeConfig());
  });

  afterEach(() => {
    state.stopCleanupTimer();
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  describe('addMessageToScript', () => {
    it('keeps message indices monotonic across buffer trimming', () => {
      const session = makeSession('s1', 100);
      const script = makeScript('sc1');
      session.scripts.set(script.id, script);
      state.addSession(session);

      for (let i = 0; i < 25; i++) {
        state.addMessageToScript('s1', 'sc1', makeMessage(i));
      }

      expect(script.messages.length).toBeLessThanOrEqual(11);
      expect(script.messages[script.messages.length - 1].index).toBe(24);
      expect(script.nextMessageIndex).toBe(25);

      const indices = script.messages.map((m) => m.index);
      for (let i = 1; i < indices.length; i++) {
        expect(indices[i]).toBeGreaterThan(indices[i - 1]);
      }
      expect(new Set(indices).size).toBe(indices.length);
    });

    it('updates session.lastActivityAt', () => {
      const session = makeSession('s1', 100, { createdAt: Date.now() - 5 * MINUTE_MS });
      const script = makeScript('sc1');
      session.scripts.set(script.id, script);
      state.addSession(session);
      expect(session.lastActivityAt).toBe(session.createdAt);

      state.addMessageToScript('s1', 'sc1', makeMessage(0));
      expect(session.lastActivityAt).toBe(Date.now());
    });

    it('ignores unknown session or script ids', () => {
      const session = makeSession('s1', 100);
      state.addSession(session);
      expect(() => state.addMessageToScript('nope', 'sc1', makeMessage(0))).not.toThrow();
      expect(() => state.addMessageToScript('s1', 'nope', makeMessage(0))).not.toThrow();
    });
  });

  describe('session capacity', () => {
    it('ensureSessionCapacity throws once maxSessions is reached', () => {
      state.addSession(makeSession('s1', 1));
      expect(() => state.ensureSessionCapacity()).not.toThrow();
      state.addSession(makeSession('s2', 2));
      expect(() => state.ensureSessionCapacity()).toThrow('Maximum session limit reached');
    });

    it('addSession throws once maxSessions is reached', () => {
      state.addSession(makeSession('s1', 1));
      state.addSession(makeSession('s2', 2));
      expect(() => state.addSession(makeSession('s3', 3))).toThrow('Maximum session limit reached');
      expect(state.sessions.size).toBe(2);
    });
  });

  describe('touchSession', () => {
    it('updates lastActivityAt to the current time', () => {
      const session = makeSession('s1', 1, { createdAt: Date.now() - 10 * MINUTE_MS });
      state.addSession(session);
      const before = session.lastActivityAt;

      vi.advanceTimersByTime(5_000);
      state.touchSession('s1');

      expect(session.lastActivityAt).toBe(Date.now());
      expect(session.lastActivityAt).not.toBe(before);
    });

    it('is a no-op for unknown session ids', () => {
      const session = makeSession('s1', 1);
      state.addSession(session);
      const before = session.lastActivityAt;
      expect(() => state.touchSession('unknown')).not.toThrow();
      expect(session.lastActivityAt).toBe(before);
    });
  });

  describe('removeSession', () => {
    it('synchronously deletes the session and its hooks/traces/coverage/oracles, keeping other sessions intact', () => {
      state.addSession(makeSession('s1', 1));
      state.addSession(makeSession('s2', 2));
      state.hooks.set('h1', makeHook('h1', 's1'));
      state.hooks.set('h2', makeHook('h2', 's2'));
      state.traces.set('t1', makeTrace('t1', 's1'));
      state.traces.set('t2', makeTrace('t2', 's2'));
      state.coverage.set('c1', { id: 'c1', scriptId: 'sc1', sessionId: 's1', scope: 'x', allTargets: [], hits: new Map(), createdAt: Date.now() });
      state.coverage.set('c2', { id: 'c2', scriptId: 'sc2', sessionId: 's2', scope: 'y', allTargets: [], hits: new Map(), createdAt: Date.now() });
      state.oracles.set('o1', { id: 'o1', scriptId: 'sc1', sessionId: 's1', pattern: 'rc4', eventCount: 0, createdAt: Date.now() });
      state.oracles.set('o2', { id: 'o2', scriptId: 'sc2', sessionId: 's2', pattern: 'rc4', eventCount: 0, createdAt: Date.now() });

      const result = state.removeSession('s1');

      expect(result).toBeInstanceOf(Promise);
      expect(state.sessions.has('s1')).toBe(false);
      expect(state.sessions.has('s2')).toBe(true);
      expect(state.hooks.has('h1')).toBe(false);
      expect(state.hooks.has('h2')).toBe(true);
      expect(state.traces.has('t1')).toBe(false);
      expect(state.traces.has('t2')).toBe(true);
      expect(state.coverage.has('c1')).toBe(false);
      expect(state.coverage.has('c2')).toBe(true);
      expect(state.oracles.has('o1')).toBe(false);
      expect(state.oracles.has('o2')).toBe(true);
    });

    it('unloads non-destroyed scripts and skips destroyed ones', async () => {
      const session = makeSession('s1', 1);
      const alive = makeScript('alive', false);
      const destroyed = makeScript('destroyed', true);
      session.scripts.set(alive.id, alive);
      session.scripts.set(destroyed.id, destroyed);
      state.addSession(session);

      await state.removeSession('s1');

      expect(alive.script.unload).toHaveBeenCalledTimes(1);
      expect(destroyed.script.unload).not.toHaveBeenCalled();
    });

    it('does not reject when a script unload rejects', async () => {
      const session = makeSession('s1', 1);
      const failing = makeScript('failing');
      (failing.script.unload as any).mockRejectedValue(new Error('boom'));
      const other = makeScript('other');
      session.scripts.set(failing.id, failing);
      session.scripts.set(other.id, other);
      state.addSession(session);

      await expect(state.removeSession('s1')).resolves.toBeUndefined();
      expect(other.script.unload).toHaveBeenCalledTimes(1);
    });

    it('resolves for an unknown session id', async () => {
      await expect(state.removeSession('missing')).resolves.toBeUndefined();
    });
  });

  describe('cleanupExpiredSessions', () => {
    it('expires sessions idle longer than sessionTimeoutMinutes and detaches them', async () => {
      const idle = makeSession('idle', 1, { createdAt: Date.now() - 3 * MINUTE_MS });
      const script = makeScript('sc');
      idle.scripts.set(script.id, script);
      const fresh = makeSession('fresh', 2);
      state.addSession(idle);
      state.addSession(fresh);

      await state.cleanupExpiredSessions(true);

      expect(state.sessions.has('idle')).toBe(false);
      expect(state.sessions.has('fresh')).toBe(true);
      expect(idle.session.detach).toHaveBeenCalledTimes(1);
      expect(script.script.unload).toHaveBeenCalledTimes(1);
      expect(fresh.session.detach).not.toHaveBeenCalled();
    });

    it('does not expire a session with an old createdAt but recent lastActivityAt', async () => {
      const session = makeSession('s1', 1, {
        createdAt: Date.now() - 60 * MINUTE_MS,
        lastActivityAt: Date.now() - 10_000,
      });
      state.addSession(session);

      await state.cleanupExpiredSessions(true);

      expect(state.sessions.has('s1')).toBe(true);
      expect(session.session.detach).not.toHaveBeenCalled();
    });

    it('continues expiring other sessions when one detach rejects', async () => {
      const bad = makeSession('bad', 1, { createdAt: Date.now() - 3 * MINUTE_MS });
      (bad.session.detach as any).mockRejectedValue(new Error('detach failed'));
      const good = makeSession('good', 2, { createdAt: Date.now() - 3 * MINUTE_MS });
      state.addSession(bad);
      state.addSession(good);

      await expect(state.cleanupExpiredSessions(true)).resolves.toBeUndefined();

      expect(state.sessions.size).toBe(0);
      expect(bad.session.detach).toHaveBeenCalledTimes(1);
      expect(good.session.detach).toHaveBeenCalledTimes(1);
    });

    it('is throttled to once per minute when not forced', async () => {
      const first = makeSession('first', 1, { createdAt: Date.now() - 3 * MINUTE_MS });
      state.addSession(first);

      await state.cleanupExpiredSessions(false);
      expect(state.sessions.has('first')).toBe(false);

      const second = makeSession('second', 2, { createdAt: Date.now() - 3 * MINUTE_MS });
      state.addSession(second);

      vi.advanceTimersByTime(30_000);
      await state.cleanupExpiredSessions(false);
      expect(state.sessions.has('second')).toBe(true);

      vi.advanceTimersByTime(MINUTE_MS);
      await state.cleanupExpiredSessions(false);
      expect(state.sessions.has('second')).toBe(false);
    });

    it('does not expire anything when sessionTimeoutMinutes <= 0', async () => {
      state = new ServerState(makeConfig({ sessionTimeoutMinutes: 0 }));
      const session = makeSession('s1', 1, { createdAt: Date.now() - 24 * 60 * MINUTE_MS });
      state.addSession(session);

      await state.cleanupExpiredSessions(true);

      expect(state.sessions.has('s1')).toBe(true);
      expect(session.session.detach).not.toHaveBeenCalled();
    });
  });

  describe('recordDetach / recordCrash', () => {
    it('keeps at most 20 detach records, dropping the oldest', () => {
      for (let n = 1; n <= 25; n++) {
        state.recordDetach(makeDetach(n));
      }
      expect(state.recentDetaches).toHaveLength(20);
      expect(state.recentDetaches[0]).toEqual(makeDetach(6));
      expect(state.recentDetaches[19]).toEqual(makeDetach(25));
    });

    it('annotates the matching session and records a process-crashed entry', () => {
      const session = makeSession('s1', 1234, { deviceId: 'dev1' });
      state.addSession(session);
      const crash = { pid: 1234, processName: 'com.example', summary: 'SIGSEGV', report: 'trace' };

      state.recordCrash('dev1', crash);

      expect(session.crash).toEqual(crash);
      expect(state.recentDetaches).toHaveLength(1);
      expect(state.recentDetaches[0]).toMatchObject({
        sessionId: 's1',
        target: 'com.example',
        pid: 1234,
        deviceId: 'dev1',
        reason: 'process-crashed',
        crash,
        timestamp: Date.now(),
      });
    });

    it('does not match a session with the same pid on a different device', () => {
      const session = makeSession('s1', 1234, { deviceId: 'dev1' });
      state.addSession(session);

      state.recordCrash('dev2', { pid: 1234, processName: 'other', summary: 'crash' });

      expect(session.crash).toBeUndefined();
      expect(state.recentDetaches[0].sessionId).toBeNull();
    });

    it('records sessionId null and target = processName for an unknown pid', () => {
      state.recordCrash('dev1', { pid: 999, processName: 'unknown.app', summary: 'abort' });

      expect(state.recentDetaches).toHaveLength(1);
      expect(state.recentDetaches[0]).toMatchObject({
        sessionId: null,
        target: 'unknown.app',
        pid: 999,
        reason: 'process-crashed',
      });
    });
  });

  describe('watchDeviceCrashes', () => {
    function makeDevice(id: string) {
      return { id, processCrashed: { connect: vi.fn() } } as any;
    }

    it('connects processCrashed exactly once per device id', () => {
      const device = makeDevice('dev1');
      state.watchDeviceCrashes(device);
      state.watchDeviceCrashes(device);
      expect(device.processCrashed.connect).toHaveBeenCalledTimes(1);

      const sameId = makeDevice('dev1');
      state.watchDeviceCrashes(sameId);
      expect(sameId.processCrashed.connect).not.toHaveBeenCalled();

      const other = makeDevice('dev2');
      state.watchDeviceCrashes(other);
      expect(other.processCrashed.connect).toHaveBeenCalledTimes(1);
    });

    it('records crashes delivered through the connected handler', () => {
      const device = makeDevice('dev1');
      const session = makeSession('s1', 42);
      state.addSession(session);
      state.watchDeviceCrashes(device);

      const handler = device.processCrashed.connect.mock.calls[0][0];
      handler({ pid: 42, processName: 'com.example', summary: 'SIGABRT', report: 'full report' });

      expect(session.crash).toEqual({
        pid: 42,
        processName: 'com.example',
        summary: 'SIGABRT',
        report: 'full report',
      });
      expect(state.recentDetaches).toHaveLength(1);
      expect(state.recentDetaches[0]).toMatchObject({
        sessionId: 's1',
        reason: 'process-crashed',
        crash: { pid: 42, summary: 'SIGABRT' },
      });
    });

    it('allows re-subscribing when connect throws', () => {
      const device = makeDevice('dev1');
      device.processCrashed.connect.mockImplementationOnce(() => {
        throw new Error('not supported');
      });

      expect(() => state.watchDeviceCrashes(device)).not.toThrow();
      state.watchDeviceCrashes(device);

      expect(device.processCrashed.connect).toHaveBeenCalledTimes(2);
    });
  });

  describe('getSessionContext', () => {
    it('returns last_detach null when nothing has been recorded', () => {
      const context = state.getSessionContext();
      expect(context.last_detach).toBeNull();
      expect(context.device).toBeNull();
      expect(context.platform).toBeNull();
      expect(context.active_sessions).toEqual([]);
      expect(context.active_hooks).toBe(0);
      expect(context.active_scripts).toBe(0);
    });

    it('returns the most recent detach record', () => {
      state.recordDetach(makeDetach(1));
      state.recordDetach({
        ...makeDetach(2),
        reason: 'process-crashed',
        crash: { pid: 2, processName: 'target-2', summary: 'SIGSEGV' },
      });

      const context = state.getSessionContext();

      expect(context.last_detach).toEqual({
        target: 'target-2',
        reason: 'process-crashed',
        crash_summary: 'SIGSEGV',
        timestamp: 2,
      });
    });

    it('reports crash_summary null for a non-crash detach', () => {
      state.recordDetach(makeDetach(7));
      expect(state.getSessionContext().last_detach).toEqual({
        target: 'target-7',
        reason: 'application-requested',
        crash_summary: null,
        timestamp: 7,
      });
    });

    it('summarises active sessions, hooks and scripts', () => {
      const session = makeSession('s1', 1);
      session.scripts.set('a', makeScript('a'));
      session.scripts.set('b', makeScript('b'));
      state.addSession(session);
      state.hooks.set('h1', makeHook('h1', 's1'));
      state.oracles.set('o1', { id: 'o1', scriptId: 'a', sessionId: 's1', pattern: 'rc4', eventCount: 0, createdAt: Date.now() });

      const context = state.getSessionContext();

      expect(context.active_sessions).toEqual([{ id: 's1', target: 'com.example', pid: 1 }]);
      expect(context.active_hooks).toBe(1);
      expect(context.active_oracles).toBe(1);
      expect(context.active_scripts).toBe(2);
    });
  });

  describe('cleanup', () => {
    it('detaches all sessions, unloads scripts, clears hooks/traces, stops the timer and disconnects mobile-mcp', async () => {
      const s1 = makeSession('s1', 1);
      const script = makeScript('sc');
      s1.scripts.set(script.id, script);
      const s2 = makeSession('s2', 2);
      state.addSession(s1);
      state.addSession(s2);
      state.hooks.set('h1', makeHook('h1', 's1'));
      state.traces.set('t1', makeTrace('t1', 's2'));
      state.coverage.set('c1', { id: 'c1', scriptId: 'sc', sessionId: 's1', scope: 'x', allTargets: [], hits: new Map(), createdAt: Date.now() });
      state.oracles.set('o1', { id: 'o1', scriptId: 'sc', sessionId: 's1', pattern: 'rc4', eventCount: 0, createdAt: Date.now() });
      state.startCleanupTimer();
      const stopSpy = vi.spyOn(state, 'stopCleanupTimer');

      await state.cleanup();

      expect(state.sessions.size).toBe(0);
      expect(state.hooks.size).toBe(0);
      expect(state.traces.size).toBe(0);
      expect(state.coverage.size).toBe(0);
      expect(state.oracles.size).toBe(0);
      expect(s1.session.detach).toHaveBeenCalledTimes(1);
      expect(s2.session.detach).toHaveBeenCalledTimes(1);
      expect(script.script.unload).toHaveBeenCalledTimes(1);
      expect(stopSpy).toHaveBeenCalledTimes(1);
      expect(disconnectMobileMcp).toHaveBeenCalledTimes(1);
      expect(vi.getTimerCount()).toBe(0);
    });

    it('still removes a session whose detach rejects', async () => {
      const bad = makeSession('bad', 1);
      (bad.session.detach as any).mockRejectedValue(new Error('gone'));
      state.addSession(bad);

      await expect(state.cleanup()).resolves.toBeUndefined();

      expect(state.sessions.size).toBe(0);
    });
  });
});

describe('initState / getState', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
  });

  afterEach(() => {
    getState().stopCleanupTimer();
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it('returns the initialised instance from getState', () => {
    const state = initState(makeConfig());
    expect(getState()).toBe(state);
  });

  it('starts a cleanup timer that expires idle sessions every minute', async () => {
    const state = initState(makeConfig());
    const sweepSpy = vi.spyOn(state, 'cleanupExpiredSessions');
    const idle = makeSession('idle', 1, { createdAt: Date.now() - 3 * MINUTE_MS });
    const fresh = makeSession('fresh', 2);
    state.addSession(idle);
    state.addSession(fresh);

    await vi.advanceTimersByTimeAsync(MINUTE_MS - 1);
    expect(sweepSpy).not.toHaveBeenCalled();
    expect(state.sessions.has('idle')).toBe(true);

    await vi.advanceTimersByTimeAsync(1);

    expect(sweepSpy).toHaveBeenCalledTimes(1);
    expect(state.sessions.has('idle')).toBe(false);
    expect(state.sessions.has('fresh')).toBe(true);
    expect(idle.session.detach).toHaveBeenCalledTimes(1);
  });

  it('stops the previous instance timer when re-initialised', () => {
    const first = initState(makeConfig());
    const stopSpy = vi.spyOn(first, 'stopCleanupTimer');

    const second = initState(makeConfig());

    expect(stopSpy).toHaveBeenCalledTimes(1);
    expect(getState()).toBe(second);
    expect(vi.getTimerCount()).toBe(1);
  });
});
