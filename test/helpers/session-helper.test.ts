import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('frida', () => ({
  default: {
    getDeviceManager: () => ({}),
    Cancellable: { withTimeout: vi.fn(() => ({ isCancelled: false })) },
  },
}));

import frida from 'frida';
import { getOrCreateSession, findRunningPid } from '../../src/helpers/session-helper.js';
import { initState, getState } from '../../src/state.js';
import { FridaMcpError } from '../../src/helpers/errors.js';
import type { SessionEntry } from '../../src/types.js';
import {
  makeDevice,
  makeDeviceManager,
  makeSession,
  SPAWNED_PID,
  TARGET,
  TEST_CONFIG,
  type FakeDevice,
} from './mock-fixtures.js';

function makeFakeEntry(over: Partial<SessionEntry> = {}): SessionEntry {
  const now = Date.now();
  return {
    id: getState().generateId(),
    session: makeSession() as any,
    pid: 1,
    deviceId: 'dev1',
    target: 'fake.target',
    platform: 'android',
    scripts: new Map(),
    createdAt: now,
    lastActivityAt: now,
    ...over,
  };
}

function callOrder(mock: { mock: { invocationCallOrder: number[] } }): number {
  return mock.mock.invocationCallOrder[0];
}

describe('getOrCreateSession', () => {
  let device: FakeDevice;
  let deviceManager: any;

  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    vi.mocked(frida.Cancellable.withTimeout).mockImplementation(() => ({ isCancelled: false }) as any);
    device = makeDevice();
    deviceManager = makeDeviceManager(device);
  });

  afterEach(() => {
    getState().stopCleanupTimer();
    vi.restoreAllMocks();
  });

  describe('target resolution', () => {
    it('attaches directly to a numeric pid without enumerating or spawning', async () => {
      const result = await getOrCreateSession(deviceManager, { target: '1234' });

      expect(device.attach).toHaveBeenCalledTimes(1);
      expect(device.attach.mock.calls[0][0]).toBe(1234);
      expect(device.enumerateApplications).not.toHaveBeenCalled();
      expect(device.enumerateProcesses).not.toHaveBeenCalled();
      expect(device.spawn).not.toHaveBeenCalled();
      expect(result.isNew).toBe(true);
      expect(result.needsResume).toBe(false);
      expect(result.sessionEntry.pid).toBe(1234);
    });

    it('resolves a running app by bundle identifier and attaches to its pid', async () => {
      device.enumerateApplications.mockResolvedValue([{ identifier: TARGET, name: 'Example', pid: 777 }]);

      await getOrCreateSession(deviceManager, { target: TARGET });

      expect(device.enumerateApplications).toHaveBeenCalledTimes(1);
      const [query, cancellable] = device.enumerateApplications.mock.calls[0];
      expect(query).toEqual({ identifiers: [TARGET], scope: 'minimal' });
      expect(cancellable).toEqual({ isCancelled: false });
      expect(device.attach.mock.calls[0][0]).toBe(777);
      expect(device.spawn).not.toHaveBeenCalled();
    });

    it('falls back to process name lookup when the app is listed but not running', async () => {
      device.enumerateApplications.mockResolvedValue([{ identifier: TARGET, name: 'Example', pid: 0 }]);
      device.enumerateProcesses.mockResolvedValue([{ pid: 555, name: TARGET }]);

      await getOrCreateSession(deviceManager, { target: TARGET });

      expect(device.enumerateProcesses).toHaveBeenCalledTimes(1);
      expect(device.attach.mock.calls[0][0]).toBe(555);
      expect(device.spawn).not.toHaveBeenCalled();
    });
  });

  describe('spawn fallback', () => {
    it('spawns, attaches and resumes in order when nothing is running', async () => {
      const result = await getOrCreateSession(deviceManager, { target: TARGET });

      expect(device.spawn).toHaveBeenCalledTimes(1);
      expect(device.spawn.mock.calls[0][0]).toBe(TARGET);
      expect(device.attach.mock.calls[0][0]).toBe(SPAWNED_PID);
      expect(device.resume).toHaveBeenCalledTimes(1);
      expect(device.resume.mock.calls[0][0]).toBe(SPAWNED_PID);

      expect(callOrder(device.spawn)).toBeLessThan(callOrder(device.attach));
      expect(callOrder(device.attach)).toBeLessThan(callOrder(device.resume));

      expect(result.isNew).toBe(true);
      expect(result.needsResume).toBe(false);
      expect(result.sessionEntry.pid).toBe(SPAWNED_PID);
    });

    it('leaves the spawned process suspended when resume is false', async () => {
      const result = await getOrCreateSession(deviceManager, { target: TARGET, resume: false });

      expect(device.spawn).toHaveBeenCalledTimes(1);
      expect(device.attach).toHaveBeenCalledTimes(1);
      expect(device.resume).not.toHaveBeenCalled();
      expect(result.needsResume).toBe(true);
    });

    it('forceSpawn spawns without consulting the running app list and leaves it suspended', async () => {
      device.enumerateApplications.mockResolvedValue([{ identifier: TARGET, name: 'Example', pid: 777 }]);

      const result = await getOrCreateSession(deviceManager, { target: TARGET, forceSpawn: true });

      expect(device.enumerateApplications).not.toHaveBeenCalled();
      expect(device.enumerateProcesses).not.toHaveBeenCalled();
      expect(device.spawn).toHaveBeenCalledTimes(1);
      expect(device.attach).toHaveBeenCalledTimes(1);
      expect(device.attach.mock.calls[0][0]).toBe(SPAWNED_PID);
      expect(device.resume).not.toHaveBeenCalled();
      expect(result.needsResume).toBe(true);
      expect(result.isNew).toBe(true);
    });
  });

  describe('session limits', () => {
    it('enforces maxSessions before touching the device', async () => {
      const state = getState();
      state.addSession(makeFakeEntry({ target: 'one.app', pid: 1 }));
      state.addSession(makeFakeEntry({ target: 'two.app', pid: 2 }));

      await expect(getOrCreateSession(deviceManager, { target: TARGET }))
        .rejects.toThrow(/Maximum session limit reached/);

      expect(device.spawn).not.toHaveBeenCalled();
      expect(device.attach).not.toHaveBeenCalled();
      expect(deviceManager.resolve).not.toHaveBeenCalled();
    });
  });

  describe('session reuse', () => {
    it('reuses a session by id and returns the device it lives on', async () => {
      const state = getState();
      const dev2 = makeDevice({ id: 'dev2' });
      deviceManager.getDevice.mockResolvedValue(dev2);
      state.selectedDevice = device as any;

      const entry = makeFakeEntry({ deviceId: 'dev2', target: 'other.app' });
      state.addSession(entry);

      const result = await getOrCreateSession(deviceManager, { target: 'whatever', sessionId: entry.id });

      expect(result.isNew).toBe(false);
      expect(result.needsResume).toBe(false);
      expect(result.sessionEntry).toBe(entry);
      expect(result.fridaDevice.id).toBe('dev2');
      expect(deviceManager.getDevice).toHaveBeenCalledWith('dev2');
      expect(entry.device).toBe(dev2);
      expect(device.attach).not.toHaveBeenCalled();
      expect(device.spawn).not.toHaveBeenCalled();
    });

    it('reuses a session by target using the cached device and touches lastActivityAt', async () => {
      const state = getState();
      const cachedDevice = makeDevice({ id: 'dev-cached' });
      const staleTimestamp = Date.now() - 60_000;
      const entry = makeFakeEntry({
        target: TARGET,
        deviceId: 'dev-cached',
        device: cachedDevice as any,
        lastActivityAt: staleTimestamp,
      });
      state.addSession(entry);

      const result = await getOrCreateSession(deviceManager, { target: TARGET });

      expect(result.isNew).toBe(false);
      expect(result.sessionEntry).toBe(entry);
      expect(result.fridaDevice).toBe(cachedDevice);
      expect(deviceManager.getDevice).not.toHaveBeenCalled();
      expect(entry.lastActivityAt).toBeGreaterThan(staleTimestamp);
      expect(device.spawn).not.toHaveBeenCalled();
    });

    it('forceSpawn skips target reuse and creates a new session', async () => {
      const state = getState();
      const entry = makeFakeEntry({ target: TARGET, device: device as any });
      state.addSession(entry);

      const result = await getOrCreateSession(deviceManager, { target: TARGET, forceSpawn: true });

      expect(device.spawn).toHaveBeenCalledTimes(1);
      expect(result.isNew).toBe(true);
      expect(result.sessionEntry).not.toBe(entry);
      expect(state.sessions.size).toBe(2);
    });
  });

  describe('error handling', () => {
    it('kills the spawned process when attach fails and reports PROCESS_NOT_FOUND', async () => {
      device.attach.mockRejectedValue(new Error('unable to find process'));

      const promise = getOrCreateSession(deviceManager, { target: TARGET });

      await expect(promise).rejects.toBeInstanceOf(FridaMcpError);
      await expect(promise).rejects.toMatchObject({ code: 'PROCESS_NOT_FOUND' });
      expect(device.spawn).toHaveBeenCalledTimes(1);
      expect(device.kill).toHaveBeenCalledTimes(1);
      expect(device.kill).toHaveBeenCalledWith(SPAWNED_PID);
      expect(getState().sessions.size).toBe(0);
    });

    it('does not kill the process when attach to a non-spawned pid fails', async () => {
      device.attach.mockRejectedValue(new Error('unable to find process'));

      await expect(getOrCreateSession(deviceManager, { target: '1234' }))
        .rejects.toMatchObject({ code: 'PROCESS_NOT_FOUND' });

      expect(device.spawn).not.toHaveBeenCalled();
      expect(device.kill).not.toHaveBeenCalled();
    });

    it('translates a spawn failure for an unknown identifier into PROCESS_NOT_FOUND', async () => {
      device.spawn.mockRejectedValue(new Error('unable to find application with identifier'));

      await expect(getOrCreateSession(deviceManager, { target: TARGET }))
        .rejects.toMatchObject({ code: 'PROCESS_NOT_FOUND' });

      expect(device.attach).not.toHaveBeenCalled();
      expect(device.kill).not.toHaveBeenCalled();
    });

    it('turns a cancelled attach into a FRIDA_TIMEOUT error naming the operation', async () => {
      vi.mocked(frida.Cancellable.withTimeout).mockImplementation(() => ({ isCancelled: true }) as any);
      device.attach.mockRejectedValue(new Error('Operation was cancelled'));

      const promise = getOrCreateSession(deviceManager, { target: '1234' });

      await expect(promise).rejects.toBeInstanceOf(FridaMcpError);
      await expect(promise).rejects.toMatchObject({ code: 'FRIDA_TIMEOUT' });
      await expect(promise).rejects.toThrow(/attach/);
    });
  });

  describe('detach handling', () => {
    type DetachHandler = (reason: string, crash: unknown) => void;

    function capturedDetachHandler(dev: FakeDevice): DetachHandler {
      expect(dev._session.detached.connect).toHaveBeenCalledTimes(1);
      return dev._session.detached.connect.mock.calls[0][0] as DetachHandler;
    }

    it('removes the session and records the crash when the process terminates', async () => {
      const state = getState();
      const { sessionEntry } = await getOrCreateSession(deviceManager, { target: TARGET });
      expect(state.sessions.has(sessionEntry.id)).toBe(true);

      const handler = capturedDetachHandler(device);
      handler('process-terminated', {
        pid: SPAWNED_PID,
        processName: TARGET,
        summary: 'SIGSEGV',
        report: '...',
      });

      expect(state.sessions.has(sessionEntry.id)).toBe(false);
      expect(state.recentDetaches).toHaveLength(1);
      expect(state.recentDetaches[0]).toMatchObject({
        sessionId: sessionEntry.id,
        target: TARGET,
        pid: SPAWNED_PID,
        deviceId: 'dev1',
        reason: 'process-terminated',
      });
      expect(state.recentDetaches[0].crash?.summary).toBe('SIGSEGV');
      expect(sessionEntry.detachReason).toBe('process-terminated');
      expect(sessionEntry.crash?.summary).toBe('SIGSEGV');
    });

    it('records a null crash when the detach carries no crash information', async () => {
      const state = getState();
      const { sessionEntry } = await getOrCreateSession(deviceManager, { target: TARGET });

      const handler = capturedDetachHandler(device);
      handler('application-requested', null);

      expect(state.sessions.has(sessionEntry.id)).toBe(false);
      expect(state.recentDetaches).toHaveLength(1);
      expect(state.recentDetaches[0].reason).toBe('application-requested');
      expect(state.recentDetaches[0].crash).toBeNull();
    });

    it('subscribes to device crash events only once per device', async () => {
      await getOrCreateSession(deviceManager, { target: 'one.app' });
      await getOrCreateSession(deviceManager, { target: 'two.app' });

      expect(getState().sessions.size).toBe(2);
      expect(device.processCrashed.connect).toHaveBeenCalledTimes(1);
    });
  });

  describe('new session entries', () => {
    it('populates lastActivityAt, device and deviceId and selects the device', async () => {
      const state = getState();
      const before = Date.now();

      const { sessionEntry, fridaDevice } = await getOrCreateSession(deviceManager, { target: TARGET });

      expect(fridaDevice).toBe(device);
      expect(sessionEntry.device).toBe(device);
      expect(sessionEntry.deviceId).toBe('dev1');
      expect(sessionEntry.target).toBe(TARGET);
      expect(sessionEntry.platform).toBe('android');
      expect(sessionEntry.lastActivityAt).toBeGreaterThanOrEqual(before);
      expect(sessionEntry.createdAt).toBeGreaterThanOrEqual(before);
      expect(state.selectedDevice).toBe(device);
      expect(state.getSession(sessionEntry.id)).toBe(sessionEntry);
      expect(deviceManager.detectPlatform).toHaveBeenCalledWith(device);
    });
  });
});

describe('findRunningPid', () => {
  let device: FakeDevice;

  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    vi.mocked(frida.Cancellable.withTimeout).mockImplementation(() => ({ isCancelled: false }) as any);
    device = makeDevice();
  });

  afterEach(() => {
    getState().stopCleanupTimer();
    vi.restoreAllMocks();
  });

  it('returns the running app pid when the identifier matches', async () => {
    device.enumerateApplications.mockResolvedValue([{ identifier: TARGET, name: 'Example', pid: 777 }]);

    await expect(findRunningPid(device as any, TARGET)).resolves.toBe(777);
    expect(device.enumerateProcesses).not.toHaveBeenCalled();
  });

  it('falls back to a process name match when the app is not running', async () => {
    device.enumerateApplications.mockResolvedValue([{ identifier: TARGET, name: 'Example', pid: 0 }]);
    device.enumerateProcesses.mockResolvedValue([
      { pid: 100, name: 'other' },
      { pid: 555, name: TARGET },
    ]);

    await expect(findRunningPid(device as any, TARGET)).resolves.toBe(555);
  });

  it('returns null when neither an app nor a process matches', async () => {
    device.enumerateProcesses.mockResolvedValue([{ pid: 100, name: 'other' }]);

    await expect(findRunningPid(device as any, TARGET)).resolves.toBeNull();
  });

  it('swallows enumerateApplications errors and still uses the process fallback', async () => {
    device.enumerateApplications.mockRejectedValue(new Error('not supported on this device'));
    device.enumerateProcesses.mockResolvedValue([{ pid: 555, name: TARGET }]);

    await expect(findRunningPid(device as any, TARGET)).resolves.toBe(555);
    expect(device.enumerateProcesses).toHaveBeenCalledTimes(1);
  });
});
