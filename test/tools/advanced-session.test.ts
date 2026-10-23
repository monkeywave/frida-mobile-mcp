import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('frida', () => ({
  default: {
    getDeviceManager: () => ({}),
    Cancellable: { withTimeout: vi.fn(() => ({ isCancelled: false })) },
  },
}));

import { registerAdvancedSessionTools } from '../../src/tools/advanced/session.js';
import { initState, getState } from '../../src/state.js';
import { rateLimiter } from '../../src/helpers/rate-limiter.js';
import {
  makeMcpHarness,
  callJson,
  makeDevice,
  makeDeviceManager,
  makeSession,
  seedSession,
  scriptEntry,
  fakeScript,
  TEST_CONFIG,
  SPAWNED_PID,
  TARGET,
  type McpHarness,
  type FakeDevice,
} from '../helpers/mock-fixtures.js';

function makeHarness(deviceManager: any): Promise<McpHarness> {
  return makeMcpHarness((server) => registerAdvancedSessionTools(server, deviceManager));
}

describe('advanced session tools', () => {
  let device: FakeDevice;
  let deviceManager: any;
  let harness: McpHarness;

  beforeEach(async () => {
    initState({ ...TEST_CONFIG });
    rateLimiter.reset();
    device = makeDevice();
    deviceManager = makeDeviceManager(device);
    harness = await makeHarness(deviceManager);
  });

  afterEach(async () => {
    await harness.close();
    rateLimiter.reset();
    getState().stopCleanupTimer();
    vi.restoreAllMocks();
  });

  describe('spawn_process', () => {
    it('spawns, attaches and registers a suspended session', async () => {
      const body = await callJson(harness.client, 'spawn_process', { program: TARGET });

      expect(device.spawn).toHaveBeenCalledWith(TARGET);
      expect(device.attach).toHaveBeenCalledWith(SPAWNED_PID);
      expect(body.result.pid).toBe(SPAWNED_PID);
      expect(body.result.status).toBe('suspended');

      const sessions = Array.from(getState().sessions.values());
      expect(sessions).toHaveLength(1);
      expect(sessions[0].target).toBe(TARGET);
      expect(device._session.detached.connect).toHaveBeenCalledTimes(1);
    });

    it('rejects an invalid program target before touching the device', async () => {
      const body = await callJson(harness.client, 'spawn_process', { program: 'bad\0name' });

      expect(body.error.code).toBeTypeOf('string');
      expect(device.spawn).not.toHaveBeenCalled();
    });

    it('enforces the session rate limit', async () => {
      initState({ ...TEST_CONFIG, rateLimits: { ...TEST_CONFIG.rateLimits, sessionsPerMinute: 1 } });

      const first = await callJson(harness.client, 'spawn_process', { program: TARGET });
      expect(first.result.pid).toBe(SPAWNED_PID);

      const second = await callJson(harness.client, 'spawn_process', { program: 'com.example.two' });
      expect(second.error.code).toBe('RATE_LIMIT_EXCEEDED');
      expect(device.spawn).toHaveBeenCalledTimes(1);
    });
  });

  describe('attach_process', () => {
    it('attaches directly to a numeric pid', async () => {
      const body = await callJson(harness.client, 'attach_process', { target: 1234 });

      expect(device.enumerateProcesses).not.toHaveBeenCalled();
      expect(device.attach).toHaveBeenCalledWith(1234);
      expect(body.result.pid).toBe(1234);
      expect(getState().sessions.size).toBe(1);
    });

    it('resolves a process name to a pid before attaching', async () => {
      device.enumerateProcesses.mockResolvedValue([{ pid: 555, name: TARGET }]);

      const body = await callJson(harness.client, 'attach_process', { target: TARGET });

      expect(device.attach).toHaveBeenCalledWith(555);
      expect(body.result.pid).toBe(555);
    });

    it('reports PROCESS_NOT_FOUND for an unknown process name', async () => {
      device.enumerateProcesses.mockResolvedValue([{ pid: 1, name: 'init' }]);

      const body = await callJson(harness.client, 'attach_process', { target: 'ghost.app' });

      expect(body.error.code).toBe('PROCESS_NOT_FOUND');
      expect(device.attach).not.toHaveBeenCalled();
    });
  });

  describe('resume_process', () => {
    it('resumes on the selected device', async () => {
      getState().selectedDevice = device as any;

      const body = await callJson(harness.client, 'resume_process', { pid: SPAWNED_PID });

      expect(device.resume).toHaveBeenCalledWith(SPAWNED_PID);
      expect(body.result.status).toBe('resumed');
    });

    it('errors with DEVICE_NOT_FOUND when nothing is selected', async () => {
      const body = await callJson(harness.client, 'resume_process', { pid: SPAWNED_PID });

      expect(body.error.code).toBe('DEVICE_NOT_FOUND');
      expect(device.resume).not.toHaveBeenCalled();
    });
  });

  describe('kill_process', () => {
    it('kills on the selected device', async () => {
      getState().selectedDevice = device as any;

      const body = await callJson(harness.client, 'kill_process', { pid: SPAWNED_PID });

      expect(device.kill).toHaveBeenCalledWith(SPAWNED_PID);
      expect(body.result.status).toBe('killed');
    });

    it('errors with DEVICE_NOT_FOUND when nothing is selected', async () => {
      const body = await callJson(harness.client, 'kill_process', { pid: SPAWNED_PID });

      expect(body.error.code).toBe('DEVICE_NOT_FOUND');
      expect(device.kill).not.toHaveBeenCalled();
    });
  });

  describe('detach_session', () => {
    it('unloads scripts, detaches and removes the session', async () => {
      const state = getState();
      const script = fakeScript();
      const entry = seedSession(state, [scriptEntry('s1', script)]);
      const session = makeSession();
      entry.session = session as any;

      const body = await callJson(harness.client, 'detach_session', { session_id: entry.id });

      expect(script.unloadCalls).toBe(1);
      expect(session.detach).toHaveBeenCalledTimes(1);
      expect(state.getSession(entry.id)).toBeUndefined();
      expect(body.result.status).toBe('detached');
    });

    it('reports SESSION_NOT_FOUND for an unknown session', async () => {
      const body = await callJson(harness.client, 'detach_session', { session_id: 'nope' });

      expect(body.error.code).toBe('SESSION_NOT_FOUND');
    });
  });

  describe('eternalize_script', () => {
    /** A script entry whose underlying frida script records eternalize() calls. */
    function seedEternalizableScript() {
      const eternalize = vi.fn().mockResolvedValue(undefined);
      const script = { ...fakeScript(), eternalize };
      const entry = seedSession(getState(), [scriptEntry('s1', script as any)]);
      return { entry, script, eternalize };
    }

    it('eternalizes the script and marks the entry', async () => {
      const { entry, eternalize } = seedEternalizableScript();

      const body = await callJson(harness.client, 'eternalize_script', { session_id: entry.id, script_id: 's1' });

      expect(eternalize).toHaveBeenCalledTimes(1);
      expect(body.result.status).toBe('eternalized');
      const scriptEntryAfter = getState().getSession(entry.id)!.scripts.get('s1')!;
      expect(scriptEntryAfter.eternalized).toBe(true);
      expect(scriptEntryAfter.persistent).toBe(true);
    });

    it('reports SESSION_NOT_FOUND for an unknown session', async () => {
      const body = await callJson(harness.client, 'eternalize_script', { session_id: 'nope', script_id: 's1' });
      expect(body.error.code).toBe('SESSION_NOT_FOUND');
    });

    it('reports SCRIPT_NOT_FOUND for an unknown script', async () => {
      const entry = seedSession(getState(), []);
      const body = await callJson(harness.client, 'eternalize_script', { session_id: entry.id, script_id: 'ghost' });
      expect(body.error.code).toBe('SCRIPT_NOT_FOUND');
    });

    it('removeSession (the reaper/cleanup path) does NOT unload eternalized scripts', async () => {
      const state = getState();
      const pinned = fakeScript();
      const normal = fakeScript();
      const pinnedEntry = scriptEntry('pinned', pinned);
      pinnedEntry.eternalized = true;
      const entry = seedSession(state, [pinnedEntry, scriptEntry('normal', normal)]);

      await state.removeSession(entry.id);

      expect(pinned.unloadCalls).toBe(0); // pinned script survives — the whole point of eternalize
      expect(normal.unloadCalls).toBe(1);
      expect(state.getSession(entry.id)).toBeUndefined();
    });
  });

  describe('list_sessions', () => {
    it('summarises the active sessions', async () => {
      const state = getState();
      seedSession(state, [], { id: 'a', target: 'one.app', pid: 1 });
      seedSession(state, [scriptEntry('s1', fakeScript())], { id: 'b', target: 'two.app', pid: 2 });

      const body = await callJson(harness.client, 'list_sessions', {});

      expect(body.result.sessions).toHaveLength(2);
      const byId = Object.fromEntries(body.result.sessions.map((s: any) => [s.id, s]));
      expect(byId.a).toMatchObject({ target: 'one.app', pid: 1, scripts: 0 });
      expect(byId.b).toMatchObject({ target: 'two.app', pid: 2, scripts: 1 });
    });

    it('returns an empty list when there are no sessions', async () => {
      const body = await callJson(harness.client, 'list_sessions', {});
      expect(body.result.sessions).toEqual([]);
    });
  });
});
