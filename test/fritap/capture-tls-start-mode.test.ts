import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('frida', () => ({
  default: {
    getDeviceManager: () => ({}),
    Cancellable: { withTimeout: vi.fn(() => ({ isCancelled: false })) },
  },
}));

vi.mock('../../src/fritap/agent-loader.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/fritap/agent-loader.js')>()),
  locateFritapAgent: vi.fn(async () => ({ path: '/x/_ssl_log.js', source: '', version: '2.0.0', origin: 'env' })),
  readFritapAbiVersion: vi.fn(async () => 4),
  configureFritapAgent: vi.fn(() => ({ answered: [] })),
}));

vi.mock('../../src/agent/script-factory.js', () => ({ createAgentScript: vi.fn() }));

import frida from 'frida';
import { createAgentScript } from '../../src/agent/script-factory.js';
import { configureFritapAgent } from '../../src/fritap/agent-loader.js';
import {
  EARLY_RESUME_LIMITATION,
  resolveCaptureStartMode,
  runCaptureTls,
  START_TIMEOUT_RETRY_NOTE,
  stopFritapCapture,
  type CaptureTlsArgs,
} from '../../src/fritap/tool.js';
import { isAppStartTimeoutFailure, shouldRetrySuspendedStart } from '../../src/fritap/start-recovery.js';
import { FridaMcpError, ProcessNotFoundError } from '../../src/helpers/errors.js';
import { rateLimiter } from '../../src/helpers/rate-limiter.js';
import { getState, initState } from '../../src/state.js';
import { makeDevice, makeDeviceManager, SPAWNED_PID, TEST_CONFIG, type FakeDevice } from '../helpers/mock-fixtures.js';

const ARGS: CaptureTlsArgs = { target: 'com.example.app', spawn: true, anti_root: false, full_capture: false, duration_seconds: 0, allow_download: false };
const RUN = { initialOutputWaitMs: 0, livenessGraceMs: 0 };

function fakeAgentScript(load: () => Promise<void> = async () => {}) {
  return {
    load: vi.fn(load),
    unload: vi.fn(async () => {}),
    message: { connect: vi.fn() },
    destroyed: { connect: vi.fn() },
    logHandler: undefined,
    exports: {},
  };
}

function order(mock: { mock: { invocationCallOrder: number[] } }, call = 0): number {
  return mock.mock.invocationCallOrder[call];
}

describe('isAppStartTimeoutFailure', () => {
  it.each([
    [new ProcessNotFoundError('com.example.app (pid 1)'), null],
    [new Error('Process has terminated'), null],
    [new Error('Killing 4242:com.example.app/u0a1 (adj 0): start timeout'), null],
    [new Error('unable to find process with pid 4242'), null],
    [new Error('Script is destroyed'), 'process-terminated'],
  ] as Array<[unknown, string | null]>)('classifies %s (detach %s) as a start timeout', (error, reason) => {
    expect(isAppStartTimeoutFailure(error, reason)).toBe(true);
  });

  it.each([
    [new Error('Timeout was reached'), null],
    [new FridaMcpError('FRIDA_TIMEOUT', 'attach timed out after 20s', []), null],
    [new Error('SyntaxError: unexpected token'), null],
    [new Error('Script is destroyed'), 'application-requested'],
  ] as Array<[unknown, string | null]>)('does not classify %s (detach %s) as a start timeout', (error, reason) => {
    expect(isAppStartTimeoutFailure(error, reason)).toBe(false);
  });
});

describe('shouldRetrySuspendedStart', () => {
  it.each([
    ['connection closed', new Error('The connection is closed'), {}],
    ['FRIDA_TIMEOUT', new FridaMcpError('FRIDA_TIMEOUT', 'script.load timed out after 20s', []), {}],
    ['glib timeout', new Error('Timeout was reached'), {}],
    ['PROCESS_TERMINATED', new FridaMcpError('PROCESS_TERMINATED', 'died', []), {}],
    ['process-terminated detach', new Error('Script is destroyed'), { detachReason: 'process-terminated' }],
    ['dead pid, unrelated error', new Error('SyntaxError: bad agent'), { pidAlive: false }],
    ['start timeout text', new Error('start timeout'), { pidAlive: null }],
  ] as Array<[string, unknown, object]>)('retries on %s', (_label, error, observation) => {
    expect(shouldRetrySuspendedStart(error, observation)).toBe(true);
  });

  it.each([
    ['agent syntax error, app alive', new Error('SyntaxError: bad agent'), { pidAlive: true }],
    ['agent syntax error, liveness unknown', new Error('SyntaxError: bad agent'), { pidAlive: null }],
    ['application-requested detach', new Error('Script is destroyed'), { detachReason: 'application-requested', pidAlive: true }],
  ] as Array<[string, unknown, object]>)('does not retry on %s', (_label, error, observation) => {
    expect(shouldRetrySuspendedStart(error, observation)).toBe(false);
  });

  it.each([
    ['timed out text', new Error('script.load timed out after 20s')],
    ['FRIDA_TIMEOUT', new FridaMcpError('FRIDA_TIMEOUT', 'script.load timed out after 20s', [])],
    ['connection closed', new Error('The connection is closed')],
    ['start timeout text', new Error('start timeout')],
  ] as Array<[string, unknown]>)('never retries %s when the app is observed alive and attached (agent hang)', (_label, error) => {
    expect(shouldRetrySuspendedStart(error, { pidAlive: true, detachReason: null })).toBe(false);
    expect(shouldRetrySuspendedStart(error, { pidAlive: true })).toBe(false);
  });

  it('retries a timeout when liveness is unknown (pidAlive undefined/null)', () => {
    const error = new FridaMcpError('FRIDA_TIMEOUT', 'script.load timed out after 20s', []);
    expect(shouldRetrySuspendedStart(error, { detachReason: null })).toBe(true);
    expect(shouldRetrySuspendedStart(error, { pidAlive: null, detachReason: null })).toBe(true);
  });

  it('retries any error when the session detached for process-terminated even though the pid probe says alive', () => {
    expect(shouldRetrySuspendedStart(new Error('SyntaxError: bad agent'), { pidAlive: true, detachReason: 'process-terminated' })).toBe(true);
  });
});

describe('resolveCaptureStartMode', () => {
  it('maps spawn/spawn_mode to the first attempt', () => {
    expect(resolveCaptureStartMode({ spawn: true })).toBe('suspended');
    expect(resolveCaptureStartMode({ spawn: true, spawn_mode: 'suspended' })).toBe('suspended');
    expect(resolveCaptureStartMode({ spawn: true, spawn_mode: 'early_resume' })).toBe('early_resume');
    expect(resolveCaptureStartMode({ spawn: false, spawn_mode: 'early_resume' })).toBe('attach');
  });
});

describe('runCaptureTls start order', () => {
  let device: FakeDevice;
  let deviceManager: any;

  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    rateLimiter.reset();
    vi.mocked(frida.Cancellable.withTimeout).mockImplementation(() => ({ isCancelled: false }) as any);
    device = makeDevice();
    // The spawned pid is alive unless a test kills it.
    device.enumerateProcesses.mockImplementation(async (options?: { pids?: number[] }) =>
      (options?.pids ?? []).filter((pid) => pid === SPAWNED_PID).map((pid) => ({ pid, name: 'app' })));
    deviceManager = makeDeviceManager(device);
  });

  function killAfterResume(times = 1): void {
    let remaining = times;
    device.resume.mockImplementation(async () => {
      if (remaining-- > 0) device.enumerateProcesses.mockResolvedValueOnce([]);
    });
  }

  afterEach(async () => {
    for (const session of getState().sessions.values()) {
      for (const id of session.scripts.keys()) await stopFritapCapture(id);
    }
    getState().stopCleanupTimer();
    vi.mocked(createAgentScript).mockReset();
  });

  it('suspended (default): spawn -> attach -> load -> resume, no early-resume limitation', async () => {
    const script = fakeAgentScript();
    vi.mocked(createAgentScript).mockResolvedValue(script as any);

    const result: any = await runCaptureTls(deviceManager, ARGS, RUN);

    expect(order(device.spawn)).toBeLessThan(order(device.attach));
    expect(order(device.attach)).toBeLessThan(order(script.load));
    expect(order(script.load)).toBeLessThan(order(device.resume));
    expect(device.resume).toHaveBeenCalledTimes(1);
    expect(result.result.spawn_mode).toBe('suspended');
    expect(result.result.start_retried).toBe(false);
    expect(result.limitations).not.toContain(EARLY_RESUME_LIMITATION);
  });

  it('early_resume: spawn -> attach -> resume -> load, with the limitation', async () => {
    const script = fakeAgentScript();
    vi.mocked(createAgentScript).mockResolvedValue(script as any);

    const result: any = await runCaptureTls(deviceManager, { ...ARGS, spawn_mode: 'early_resume' }, RUN);

    expect(order(device.spawn)).toBeLessThan(order(device.attach));
    expect(order(device.attach)).toBeLessThan(order(device.resume));
    expect(order(device.resume)).toBeLessThan(order(script.load));
    expect(device.spawn).toHaveBeenCalledTimes(1);
    expect(result.result.spawn_mode).toBe('early_resume');
    expect(result.limitations).toContain(EARLY_RESUME_LIMITATION);
    expect(result.limitations).not.toContain(START_TIMEOUT_RETRY_NOTE);
  });

  it('retries once in early-resume mode when the suspended app is killed during load', async () => {
    const killed = fakeAgentScript(async () => {
      device.enumerateProcesses.mockResolvedValueOnce([]);
      throw new Error('Process has terminated');
    });
    const second = fakeAgentScript();
    vi.mocked(createAgentScript).mockResolvedValueOnce(killed as any).mockResolvedValueOnce(second as any);

    const result: any = await runCaptureTls(deviceManager, ARGS, RUN);

    expect(device.spawn).toHaveBeenCalledTimes(2);
    expect(device.kill).toHaveBeenCalledWith(SPAWNED_PID);
    // Second attempt: attach -> resume -> load.
    expect(order(device.attach, 1)).toBeLessThan(order(device.resume, 0));
    expect(order(device.resume, 0)).toBeLessThan(order(second.load));
    expect(device.resume).toHaveBeenCalledTimes(1);
    expect(result.result.spawn_mode).toBe('early_resume');
    expect(result.result.start_retried).toBe(true);
    expect(result.limitations).toEqual(expect.arrayContaining([EARLY_RESUME_LIMITATION, START_TIMEOUT_RETRY_NOTE]));
  });

  it('retries when the attach finds the spawned process gone (PROCESS_NOT_FOUND)', async () => {
    device.attach.mockRejectedValueOnce(new Error('unable to find process with pid 4242'));
    vi.mocked(createAgentScript).mockResolvedValue(fakeAgentScript() as any);

    const result: any = await runCaptureTls(deviceManager, ARGS, RUN);

    expect(device.spawn).toHaveBeenCalledTimes(2);
    expect(result.result.start_retried).toBe(true);
  });

  it('retries at most once', async () => {
    const dies = () => fakeAgentScript(async () => {
      device.enumerateProcesses.mockResolvedValueOnce([]);
      throw new Error('Process has terminated');
    });
    vi.mocked(createAgentScript).mockResolvedValueOnce(dies() as any).mockResolvedValueOnce(dies() as any);

    await expect(runCaptureTls(deviceManager, ARGS, RUN)).rejects.toThrow(/terminated/);
    expect(device.spawn).toHaveBeenCalledTimes(2);
    expect(getState().sessions.size).toBe(0);
  });

  it('does not retry other failures', async () => {
    vi.mocked(createAgentScript).mockResolvedValue(fakeAgentScript(async () => { throw new Error('SyntaxError: bad agent'); }) as any);

    await expect(runCaptureTls(deviceManager, ARGS, RUN)).rejects.toThrow(/SyntaxError/);
    expect(device.spawn).toHaveBeenCalledTimes(1);
    expect(device.kill).toHaveBeenCalledWith(SPAWNED_PID);
  });

  it('does not retry an explicit early_resume start', async () => {
    vi.mocked(createAgentScript).mockResolvedValue(fakeAgentScript(async () => { throw new Error('Process has terminated'); }) as any);

    await expect(runCaptureTls(deviceManager, { ...ARGS, spawn_mode: 'early_resume' }, RUN)).rejects.toThrow(/terminated/);
    expect(device.spawn).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['The connection is closed', new Error('The connection is closed')],
    ['FRIDA_TIMEOUT', new FridaMcpError('FRIDA_TIMEOUT', 'script.load timed out after 20s', [])],
  ])('retries when the suspended load fails with %s and liveness is unknown', async (_label, error) => {
    vi.mocked(createAgentScript)
      .mockResolvedValueOnce(fakeAgentScript(async () => {
        device.enumerateProcesses.mockRejectedValueOnce(new Error('probe failed'));
        throw error;
      }) as any)
      .mockResolvedValueOnce(fakeAgentScript() as any);

    const result: any = await runCaptureTls(deviceManager, ARGS, RUN);

    expect(device.spawn).toHaveBeenCalledTimes(2);
    expect(result.result.start_retried).toBe(true);
    expect(result.result.spawn_mode).toBe('early_resume');
  });

  it('surfaces an agent hang (FRIDA_TIMEOUT) without retry when the app is observed alive and attached', async () => {
    const hang = new FridaMcpError('FRIDA_TIMEOUT', 'script.load timed out after 20s', []);
    vi.mocked(createAgentScript).mockResolvedValue(fakeAgentScript(async () => { throw hang; }) as any);

    const error = await runCaptureTls(deviceManager, ARGS, RUN).catch((e) => e);

    expect(error).toBe(hang);
    expect(device.spawn).toHaveBeenCalledTimes(1);
  });

  it('retries an unrelated load error when the spawned pid is gone (state wins over message)', async () => {
    vi.mocked(createAgentScript)
      .mockResolvedValueOnce(fakeAgentScript(async () => {
        device.enumerateProcesses.mockResolvedValueOnce([]);
        throw new Error('Error: script is not loaded');
      }) as any)
      .mockResolvedValueOnce(fakeAgentScript() as any);

    const result: any = await runCaptureTls(deviceManager, ARGS, RUN);

    expect(result.result.start_retried).toBe(true);
  });

  it('observes the target before killing it on a failed start', async () => {
    vi.mocked(createAgentScript).mockResolvedValue(fakeAgentScript(async () => { throw new Error('SyntaxError: bad agent'); }) as any);

    await expect(runCaptureTls(deviceManager, ARGS, RUN)).rejects.toThrow(/SyntaxError/);
    expect(order(device.enumerateProcesses)).toBeLessThan(order(device.kill));
  });

  it('never reports success for an app killed right after the resume: retries in early_resume', async () => {
    killAfterResume(1);
    vi.mocked(createAgentScript).mockResolvedValue(fakeAgentScript() as any);

    const result: any = await runCaptureTls(deviceManager, ARGS, RUN);

    expect(device.spawn).toHaveBeenCalledTimes(2);
    expect(device.resume).toHaveBeenCalledTimes(2);
    expect(result.result.start_retried).toBe(true);
    expect(result.result.spawn_mode).toBe('early_resume');
  });

  it('treats a session detached after the resume as dead', async () => {
    let first = true;
    device.resume.mockImplementation(async () => {
      if (!first) return;
      first = false;
      const entry = [...getState().sessions.values()][0];
      entry.detachReason = 'process-terminated';
    });
    vi.mocked(createAgentScript).mockResolvedValue(fakeAgentScript() as any);

    const result: any = await runCaptureTls(deviceManager, ARGS, RUN);

    expect(result.result.start_retried).toBe(true);
  });

  it('returns PROCESS_TERMINATED when the app also dies after the early_resume retry', async () => {
    killAfterResume(2);
    vi.mocked(createAgentScript).mockResolvedValue(fakeAgentScript() as any);

    const error = await runCaptureTls(deviceManager, ARGS, RUN).catch((e) => e);

    expect(error).toBeInstanceOf(FridaMcpError);
    expect(error.code).toBe('PROCESS_TERMINATED');
    expect(error.remediation).toMatch(/early_resume|spawn=false/);
    expect(device.spawn).toHaveBeenCalledTimes(2);
    expect(getState().sessions.size).toBe(0);
  });

  it('returns PROCESS_TERMINATED without retry for an explicit early_resume start whose app dies', async () => {
    killAfterResume(1);
    vi.mocked(createAgentScript).mockResolvedValue(fakeAgentScript() as any);

    const error = await runCaptureTls(deviceManager, { ...ARGS, spawn_mode: 'early_resume' }, RUN).catch((e) => e);

    expect(error.code).toBe('PROCESS_TERMINATED');
    expect(device.spawn).toHaveBeenCalledTimes(1);
  });

  it('spawn=false attaches to the running process without spawning or retrying', async () => {
    device.enumerateApplications.mockResolvedValue([{ identifier: ARGS.target, name: 'Example', pid: 777 }]);
    vi.mocked(createAgentScript).mockResolvedValue(fakeAgentScript(async () => { throw new Error('Process has terminated'); }) as any);

    await expect(runCaptureTls(deviceManager, { ...ARGS, spawn: false }, RUN)).rejects.toThrow(/terminated/);
    expect(device.spawn).not.toHaveBeenCalled();
    expect(device.attach).toHaveBeenCalledTimes(1);
    expect(device.kill).not.toHaveBeenCalled();
    // The session this capture created is removed again.
    expect(getState().sessions.size).toBe(0);
  });

  it('a failed spawn=false capture on an existing shared session only unloads its own friTap script', async () => {
    device.enumerateApplications.mockResolvedValue([{ identifier: ARGS.target, name: 'Example', pid: 777 }]);
    vi.mocked(createAgentScript).mockResolvedValueOnce(fakeAgentScript() as any);
    const first: any = await runCaptureTls(deviceManager, { ...ARGS, spawn: false }, RUN);
    const session = getState().getSession(first.result.session_id)!;
    // A second friTap agent in one process is refused (FRITAP_CAPTURE_ACTIVE), so the first
    // capture is stopped; the session (and the user's hook) stays shared.
    await stopFritapCapture(first.result.script_id);
    const userHook = fakeAgentScript();
    session.scripts.set('user-hook', { id: 'user-hook', script: userHook as any, messages: [], createdAt: Date.now() });
    const failing = fakeAgentScript(async () => { throw new Error('SyntaxError: bad agent'); });
    vi.mocked(createAgentScript).mockResolvedValueOnce(failing as any);

    await expect(runCaptureTls(deviceManager, { ...ARGS, spawn: false }, RUN)).rejects.toThrow(/SyntaxError/);

    expect(getState().getSession(session.id)).toBe(session);
    expect(session.scripts.has('user-hook')).toBe(true);
    expect(session.scripts.size).toBe(1);
    expect(failing.unload).toHaveBeenCalled();
    expect(userHook.unload).not.toHaveBeenCalled();
    expect(device.kill).not.toHaveBeenCalled();
    expect(device.attach).toHaveBeenCalledTimes(1);
  });

  it('refuses a second capture into a process that already runs one (FRITAP_CAPTURE_ACTIVE)', async () => {
    device.enumerateApplications.mockResolvedValue([{ identifier: ARGS.target, name: 'Example', pid: 777 }]);
    const firstScript = fakeAgentScript();
    vi.mocked(createAgentScript).mockResolvedValueOnce(firstScript as any);
    const first: any = await runCaptureTls(deviceManager, { ...ARGS, spawn: false }, RUN);
    const session = getState().getSession(first.result.session_id)!;

    const err: any = await runCaptureTls(deviceManager, { ...ARGS, spawn: false }, RUN).catch((e) => e);

    expect(err).toBeInstanceOf(FridaMcpError);
    expect(err.code).toBe('FRITAP_CAPTURE_ACTIVE');
    expect(err.category).toBe('request');
    expect(err.retryable).toBe(false);
    expect(err.message).toContain(first.result.script_id);
    expect(err.context).toMatchObject({ session_id: session.id, script_id: first.result.script_id, pid: 777 });
    expect(err.recoveryActions.map((a: any) => a.tool)).toEqual(['get_messages', 'unload_script', 'stop_instrumentation']);
    // Nothing new was created, the running capture is untouched.
    expect(createAgentScript).toHaveBeenCalledTimes(1);
    expect(firstScript.unload).not.toHaveBeenCalled();
    expect(getState().getSession(session.id)).toBe(session);
    expect(session.scripts.has(first.result.script_id)).toBe(true);
    expect(device.kill).not.toHaveBeenCalled();
  });

  it('refuses a second capture into the same pid even through another session', async () => {
    device.enumerateApplications.mockResolvedValue([{ identifier: ARGS.target, name: 'Example', pid: 777 }]);
    vi.mocked(createAgentScript).mockResolvedValueOnce(fakeAgentScript() as any);
    const first: any = await runCaptureTls(deviceManager, { ...ARGS, spawn: false }, RUN);
    // Move the first session to another realm so the second call cannot reuse it and attaches anew.
    const firstSession = getState().getSession(first.result.session_id)!;
    (firstSession as any).realm = 'emulated';

    const err: any = await runCaptureTls(deviceManager, { ...ARGS, spawn: false }, RUN).catch((e) => e);

    expect(err.code).toBe('FRITAP_CAPTURE_ACTIVE');
    expect(device.attach).toHaveBeenCalledTimes(2);
    expect(createAgentScript).toHaveBeenCalledTimes(1);
    // The session the refused attempt created is removed again; the capture's session stays.
    expect([...getState().sessions.keys()]).toEqual([firstSession.id]);
  });

  it('allows a new capture into the process once the previous one is stopped', async () => {
    device.enumerateApplications.mockResolvedValue([{ identifier: ARGS.target, name: 'Example', pid: 777 }]);
    vi.mocked(createAgentScript).mockResolvedValue(fakeAgentScript() as any);
    const first: any = await runCaptureTls(deviceManager, { ...ARGS, spawn: false }, RUN);
    await stopFritapCapture(first.result.script_id);

    const second: any = await runCaptureTls(deviceManager, { ...ARGS, spawn: false }, RUN);

    expect(second.result.session_id).toBe(first.result.session_id);
    expect(second.result.script_id).not.toBe(first.result.script_id);
  });

  it.each([
    ['patterns', 'not json {'],
    ['patterns', '[1,2]'],
    ['patterns', 42],
    ['offsets', 'null'],
    ['offsets', ['0x1234']],
    ['offsets', '"0x1234"'],
  ])('rejects invalid %s %j with INVALID_ARGUMENT before any spawn or attach', async (field, value) => {
    const err: any = await runCaptureTls(deviceManager, { ...ARGS, [field]: value }, RUN).catch((e) => e);

    expect(err.code).toBe('INVALID_ARGUMENT');
    expect(err.message).toMatch(new RegExp(`^${field} `));
    expect(device.spawn).not.toHaveBeenCalled();
    expect(device.attach).not.toHaveBeenCalled();
    expect(createAgentScript).not.toHaveBeenCalled();
  });

  it.each([
    ['patterns as a JSON string', { patterns: '{"modules":{}}' }],
    ['offsets as an object', { offsets: { openssl: { SSL_read: { address: '0x10', absolute: false } } } }],
  ])('accepts %s', async (_label, overrides) => {
    vi.mocked(createAgentScript).mockResolvedValue(fakeAgentScript() as any);
    await expect(runCaptureTls(deviceManager, { ...ARGS, ...overrides }, RUN)).resolves.toBeDefined();
  });

  it.each([
    ['suspended', { spawn_mode: 'suspended' as const }, true],
    ['early_resume (app resumed before the load, still in its startup window)', { spawn_mode: 'early_resume' as const }, true],
    ['attach to a running process', { spawn: false }, false],
  ])('passes the friTap spawned flag for %s', async (_label, overrides, spawned) => {
    device.enumerateApplications.mockResolvedValue([{ identifier: ARGS.target, name: 'Example', pid: 777 }]);
    vi.mocked(createAgentScript).mockResolvedValue(fakeAgentScript() as any);
    vi.mocked(configureFritapAgent).mockClear();

    await runCaptureTls(deviceManager, { ...ARGS, ...overrides }, RUN);

    expect(vi.mocked(configureFritapAgent).mock.calls[0][1]).toMatchObject({ spawned });
  });
});
