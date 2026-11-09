import { describe, it, expect, vi } from 'vitest';

vi.mock('frida', () => ({
  default: { Cancellable: { withTimeout: vi.fn(() => ({ isCancelled: false })) } },
}));

import {
  isTargetDead,
  probePidAlive,
  processTerminatedError,
  waitForDetach,
} from '../../src/fritap/start-recovery.js';

function deviceWith(enumerate: (...args: any[]) => Promise<any>) {
  return { enumerateProcesses: vi.fn(enumerate) } as any;
}

describe('probePidAlive', () => {
  it('queries only the pid and reports whether it is listed', async () => {
    const device = deviceWith(async () => [{ pid: 7, name: 'app' }]);
    expect(await probePidAlive(device, 7)).toBe(true);
    expect(device.enumerateProcesses.mock.calls[0][0]).toMatchObject({ pids: [7] });
    expect(await probePidAlive(deviceWith(async () => []), 7)).toBe(false);
  });

  it('returns null (unknown) when the device query fails', async () => {
    expect(await probePidAlive(deviceWith(async () => { throw new Error('The connection is closed'); }), 7)).toBeNull();
  });
});

describe('waitForDetach', () => {
  it('returns the recorded detach reason immediately', async () => {
    expect(await waitForDetach({ detachReason: 'process-terminated', session: {} } as any, 5_000)).toBe('process-terminated');
  });

  it('notices a detach that arrives within the grace period', async () => {
    const entry: any = { session: {} };
    setTimeout(() => { entry.detachReason = 'process-terminated'; }, 20);
    expect(await waitForDetach(entry, 2_000)).toBe('process-terminated');
  });

  it('uses session.isDetached() and returns null for a live session after the grace', async () => {
    expect(await waitForDetach({ session: { isDetached: () => true } } as any, 0)).toBe('detached');
    expect(await waitForDetach({ session: { isDetached: () => false } } as any, 0)).toBeNull();
  });
});

describe('isTargetDead / processTerminatedError', () => {
  it('is dead when detached or the pid is gone, alive when unknown', () => {
    expect(isTargetDead({ detachReason: 'process-terminated' })).toBe(true);
    expect(isTargetDead({ pidAlive: false })).toBe(true);
    expect(isTargetDead({ pidAlive: null })).toBe(false);
    expect(isTargetDead({ detachReason: null, pidAlive: true })).toBe(false);
  });

  it('builds a structured, retryable PROCESS_TERMINATED error with remediation', () => {
    const error = processTerminatedError('com.example.app', 42, { pidAlive: false });
    expect(error.code).toBe('PROCESS_TERMINATED');
    expect(error.retryable).toBe(true);
    expect(error.message).toContain('pid 42');
    expect(error.remediation).toContain('early_resume');
    expect(error.context).toMatchObject({ pid: 42, pid_alive: false });
  });
});
