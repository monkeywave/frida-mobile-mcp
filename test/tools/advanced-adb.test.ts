import { describe, it, expect } from 'vitest';
import { buildLogcatArgs, adbForward, adbLogcat, adbPull, type AdbOpContext } from '../../src/tools/advanced/adb.js';
import type { AdbExecDeps, ExecResult } from '../../src/helpers/adb.js';

function fakeDeps(route: (argv: string) => Partial<ExecResult> = () => ({})): { deps: AdbExecDeps; calls: string[][] } {
  const calls: string[][] = [];
  const deps: AdbExecDeps = {
    which: async (bin) => (bin === 'adb' ? '/usr/bin/adb' : null),
    exec: async (_cmd, args) => {
      calls.push(args);
      return { stdout: '', stderr: '', code: 0, ...route(args.join(' ')) };
    },
  };
  return { deps, calls };
}

function ctxFor(deps: AdbExecDeps): AdbOpContext {
  return { deps, adbPath: '/usr/bin/adb', serial: 'emulator-5554' };
}

describe('buildLogcatArgs', () => {
  it('builds a bounded one-shot dump with filters', () => {
    expect(buildLogcatArgs({ lines: 50, filters: ['MyTag:D', '*:S'], clear: false })).toEqual(['logcat', '-t', '50', 'MyTag:D', '*:S']);
  });

  it('builds a clear command', () => {
    expect(buildLogcatArgs({ lines: 200, filters: [], clear: true })).toEqual(['logcat', '-c']);
  });
});

describe('adb ops scope to the serial', () => {
  it('adbLogcat passes -s <serial> and the logcat args', async () => {
    const { deps, calls } = fakeDeps();
    await adbLogcat(ctxFor(deps), { lines: 10, filters: [], clear: false });
    expect(calls[0].slice(0, 2)).toEqual(['-s', 'emulator-5554']);
    expect(calls[0]).toContain('logcat');
    expect(calls[0]).toContain('-t');
  });

  it('adbPull passes pull with remote and local paths', async () => {
    const { deps, calls } = fakeDeps();
    await adbPull(ctxFor(deps), '/data/local/tmp/x', './x');
    expect(calls[0]).toEqual(['-s', 'emulator-5554', 'pull', '/data/local/tmp/x', './x']);
  });
});

describe('adbForward', () => {
  it('requires both endpoints when adding', async () => {
    const { deps } = fakeDeps();
    await expect(adbForward(ctxFor(deps), { local: 'tcp:27042' })).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
  });

  it('lists forwards', async () => {
    const { deps, calls } = fakeDeps();
    await adbForward(ctxFor(deps), { list: true });
    expect(calls[0]).toEqual(['-s', 'emulator-5554', 'forward', '--list']);
  });

  it('adds a forward', async () => {
    const { deps, calls } = fakeDeps();
    await adbForward(ctxFor(deps), { local: 'tcp:27042', remote: 'tcp:12345' });
    expect(calls[0]).toEqual(['-s', 'emulator-5554', 'forward', 'tcp:27042', 'tcp:12345']);
  });

  it('removes a forward', async () => {
    const { deps, calls } = fakeDeps();
    await adbForward(ctxFor(deps), { remove: 'tcp:27042' });
    expect(calls[0]).toEqual(['-s', 'emulator-5554', 'forward', '--remove', 'tcp:27042']);
  });
});
