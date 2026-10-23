import { describe, it, expect } from 'vitest';
import {
  abiToFridaArch,
  assertSafeToken,
  buildStartCommand,
  buildStopCommand,
  fridaServerAssetUrl,
  fridaServerInstall,
  fridaServerStart,
  fridaServerStatus,
  fridaServerStop,
  parsePids,
  selfExcludingPattern,
  type ServerOpContext,
} from '../../src/tools/advanced/server.js';
import type { AdbExecDeps, ExecResult } from '../../src/helpers/adb.js';

/** Build a fake adb deps whose exec is driven by a matcher over the joined argv. */
function fakeDeps(route: (argv: string) => Partial<ExecResult>): { deps: AdbExecDeps; calls: string[] } {
  const calls: string[] = [];
  const deps: AdbExecDeps = {
    which: async (bin) => (bin === 'adb' ? '/usr/bin/adb' : null),
    exec: async (_cmd, args) => {
      const argv = args.join(' ');
      calls.push(argv);
      return { stdout: '', stderr: '', code: 0, ...route(argv) };
    },
  };
  return { deps, calls };
}

function ctxFor(deps: AdbExecDeps): ServerOpContext {
  return { deps, adbPath: '/usr/bin/adb', serial: 'emulator-5554' };
}

describe('server pure helpers', () => {
  it('maps Android ABIs to frida release archs', () => {
    expect(abiToFridaArch('arm64-v8a')).toBe('arm64');
    expect(abiToFridaArch('armeabi-v7a')).toBe('arm');
    expect(abiToFridaArch('x86_64')).toBe('x86_64');
    expect(abiToFridaArch('x86')).toBe('x86');
    expect(abiToFridaArch('mips')).toBeNull();
  });

  it('builds the GitHub asset URL for a version + arch', () => {
    expect(fridaServerAssetUrl('17.2.1', 'arm64')).toBe(
      'https://github.com/frida/frida/releases/download/v17.2.1/frida-server-17.2.1-android-arm64.xz',
    );
    expect(fridaServerAssetUrl('v17.2.1', 'arm64')).toContain('/v17.2.1/');
  });

  it('builds a daemonized start command with a custom port, via su', () => {
    const cmd = buildStartCommand({ remotePath: '/data/local/tmp/fs1', listenAddress: '127.0.0.1', port: 12345, extraArgs: [], useSu: true });
    expect(cmd).toBe("su -c '/data/local/tmp/fs1 -l 127.0.0.1:12345 -D'");
  });

  it('builds a start command without su when requested', () => {
    const cmd = buildStartCommand({ remotePath: '/data/local/tmp/frida-server', listenAddress: '0.0.0.0', port: 27042, extraArgs: ['-v'], useSu: false });
    expect(cmd).toBe('/data/local/tmp/frida-server -l 0.0.0.0:27042 -D -v');
  });

  it('builds a stop command whose pattern cannot self-match the pkill wrapper', () => {
    // The [f]-class means the literal "[f]s1" in `sh -c '... [f]s1'` does not match the regex,
    // but a real "fs1" process still does — so pkill never signals its own shell wrapper.
    expect(buildStopCommand({ processName: 'fs1', signal: 'KILL', useSu: true })).toBe("su -c 'pkill -KILL -f [f]s1'");
  });

  it('builds a self-excluding pgrep/pkill pattern', () => {
    expect(selfExcludingPattern('frida-server')).toBe('[f]rida-server');
    expect(selfExcludingPattern('x')).toBe('[x]');
  });

  it('rejects shell-metacharacter injection in tokens', () => {
    expect(() => assertSafeToken('a; rm -rf /', 'x')).toThrow(/not allowed/);
    expect(() => buildStartCommand({ remotePath: '/tmp/x$(id)', listenAddress: '127.0.0.1', port: 1, extraArgs: [], useSu: true })).toThrow(/not allowed/);
    expect(() => buildStopCommand({ processName: 'fs && reboot', signal: 'TERM', useSu: false })).toThrow(/not allowed/);
  });

  it('parses pids from pgrep output', () => {
    expect(parsePids('123\n456\n')).toEqual([123, 456]);
    expect(parsePids('  789 ')).toEqual([789]);
    expect(parsePids('')).toEqual([]);
  });
});

describe('fridaServerStatus', () => {
  it('reports running when pgrep returns pids and maps the ABI', async () => {
    const { deps, calls } = fakeDeps((argv) => {
      if (argv.includes('pgrep')) return { stdout: '4321\n' };
      if (argv.includes('ro.product.cpu.abi')) return { stdout: 'arm64-v8a\n' };
      return {};
    });
    const status = await fridaServerStatus(ctxFor(deps), { processName: 'frida-server', port: 27042 });
    expect(status.running).toBe(true);
    expect(status.pids).toEqual([4321]);
    expect(status.deviceAbi).toBe('arm64-v8a');
    expect(status.fridaArch).toBe('arm64');
    // The pgrep must use the self-excluding pattern, not the bare name.
    expect(calls.some((c) => c.includes('pgrep -f [f]rida-server'))).toBe(true);
  });

  it('reports not running when pgrep is empty', async () => {
    const { deps } = fakeDeps((argv) => (argv.includes('ro.product.cpu.abi') ? { stdout: 'x86_64' } : {}));
    const status = await fridaServerStatus(ctxFor(deps), { processName: 'frida-server', port: 27042 });
    expect(status.running).toBe(false);
    expect(status.pids).toEqual([]);
  });
});

describe('fridaServerStart', () => {
  it('starts and confirms the server came up', async () => {
    const { deps, calls } = fakeDeps((argv) => (argv.includes('pgrep') ? { stdout: '555' } : {}));
    const result = await fridaServerStart(
      ctxFor(deps),
      { remotePath: '/data/local/tmp/frida-server', listenAddress: '127.0.0.1', port: 27042, extraArgs: [], useSu: true, processName: 'frida-server' },
      async () => {},
    );
    expect(result.started).toBe(true);
    expect(result.pids).toEqual([555]);
    expect(calls.some((c) => c.includes('-D') && c.includes('&'))).toBe(true);
  });

  it('throws when the server never appears', async () => {
    const { deps } = fakeDeps(() => ({ stdout: '' }));
    await expect(
      fridaServerStart(
        ctxFor(deps),
        { remotePath: '/data/local/tmp/frida-server', listenAddress: '127.0.0.1', port: 27042, extraArgs: [], useSu: true, processName: 'frida-server' },
        async () => {},
      ),
    ).rejects.toThrow(/did not come up/);
  });
});

describe('fridaServerInstall', () => {
  it('rejects a missing local binary before touching the device', async () => {
    const { deps, calls } = fakeDeps(() => ({}));
    await expect(
      fridaServerInstall(ctxFor(deps), { binaryPath: '/nope/frida-server', remotePath: '/data/local/tmp/frida-server', overwrite: false }),
    ).rejects.toThrow(/does not exist/);
    expect(calls).toHaveLength(0);
  });
});

describe('fridaServerStop', () => {
  it('reports stopped when no pids remain', async () => {
    const { deps } = fakeDeps(() => ({ stdout: '' }));
    const result = await fridaServerStop(ctxFor(deps), { processName: 'frida-server', signal: 'TERM', useSu: true });
    expect(result.stopped).toBe(true);
    expect(result.remaining).toEqual([]);
  });
});
