import { describe, it, expect, beforeEach } from 'vitest';
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
  redactTokenArg,
  selfExcludingPattern,
  type ServerOpContext,
} from '../../src/tools/advanced/server.js';
import type { AdbExecDeps, ExecResult } from '../../src/helpers/adb.js';
import { clearSuStyleCache, detectSuStyle, shellSingleQuote, wrapWithSu } from '../../src/helpers/root-elevation.js';

type Route = (argv: string) => Partial<ExecResult>;

/** The adb shell command of a fake call (argv is `-s <serial> shell <command>`). */
function shellCommandOf(argv: string): string {
  return argv.split(' shell ')[1] ?? '';
}

/** Route that answers the su-style probes like a Magisk device, delegating everything else. */
function magisk(route: Route): Route {
  return (argv) => (shellCommandOf(argv) === 'su -v' ? { stdout: '26.1:MAGISK\n' } : route(argv));
}

/** Route that answers the su-style probes like an emulator with AOSP `su` (uid argument, no `-c`). */
function legacySu(route: Route): Route {
  return (argv) => {
    const command = shellCommandOf(argv);
    if (command === 'id -u') return { stdout: '2000\n' };
    if (command === 'su -v') return { stderr: "su: invalid uid/gid '-v'", code: 1 };
    if (command === 'su 0 id -u') return { stdout: '0\n' };
    return route(argv);
  };
}

beforeEach(() => clearSuStyleCache());

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
    expect(() => assertSafeToken('~/frida-server', 'remote_path')).toThrow(/remote_path "~\/frida-server" contains characters/);
    expect(assertSafeToken('/data/local/tmp/frida-server', 'remote_path')).toBe('/data/local/tmp/frida-server');
    expect(() => buildStartCommand({ remotePath: '/tmp/x', listenAddress: '127.0.0.1', port: 1, extraArgs: [], useSu: false, token: 's3cret$(id)' })).toThrow(/^(?!.*s3cret).*token.*not allowed/);
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
    const { deps, calls } = fakeDeps(magisk((argv) => (argv.includes('pgrep') ? { stdout: '555' } : {})));
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
    const { deps } = fakeDeps(magisk(() => ({ stdout: '' })));
    await expect(
      fridaServerStart(
        ctxFor(deps),
        { remotePath: '/data/local/tmp/frida-server', listenAddress: '127.0.0.1', port: 27042, extraArgs: [], useSu: true, processName: 'frida-server' },
        async () => {},
      ),
    ).rejects.toThrow(/did not come up/);
  });
});

describe('frida-server --token', () => {
  const base = { remotePath: '/data/local/tmp/frida-server', listenAddress: '0.0.0.0', port: 27042, extraArgs: [], useSu: true, processName: 'frida-server' };

  it('appends --token to the start argv', () => {
    const cmd = buildStartCommand({ ...base, token: 'Tok_123' });
    expect(cmd).toBe("su -c '/data/local/tmp/frida-server -l 0.0.0.0:27042 -D --token Tok_123'");
  });

  it('rejects an unsafe token without echoing it', () => {
    expect(() => buildStartCommand({ ...base, token: "x';reboot;'" })).toThrow(/token contains characters/);
    try {
      buildStartCommand({ ...base, token: 'bad$(id)' });
    } catch (err) {
      expect((err as Error).message).not.toContain('bad$(id)');
    }
  });

  it('spawns with the real token but reports it redacted', async () => {
    const { deps, calls } = fakeDeps(magisk((argv) => (argv.includes('pgrep') ? { stdout: '555' } : {})));
    const result = await fridaServerStart(ctxFor(deps), { ...base, token: 'Tok_123' }, async () => {});
    expect(calls.some((c) => c.includes('--token Tok_123'))).toBe(true);
    expect(result.command).toContain('--token ***');
    expect(result.command).not.toContain('Tok_123');
  });

  it('redactTokenArg is a no-op without a token', () => {
    expect(redactTokenArg('a -D', undefined)).toBe('a -D');
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
    const { deps } = fakeDeps(magisk(() => ({ stdout: '' })));
    const result = await fridaServerStop(ctxFor(deps), { processName: 'frida-server', signal: 'TERM', useSu: true });
    expect(result.stopped).toBe(true);
    expect(result.remaining).toEqual([]);
  });

  it('waits for a still-exiting server instead of reporting it as remaining', async () => {
    let pgrepCalls = 0;
    const { deps } = fakeDeps(magisk((cmd) => {
      if (!cmd.includes('pgrep')) return { stdout: '' };
      pgrepCalls += 1;
      return { stdout: pgrepCalls < 3 ? '4242\n' : '' };
    }));
    const sleeps: number[] = [];
    const result = await fridaServerStop(
      ctxFor(deps),
      { processName: 'frida-server', signal: 'TERM', useSu: true },
      async (ms) => { sleeps.push(ms); },
    );
    expect(result).toEqual({ stopped: true, remaining: [] });
    expect(sleeps.length).toBeGreaterThan(0);
  });

  it('reports remaining pids when the server outlives the wait', async () => {
    const { deps } = fakeDeps(magisk((cmd) => {
      return { stdout: cmd.includes('pgrep') ? '4242\n' : '' };
    }));
    const result = await fridaServerStop(
      ctxFor(deps),
      { processName: 'frida-server', signal: 'TERM', useSu: true },
      async () => {},
    );
    expect(result).toEqual({ stopped: false, remaining: [4242] });
  });
});

describe('root elevation (su style)', () => {
  const startBase = { remotePath: '/data/local/tmp/frida-server', listenAddress: '127.0.0.1', port: 27042, extraArgs: [], useSu: true, processName: 'frida-server' };

  it('wraps commands for every su style', () => {
    expect(wrapWithSu('id -u', 'none')).toBe('id -u');
    expect(wrapWithSu('id -u', 'magisk')).toBe("su -c 'id -u'");
    expect(wrapWithSu('id -u', 'legacy')).toBe("su 0 sh -c 'id -u'");
  });

  it('escapes single quotes inside the wrapped command', () => {
    expect(shellSingleQuote("echo 'hi'")).toBe("'echo '\\''hi'\\'''");
    expect(wrapWithSu("echo 'a b'", 'magisk')).toBe("su -c 'echo '\\''a b'\\'''");
    expect(wrapWithSu("echo 'a b'", 'legacy')).toBe("su 0 sh -c 'echo '\\''a b'\\'''");
  });

  it('detects adbd root as style none without probing su', async () => {
    const { deps, calls } = fakeDeps((argv) => (shellCommandOf(argv) === 'id -u' ? { stdout: '0\n' } : {}));
    expect(await detectSuStyle(ctxFor(deps))).toBe('none');
    expect(calls).toHaveLength(1);
  });

  it('detects Magisk via su -v', async () => {
    const { deps } = fakeDeps(magisk((argv) => (shellCommandOf(argv) === 'id -u' ? { stdout: '2000' } : {})));
    expect(await detectSuStyle(ctxFor(deps))).toBe('magisk');
  });

  it('detects legacy su 0 when su -v fails', async () => {
    const { deps, calls } = fakeDeps(legacySu(() => ({})));
    expect(await detectSuStyle(ctxFor(deps))).toBe('legacy');
    expect(calls.map(shellCommandOf)).toEqual(['id -u', 'su -v', 'su 0 id -u']);
  });

  it('returns null when no root path works, tolerating exec errors', async () => {
    const deps: AdbExecDeps = {
      which: async () => '/usr/bin/adb',
      exec: async (_cmd, args) => {
        if (args.join(' ').endsWith('su -v')) throw new Error('timeout');
        return { stdout: '2000', stderr: '', code: 0 };
      },
    };
    expect(await detectSuStyle(ctxFor(deps))).toBeNull();
  });

  it('caches the detected style per serial', async () => {
    const { deps, calls } = fakeDeps(legacySu(() => ({})));
    await detectSuStyle(ctxFor(deps));
    await detectSuStyle(ctxFor(deps));
    expect(calls).toHaveLength(3);
    clearSuStyleCache('emulator-5554');
    await detectSuStyle(ctxFor(deps));
    expect(calls).toHaveLength(6);
  });

  it('builds a legacy-su start command', () => {
    expect(buildStartCommand({ ...startBase, suStyle: 'legacy' })).toBe("su 0 sh -c '/data/local/tmp/frida-server -l 127.0.0.1:27042 -D'");
    expect(buildStopCommand({ processName: 'fs1', signal: 'TERM', useSu: true, suStyle: 'none' })).toBe('pkill -TERM -f [f]s1');
  });

  it('starts frida-server via su 0 sh -c on a legacy-su device', async () => {
    const { deps, calls } = fakeDeps(legacySu((argv) => (argv.includes('pgrep') ? { stdout: '777' } : {})));
    const result = await fridaServerStart(ctxFor(deps), startBase, async () => {});
    expect(result.command).toBe("su 0 sh -c '/data/local/tmp/frida-server -l 127.0.0.1:27042 -D'");
    expect(calls).toContain("-s emulator-5554 shell su 0 sh -c '/data/local/tmp/frida-server -l 127.0.0.1:27042 -D' >/dev/null 2>&1 &");
  });

  it('stops frida-server without su wrapping when adbd is root', async () => {
    const { deps, calls } = fakeDeps((argv) => (shellCommandOf(argv) === 'id -u' ? { stdout: '0' } : {}));
    await fridaServerStop(ctxFor(deps), { processName: 'frida-server', signal: 'TERM', useSu: true });
    expect(calls).toContain('-s emulator-5554 shell pkill -TERM -f [f]rida-server');
  });

  it('fails with a clear error on a non-rooted device', async () => {
    const { deps, calls } = fakeDeps((argv) => (shellCommandOf(argv).startsWith('su') ? { stderr: 'su: not found', code: 127 } : { stdout: '2000' }));
    await expect(fridaServerStart(ctxFor(deps), startBase, async () => {})).rejects.toThrow(/not appear to be rooted.*adb root/);
    expect(calls.some((c) => c.includes('-D'))).toBe(false);
  });

  it('skips detection entirely when useSu is false', async () => {
    const { deps, calls } = fakeDeps((argv) => (argv.includes('pgrep') ? { stdout: '1' } : {}));
    await fridaServerStart(ctxFor(deps), { ...startBase, useSu: false }, async () => {});
    expect(calls.some((c) => c.endsWith('shell id -u') || c.includes('su -v'))).toBe(false);
  });
});
