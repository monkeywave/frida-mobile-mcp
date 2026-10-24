import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

vi.mock('frida', () => ({
  default: {
    getDeviceManager: () => ({}),
    Cancellable: { withTimeout: vi.fn(() => ({ isCancelled: false })) },
  },
}));

import {
  isSafeDevicePath,
  parseDumpsysPackage,
  parsePmPath,
  parseSha256sum,
  parseStatSizes,
  registerAppInfoTool,
  sanitizeFridaParameters,
} from '../../src/tools/app-info.js';
import { initState, getState } from '../../src/state.js';
import type { AdbExecDeps, ExecResult } from '../../src/helpers/adb.js';
import { sha256Hex } from '../../src/helpers/sanitize.js';
import { makeMcpHarness, callJson, makeDevice, makeDeviceManager, TEST_CONFIG, type McpHarness } from '../helpers/mock-fixtures.js';

const PKG = 'com.example.rc4demo';
const SERIAL = 'emulator-5554';
const APK_DIR = `/data/app/~~QmV4YW1wbGU_aGFzaA==/${PKG}-Ab1cD2eF3gH4iJ5kL6mN7w==`;
const BASE = `${APK_DIR}/base.apk`;
const SPLIT_ABI = `${APK_DIR}/split_config.arm64_v8a.apk`;
const SPLIT_DPI = `${APK_DIR}/split_config.xxhdpi.apk`;

const PM_PATH_OUT = [`package:${BASE}`, `package:${SPLIT_ABI}`, `package:${SPLIT_DPI}`, ''].join('\n');

const DUMPSYS_OUT = `Activity Resolver Table:
  Non-Data Actions:
      android.intent.action.MAIN:
        a1b2c3 ${PKG}/.MainActivity filter d4e5f6
Key Set Manager:
  [${PKG}]
      Signing KeySets: 57

Packages:
  Package [${PKG}] (8f3e2a1):
    userId=10187
    pkg=Package{5c1d2e3 ${PKG}}
    codePath=${APK_DIR}
    resourcePath=${APK_DIR}
    legacyNativeLibraryDir=${APK_DIR}/lib
    extractNativeLibs=false
    primaryCpuAbi=arm64-v8a
    secondaryCpuAbi=null
    cpuAbiOverride=null
    versionCode=7 minSdk=24 targetSdk=34
    minExtensionVersions=[]
    versionName=1.4.2
    usesNonSdkApi=false
    splits=[base, config.arm64_v8a, config.xxhdpi]
    apkSigningVersion=2
    flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
    privateFlags=[ PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE ]
    forceQueryable=false
    dataDir=/data/user/0/${PKG}
    timeStamp=2026-10-20 14:03:11
    firstInstallTime=2026-10-20 14:03:12
    lastUpdateTime=2026-10-21 09:15:40
    installerPackageName=com.android.vending
    installPermissionsFixed=true
    pkgFlags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
    User 0: ceDataInode=12345 installed=true hidden=false suspended=false stopped=false notLaunched=false enabled=0
      gids=[3003]
      runtime permissions:

Hidden system packages:
  Package [${PKG}] (deadbeef):
    versionCode=1 minSdk=21 targetSdk=30
    versionName=0.9
    flags=[ SYSTEM HAS_CODE ]
`;

const CONTENT: Record<string, string> = { [BASE]: 'base-apk-bytes', [SPLIT_ABI]: 'abi-split-bytes', [SPLIT_DPI]: 'dpi-split-bytes' };
const sha = sha256Hex;

function sha256Out(paths: string[], override: Record<string, string> = {}): string {
  return paths.map((p) => `${override[p] ?? sha(CONTENT[p])}  ${p}`).join('\n') + '\n';
}

function statOut(paths: string[]): string {
  return paths.map((p) => `${Buffer.byteLength(CONTENT[p])} ${p}`).join('\n') + '\n';
}

interface FakeAdbOptions {
  pmPath?: string;
  hashOverride?: Record<string, string>;
}

/** Fake adb that answers the fixed get_app_info command set and writes pulled files. */
function fakeAdb(options: FakeAdbOptions = {}): { deps: AdbExecDeps; calls: string[][] } {
  const calls: string[][] = [];
  const respond = (args: string[]): Partial<ExecResult> => {
    const argv = args.join(' ');
    if (args[0] === 'devices') return { stdout: `List of devices attached\n${SERIAL}\tdevice\n` };
    if (argv.includes('pm path')) return { stdout: options.pmPath ?? PM_PATH_OUT };
    if (argv.includes('dumpsys package')) return { stdout: DUMPSYS_OUT };
    const paths = args.filter((a) => a.startsWith('/data/app/'));
    if (argv.includes('sha256sum')) return { stdout: sha256Out(paths, options.hashOverride) };
    if (argv.includes('stat')) return { stdout: statOut(paths) };
    if (args.includes('pull')) {
      const [remote, local] = args.slice(args.indexOf('pull') + 1);
      writeFileSync(local, CONTENT[remote]);
      return {};
    }
    return { code: 1, stderr: 'unexpected' };
  };
  const deps: AdbExecDeps = {
    which: async (bin) => (bin === 'adb' ? '/usr/bin/adb' : null),
    exec: async (_cmd, args) => {
      calls.push(args);
      return { stdout: '', stderr: '', code: 0, ...respond(args) };
    },
  };
  return { deps, calls };
}

const FRIDA_APP = {
  identifier: PKG,
  name: 'RC4 Demo',
  pid: 0,
  parameters: { version: '1.4.2', build: '7', sources: [BASE, SPLIT_ABI, SPLIT_DPI], 'data-dir': `/data/user/0/${PKG}`, icons: [Buffer.from('png')] },
};

// ---------------------------------------------------------------------------
// Pure parsers
// ---------------------------------------------------------------------------

describe('get_app_info parsers', () => {
  it('parsePmPath strips the package: prefix and keeps base + splits', () => {
    expect(parsePmPath(PM_PATH_OUT)).toEqual([BASE, SPLIT_ABI, SPLIT_DPI]);
    expect(parsePmPath('')).toEqual([]);
    expect(parsePmPath('Error: unknown package\n')).toEqual([]);
  });

  it('parseDumpsysPackage reads the first Package block only', () => {
    expect(parseDumpsysPackage(DUMPSYS_OUT)).toEqual({
      version_name: '1.4.2',
      version_code: 7,
      target_sdk: 34,
      min_sdk: 24,
      debuggable: true,
      primary_cpu_abi: 'arm64-v8a',
      native_lib_dir: `${APK_DIR}/lib`,
      data_dir: `/data/user/0/${PKG}`,
      installer: 'com.android.vending',
      last_update_time: '2026-10-21 09:15:40',
    });
  });

  it('parseDumpsysPackage reports debuggable false and omits null/missing fields', () => {
    const out = `Packages:\n  Package [a.b] (1):\n    versionCode=3 minSdk=21 targetSdk=33\n    flags=[ HAS_CODE ]\n    primaryCpuAbi=null\n    installerPackageName=null\n`;
    expect(parseDumpsysPackage(out)).toEqual({ version_code: 3, min_sdk: 21, target_sdk: 33, debuggable: false });
    expect(parseDumpsysPackage('')).toEqual({});
  });

  it('parseSha256sum and parseStatSizes map paths to values', () => {
    const hash = 'A'.repeat(64);
    expect(parseSha256sum(`${hash}  ${BASE}\nsha256sum: /x: No such file\n`)).toEqual({ [BASE]: 'a'.repeat(64) });
    expect(parseStatSizes(`1234 ${BASE}\n99 ${SPLIT_ABI}\nstat: bad\n`)).toEqual({ [BASE]: 1234, [SPLIT_ABI]: 99 });
  });

  it('isSafeDevicePath rejects hostile pm path entries', () => {
    expect(isSafeDevicePath(BASE)).toBe(true);
    expect(isSafeDevicePath('/data/app/~~x==/pkg-y==/base.apk')).toBe(true);
    for (const bad of ['~/base.apk', '/data/app/a~b.apk', '/data/app/x=~/base.apk', 'relative/base.apk', '/data/app/x;reboot', '/data/app/a b.apk', '/data/app/$(id).apk', '/data/app/`id`', "/data/app/x'y", '/data/app/x|y', '/data/../etc/passwd']) {
      expect(isSafeDevicePath(bad), bad).toBe(false);
    }
  });

  it('sanitizeFridaParameters converts BigInt values (frida reports e.g. ppid/user as bigint)', () => {
    expect(sanitizeFridaParameters({ ppid: 1234n, huge: 2n ** 64n })).toEqual({ ppid: 1234, huge: '18446744073709551616' });
  });

  it('sanitizeFridaParameters drops icon blobs', () => {
    expect(sanitizeFridaParameters(FRIDA_APP.parameters)).toEqual({
      version: '1.4.2', build: '7', sources: [BASE, SPLIT_ABI, SPLIT_DPI], 'data-dir': `/data/user/0/${PKG}`,
    });
  });
});

// ---------------------------------------------------------------------------
// Tool
// ---------------------------------------------------------------------------

describe('get_app_info tool', () => {
  let harness: McpHarness | undefined;
  let pullDir: string;

  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    pullDir = mkdtempSync(join(tmpdir(), 'fmcp-appinfo-'));
  });

  afterEach(async () => {
    await harness?.close();
    harness = undefined;
    getState().stopCleanupTimer();
    rmSync(pullDir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  async function setup(platform: string, deps: AdbExecDeps, app: unknown = FRIDA_APP) {
    const device = makeDevice({ id: SERIAL, type: 'usb', enumerateApplications: vi.fn().mockResolvedValue(app ? [app] : []) });
    const deviceManager = makeDeviceManager(device);
    deviceManager.detectPlatform.mockResolvedValue(platform);
    harness = await makeMcpHarness((server) => registerAppInfoTool(server, deviceManager, deps));
    return { device, deviceManager };
  }

  it('Android: returns dumpsys facts and every APK with sha256 and size', async () => {
    const { deps, calls } = fakeAdb();
    const { device } = await setup('android', deps);

    const body = await callJson(harness!.client, 'get_app_info', { target: PKG });

    expect(device.enumerateApplications).toHaveBeenCalledWith({ identifiers: [PKG], scope: 'full' });
    expect(body.result).toMatchObject({
      identifier: PKG, name: 'RC4 Demo', platform: 'android', version_name: '1.4.2', version_code: 7,
      target_sdk: 34, min_sdk: 24, debuggable: true, installer: 'com.android.vending', data_dir: `/data/user/0/${PKG}`,
    });
    expect(body.result.artifacts).toEqual([BASE, SPLIT_ABI, SPLIT_DPI].map((p) => ({ path: p, sha256: sha(CONTENT[p]), size: Buffer.byteLength(CONTENT[p]) })));
    expect(body.result.frida_parameters.icons).toBeUndefined();
    expect(body.coverage.status).toBe('complete');
    expect(body.limitations).toEqual([]);
    expect(body.suggested_next.map((s: any) => s.tool)).toEqual(['get_app_info', 'adb_pull']);
    expect(body.suggested_next[1].reason).toContain('inspect_android_package');

    const shellCommands = calls.filter((c) => c.includes('shell')).map((c) => c.slice(c.indexOf('shell') + 1).join(' '));
    expect(shellCommands).toEqual([
      `pm path ${PKG}`,
      `dumpsys package ${PKG}`,
      `sha256sum ${BASE} ${SPLIT_ABI} ${SPLIT_DPI}`,
      `stat -c '%s %n' ${BASE} ${SPLIT_ABI} ${SPLIT_DPI}`,
    ]);
    expect(calls.every((c) => c[0] === 'devices' || (c[0] === '-s' && c[1] === SERIAL))).toBe(true);
  });

  it('iOS: skips adb and reports the limitation', async () => {
    const { deps, calls } = fakeAdb();
    const iosApp = { identifier: 'com.example.ios', name: 'iOS', pid: 0, parameters: { version: '2.0', build: '200', path: '/private/var/containers/Bundle/Application/X/App.app' } };
    await setup('ios', deps, iosApp);

    const body = await callJson(harness!.client, 'get_app_info', { target: 'com.example.ios' });

    expect(calls).toEqual([]);
    expect(body.result).toMatchObject({ platform: 'ios', version_name: '2.0', version_code: '200' });
    expect(body.result.artifacts).toEqual([{ path: '/private/var/containers/Bundle/Application/X/App.app' }]);
    expect(body.limitations).toContain('sha256/size unavailable: no on-device shell for this platform');
    expect(body.coverage.status).toBe('unknown');
  });

  it('rejects an invalid package name with INVALID_ARGUMENT', async () => {
    const { deps, calls } = fakeAdb();
    const { device } = await setup('android', deps);

    for (const target of ['com.example;reboot', 'noDots', '1com.example', 'com..example']) {
      const body = await callJson(harness!.client, 'get_app_info', { target });
      expect(body.error.code, target).toBe('INVALID_ARGUMENT');
    }
    expect(device.enumerateApplications).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  it('pull_to: pulls each APK and marks it verified when the hashes match', async () => {
    const { deps } = fakeAdb();
    await setup('android', deps);

    const body = await callJson(harness!.client, 'get_app_info', { target: PKG, pull_to: pullDir });

    expect(body.result.pulled).toHaveLength(3);
    for (const pulled of body.result.pulled) {
      expect(pulled.host_path.startsWith(join(pullDir, PKG))).toBe(true);
      expect(existsSync(pulled.host_path)).toBe(true);
      expect(pulled.verified).toBe(true);
      expect(pulled.sha256).toBe(sha(CONTENT[pulled.device_path]));
    }
    expect(body.coverage.status).toBe('complete');
    expect(body.suggested_next[0]).toMatchObject({ tool: 'inspect_android_package', args: { path: join(pullDir, PKG, 'base.apk') } });
  });

  it('pull_to: a hash mismatch yields verified=false and a limitation', async () => {
    const { deps } = fakeAdb({ hashOverride: { [BASE]: 'f'.repeat(64) } });
    await setup('android', deps);

    const body = await callJson(harness!.client, 'get_app_info', { target: PKG, pull_to: pullDir });

    const base = body.result.pulled.find((p: any) => p.device_path === BASE);
    expect(base.verified).toBe(false);
    expect(body.limitations.some((l: string) => l.includes('sha256 mismatch') && l.includes(BASE))).toBe(true);
    expect(body.coverage.status).toBe('unknown');
  });

  it('pull_to outside the allowed roots is rejected', async () => {
    const { deps } = fakeAdb();
    await setup('android', deps);

    const body = await callJson(harness!.client, 'get_app_info', { target: PKG, pull_to: '/etc/frida-pull' });

    expect(body.error.code).toBe('INVALID_PATH');
  });

  it('drops a hostile pm path line and never passes it to a device command', async () => {
    const hostile = `/data/app/x.apk;reboot`;
    const { deps, calls } = fakeAdb({ pmPath: `${PM_PATH_OUT}package:${hostile}\n` });
    await setup('android', deps);

    const body = await callJson(harness!.client, 'get_app_info', { target: PKG });

    expect(body.result.artifacts.map((a: any) => a.path)).toEqual([BASE, SPLIT_ABI, SPLIT_DPI]);
    expect(calls.some((c) => c.join(' ').includes('reboot'))).toBe(false);
    expect(body.limitations.some((l: string) => l.includes('unexpected characters'))).toBe(true);
    expect(body.coverage.status).toBe('unknown');
  });

  it('reports a missing app as PROCESS_NOT_FOUND', async () => {
    const { deps } = fakeAdb({ pmPath: '' });
    await setup('android', deps, null);

    const body = await callJson(harness!.client, 'get_app_info', { target: 'com.example.missing' });

    expect(body.error.code).toBe('PROCESS_NOT_FOUND');
  });

  it('falls back to Frida sources with a limitation when adb is unavailable', async () => {
    const deps: AdbExecDeps = { which: async () => null, exec: vi.fn() as any };
    await setup('android', deps);

    const body = await callJson(harness!.client, 'get_app_info', { target: PKG });

    expect(body.result.artifacts).toEqual([{ path: BASE }, { path: SPLIT_ABI }, { path: SPLIT_DPI }]);
    expect(body.limitations[0]).toMatch(/sha256\/size unavailable: adb query failed/);
    expect(body.coverage.status).toBe('unknown');
  });
});
