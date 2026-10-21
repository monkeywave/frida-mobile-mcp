import { describe, it, expect, vi } from 'vitest';
import {
  checkNodeVersion,
  parseNodeMajorMinor,
  classifyFridaError,
  doctorExitCode,
  formatDoctorTable,
  parseAdbDevices,
  runDoctorChecks,
  withTimeout,
  type CheckResult,
  type DoctorDeps,
  type DoctorDevice,
} from '../../src/cli/doctor.js';

type FridaModule = typeof import('frida');

function fakeUsbDevice(overrides: Partial<DoctorDevice> = {}): DoctorDevice {
  return {
    id: 'emulator-5554',
    name: 'Pixel',
    type: 'usb',
    querySystemParameters: vi.fn().mockResolvedValue({ os: { id: 'android', version: '14' }, arch: 'arm64' }),
    enumerateProcesses: vi.fn().mockResolvedValue([{}, {}, {}]),
    ...overrides,
  };
}

function fakeFrida(devices: DoctorDevice[]): FridaModule {
  return {
    getDeviceManager: () => ({}),
    enumerateDevices: vi.fn().mockResolvedValue(devices),
  } as unknown as FridaModule;
}

function fakeDeps(overrides: Partial<DoctorDeps> = {}): Partial<DoctorDeps> {
  return {
    nodeVersion: 'v22.12.0',
    platform: 'darwin',
    loadFrida: async () => fakeFrida([{ id: 'local', name: 'Local System', type: 'local' } as DoctorDevice, fakeUsbDevice()]),
    fridaNodeVersion: () => '17.24.3',
    which: async (bin) => (bin === 'adb' ? '/usr/bin/adb' : null),
    exec: async () => ({ stdout: 'List of devices attached\nemulator-5554\tdevice\n\n', stderr: '', code: 0 }),
    areBridgesBuilt: () => true,
    configPath: '/home/test/.config/frida-mobile-mcp/config.json',
    configExists: () => false,
    loadConfig: () => ({ allowCustomScripts: false, memoryWriteEnabled: false, allowedDevices: [] }),
    timeoutMs: 200,
    ...overrides,
  };
}

function findResult(results: CheckResult[], name: string): CheckResult {
  const result = results.find((entry) => entry.name === name);
  if (!result) throw new Error(`missing check "${name}" in ${results.map((entry) => entry.name).join(', ')}`);
  return result;
}

describe('checkNodeVersion', () => {
  it('accepts versions at or above the minimum major.minor', () => {
    expect(checkNodeVersion('v22.12.0').status).toBe('ok');
    expect(checkNodeVersion('v22.20.1').status).toBe('ok');
    expect(checkNodeVersion('v24.0.0').status).toBe('ok');
  });

  it('fails versions below the minimum and is required', () => {
    const result = checkNodeVersion('v20.19.0');
    expect(result.status).toBe('fail');
    expect(result.required).toBe(true);
    expect(result.detail).toContain('>= 22.12');
  });

  it('fails an older minor of the minimum major', () => {
    expect(checkNodeVersion('v22.11.0').status).toBe('fail');
  });

  it('honours a custom minimum', () => {
    expect(checkNodeVersion('v18.0.0', '18').status).toBe('ok');
    expect(checkNodeVersion('v18.0.0', '18.1').status).toBe('fail');
  });

  it('fails on unparsable input', () => {
    expect(checkNodeVersion('garbage').status).toBe('fail');
  });
});

describe('parseNodeMajorMinor', () => {
  it('parses full versions and bare minimums', () => {
    expect(parseNodeMajorMinor('v22.12.0')).toEqual([22, 12]);
    expect(parseNodeMajorMinor('24')).toEqual([24, 0]);
    expect(parseNodeMajorMinor('garbage')).toEqual([NaN, NaN]);
  });
});

describe('parseAdbDevices', () => {
  it('skips the header and parses id/state pairs', () => {
    const out = 'List of devices attached\nemulator-5554\tdevice\nZY22ABC\tunauthorized\n1234\toffline\n\n';
    expect(parseAdbDevices(out)).toEqual([
      { id: 'emulator-5554', state: 'device' },
      { id: 'ZY22ABC', state: 'unauthorized' },
      { id: '1234', state: 'offline' },
    ]);
  });

  it('ignores daemon start-up noise and blank lines', () => {
    const out = '* daemon not running; starting now\n* daemon started successfully\nList of devices attached\n\n';
    expect(parseAdbDevices(out)).toEqual([]);
  });
});

describe('classifyFridaError', () => {
  it('explains an unreachable frida-server', () => {
    const hint = classifyFridaError('unable to connect to remote frida-server: Connection refused', '17.24.3');
    expect(hint).toContain('frida-server is not running or not forwarded');
    expect(hint).toContain('adb shell');
    expect(hint).toContain('major version 17');
  });

  it('explains a protocol / version mismatch', () => {
    expect(classifyFridaError('Unexpected protocol error', '17.24.3')).toContain('must match frida-node 17.24.3');
    expect(classifyFridaError('incompatible frida-server', '17.24.3')).toContain('must match frida-node 17.24.3');
  });

  it('explains timeouts and permission problems', () => {
    expect(classifyFridaError('operation timed out', '17.24.3')).toContain('busy');
    expect(classifyFridaError('Permission denied', '17.24.3')).toContain('as root');
  });

  it('falls back to the raw message', () => {
    expect(classifyFridaError('something odd happened', null)).toBe('something odd happened');
  });
});

describe('withTimeout', () => {
  it('resolves when the promise settles in time', async () => {
    await expect(withTimeout(Promise.resolve(42), 100, 'fast')).resolves.toBe(42);
  });

  it('rejects with a labelled error when the promise hangs', async () => {
    await expect(withTimeout(new Promise(() => {}), 10, 'slow call')).rejects.toThrow('slow call timed out after 10 ms');
  });
});

describe('doctorExitCode', () => {
  const base: CheckResult = { name: 'x', status: 'ok', detail: '', required: true };

  it('returns 1 only when a required check fails', () => {
    expect(doctorExitCode([base, { ...base, status: 'fail', required: true }])).toBe(1);
  });

  it('ignores optional failures and warnings', () => {
    expect(doctorExitCode([{ ...base, status: 'fail', required: false }, { ...base, status: 'warn' }])).toBe(0);
  });
});

describe('formatDoctorTable', () => {
  it('lists check names, statuses, details and a summary line without emojis', () => {
    const table = formatDoctorTable([
      { name: 'Node.js version', status: 'ok', detail: 'v22.1.0', required: true },
      { name: 'adb', status: 'warn', detail: 'not found on PATH', required: false },
    ]);
    expect(table).toContain('STATUS');
    expect(table).toContain('CHECK');
    expect(table).toContain('DETAIL');
    expect(table).toContain('Node.js version');
    expect(table).toMatch(/^OK\s+\|/m);
    expect(table).toMatch(/^WARN\s+\|/m);
    expect(table).toContain('Summary: 1 ok, 1 warn, 0 fail, 0 skip');
    expect(table).not.toMatch(/[\u{1F300}-\u{1FAFF}✅❌]/u);
  });
});

describe('runDoctorChecks (mocked environment)', () => {
  it('reports a healthy environment with one USB device', async () => {
    const results = await runDoctorChecks(fakeDeps());

    expect(findResult(results, 'Node.js version').status).toBe('ok');
    expect(findResult(results, 'frida native binding')).toMatchObject({ status: 'ok', detail: expect.stringContaining('17.24.3') });
    expect(findResult(results, 'adb')).toMatchObject({ status: 'ok', detail: expect.stringContaining('emulator-5554 (device)') });

    const devices = findResult(results, 'Frida devices');
    expect(devices.status).toBe('ok');
    expect(devices.detail).toContain('emulator-5554 [usb]');
    expect(devices.detail).toContain('local');

    const usb = findResult(results, 'USB device emulator-5554');
    expect(usb.status).toBe('ok');
    expect(usb.detail).toBe('android 14 arm64, 3 processes');

    expect(findResult(results, 'Bridge bundles').status).toBe('ok');
    expect(findResult(results, 'fritap')).toMatchObject({ status: 'warn', detail: 'not found - fritap tools unavailable' });
    expect(findResult(results, 'Config').detail).toContain('allowCustomScripts=false');
    expect(doctorExitCode(results)).toBe(0);
  });

  it('warns with a frida-server hint when the device refuses connections', async () => {
    const device = fakeUsbDevice({
      enumerateProcesses: vi.fn().mockRejectedValue(new Error('unable to connect to remote frida-server')),
    });
    const results = await runDoctorChecks(fakeDeps({ loadFrida: async () => fakeFrida([device]) }));

    const usb = findResult(results, 'USB device emulator-5554');
    expect(usb.status).toBe('warn');
    expect(usb.required).toBe(false);
    expect(usb.detail).toContain('frida-server is not running or not forwarded');
    expect(usb.detail).toContain('major version 17');
    expect(doctorExitCode(results)).toBe(0);
  });

  it('warns when adb is missing and when no USB device is attached', async () => {
    const results = await runDoctorChecks(fakeDeps({ which: async () => null, loadFrida: async () => fakeFrida([]) }));

    expect(findResult(results, 'adb')).toMatchObject({ status: 'warn', required: false });
    expect(findResult(results, 'USB device')).toMatchObject({ status: 'warn', detail: 'no USB device attached' });
  });

  it('flags unauthorized adb devices as a warning', async () => {
    const results = await runDoctorChecks(
      fakeDeps({ exec: async () => ({ stdout: 'List of devices attached\nZY22\tunauthorized\n', stderr: '', code: 0 }) }),
    );
    expect(findResult(results, 'adb')).toMatchObject({ status: 'warn', detail: expect.stringContaining('ZY22 (unauthorized)') });
  });

  it('fails with exit code 1 when bridge bundles are missing', async () => {
    const results = await runDoctorChecks(fakeDeps({ areBridgesBuilt: () => false }));

    const bridges = findResult(results, 'Bridge bundles');
    expect(bridges).toMatchObject({ status: 'fail', required: true });
    expect(bridges.detail).toContain('npm run build:bridges');
    expect(doctorExitCode(results)).toBe(1);
  });

  it('turns a throwing frida import into a required failure and skips device checks', async () => {
    const results = await runDoctorChecks(fakeDeps({ loadFrida: async () => { throw new Error('prebuild missing'); } }));

    expect(findResult(results, 'frida native binding')).toMatchObject({ status: 'fail', detail: expect.stringContaining('prebuild missing') });
    expect(findResult(results, 'Frida devices').status).toBe('skip');
    expect(findResult(results, 'Config').status).toBe('ok');
    expect(doctorExitCode(results)).toBe(1);
  });

  it('converts a throwing check into a fail without aborting the rest', async () => {
    const results = await runDoctorChecks(fakeDeps({ loadConfig: () => { throw new Error('bad json'); } }));

    expect(findResult(results, 'Config')).toMatchObject({ status: 'fail', detail: 'bad json', required: false });
    expect(findResult(results, 'Bridge bundles').status).toBe('ok');
  });
});
