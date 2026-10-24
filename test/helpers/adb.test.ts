import { describe, it, expect } from 'vitest';
import { assertSafeShellWord, isSafeShellWord, resolveAllowedSerial, requireAdbPath, type AdbExecDeps } from '../../src/helpers/adb.js';

function depsWith(devicesStdout: string, adbFound = true): AdbExecDeps {
  return {
    which: async (bin) => (adbFound && bin === 'adb' ? '/usr/bin/adb' : null),
    exec: async () => ({ stdout: devicesStdout, stderr: '', code: 0 }),
  };
}

const TWO_DEVICES = 'List of devices attached\nemulator-5554\tdevice\nemulator-5556\tdevice\n';
const ONE_DEVICE = 'List of devices attached\nemulator-5554\tdevice\n';
const UNAUTHORIZED = 'List of devices attached\nemulator-5554\tunauthorized\n';

describe('assertSafeShellWord', () => {
  it('accepts path, address and flag characters', () => {
    for (const ok of ['/data/local/tmp/frida-server', '127.0.0.1:27042', '/data/app/x==/pkg-y==/base.apk', '--verbose', 'TERM']) {
      expect(assertSafeShellWord(ok, 'x')).toBe(ok);
    }
  });

  it('rejects ~ (an unquoted leading ~ is tilde-expanded by the device shell)', () => {
    for (const bad of ['~', '~/frida-server', '~root/x', '/data/app/~~x==/base.apk']) {
      expect(isSafeShellWord(bad), bad).toBe(false);
    }
  });

  it('rejects shell metacharacters without echoing the value', () => {
    for (const bad of ['a; rm -rf /', '/tmp/x$(id)', 'a b', '`id`', "x'y", 'x|y', '']) {
      expect(isSafeShellWord(bad)).toBe(false);
      expect(() => assertSafeShellWord(bad, 'token')).toThrow(expect.objectContaining({ code: 'INVALID_ARGUMENT' }));
    }
    expect(() => assertSafeShellWord('s3cret$(id)', 'token')).toThrow(/^token contains characters that are not allowed/);
  });
});

describe('requireAdbPath', () => {
  it('throws a DEVICE_NOT_FOUND error when adb is absent', async () => {
    await expect(requireAdbPath(depsWith('', false))).rejects.toMatchObject({ code: 'DEVICE_NOT_FOUND' });
  });
});

describe('resolveAllowedSerial', () => {
  it('auto-selects the sole healthy device', async () => {
    const serial = await resolveAllowedSerial(depsWith(ONE_DEVICE), '/usr/bin/adb', undefined, []);
    expect(serial).toBe('emulator-5554');
  });

  it('requires an explicit serial when several are attached', async () => {
    await expect(resolveAllowedSerial(depsWith(TWO_DEVICES), '/usr/bin/adb', undefined, [])).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
  });

  it('accepts a requested serial that is connected and healthy', async () => {
    const serial = await resolveAllowedSerial(depsWith(TWO_DEVICES), '/usr/bin/adb', 'emulator-5556', []);
    expect(serial).toBe('emulator-5556');
  });

  it('rejects a requested serial that is not attached', async () => {
    await expect(resolveAllowedSerial(depsWith(TWO_DEVICES), '/usr/bin/adb', 'ghost', [])).rejects.toMatchObject({ code: 'DEVICE_NOT_FOUND' });
  });

  it('rejects an unauthorized device', async () => {
    await expect(resolveAllowedSerial(depsWith(UNAUTHORIZED), '/usr/bin/adb', 'emulator-5554', [])).rejects.toMatchObject({ code: 'DEVICE_NOT_FOUND' });
  });

  it('enforces the allowedDevices allowlist', async () => {
    await expect(resolveAllowedSerial(depsWith(ONE_DEVICE), '/usr/bin/adb', 'emulator-5554', ['emulator-9999'])).rejects.toMatchObject({ code: 'DEVICE_NOT_ALLOWED' });
    const ok = await resolveAllowedSerial(depsWith(ONE_DEVICE), '/usr/bin/adb', 'emulator-5554', ['emulator-5554']);
    expect(ok).toBe('emulator-5554');
  });
});
