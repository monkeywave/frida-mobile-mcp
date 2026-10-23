import { describe, it, expect } from 'vitest';
import { resolveAllowedSerial, requireAdbPath, type AdbExecDeps } from '../../src/helpers/adb.js';

function depsWith(devicesStdout: string, adbFound = true): AdbExecDeps {
  return {
    which: async (bin) => (adbFound && bin === 'adb' ? '/usr/bin/adb' : null),
    exec: async () => ({ stdout: devicesStdout, stderr: '', code: 0 }),
  };
}

const TWO_DEVICES = 'List of devices attached\nemulator-5554\tdevice\nemulator-5556\tdevice\n';
const ONE_DEVICE = 'List of devices attached\nemulator-5554\tdevice\n';
const UNAUTHORIZED = 'List of devices attached\nemulator-5554\tunauthorized\n';

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
