import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

vi.mock('frida', () => ({
  default: {
    getDeviceManager: () => ({}),
    getLocalDevice: vi.fn(),
    getUsbDevice: vi.fn(),
    Cancellable: { withTimeout: vi.fn(() => ({ isCancelled: false })) },
  },
}));

import { DeviceManager, addRemoteDeviceForState, loadRemoteCertificate } from '../../src/device/manager.js';
import { resolveDevice, toRemoteDeviceOptions } from '../../src/device/resolver.js';
import { initState, getState } from '../../src/state.js';
import { makeDevice, TEST_CONFIG } from '../helpers/mock-fixtures.js';

const PEM = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n';

describe('toRemoteDeviceOptions', () => {
  it('returns undefined when no auth is given', () => {
    expect(toRemoteDeviceOptions({})).toBeUndefined();
    expect(toRemoteDeviceOptions()).toBeUndefined();
  });

  it('keeps only the given fields', () => {
    expect(toRemoteDeviceOptions({ token: 't' })).toEqual({ token: 't' });
    expect(toRemoteDeviceOptions({ token: 't', certificate: PEM })).toEqual({ token: 't', certificate: PEM });
  });
});

describe('loadRemoteCertificate', () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'fmcp-cert-')); });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('reads a certificate path into PEM text', () => {
    const path = join(dir, 'server.pem');
    writeFileSync(path, PEM);
    expect(loadRemoteCertificate(path)).toBe(PEM);
  });

  it('passes PEM text and undefined through', () => {
    expect(loadRemoteCertificate(PEM)).toBe(PEM);
    expect(loadRemoteCertificate(undefined)).toBeUndefined();
  });

  it('throws INVALID_ARGUMENT for an unreadable path', () => {
    expect(() => loadRemoteCertificate(join(dir, 'missing.pem'))).toThrow(expect.objectContaining({ code: 'INVALID_ARGUMENT' }));
  });
});

describe('resolveDevice (remote)', () => {
  it('passes token/certificate to addRemoteDevice', async () => {
    const remote = makeDevice({ id: 'socket@h:1' });
    const fake = { addRemoteDevice: vi.fn().mockResolvedValue(remote) } as any;

    await resolveDevice(fake, { type: 'remote', host: 'h:1', token: 'tok', certificate: PEM });

    expect(fake.addRemoteDevice).toHaveBeenCalledWith('h:1', { token: 'tok', certificate: PEM });
  });

  it('passes no options when no auth is given', async () => {
    const fake = { addRemoteDevice: vi.fn().mockResolvedValue(makeDevice()) } as any;

    await resolveDevice(fake, { type: 'remote', host: 'h:1' });

    expect(fake.addRemoteDevice).toHaveBeenCalledWith('h:1', undefined);
  });
});

describe('DeviceManager.addRemoteDevice', () => {
  let dir: string;
  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    dir = mkdtempSync(join(tmpdir(), 'fmcp-cert-'));
  });
  afterEach(() => {
    getState().stopCleanupTimer();
    rmSync(dir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it('forwards the token and the certificate file contents', async () => {
    const path = join(dir, 'server.pem');
    writeFileSync(path, PEM);
    const remote = makeDevice({ id: 'socket@h:1' });
    const fake = { addRemoteDevice: vi.fn().mockResolvedValue(remote) } as any;
    const manager = new DeviceManager(fake, { ...TEST_CONFIG });

    await expect(manager.addRemoteDevice('h:1', { token: 'tok', certificate: path })).resolves.toBe(remote);
    expect(fake.addRemoteDevice).toHaveBeenCalledWith('h:1', { token: 'tok', certificate: PEM });
  });

  it('applies the allowlist to the added device', async () => {
    const fake = { addRemoteDevice: vi.fn().mockResolvedValue(makeDevice({ id: 'socket@h:1' })) } as any;
    const manager = new DeviceManager(fake, { ...TEST_CONFIG, allowedDevices: ['dev1'] });

    await expect(manager.addRemoteDevice('h:1')).rejects.toMatchObject({ code: 'DEVICE_NOT_FOUND' });
  });

  it('resolve() loads the certificate path before reaching frida', async () => {
    const path = join(dir, 'server.pem');
    writeFileSync(path, PEM);
    const fake = { addRemoteDevice: vi.fn().mockResolvedValue(makeDevice({ id: 'socket@h:1' })) } as any;
    const manager = new DeviceManager(fake, { ...TEST_CONFIG });

    await manager.resolve({ type: 'remote', host: 'h:1', token: 'tok', certificate: path });

    expect(fake.addRemoteDevice).toHaveBeenCalledWith('h:1', { token: 'tok', certificate: PEM });
  });
});

describe('addRemoteDeviceForState (startup --remote)', () => {
  let dir: string;
  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    dir = mkdtempSync(join(tmpdir(), 'fmcp-cert-'));
  });
  afterEach(() => {
    getState().stopCleanupTimer();
    rmSync(dir, { recursive: true, force: true });
  });

  it('loads the certificate path before handing it to the raw frida manager', async () => {
    const path = join(dir, 'server.pem');
    writeFileSync(path, PEM);
    const remote = makeDevice({ id: 'socket@h:1' });
    const raw = { addRemoteDevice: vi.fn().mockResolvedValue(remote) } as any;

    await expect(addRemoteDeviceForState({ deviceManager: raw, config: { ...TEST_CONFIG } }, 'h:1', { token: 'tok', certificate: path }))
      .resolves.toBe(remote);
    expect(raw.addRemoteDevice).toHaveBeenCalledWith('h:1', { token: 'tok', certificate: PEM });
  });

  it('rejects a remote device that is not on the allowlist', async () => {
    const raw = { addRemoteDevice: vi.fn().mockResolvedValue(makeDevice({ id: 'socket@h:1' })) } as any;

    await expect(addRemoteDeviceForState({ deviceManager: raw, config: { ...TEST_CONFIG, allowedDevices: ['dev1'] } }, 'h:1'))
      .rejects.toMatchObject({ code: 'DEVICE_NOT_FOUND' });
  });
});
