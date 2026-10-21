import { describe, it, expect, beforeEach } from 'vitest';
import { resolveMobileDeviceId, clearMobileDeviceCache } from '../../src/mobile-mcp/device-resolve.js';

describe('resolveMobileDeviceId', () => {
  beforeEach(() => clearMobileDeviceCache());

  it('returns undefined for a missing device id', async () => {
    expect(await resolveMobileDeviceId(undefined)).toBeUndefined();
  });

  it('passes a physical-device serial through unchanged (no adb translation)', async () => {
    expect(await resolveMobileDeviceId('PIXEL7ABC123')).toBe('PIXEL7ABC123');
  });

  it('passes an already-resolved AVD name through unchanged', async () => {
    expect(await resolveMobileDeviceId('Pixel_9_Pro_-root')).toBe('Pixel_9_Pro_-root');
  });

  it('maps an emulator serial via adb, falling back to the serial when adb cannot resolve it', async () => {
    // A port that is not a running emulator: adb fails, so we must fall back to the serial itself
    // rather than returning undefined (never break the caller just because the mapping is unknown).
    const resolved = await resolveMobileDeviceId('emulator-59999');
    expect(resolved).toBe('emulator-59999');
  });
});
