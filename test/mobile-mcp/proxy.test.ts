import { describe, it, expect } from 'vitest';

describe('MobileMcpProxy', () => {
  it('proxy module exports getMobileMcpProxy', async () => {
    const mod = await import('../../src/mobile-mcp/proxy.js');
    expect(typeof mod.getMobileMcpProxy).toBe('function');
  });

  it('client module exports expected functions', async () => {
    const mod = await import('../../src/mobile-mcp/client.js');
    expect(typeof mod.getMobileMcpClient).toBe('function');
    expect(typeof mod.disconnectMobileMcp).toBe('function');
    expect(typeof mod.isMobileMcpConnected).toBe('function');
  });

  it('device-map module exports expected functions', async () => {
    const mod = await import('../../src/mobile-mcp/device-map.js');
    expect(typeof mod.resolveMobileDeviceId).toBe('function');
    expect(typeof mod.clearDeviceCache).toBe('function');
  });
});
