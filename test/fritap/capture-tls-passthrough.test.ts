import { describe, it, expect, afterAll } from 'vitest';
import { registerFritapTool } from '../../src/fritap/tool.js';
import { buildFritapConfigBatch } from '../../src/fritap/agent-loader.js';
import { getState, initState } from '../../src/state.js';
import { makeMcpHarness, makeDeviceManager, makeDevice, TEST_CONFIG } from '../helpers/mock-fixtures.js';

/**
 * Part-2 wiring check (device-free): capture_tls exposes `patterns`/`offsets` on its input schema,
 * and the friTap config batch serialises whatever the tool forwards. The full spawn/handshake path
 * is covered by the on-device e2e suite; here we assert the inputs exist and are plumbed.
 */
describe('capture_tls patterns/offsets passthrough', () => {
  afterAll(() => {
    getState().stopCleanupTimer();
  });

  it('accepts patterns and offsets on the input schema', async () => {
    initState({ ...TEST_CONFIG });
    const deviceManager = makeDeviceManager(makeDevice());
    const { client, close } = await makeMcpHarness((server) => registerFritapTool(server, deviceManager));
    try {
      const { tools } = await client.listTools();
      const tool = tools.find((t) => t.name === 'capture_tls');
      expect(tool).toBeDefined();
      const props = (tool!.inputSchema as any).properties;
      expect(props.patterns).toBeDefined();
      expect(props.offsets).toBeDefined();
    } finally {
      await close();
    }
  });

  it('serialises forwarded object patterns/offsets into the friTap config batch', () => {
    const batch = buildFritapConfigBatch({ patterns: { rules: [1] }, offsets: { libfoo: { KEY: 1 } } });
    expect(batch.patterns).toBe('{"rules":[1]}');
    expect(batch.offsets).toBe('{"libfoo":{"KEY":1}}');
  });
});
