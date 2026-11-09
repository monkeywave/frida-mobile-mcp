import { describe, it, expect, afterAll } from 'vitest';
import { agentOptionsFromArgs, registerFritapTool, type CaptureTlsArgs } from '../../src/fritap/tool.js';
import { buildFritapConfigBatch, fritapHandshakeReply } from '../../src/fritap/agent-loader.js';
import { gateServer, type ToolPolicy } from '../../src/tools/tool-gate.js';
import { getState, initState } from '../../src/state.js';
import { makeMcpHarness, makeDeviceManager, makeDevice, TEST_CONFIG } from '../helpers/mock-fixtures.js';

const BASE_ARGS: CaptureTlsArgs = {
  target: 'com.example.app',
  spawn: true,
  anti_root: false,
  full_capture: false,
  duration_seconds: 0,
  allow_download: false,
};

const NEW_PARAMS = [
  'protocols', 'pairip_safe', 'no_loader_hook', 'probe', 'attribute_sdk', 'default_fd', 'library_scan', 'experimental',
] as const;

function batchFor(extra: Partial<CaptureTlsArgs>): Record<string, unknown> {
  return buildFritapConfigBatch(agentOptionsFromArgs({ ...BASE_ARGS, ...extra }, false, true));
}

describe('capture_tls params -> config_batch', () => {
  it('keeps today\'s defaults when no new param is given', () => {
    const batch = batchFor({});
    expect(batch).toMatchObject({
      protocol_select: 'tls',
      pairip_safe: false,
      no_loader_hook: false,
      probe: false,
      attribute_sdk: false,
      defaultFD: false,
      library_scan_enabled: false,
      library_scan: null,
      experimental: false,
      lean_wine: false,
      socket_tracing: false,
      keylog_enabled: true,
      spawned: true,
    });
  });

  it.each([
    [{ protocols: ['tls', 'rc4'] }, 'protocol_select', 'tls,rc4'],
    [{ protocols: ['auto'] }, 'protocol_select', 'auto'],
    [{ protocols: ['all'] }, 'protocol_select', 'all'],
    [{ pairip_safe: true }, 'pairip_safe', true],
    [{ no_loader_hook: true }, 'no_loader_hook', true],
    [{ probe: true }, 'probe', true],
    [{ attribute_sdk: true }, 'attribute_sdk', true],
    [{ default_fd: true }, 'defaultFD', true],
    [{ library_scan: true }, 'library_scan_enabled', true],
    [{ experimental: true }, 'experimental', true],
  ] as Array<[Partial<CaptureTlsArgs>, string, unknown]>)('maps %o to %s', (extra, field, expected) => {
    expect(batchFor(extra)[field]).toEqual(expected);
  });

  it('only flips the targeted field', () => {
    const before = batchFor({});
    const after = batchFor({ attribute_sdk: true });
    const changed = Object.keys(after).filter((key) => JSON.stringify(after[key]) !== JSON.stringify(before[key]));
    expect(changed).toEqual(['attribute_sdk']);
  });

  it('answers the legacy per-field channels from the same options', () => {
    const options = agentOptionsFromArgs({ ...BASE_ARGS, default_fd: true, protocols: ['tls', 'rc4'] }, false, false);
    expect(fritapHandshakeReply('defaultFD', options)).toEqual({ type: 'defaultFD', payload: true });
    expect(fritapHandshakeReply('protocol_select', options)).toEqual({ type: 'protocol_select', payload: 'tls,rc4' });
    expect(fritapHandshakeReply('defaultFD', {})).toEqual({ type: 'defaultFD', payload: false });
    expect(fritapHandshakeReply('protocol_select', {})).toEqual({ type: 'protocol_select', payload: 'tls' });
  });

  it('rejects mixed meta protocols before anything is built', () => {
    expect(() => batchFor({ protocols: ['auto', 'tls'] })).toThrow(/cannot be combined/);
  });
});

describe('capture_tls input schema', () => {
  afterAll(() => {
    getState().stopCleanupTimer();
  });

  async function listCaptureTlsSchema(schemaProfile: 'full' | 'compact') {
    initState({ ...TEST_CONFIG });
    const deviceManager = makeDeviceManager(makeDevice());
    const policy: ToolPolicy = { toolProfile: 'full', toolsExclude: [], schemaProfile, effects: {} };
    const { client, close } = await makeMcpHarness((server) => registerFritapTool(gateServer(server, policy), deviceManager));
    try {
      const { tools } = await client.listTools();
      return tools.find((t) => t.name === 'capture_tls')!.inputSchema as any;
    } finally {
      await close();
    }
  }

  it.each(['full', 'compact'] as const)('exposes every new param with a description (%s profile)', async (profile) => {
    const schema = await listCaptureTlsSchema(profile);
    for (const name of NEW_PARAMS) {
      expect(schema.properties[name], name).toBeDefined();
      expect(schema.properties[name].description, name).toMatch(/\w/);
      expect(schema.required ?? []).not.toContain(name);
    }
    expect(schema.properties.protocols.items.enum).toEqual(['tls', 'rc4', 'auto', 'all']);
  });
});
