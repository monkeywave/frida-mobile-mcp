import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Keep every device/script call off-device: a fake frida and a stubbed agent script.
vi.mock('frida', () => ({
  default: {
    getDeviceManager: () => ({}),
    Cancellable: { withTimeout: () => ({ isCancelled: false }) },
  },
}));

const { createAgentScript } = vi.hoisted(() => ({ createAgentScript: vi.fn() }));
vi.mock('../../src/agent/script-factory.js', () => ({ createAgentScript }));

import { registerDetectTool } from '../../src/tools/detect.js';
import { initState, getState } from '../../src/state.js';
import {
  callJson,
  makeDevice,
  makeDeviceManager,
  makeMcpHarness,
  TEST_CONFIG,
  type Json,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

/** A stub agent script whose rpc `detect` export returns (or rejects with) whatever a test wants. */
function fakeDetectScript(result: Record<string, string[]> | Error) {
  const detect = vi.fn(() => (result instanceof Error ? Promise.reject(result) : Promise.resolve(result)));
  return {
    detect,
    unload: vi.fn().mockResolvedValue(undefined),
    script: {
      load: vi.fn().mockResolvedValue(undefined),
      unload: vi.fn().mockResolvedValue(undefined),
      message: { connect: vi.fn() },
      exports: { detect },
    },
  };
}

describe('detect_app_technologies MCP tool', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];
  let device: ReturnType<typeof makeDevice>;
  let deviceManager: any;

  beforeEach(async () => {
    initState({ ...TEST_CONFIG });
    device = makeDevice();
    deviceManager = makeDeviceManager(device);
    createAgentScript.mockReset();
    ({ client, close } = await makeMcpHarness((server) => registerDetectTool(server, deviceManager)));
  });

  afterEach(async () => {
    await close();
    getState().stopCleanupTimer();
    vi.restoreAllMocks();
  });

  it('is registered as a read-only, idempotent, open-world tool', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'detect_app_technologies');
    expect(tool).toBeDefined();
    expect(tool!.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true });
    expect(tool!.outputSchema).toBeDefined();
  });

  it('runs the android fingerprint rpc and maps detections to prebuilt-script recommendations', async () => {
    const fake = fakeDetectScript({
      ssl_pinning: ['okhttp_pinner'],
      ssl_library: ['conscrypt'],
      root_detection: ['rootbeer'],
      crypto: ['javax_crypto'],
      storage: ['room'],
    });
    createAgentScript.mockResolvedValue(fake.script as any);

    const parsed = await callJson(client, 'detect_app_technologies', { target: 'com.example.app' });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result.platform).toBe('android');
    expect(parsed.result.target).toBe('com.example.app');
    expect(parsed.result.detected).toMatchObject({
      ssl_pinning: ['okhttp_pinner'],
      root_detection: ['rootbeer'],
      crypto: ['javax_crypto'],
      storage: ['room'],
    });
    // The rpc export is called once with the fingerprint table and the script is unloaded after.
    expect(fake.detect).toHaveBeenCalledTimes(1);
    expect(Array.isArray(fake.detect.mock.calls[0][0])).toBe(true);
    expect(fake.script.unload).toHaveBeenCalledTimes(1);

    const scripts = parsed.result.recommendations.map((r: Json) => r.script).sort();
    expect(scripts).toEqual(['crypto_monitor', 'keychain_prefs', 'root_jailbreak_bypass', 'ssl_pinning_bypass']);
    const sslRec = parsed.result.recommendations.find((r: Json) => r.script === 'ssl_pinning_bypass');
    expect(sslRec.targets).toBe('okhttp,conscrypt');
    // Each recommendation becomes a suggested run_prebuilt_script action.
    expect(parsed.suggested_next).toHaveLength(4);
    expect(parsed.suggested_next.every((s: Json) => s.tool === 'run_prebuilt_script')).toBe(true);
  });

  it('runs the ios rpc (no fingerprint argument) and still recommends an SSL bypass', async () => {
    deviceManager.detectPlatform.mockResolvedValue('ios');
    const fake = fakeDetectScript({ ssl_library: ['boringssl'], http_client: ['afnetworking'] });
    createAgentScript.mockResolvedValue(fake.script as any);

    const parsed = await callJson(client, 'detect_app_technologies', { target: 'com.example.ios' });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result.platform).toBe('ios');
    expect(fake.detect).toHaveBeenCalledWith();
    const sslRec = parsed.result.recommendations.find((r: Json) => r.script === 'ssl_pinning_bypass');
    expect(sslRec.targets).toBe('boringssl');
  });

  it('returns no recommendations when nothing is detected', async () => {
    const fake = fakeDetectScript({});
    createAgentScript.mockResolvedValue(fake.script as any);

    const parsed = await callJson(client, 'detect_app_technologies', { target: 'com.example.empty' });

    expect(parsed.result.detected).toEqual({});
    expect(parsed.result.recommendations).toEqual([]);
    expect(parsed.suggested_next).toEqual([]);
  });

  it('unloads the script and surfaces an error envelope when the detection rpc fails', async () => {
    const fake = fakeDetectScript(new Error('rpc blew up'));
    createAgentScript.mockResolvedValue(fake.script as any);

    const parsed = await callJson(client, 'detect_app_technologies', { target: 'com.example.app' });

    expect(parsed.result).toBeUndefined();
    expect(parsed.error.code).toBe('FRIDA_ERROR');
    expect(fake.script.unload).toHaveBeenCalledTimes(1);
  });

  it('wraps a device resolution failure as a DEVICE_NOT_FOUND error', async () => {
    deviceManager.resolve.mockRejectedValue(new Error('unable to find device'));

    const parsed = await callJson(client, 'detect_app_technologies', { target: 'com.example.app' });

    expect(parsed.error.code).toBe('DEVICE_NOT_FOUND');
    expect(parsed.error.category).toBe('capability');
    expect(createAgentScript).not.toHaveBeenCalled();
  });
});
