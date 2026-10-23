import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('frida', () => ({
  default: {
    getDeviceManager: () => ({}),
    Cancellable: { withTimeout: vi.fn(() => ({ isCancelled: false })) },
  },
}));

import { registerInjectTools } from '../../src/tools/advanced/inject.js';
import { initState, getState } from '../../src/state.js';
import { rateLimiter } from '../../src/helpers/rate-limiter.js';
import {
  makeMcpHarness,
  callJson,
  makeDevice,
  makeDeviceManager,
  TEST_CONFIG,
  type McpHarness,
  type FakeDevice,
} from '../helpers/mock-fixtures.js';

describe('inject_library tool', () => {
  let device: FakeDevice & { injectLibraryFile: ReturnType<typeof vi.fn> };
  let deviceManager: any;
  let harness: McpHarness;

  beforeEach(async () => {
    initState({ ...TEST_CONFIG });
    rateLimiter.reset();
    device = makeDevice({ injectLibraryFile: vi.fn().mockResolvedValue(7) }) as any;
    deviceManager = makeDeviceManager(device);
    harness = await makeMcpHarness((server) => registerInjectTools(server, deviceManager));
  });

  afterEach(async () => {
    await harness.close();
    rateLimiter.reset();
    getState().stopCleanupTimer();
    vi.restoreAllMocks();
  });

  it('refuses injection unless allowNativeInjection is set', async () => {
    const body = await callJson(harness.client, 'inject_library', { target: 1234, library_path: '/tmp/agent.so' });
    expect(body.error.code).toBe('NATIVE_INJECTION_DISABLED');
    expect(device.injectLibraryFile).not.toHaveBeenCalled();
  });

  it('is gated on allowNativeInjection, not allowCustomScripts', async () => {
    // allowCustomScripts (the JS-agent capability) must NOT grant native injection.
    initState({ ...TEST_CONFIG, allowCustomScripts: true, allowNativeInjection: false });
    const body = await callJson(harness.client, 'inject_library', { target: 1234, library_path: '/tmp/agent.so' });
    expect(body.error.code).toBe('NATIVE_INJECTION_DISABLED');
    expect(device.injectLibraryFile).not.toHaveBeenCalled();
  });

  it('injects the library and returns the injectee id when enabled', async () => {
    initState({ ...TEST_CONFIG, allowNativeInjection: true });
    getState().selectedDevice = device as any;

    const body = await callJson(harness.client, 'inject_library', {
      target: 1234,
      library_path: '/tmp/agent.so',
      entrypoint: 'frida_agent_main',
      data: 'hello',
    });

    expect(device.injectLibraryFile).toHaveBeenCalledWith(1234, '/tmp/agent.so', 'frida_agent_main', 'hello');
    expect(body.result.status).toBe('injected');
    expect(body.result.injectee_id).toBe(7);
    expect(body.result.entrypoint).toBe('frida_agent_main');
  });

  it('defaults entrypoint and data to empty strings', async () => {
    initState({ ...TEST_CONFIG, allowNativeInjection: true });
    getState().selectedDevice = device as any;

    const body = await callJson(harness.client, 'inject_library', { target: 'com.example.app', library_path: '/tmp/x.so' });

    expect(device.injectLibraryFile).toHaveBeenCalledWith('com.example.app', '/tmp/x.so', '', '');
    expect(body.result.entrypoint).toBeNull();
  });

  it('surfaces an injector failure as an error envelope', async () => {
    initState({ ...TEST_CONFIG, allowNativeInjection: true });
    getState().selectedDevice = device as any;
    device.injectLibraryFile.mockRejectedValue(new Error('unable to find entrypoint'));

    const body = await callJson(harness.client, 'inject_library', { target: 1234, library_path: '/tmp/bad.so' });

    expect(body.error).toBeDefined();
    expect(body.error.message).toContain('unable to find entrypoint');
  });
});
