import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Off-device: fake frida + a stubbed agent script. Traces use duration_seconds: 0 so the
// handler's fixed-duration wait returns immediately. Pure option helpers live in
// interceptor-options.test.ts; this file exercises the registered trace_method handler.
vi.mock('frida', () => ({
  default: {
    getDeviceManager: () => ({}),
    Cancellable: { withTimeout: () => ({ isCancelled: false }) },
  },
}));

const { createAgentScript } = vi.hoisted(() => ({ createAgentScript: vi.fn() }));
vi.mock('../../src/agent/script-factory.js', () => ({ createAgentScript }));

import { registerTraceTool } from '../../src/tools/trace.js';
import { initState, getState } from '../../src/state.js';
import {
  callJson,
  fakeScript,
  makeDevice,
  makeDeviceManager,
  makeMcpHarness,
  scriptEntry,
  seedSession,
  stubAgentScript,
  DEFAULT_SESSION_ID,
  TEST_CONFIG,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

describe('trace_method MCP tool handler', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];
  let device: ReturnType<typeof makeDevice>;
  let deviceManager: any;
  let script: ReturnType<typeof stubAgentScript>;

  beforeEach(async () => {
    initState({ ...TEST_CONFIG });
    device = makeDevice();
    deviceManager = makeDeviceManager(device);
    script = stubAgentScript();
    createAgentScript.mockReset();
    createAgentScript.mockResolvedValue(script as any);
    ({ client, close } = await makeMcpHarness((server) => registerTraceTool(server, deviceManager)));
  });

  afterEach(async () => {
    await close();
    getState().stopCleanupTimer();
    vi.restoreAllMocks();
  });

  it('is registered as a non-read-only, non-idempotent, open-world tool', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'trace_method')!;
    expect(tool.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true });
  });

  it('runs a Java trace for the given duration then unloads the script and clears the trace', async () => {
    const parsed = await callJson(client, 'trace_method', {
      target: 'com.example.app',
      method: 'com.example.*',
      duration_seconds: 0,
    });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result.method).toBe('com.example.*');
    expect(parsed.result.duration_seconds).toBe(0);
    expect(parsed.result.invocations_count).toBe(0);
    expect(parsed.result.truncated).toBe(false);
    expect(parsed.result.interceptor_options).toBeNull();
    expect(parsed.limitations).toEqual([]);
    expect(script.load).toHaveBeenCalledTimes(1);
    expect(script.unload).toHaveBeenCalledTimes(1);
    // The transient trace is removed from state once the duration elapses.
    expect(getState().traces.size).toBe(0);
  });

  it('echoes interceptor_options for a native trace and records no limitations', async () => {
    const parsed = await callJson(client, 'trace_method', {
      target: 'com.example.app',
      method: 'libc.so!op*',
      duration_seconds: 0,
      interceptor_options: { relocation: 'unchecked' },
    });

    expect(parsed.result.interceptor_options).toEqual({ relocation: 'unchecked' });
    expect(parsed.limitations).toEqual([]);
  });

  it('drops interceptor_options for a Java trace but reports the limitation', async () => {
    const parsed = await callJson(client, 'trace_method', {
      target: 'com.example.app',
      method: 'com.example.*',
      duration_seconds: 0,
      interceptor_options: { relocation: 'unchecked' },
    });

    expect(parsed.result.interceptor_options).toBeNull();
    expect(parsed.limitations[0]).toMatch(/ignored for this java hook/);
  });

  it('traces inside an existing session by session_id without spawning', async () => {
    seedSession(getState(), [scriptEntry('pre-existing', fakeScript())]);

    const parsed = await callJson(client, 'trace_method', {
      session_id: DEFAULT_SESSION_ID,
      method: 'com.example.*',
      duration_seconds: 0,
    });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result.session_id).toBe(DEFAULT_SESSION_ID);
    expect(device.spawn).not.toHaveBeenCalled();
    expect(deviceManager.resolve).not.toHaveBeenCalled();
  });

  it('rejects a call with neither target nor session_id', async () => {
    const parsed = await callJson(client, 'trace_method', { method: 'com.example.*' });
    expect(parsed.error.code).toBe('INVALID_ARGUMENT');
    expect(createAgentScript).not.toHaveBeenCalled();
  });

  it('wraps a device resolution failure as DEVICE_NOT_FOUND', async () => {
    deviceManager.resolve.mockRejectedValue(new Error('unable to find device'));

    const parsed = await callJson(client, 'trace_method', {
      target: 'com.example.app',
      method: 'com.example.*',
      duration_seconds: 0,
    });

    expect(parsed.error.code).toBe('DEVICE_NOT_FOUND');
    expect(createAgentScript).not.toHaveBeenCalled();
  });
});
