import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Off-device: fake frida + a stubbed agent script so the registered handler path runs
// end-to-end without an emulator. The pure option helpers are covered in
// interceptor-options.test.ts; this file exercises the registered hook_method handler.
vi.mock('frida', () => ({
  default: {
    getDeviceManager: () => ({}),
    Cancellable: { withTimeout: () => ({ isCancelled: false }) },
  },
}));

const { createAgentScript } = vi.hoisted(() => ({ createAgentScript: vi.fn() }));
vi.mock('../../src/agent/script-factory.js', () => ({ createAgentScript }));

import { registerHookTool } from '../../src/tools/hook.js';
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
  SPAWNED_PID,
  TEST_CONFIG,
  type Json,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

describe('hook_method MCP tool handler', () => {
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
    ({ client, close } = await makeMcpHarness((server) => registerHookTool(server, deviceManager)));
  });

  afterEach(async () => {
    await close();
    getState().stopCleanupTimer();
    vi.restoreAllMocks();
  });

  it('is registered as a non-read-only, non-idempotent, open-world tool', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'hook_method')!;
    expect(tool.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true });
  });

  it('spawns a session, installs a Java hook and registers it in state', async () => {
    const parsed = await callJson(client, 'hook_method', { target: 'com.example.app', method: 'com.example.Foo.bar' });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result.hook_type).toBe('java');
    expect(parsed.result.status).toBe('active');
    expect(parsed.result.method).toBe('com.example.Foo.bar');
    expect(parsed.result.pid).toBe(SPAWNED_PID);
    expect(parsed.result.interceptor_options).toBeNull();
    expect(parsed.limitations).toEqual([]);
    expect(script.load).toHaveBeenCalledTimes(1);
    // The hook is tracked in state under the returned id.
    const state = getState();
    expect(state.hooks.get(parsed.result.hook_id)).toMatchObject({ target: 'com.example.Foo.bar', type: 'java', status: 'active' });
    expect(state.getSession(parsed.result.session_id)?.scripts.has(parsed.result.script_id)).toBe(true);
  });

  it('echoes interceptor_options for a native hook and records no limitations', async () => {
    const parsed = await callJson(client, 'hook_method', {
      target: 'com.example.app',
      method: 'libc.so!open',
      interceptor_options: { scenario: 'offline', scratchRegister: 'x16' },
    });

    expect(parsed.result.hook_type).toBe('native');
    expect(parsed.result.interceptor_options).toEqual({ scenario: 'offline', scratchRegister: 'x16' });
    expect(parsed.limitations).toEqual([]);
  });

  it('drops interceptor_options for a Java hook but reports the limitation', async () => {
    const parsed = await callJson(client, 'hook_method', {
      target: 'com.example.app',
      method: 'com.example.Foo.bar',
      interceptor_options: { scenario: 'offline' },
    });

    expect(parsed.result.hook_type).toBe('java');
    expect(parsed.result.interceptor_options).toBeNull();
    expect(parsed.limitations[0]).toMatch(/ignored for this java hook/);
  });

  it('attaches to an existing session by session_id without spawning a new process', async () => {
    seedSession(getState(), [scriptEntry('pre-existing', fakeScript())]);

    const parsed = await callJson(client, 'hook_method', { session_id: DEFAULT_SESSION_ID, method: 'com.example.Foo.bar' });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result.session_id).toBe(DEFAULT_SESSION_ID);
    expect(device.spawn).not.toHaveBeenCalled();
    expect(deviceManager.resolve).not.toHaveBeenCalled();
  });

  it('rejects a call with neither target nor session_id', async () => {
    const parsed = await callJson(client, 'hook_method', { method: 'com.example.Foo.bar' });
    expect(parsed.error.code).toBe('INVALID_ARGUMENT');
    expect(parsed.error.category).toBe('request');
    expect(createAgentScript).not.toHaveBeenCalled();
  });

  it('wraps a device resolution failure as DEVICE_NOT_FOUND', async () => {
    deviceManager.resolve.mockRejectedValue(new Error('unable to find device'));

    const parsed = await callJson(client, 'hook_method', { target: 'com.example.app', method: 'com.example.Foo.bar' });

    expect(parsed.error.code).toBe('DEVICE_NOT_FOUND');
    expect(createAgentScript).not.toHaveBeenCalled();
  });
});
