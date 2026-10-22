import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// The stubbed agent script keeps the registered hook_function/unhook_function handlers
// off-device. The pure buildHookFunctionOptions helper is covered in
// interceptor-options.test.ts; this file exercises the registered handler paths.
const { createAgentScript } = vi.hoisted(() => ({ createAgentScript: vi.fn() }));
vi.mock('../../src/agent/script-factory.js', () => ({ createAgentScript }));

import { registerAdvancedInterceptTools } from '../../src/tools/advanced/intercept.js';
import { initState, getState } from '../../src/state.js';
import {
  callJson,
  fakeScript,
  makeMcpHarness,
  scriptEntry,
  seedHook,
  seedSession,
  stubAgentScript,
  DEFAULT_SESSION_ID,
  TEST_CONFIG,
  type Json,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

function initWith(overrides: Partial<typeof TEST_CONFIG> = {}) {
  initState({ ...TEST_CONFIG, ...overrides });
}

describe('hook_function / unhook_function MCP tool handlers', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];
  let script: ReturnType<typeof stubAgentScript>;

  beforeEach(async () => {
    initWith();
    script = stubAgentScript();
    createAgentScript.mockReset();
    createAgentScript.mockResolvedValue(script as any);
    ({ client, close } = await makeMcpHarness((server) => registerAdvancedInterceptTools(server)));
  });

  afterEach(async () => {
    await close();
    getState().stopCleanupTimer();
    vi.restoreAllMocks();
  });

  describe('hook_function', () => {
    it('is registered as a non-read-only, open-world tool', async () => {
      const { tools } = await client.listTools();
      const tool = tools.find((t) => t.name === 'hook_function')!;
      expect(tool.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true });
    });

    it('returns SESSION_NOT_FOUND when the session does not exist', async () => {
      const parsed = await callJson(client, 'hook_function', { session_id: 'missing', target: 'libc.so!open' });
      expect(parsed.error.code).toBe('SESSION_NOT_FOUND');
      expect(parsed.error.category).toBe('request');
      expect(createAgentScript).not.toHaveBeenCalled();
    });

    it('installs a default hook (no custom handlers) even when allowCustomScripts is disabled', async () => {
      seedSession(getState(), []);

      const parsed = await callJson(client, 'hook_function', { session_id: DEFAULT_SESSION_ID, target: 'libc.so!open' });

      expect(parsed.error).toBeUndefined();
      expect(parsed.result.status).toBe('active');
      expect(parsed.result.target).toBe('libc.so!open');
      expect(parsed.result.interceptor_options).toBeNull();
      expect(script.load).toHaveBeenCalledTimes(1);
      const state = getState();
      expect(state.hooks.get(parsed.result.hook_id)).toMatchObject({ target: 'libc.so!open', status: 'active' });
      expect(state.getSession(DEFAULT_SESSION_ID)?.scripts.has(parsed.result.script_id)).toBe(true);
    });

    it('rejects custom on_enter/on_leave handlers when allowCustomScripts is disabled', async () => {
      seedSession(getState(), []);

      const parsed = await callJson(client, 'hook_function', {
        session_id: DEFAULT_SESSION_ID,
        target: 'libc.so!open',
        on_enter: 'send({ hi: 1 })',
      });

      expect(parsed.error.code).toBe('CUSTOM_SCRIPTS_DISABLED');
      expect(parsed.error.category).toBe('authorization');
      expect(createAgentScript).not.toHaveBeenCalled();
    });

    it('allows custom handlers when allowCustomScripts is enabled and passes them to the agent', async () => {
      initWith({ allowCustomScripts: true });
      seedSession(getState(), []);

      const parsed = await callJson(client, 'hook_function', {
        session_id: DEFAULT_SESSION_ID,
        target: 'libc.so!open',
        on_enter: 'this.fd = args[0]',
        on_leave: 'send({ fd: this.fd })',
      });

      expect(parsed.error).toBeUndefined();
      expect(parsed.result.status).toBe('active');
      const options = createAgentScript.mock.calls[0][1].options as Json;
      expect(options.on_enter).toBe('this.fd = args[0]');
      expect(options.on_leave).toBe('send({ fd: this.fd })');
    });

    it('echoes the interceptor_options on the hook result', async () => {
      seedSession(getState(), []);

      const parsed = await callJson(client, 'hook_function', {
        session_id: DEFAULT_SESSION_ID,
        target: 'libc.so!open',
        interceptor_options: { scenario: 'offline' },
      });

      expect(parsed.result.interceptor_options).toEqual({ scenario: 'offline' });
    });
    it('resolves native {module, offset} evidence to module+0xoff', async () => {
      seedSession(getState(), []);

      const parsed = await callJson(client, 'hook_function', {
        session_id: DEFAULT_SESSION_ID,
        evidence: { module: 'librc4.so', offset: 4660 },
      });

      expect(parsed.error).toBeUndefined();
      expect(parsed.result.target).toBe('librc4.so+0x1234');
      expect(parsed.result.evidence).toEqual({ module: 'librc4.so', offset: 4660 });
      const options = createAgentScript.mock.calls[0][1].options as Json;
      expect(options.nativeTarget).toEqual({ kind: 'offset', module: 'librc4.so', offset: '0x1234' });
    });

    it('rejects Java evidence and a call with neither target nor evidence', async () => {
      seedSession(getState(), []);

      const java = await callJson(client, 'hook_function', { session_id: DEFAULT_SESSION_ID, evidence: { class: 'a.B', signature: 'f()' } });
      expect(java.error.code).toBe('INVALID_ARGUMENT');
      const neither = await callJson(client, 'hook_function', { session_id: DEFAULT_SESSION_ID });
      expect(neither.error.code).toBe('INVALID_ARGUMENT');
      expect(createAgentScript).not.toHaveBeenCalled();
    });
  });

  describe('unhook_function', () => {
    it('is registered as an idempotent tool', async () => {
      const { tools } = await client.listTools();
      const tool = tools.find((t) => t.name === 'unhook_function')!;
      expect(tool.annotations).toMatchObject({ idempotentHint: true });
    });

    it('returns HOOK_NOT_FOUND for an unknown hook id', async () => {
      const parsed = await callJson(client, 'unhook_function', { hook_id: 'nope' });
      expect(parsed.error.code).toBe('HOOK_NOT_FOUND');
      expect(parsed.error.category).toBe('request');
    });

    it('unloads the hook script and removes the hook from state', async () => {
      const state = getState();
      const target = fakeScript();
      seedSession(state, [scriptEntry('script-x', target)]);
      seedHook(state, 'hook-x', 'script-x', DEFAULT_SESSION_ID);

      const parsed = await callJson(client, 'unhook_function', { hook_id: 'hook-x' });

      expect(parsed.error).toBeUndefined();
      expect(parsed.result.status).toBe('removed');
      expect(parsed.result.hook_id).toBe('hook-x');
      expect(target.unloadCalls).toBe(1);
      expect(state.hooks.has('hook-x')).toBe(false);
      expect(state.getSession(DEFAULT_SESSION_ID)?.scripts.has('script-x')).toBe(false);
    });
  });
});
