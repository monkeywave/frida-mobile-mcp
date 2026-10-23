import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { registerPrebuiltTool } from '../../src/tools/prebuilt.js';
import { initState, getState } from '../../src/state.js';
import { rateLimiter } from '../../src/helpers/rate-limiter.js';
import {
  agentOptions,
  callJson,
  makeMcpHarness,
  makeScriptingSetup,
  TEST_CONFIG,
  TARGET,
  type FakeAgentScript,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

describe('run_prebuilt_script MCP tool', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];
  let scripts: FakeAgentScript[];
  let emitOnLoad: Array<{ message: any; data?: any }>;

  beforeAll(async () => {
    const setup = makeScriptingSetup(({ name }) => (name?.startsWith('prebuilt:') ? { emitOnLoad } : {}));
    scripts = setup.scripts;
    ({ client, close } = await makeMcpHarness((server) => registerPrebuiltTool(server, setup.deviceManager)));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
  });

  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    rateLimiter.reset();
    scripts.length = 0;
    emitOnLoad = [];
  });

  it('lists all nine built-in scripts when called without a script_name', async () => {
    const parsed = await callJson(client, 'run_prebuilt_script', {});
    expect(parsed.error).toBeUndefined();
    const names = parsed.result.available_scripts.map((s: any) => s.name);
    expect(names).toHaveLength(9);
    expect(names).toContain('ssl_pinning_bypass');
    expect(names).toContain('crypto_monitor');
    // Each entry carries the metadata agents use to choose a script.
    expect(parsed.result.available_scripts[0]).toHaveProperty('description');
    expect(parsed.result.available_scripts[0]).toHaveProperty('risk_tier');
  });

  it('requires a target when a script_name is given', async () => {
    const parsed = await callJson(client, 'run_prebuilt_script', { script_name: 'crypto_monitor' });
    expect(parsed.error.code).toBe('INVALID_ARGUMENT');
    expect(parsed.error.category).toBe('request');
  });

  it('returns SCRIPT_NOT_FOUND for an unknown script', async () => {
    const parsed = await callJson(client, 'run_prebuilt_script', { script_name: 'does_not_exist', target: TARGET });
    expect(parsed.error.code).toBe('SCRIPT_NOT_FOUND');
  });

  it('loads a script, collects initial output and passes options through to the agent', async () => {
    emitOnLoad = [{ message: { type: 'send', payload: { event: 'cipher', algo: 'AES' } } }];

    const parsed = await callJson(client, 'run_prebuilt_script', {
      script_name: 'crypto_monitor',
      target: TARGET,
      options: { verbose: true },
    });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result).toMatchObject({ script_name: 'crypto_monitor', session_id: expect.any(String) });
    expect(parsed.result.initial_messages).toEqual([{ event: 'cipher', algo: 'AES' }]);
    expect(parsed.result.message).toMatch(/loaded and running/);

    // Options reach the agent as data (the preamble literal), merged with the detected platform.
    const script = scripts.find((s) => s.name === 'prebuilt:crypto_monitor')!;
    expect(agentOptions(script.source)).toMatchObject({ verbose: true, platform: 'android' });

    // The running script is tracked on the session.
    const session = getState().getSession(parsed.result.session_id)!;
    expect(session.scripts.get(parsed.result.script_id)!.name).toBe('prebuilt:crypto_monitor');
  });

  it('enforces the per-minute script rate limit', async () => {
    for (let i = 0; i < TEST_CONFIG.rateLimits.scriptsPerMinute; i++) rateLimiter.record('script');
    const parsed = await callJson(client, 'run_prebuilt_script', { script_name: 'crypto_monitor', target: TARGET });
    expect(parsed.error.code).toBe('RATE_LIMIT_EXCEEDED');
  });
});
