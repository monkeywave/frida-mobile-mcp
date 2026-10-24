import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { registerSearchTool } from '../../src/tools/search.js';
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

describe('search_classes_and_methods MCP tool', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];
  let scripts: FakeAgentScript[];
  let deviceManager: ReturnType<typeof makeScriptingSetup>['deviceManager'];
  let searchResult: unknown;

  beforeAll(async () => {
    const setup = makeScriptingSetup(({ name }) =>
      name?.startsWith('search_classes_and_methods:') ? { exports: { search: async () => searchResult } } : {}
    );
    scripts = setup.scripts;
    deviceManager = setup.deviceManager;
    ({ client, close } = await makeMcpHarness((server) => registerSearchTool(server, deviceManager)));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
  });

  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    rateLimiter.reset();
    scripts.length = 0;
    deviceManager.detectPlatform.mockResolvedValue('android');
    searchResult = [{ name: 'com.example.LoginActivity', methods: ['onCreate', 'doLogin'] }];
  });

  const searchScript = () => scripts.find((s) => s.name?.startsWith('search_classes_and_methods:'))!;

  it('is a read-only, idempotent tool', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'search_classes_and_methods')!;
    expect(tool.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false, idempotentHint: true });
  });

  it('returns matched classes and suggests hooking the first match', async () => {
    const parsed = await callJson(client, 'search_classes_and_methods', { target: TARGET, pattern: 'Login' });
    expect(parsed.error).toBeUndefined();
    expect(parsed.result).toMatchObject({ platform: 'android', pattern: 'Login', total_matches: 1, truncated: false });
    expect(parsed.result.classes).toEqual([{ name: 'com.example.LoginActivity', methods: ['onCreate', 'doLogin'] }]);
    const hook = parsed.suggested_next.find((s: any) => s.tool === 'hook_method');
    expect(hook.args.method).toBe('com.example.LoginActivity');
  });

  it('forwards pattern, include_methods and limit to the agent as options', async () => {
    await callJson(client, 'search_classes_and_methods', { target: TARGET, pattern: 'Login', include_methods: true, limit: 25 });
    expect(agentOptions(searchScript().source)).toMatchObject({ pattern: 'Login', includeMethods: true, maxResults: 25 });
  });

  it('defaults include_methods to false and the limit to 50', async () => {
    await callJson(client, 'search_classes_and_methods', { target: TARGET, pattern: 'Login' });
    expect(agentOptions(searchScript().source)).toMatchObject({ includeMethods: false, maxResults: 50 });
  });

  it('flags truncation when matches reach the limit', async () => {
    searchResult = [{ name: 'A' }, { name: 'B' }];
    const parsed = await callJson(client, 'search_classes_and_methods', { target: TARGET, pattern: '.', limit: 2 });
    expect(parsed.result.truncated).toBe(true);
  });

  it('selects the ObjC search variant on iOS', async () => {
    deviceManager.detectPlatform.mockResolvedValue('ios');
    searchResult = [{ name: 'NSURLSession' }];
    const parsed = await callJson(client, 'search_classes_and_methods', { target: TARGET, pattern: 'NSURL' });
    expect(parsed.result.platform).toBe('ios');
    expect(searchScript().name).toBe('search_classes_and_methods:ios');
  });

  it('reports INVALID_PATTERN when the agent rejects the regex', async () => {
    searchResult = { error: 'invalid_pattern', message: 'Unterminated group' };
    const parsed = await callJson(client, 'search_classes_and_methods', { target: TARGET, pattern: '(' });
    expect(parsed.error.code).toBe('INVALID_PATTERN');
    expect(parsed.error.message).toMatch(/Invalid pattern regex/);
  });

  it('carries a hostile pattern to the agent purely as escaped data', async () => {
    const hostile = '"}; globalThis.pwned = 1; ({"x":"';
    await callJson(client, 'search_classes_and_methods', { target: TARGET, pattern: hostile });
    // Round-trips byte-for-byte: the pattern was embedded as a JSON value, never code.
    expect(agentOptions(searchScript().source).pattern).toBe(hostile);
  });

  it('rejects an empty target with no session to fall back on', async () => {
    const parsed = await callJson(client, 'search_classes_and_methods', { target: '', pattern: 'x' });
    expect(parsed.error).toBeDefined();
    expect(parsed.error.message).toMatch(/provide target.*or session_id/i);
  });
  it('reports partial coverage with a limitation when matches reach the limit', async () => {
    searchResult = [{ name: 'A' }, { name: 'B' }];
    const parsed = await callJson(client, 'search_classes_and_methods', { target: TARGET, pattern: 'Login', limit: 2 });
    expect(parsed.coverage).toEqual({ status: 'partial', scope: 'android loaded classes matching Login', truncated: true });
    expect(parsed.limitations).toContainEqual(expect.stringMatching(/Stopped at limit=2/));
  });

  it('reports complete coverage when matches stay below the limit', async () => {
    const parsed = await callJson(client, 'search_classes_and_methods', { target: TARGET, pattern: 'Login', limit: 5 });
    expect(parsed.coverage).toEqual({ status: 'complete', scope: 'android loaded classes matching Login' });
    expect(parsed.limitations ?? []).not.toContainEqual(expect.stringMatching(/Stopped at limit/));
  });
});
