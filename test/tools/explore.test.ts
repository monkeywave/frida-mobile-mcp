import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { registerExploreTool } from '../../src/tools/explore.js';
import { initState, getState } from '../../src/state.js';
import { rateLimiter } from '../../src/helpers/rate-limiter.js';
import { escapeRegExp } from '../../src/helpers/regex.js';
import {
  agentLiteral,
  agentOptions,
  callJson,
  makeMcpHarness,
  makeScriptingSetup,
  TEST_CONFIG,
  SPAWNED_PID,
  TARGET,
  type FakeAgentScript,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

const MODULES_SCRIPT = 'explore_app:modules';
const CLASSES_SCRIPT = 'explore_app:classes';

function module(i: number) {
  return { name: `lib${i}.so`, base: `0x${(0x1000 + i).toString(16)}`, size: 4096, path: `/system/lib/lib${i}.so` };
}

describe('explore_app MCP tool', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];
  let scripts: FakeAgentScript[];
  let device: ReturnType<typeof makeScriptingSetup>['device'];
  // The two rpc results the happy path returns; tests reassign them before calling.
  let modulesResult: unknown[];
  let classesResult: unknown;

  beforeAll(async () => {
    const setup = makeScriptingSetup(({ name }) => {
      if (name === MODULES_SCRIPT) return { exports: { run: async () => modulesResult } };
      if (name === CLASSES_SCRIPT) return { exports: { run: async () => classesResult } };
      return {};
    });
    scripts = setup.scripts;
    device = setup.device;
    ({ client, close } = await makeMcpHarness((server) => registerExploreTool(server, setup.deviceManager)));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
  });

  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    rateLimiter.reset();
    scripts.length = 0;
    modulesResult = [module(1), module(2)];
    classesResult = ['com.example.app.MainActivity', 'com.example.app.Login'];
  });

  const classesScript = () => scripts.find((s) => s.name === CLASSES_SCRIPT)!;

  it('is registered as a non-readonly, open-world tool with an output schema', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'explore_app');
    expect(tool).toBeDefined();
    expect(tool!.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true });
    expect(tool!.outputSchema).toBeDefined();
  });

  it('spawns, resumes and returns pid, platform, modules and classes', async () => {
    const parsed = await callJson(client, 'explore_app', { target: TARGET });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result).toMatchObject({
      pid: SPAWNED_PID,
      platform: 'android',
      spawned: true,
      modules_count: 2,
      classes_count: 2,
    });
    expect(parsed.result.classes).toEqual(['com.example.app.MainActivity', 'com.example.app.Login']);
    expect(parsed.result.modules).toEqual([
      { name: 'lib1.so', base: '0x1001', size: 4096, path: '/system/lib/lib1.so' },
      { name: 'lib2.so', base: '0x1002', size: 4096, path: '/system/lib/lib2.so' },
    ]);
    expect(parsed.result.truncated).toEqual({ modules: false, classes: false });
    // System libs are not app-owned, so app_modules stays empty here.
    expect(parsed.result.app_modules).toEqual([]);
    expect(device.resume).toHaveBeenCalledWith(SPAWNED_PID);
    expect(parsed.suggested_next.map((s: any) => s.tool)).toContain('bypass_ssl_pinning');
  });

  it('truncates to 50 modules and 100 classes and flags the truncation', async () => {
    modulesResult = Array.from({ length: 60 }, (_, i) => module(i));
    classesResult = Array.from({ length: 150 }, (_, i) => `com.example.C${i}`);

    const parsed = await callJson(client, 'explore_app', { target: TARGET });

    expect(parsed.result.modules_count).toBe(60);
    expect(parsed.result.modules).toHaveLength(50);
    expect(parsed.result.classes_count).toBe(150);
    expect(parsed.result.classes).toHaveLength(100);
    expect(parsed.result.truncated).toEqual({ modules: true, classes: true });
  });

  it('defaults the class filter to the regex-escaped target on android', async () => {
    await callJson(client, 'explore_app', { target: TARGET });
    expect(agentOptions(classesScript().source).filter).toBe(escapeRegExp(TARGET));
    expect(agentOptions(classesScript().source).filter).toBe('com\\.example\\.app');
  });

  it('passes a user-supplied class_filter straight through as the agent filter option', async () => {
    await callJson(client, 'explore_app', { target: TARGET, class_filter: 'com\\.acme\\..*' });
    expect(agentOptions(classesScript().source).filter).toBe('com\\.acme\\..*');
  });

  // The escaping bug that once slipped through: options must reach the agent only as a JSON
  // literal, never spliced into code position. Each hostile filter must round-trip byte-for-byte
  // and leave the preamble assignment intact.
  const hostileFilters = [
    'quote"inside',
    "apostrophe'inside",
    'back\\slash',
    'new\nline',
    'tab\tstop',
    'template${injection}',
    'close</script>tag',
    'unicode sep',
    '"}; globalThis.pwned = 1; ({"x":"',
    '*/ rpc.exports.run = function(){ return "pwned"; }; /*',
  ];

  it.each(hostileFilters)('safely escapes a hostile class_filter: %j', async (filter) => {
    await callJson(client, 'explore_app', { target: TARGET, class_filter: filter });
    const source = classesScript().source;

    // The whole assignment is one well-formed JSON object: the payload never broke out of the
    // literal into code position (that is what the escaping bug would have allowed).
    const parsed = JSON.parse(agentLiteral(source));
    // And the value survives the round-trip byte-for-byte, so it was carried purely as data.
    expect(parsed.options.filter).toBe(filter);
  });

  it('reports INVALID_PATTERN when the agent rejects the filter regex', async () => {
    classesResult = { error: 'invalid_pattern', message: 'Unterminated group' };
    const parsed = await callJson(client, 'explore_app', { target: TARGET, class_filter: '(' });
    expect(parsed.error.code).toBe('INVALID_PATTERN');
    expect(parsed.error.message).toMatch(/Invalid class_filter regex/);
  });

  it('unloads both the modules and classes scripts even on the happy path', async () => {
    await callJson(client, 'explore_app', { target: TARGET });
    expect(scripts.find((s) => s.name === MODULES_SCRIPT)!.unloadCalls).toBe(1);
    expect(classesScript().unloadCalls).toBe(1);
  });

  it('enforces the per-minute session rate limit', async () => {
    for (let i = 0; i < TEST_CONFIG.rateLimits.sessionsPerMinute; i++) rateLimiter.record('session');
    const parsed = await callJson(client, 'explore_app', { target: TARGET });
    expect(parsed.error.code).toBe('RATE_LIMIT_EXCEEDED');
    expect(parsed.error.category).toBe('resource');
  });
});
