import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { RegisterAllOptions } from '../../src/tools/register-all.js';
import {
  CORE_TOOLS,
  COMPACT_DESCRIPTION_MAX,
  TARGET_PROVENANCE,
  firstSentence,
  globToRegExp,
  isToolExposed,
} from '../../src/tools/tool-gate.js';
import { TOOL_EFFECTS } from '../../src/tools/effects.js';
import type { RuntimeConfig } from '../../src/config.js';
import { initState, getState } from '../../src/state.js';
import {
  callJson,
  fakeScript,
  listRegisteredTools,
  makeFullHarness,
  scriptEntry,
  seedSession,
  DEFAULT_SESSION_ID,
  FULL_TOOL_POLICY,
  TEST_CONFIG,
  type Json,
} from '../helpers/mock-fixtures.js';

type Tool = Json & { name: string; description?: string; inputSchema: Json; _meta?: Json };

/** Register every tool under `options` and return the advertised `tools/list` entries. */
async function listToolsWith(options: RegisterAllOptions): Promise<Tool[]> {
  return (await listRegisteredTools(options)) as Tool[];
}

const names = (tools: Tool[]) => tools.map((t) => t.name).sort();
const bytes = (tools: Tool[]) => Buffer.byteLength(JSON.stringify({ tools }), 'utf8');

describe('tool gate helpers', () => {
  it('globToRegExp anchors, escapes and expands *', () => {
    expect(globToRegExp('adb_*').test('adb_shell')).toBe(true);
    expect(globToRegExp('adb_*').test('x_adb_shell')).toBe(false);
    expect(globToRegExp('a.b').test('axb')).toBe(false);
    expect(globToRegExp('*_memory').test('read_memory')).toBe(true);
  });

  it('isToolExposed applies profile and excludes', () => {
    expect(isToolExposed('adb_shell', { toolProfile: 'full', toolsExclude: [] })).toBe(true);
    expect(isToolExposed('adb_shell', { toolProfile: 'core', toolsExclude: [] })).toBe(false);
    expect(isToolExposed('hook_method', { toolProfile: 'core', toolsExclude: ['hook_*'] })).toBe(false);
  });

  it('firstSentence stops at the first sentence and caps the length', () => {
    expect(firstSentence('One thing. Two things.', 160)).toBe('One thing.');
    expect(firstSentence('v1.2 is fine. Next.', 160)).toBe('v1.2 is fine.');
    const long = firstSentence('x'.repeat(300), 160);
    expect(long.length).toBe(160);
    expect(long.endsWith('...')).toBe(true);
  });
});

describe('tool exposure profiles', () => {
  let full: Tool[];
  let core: Tool[];
  let compact: Tool[];
  let coreCompact: Tool[];

  beforeAll(async () => {
    full = await listToolsWith({ ...FULL_TOOL_POLICY });
    core = await listToolsWith({ ...FULL_TOOL_POLICY, toolProfile: 'core' });
    compact = await listToolsWith({ ...FULL_TOOL_POLICY, schemaProfile: 'compact' });
    coreCompact = await listToolsWith({ toolProfile: 'core', toolsExclude: [], schemaProfile: 'compact' });
  });

  it('core registers exactly CORE_TOOLS that exist in the full catalog', () => {
    const fullNames = new Set(names(full));
    const expected = CORE_TOOLS.filter((n) => fullNames.has(n)).sort();
    expect(names(core)).toEqual(expected);
    // Sanity: the curated set is mostly present already (missing ones are future tools).
    expect(expected.length).toBeGreaterThanOrEqual(25);
  });

  it('toolsExclude removes exactly the matching tools', async () => {
    const excluded = await listToolsWith({ ...FULL_TOOL_POLICY, toolsExclude: ['adb_*', 'frida_server_*'] });
    const removed = names(full).filter((n) => n.startsWith('adb_') || n.startsWith('frida_server_'));
    expect(removed.length).toBeGreaterThan(0);
    expect(names(excluded)).toEqual(names(full).filter((n) => !removed.includes(n)));
  });

  it('compact drops response_format and outputSchema and shortens descriptions; full keeps them', () => {
    for (const tool of compact) {
      expect(tool.inputSchema.properties?.response_format, tool.name).toBeUndefined();
      expect(tool.outputSchema, tool.name).toBeUndefined();
      expect(tool.description?.length ?? 0, tool.name).toBeGreaterThan(0);
      expect(tool.description!.length, tool.name).toBeLessThanOrEqual(COMPACT_DESCRIPTION_MAX);
    }
    expect(full.filter((t) => !t.outputSchema).map((t) => t.name)).toEqual([]);
    const withFormat = full.filter((t) => t.inputSchema.properties?.response_format);
    expect(withFormat.length).toBeGreaterThan(full.length / 2);
    expect(full.some((t) => (t.description?.length ?? 0) > COMPACT_DESCRIPTION_MAX)).toBe(true);
  });

  it('stamps _meta.effects on every tool and _meta.provenance only on target-derived ones', () => {
    for (const tool of full) {
      expect(tool._meta?.effects, tool.name).toEqual({ ...TOOL_EFFECTS[tool.name], idempotent: expect.any(Boolean) });
      if (TOOL_EFFECTS[tool.name].targetDerived) expect(tool._meta?.provenance, tool.name).toEqual(TARGET_PROVENANCE);
      else expect(tool._meta?.provenance, tool.name).toBeUndefined();
    }
  });

  it('shrinks the serialized tools/list catalog', () => {
    const sizes = { full: bytes(full), core: bytes(core), compact: bytes(compact), coreCompact: bytes(coreCompact) };
    console.log(`tools/list bytes: full=${sizes.full} core=${sizes.core} compact=${sizes.compact} core+compact=${sizes.coreCompact}`);
    expect(sizes.core).toBeLessThan(sizes.full);
    expect(sizes.compact).toBeLessThan(sizes.full);
    // Measured ~17% of full; 25% leaves headroom for new core tools.
    expect(sizes.coreCompact).toBeLessThan(sizes.full * 0.25);
  });
});

describe('target-derived handler results', () => {
  beforeAll(() => {
    initState({ ...TEST_CONFIG });
  });

  afterAll(() => {
    getState().stopCleanupTimer();
  });

  it('get_messages returns _meta.provenance on success but not on error', async () => {
    seedSession(getState(), [scriptEntry('script-a', fakeScript())]);
    const harness = await makeFullHarness();
    try {
      const ok = (await harness.client.callTool({ name: 'get_messages', arguments: { session_id: DEFAULT_SESSION_ID } })) as Json;
      expect(ok.isError).toBeFalsy();
      expect(ok._meta?.provenance).toEqual(TARGET_PROVENANCE);

      const failed = (await harness.client.callTool({ name: 'get_messages', arguments: { session_id: 'nope' } })) as Json;
      expect(failed.isError).toBe(true);
      expect(failed._meta?.provenance).toBeUndefined();
    } finally {
      await harness.close();
    }
  });
});

describe('get_status hidden tools', () => {
  /** get_status on a server registered with `config`'s exposure policy (as server.ts/lib.ts apply it). */
  async function statusUnder(config: Partial<RuntimeConfig>, registered: RegisterAllOptions = config): Promise<Json> {
    initState({ ...TEST_CONFIG, ...config } as RuntimeConfig);
    const harness = await makeFullHarness({ toolProfile: registered.toolProfile, toolsExclude: registered.toolsExclude });
    try {
      return (await callJson(harness.client, 'get_status', {})).result;
    } finally {
      await harness.close();
      getState().stopCleanupTimer();
    }
  }

  it('reports the tools the config profile hides, with their names', async () => {
    const full = names(await listToolsWith({ ...FULL_TOOL_POLICY }));
    const core = names(await listToolsWith({ ...FULL_TOOL_POLICY, toolProfile: 'core' }));
    const status = await statusUnder({ toolProfile: 'core', toolsExclude: [] });
    expect(status.hidden_tools).toBe(full.length - core.length);
    expect(status.hidden_tool_names).toEqual(full.filter((n) => !core.includes(n)));
  });

  it('reports the policy registerAllTools applied, not the state config', async () => {
    // lib.ts passes options.config's policy explicitly while state.config may differ.
    const status = await statusUnder({ toolProfile: 'full', toolsExclude: [] }, { toolProfile: 'full', toolsExclude: ['adb_*'] });
    expect(status.hidden_tool_names.length).toBeGreaterThan(0);
    expect(status.hidden_tool_names.every((n: string) => n.startsWith('adb_'))).toBe(true);
  });

  it('falls back to the config policy when no registration was recorded', async () => {
    initState({ ...TEST_CONFIG, toolProfile: 'full', toolsExclude: ['adb_*'] } as RuntimeConfig);
    const harness = await makeFullHarness();
    try {
      getState().toolExposure = null;
      const status = (await callJson(harness.client, 'get_status', {})).result;
      expect(status.hidden_tool_names.length).toBeGreaterThan(0);
      expect(status.hidden_tool_names.every((n: string) => n.startsWith('adb_'))).toBe(true);
    } finally {
      await harness.close();
      getState().stopCleanupTimer();
    }
  });

  it('reports no hidden tools for the full profile', async () => {
    const status = await statusUnder({ toolProfile: 'full', toolsExclude: [] });
    expect(status.hidden_tools).toBe(0);
    expect(status.hidden_tool_names).toEqual([]);
  });
});
