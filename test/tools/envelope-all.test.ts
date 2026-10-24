import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { initState, getState } from '../../src/state.js';
import { TOOL_RESULT_OUTPUT_SHAPE } from '../../src/helpers/output-schema.js';
import { rateLimiter } from '../../src/helpers/rate-limiter.js';
import { makeFullHarness, TEST_CONFIG, type McpHarness } from '../helpers/mock-fixtures.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Tools that need no device or session, with arguments that keep them offline. */
const DEVICE_FREE_CALLS: Array<[string, Record<string, unknown>]> = [
  ['get_status', {}],
  ['frida_help', {}],
  ['validate_script', { source: 'send(1);', language: 'js' }],
  ['search_recipes', { query: 'rc4' }],
  ['list_saved_scripts', {}],
  ['run_prebuilt_script', {}],
];

describe('every tool honours the result envelope', () => {
  let harness: McpHarness;

  beforeAll(async () => {
    initState({ ...TEST_CONFIG });
    rateLimiter.reset();
    harness = await makeFullHarness();
  });

  afterAll(async () => {
    await harness.close();
    getState().stopCleanupTimer();
  });

  it('declares an outputSchema on every registered tool', async () => {
    const { tools } = await harness.client.listTools();
    expect(tools.length).toBeGreaterThan(30);
    expect(tools.filter((t) => !t.outputSchema).map((t) => t.name)).toEqual([]);
  });

  it.each(DEVICE_FREE_CALLS)('%s returns a valid envelope with a UUID evidence_id', async (name, args) => {
    const response = (await harness.client.callTool({ name, arguments: args })) as { structuredContent?: unknown; isError?: boolean };
    expect(response.structuredContent, `${name} should return structuredContent`).toBeDefined();
    const parsed = TOOL_RESULT_OUTPUT_SHAPE.safeParse(response.structuredContent);
    expect(parsed.success, parsed.success ? '' : JSON.stringify(parsed.error.issues)).toBe(true);
    if (parsed.success) expect(parsed.data.evidence_id).toMatch(UUID);
  });
});
