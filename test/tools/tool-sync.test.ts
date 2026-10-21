import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { getRegisteredToolNames } from '../helpers/mock-fixtures.js';

/**
 * Enforces the rule AGENTS.md states but nothing used to check: the tools registered in
 * src/tools/register-all.ts must stay in sync with every surface that advertises them.
 * The registered set (introspected live via listTools) is the single source of truth;
 * manifest.json and README.md are each checked against it here. The help.ts coverage
 * check is owned by help.test.ts (which already reads help.ts), so it is not repeated.
 */
describe('tool-list sync', () => {
  let registered: string[];

  beforeAll(async () => {
    registered = await getRegisteredToolNames();
  });

  function read(rel: string): string {
    return readFileSync(join(process.cwd(), rel), 'utf-8');
  }

  it('registers a non-trivial set of uniquely-named tools', () => {
    expect(registered.length).toBeGreaterThan(30);
    expect(new Set(registered).size).toBe(registered.length);
  });

  it('manifest.json tools[] matches the registered tools exactly', () => {
    const manifest = JSON.parse(read('manifest.json')) as { tools: { name: string }[] };
    const manifestTools = manifest.tools.map((t) => t.name).sort();
    expect(manifestTools).toEqual(registered);
  });

  it('README.md documents every registered tool', () => {
    const readme = read('README.md');
    for (const tool of registered) {
      expect(readme, `README.md should mention ${tool}`).toContain(tool);
    }
  });
});
