import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { getRegisteredToolNames } from '../helpers/mock-fixtures.js';
import { getScriptRegistry } from '../../src/scripts/registry.js';

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

  it('README.md and llms.txt advertise the live tool and prebuilt-script counts', () => {
    const scriptCount = getScriptRegistry().listAll().length;
    const readmeTools = /exposes\s+(\d+)\s+tools/.exec(read('README.md'));
    expect(readmeTools, 'README.md should contain "exposes N tools"').not.toBeNull();
    expect(Number(readmeTools![1]), 'README.md tool count').toBe(registered.length);

    const llms = read('llms.txt');
    const llmsTools = /(\d+)\s+tools/.exec(llms);
    const llmsScripts = /(\d+)\s+prebuilt scripts/.exec(llms);
    expect(llmsTools, 'llms.txt should contain "N tools"').not.toBeNull();
    expect(llmsScripts, 'llms.txt should contain "N prebuilt scripts"').not.toBeNull();
    expect(Number(llmsTools![1]), 'llms.txt tool count').toBe(registered.length);
    expect(Number(llmsScripts![1]), 'llms.txt prebuilt script count').toBe(scriptCount);
  });

  it('skills/mobile-dynamic-analysis/SKILL.md mentions every registered tool', () => {
    const skill = read('skills/mobile-dynamic-analysis/SKILL.md');
    const missing = registered.filter((tool) => !skill.includes(`\`${tool}\``));
    expect(missing, `SKILL.md is missing backticked tool names: ${missing.join(', ')}`).toEqual([]);
  });

  describe('environment variables', () => {
    const ENV_NAME = /FRIDA_MCP_[A-Z0-9_]+|FRITAP_[A-Z0-9_]+|FRIDA_DEVICE_ID/;
    // Files whose env reads must be documented. agent-loader holds the FRITAP_* reads.
    const SOURCES = ['src/config.ts', 'src/index.ts', 'src/fritap/agent-loader.ts'];

    function readEnvNames(): string[] {
      const names = new Set<string>();
      for (const file of SOURCES) {
        for (const m of read(file).matchAll(new RegExp(`env\\.(${ENV_NAME.source})`, 'g'))) names.add(m[1]);
      }
      return [...names].sort();
    }

    it('finds the env vars the code reads', () => {
      const names = readEnvNames();
      expect(names).toContain('FRIDA_MCP_SCHEMA_PROFILE');
      expect(names).toContain('FRIDA_DEVICE_ID');
    });

    it('every env var read by the code is in server.json, README.md and docs/clients.md', () => {
      const names = readEnvNames();
      const server = JSON.parse(read('server.json')) as {
        packages?: { environmentVariables?: { name: string }[] }[];
      };
      const declared = new Set((server.packages ?? []).flatMap((p) => (p.environmentVariables ?? []).map((e) => e.name)));
      const readme = read('README.md');
      const clients = read('docs/clients.md');
      expect(names.filter((n) => !declared.has(n)), 'missing from server.json environmentVariables').toEqual([]);
      expect(names.filter((n) => !readme.includes(n)), 'missing from README.md').toEqual([]);
      expect(names.filter((n) => !clients.includes(n)), 'missing from docs/clients.md').toEqual([]);
    });
  });

  it('every registered prompt is listed in manifest.json prompts[]', () => {
    const prompts = [...read('src/prompts.ts').matchAll(/registerPrompt\(\s*'([^']+)'/g)].map((m) => m[1]);
    expect(prompts.length).toBeGreaterThan(0);
    const manifest = JSON.parse(read('manifest.json')) as { prompts: { name: string }[] };
    const listed = new Set(manifest.prompts.map((p) => p.name));
    expect(prompts.filter((n) => !listed.has(n)), 'prompts missing from manifest.json').toEqual([]);
  });
});
