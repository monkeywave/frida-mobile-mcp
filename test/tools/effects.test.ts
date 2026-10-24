import { describe, it, expect, beforeAll } from 'vitest';
import { listRegisteredTools } from '../helpers/mock-fixtures.js';
import { TOOL_EFFECTS, effectsFor } from '../../src/tools/effects.js';

interface ToolMeta {
  name: string;
  annotations?: { readOnlyHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean };
  _meta?: { effects?: Record<string, boolean> };
}

describe('tool effects table', () => {
  let tools: ToolMeta[];

  beforeAll(async () => {
    tools = (await listRegisteredTools()) as ToolMeta[];
  });

  it('has an entry for every registered tool and none for unregistered names', () => {
    const registered = tools.map((t) => t.name).sort();
    expect(Object.keys(TOOL_EFFECTS).sort()).toEqual(registered);
  });

  it('effectsFor returns the entry or undefined', () => {
    expect(effectsFor('hook_method')).toBe(TOOL_EFFECTS.hook_method);
    expect(effectsFor('toString')).toBeUndefined();
    expect(effectsFor('no_such_tool')).toBeUndefined();
  });

  it('is consistent with each tool annotation', () => {
    for (const tool of tools) {
      const fx = TOOL_EFFECTS[tool.name];
      const a = tool.annotations ?? {};
      const mutates = fx.mutatesTarget || fx.mutatesDevice;
      // readOnlyHint is allowed alongside executesForeignCode: read-only tools (read_memory,
      // enumerate_*, ...) load the server's own agent script but change nothing in the target.
      expect(!(mutates && a.readOnlyHint === true), `${tool.name}: mutating tool must not be readOnlyHint`).toBe(true);
      if (fx.executesForeignCode && a.readOnlyHint !== true) expect(a.readOnlyHint, tool.name).toBe(false);
      if (fx.accessesNetwork) expect(a.openWorldHint, `${tool.name}: network needs openWorldHint`).not.toBe(false);
    }
  });

  it('stamps _meta.effects.idempotent from the idempotentHint annotation', () => {
    for (const tool of tools) {
      expect(tool._meta?.effects?.idempotent, tool.name).toBe(tool.annotations?.idempotentHint === true);
    }
  });
});
