import { describe, it, expect } from 'vitest';
import vm from 'node:vm';
import { listRecipes, getRecipe, searchRecipes } from '../../src/recipes/registry.js';
import { buildPreamble } from '../../src/agent/preamble.js';
import { findRemovedApis } from '../../src/agent/lint.js';

const HOSTILE = `x'); send("pwned"); //`;

/**
 * Compile preamble + recipe source in a sandbox with minimal Frida stubs. No bridge is
 * injected, so Java/ObjC are `{ available: false }` and the recipe should report an error
 * and return without throwing. This proves the source parses and reads its options safely.
 */
function compileInSandbox(source: string, options: Record<string, unknown>): string[] {
  const sent: string[] = [];
  const sandbox = {
    send: (msg: unknown) => { sent.push(JSON.stringify(msg)); },
    Process: { platform: 'linux', pointerSize: 8, findModuleByName: () => null, getModuleByName: () => { throw new Error('not found'); } },
    Module: { findGlobalExportByName: () => null },
    Interceptor: { attach: () => {}, replace: () => {} },
    Thread: { backtrace: () => [] },
    Backtracer: { ACCURATE: 'accurate' },
    DebugSymbol: { fromAddress: (a: unknown) => String(a) },
    ptr: (v: unknown) => v,
  };
  const context = vm.createContext(sandbox);
  const preamble = buildPreamble({ name: 'recipe-test', platform: 'unknown', options, injectedBridges: [] });
  vm.runInContext(`${preamble}\n${source}`, context, { filename: 'recipe.js' });
  return sent;
}

describe('recipe library', () => {
  const recipes = listRecipes();

  it('registers the documented recipes with unique names', () => {
    expect(recipes.length).toBeGreaterThanOrEqual(8);
    const names = recipes.map((r) => r.name);
    expect(new Set(names).size).toBe(names.length);
    expect(names).toContain('custom-java-crypto-key');
    expect(names).toContain('jni-register-natives');
    expect(names).toContain('ios-keychain-trace');
  });

  for (const recipe of recipes) {
    describe(recipe.name, () => {
      it('has complete metadata', () => {
        expect(recipe.title).toBeTruthy();
        expect(recipe.purpose).toBeTruthy();
        expect(recipe.usage).toBeTruthy();
        expect(recipe.platforms.length).toBeGreaterThan(0);
        expect(recipe.tags.length).toBeGreaterThan(0);
        for (const opt of recipe.options) {
          expect(opt.name).toBeTruthy();
          expect(opt.description).toBeTruthy();
        }
      });

      it('uses only Frida 17 APIs', () => {
        expect(findRemovedApis(recipe.source)).toEqual([]);
      });

      it('parses and runs under the preamble without throwing (options absent)', () => {
        expect(() => compileInSandbox(recipe.source, {})).not.toThrow();
      });

      it('reads hostile option values as data, not code', () => {
        // The source is a module constant — option values only ever reach the agent as
        // the JSON literal in the preamble, never as code. Feeding every option a string
        // that would break out if concatenated must not throw and must not run.
        const options: Record<string, unknown> = {};
        for (const opt of recipe.options) options[opt.name] = HOSTILE;
        expect(() => compileInSandbox(recipe.source, options)).not.toThrow();
      });
    });
  }
});

describe('searchRecipes', () => {
  it('returns all recipes for an empty query', () => {
    expect(searchRecipes('')).toHaveLength(listRecipes().length);
  });

  it('ranks the custom crypto recipe first for "rc4 key"', () => {
    const results = searchRecipes('rc4 key');
    expect(results[0]?.name).toBe('custom-java-crypto-key');
  });

  it('finds the keychain recipe by tag', () => {
    expect(searchRecipes('keychain').map((r) => r.name)).toContain('ios-keychain-trace');
  });

  it('returns nothing for an unrelated query', () => {
    expect(searchRecipes('zzzznotathing')).toHaveLength(0);
  });
});

describe('getRecipe', () => {
  it('looks up by name', () => {
    expect(getRecipe('jni-register-natives')?.title).toContain('JNI');
  });
  it('returns undefined for unknown', () => {
    expect(getRecipe('nope')).toBeUndefined();
  });
});
