import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import {
  getState,
  initState,
  newerJavaBridgeScripts,
  scriptsNewestFirst,
  unloadScriptsNewestFirst,
} from '../../src/state.js';
import { recordJavaBridgeUsage } from '../../src/agent/script-traits.js';
import type { ScriptEntry } from '../../src/types.js';
import { fakeScript, scriptEntry, seedSession, TEST_CONFIG, type FakeScript } from '../helpers/mock-fixtures.js';

/** Fake script that appends its id to `order` when unloaded. */
function orderedScript(id: string, order: string[], options: { java?: boolean; failWith?: string } = {}): FakeScript {
  const script = fakeScript({ failWith: options.failWith });
  const unload = script.unload.bind(script);
  script.unload = async () => { order.push(id); await unload(); };
  recordJavaBridgeUsage(script, options.java ?? false);
  return script;
}

function entries(order: string[], specs: Array<[string, { java?: boolean; failWith?: string; eternalized?: boolean }?]>): ScriptEntry[] {
  return specs.map(([id, opts]) => {
    const entry = scriptEntry(id, orderedScript(id, order, opts));
    if (opts?.eternalized) entry.eternalized = true;
    return entry;
  });
}

describe('teardown order helpers', () => {
  beforeAll(() => initState({ ...TEST_CONFIG }));
  afterAll(() => getState().stopCleanupTimer());
  beforeEach(() => getState().sessions.clear());

  it('scriptsNewestFirst returns the reverse of load (insertion) order', () => {
    const order: string[] = [];
    const session = seedSession(getState(), entries(order, [['a'], ['b'], ['c']]));
    expect(scriptsNewestFirst(session).map((s) => s.id)).toEqual(['c', 'b', 'a']);
  });

  it('unloadScriptsNewestFirst unloads LIFO and skips eternalized and destroyed scripts', async () => {
    const order: string[] = [];
    const scripts = entries(order, [['a'], ['b', { eternalized: true }], ['c'], ['d']]);
    (scripts[2].script as unknown as FakeScript).isDestroyed = true;
    const session = seedSession(getState(), scripts);

    const attempted = await unloadScriptsNewestFirst(session);

    expect(order).toEqual(['d', 'a']);
    expect(attempted).toEqual(['d', 'a']);
  });

  it('keeps going when one unload throws', async () => {
    const order: string[] = [];
    const session = seedSession(getState(), entries(order, [['a'], ['b', { failWith: 'process gone' }], ['c']]));
    await unloadScriptsNewestFirst(session);
    expect(order).toEqual(['c', 'b', 'a']);
  });

  it('uses a custom unloader in the same order', async () => {
    const order: string[] = [];
    const seen: string[] = [];
    const session = seedSession(getState(), entries(order, [['a'], ['b']]));
    await unloadScriptsNewestFirst(session, async (entry) => { seen.push(entry.id); });
    expect(seen).toEqual(['b', 'a']);
    expect(order).toEqual([]);
  });

  it('removeSession (expiry, process exit) unloads newest-first', async () => {
    const order: string[] = [];
    seedSession(getState(), entries(order, [['a', { java: true }], ['b', { java: true }], ['c']]));
    await getState().removeSession('sess-1');
    expect(order).toEqual(['c', 'b', 'a']);
  });

  it('state.cleanup (server shutdown) unloads newest-first', async () => {
    const order: string[] = [];
    seedSession(getState(), entries(order, [['a'], ['b']]));
    await getState().cleanup();
    expect(order).toEqual(['b', 'a']);
  });

  describe('newerJavaBridgeScripts', () => {
    it('lists the newer live Java-bridge scripts newest-first', () => {
      const order: string[] = [];
      const session = seedSession(getState(), entries(order, [
        ['old', { java: true }], ['native', { java: false }], ['mid', { java: true }], ['new', { java: true }],
      ]));
      expect(newerJavaBridgeScripts(session, 'old').map((s) => s.id)).toEqual(['new', 'mid']);
      expect(newerJavaBridgeScripts(session, 'mid').map((s) => s.id)).toEqual(['new']);
      expect(newerJavaBridgeScripts(session, 'new')).toEqual([]);
    });

    it('is empty when the script itself has no Java bridge', () => {
      const order: string[] = [];
      const session = seedSession(getState(), entries(order, [['native', { java: false }], ['java', { java: true }]]));
      expect(newerJavaBridgeScripts(session, 'native')).toEqual([]);
    });

    it('ignores eternalized and destroyed newer scripts, and unknown ids', () => {
      const order: string[] = [];
      const scripts = entries(order, [['old', { java: true }], ['pinned', { java: true, eternalized: true }], ['dead', { java: true }]]);
      (scripts[2].script as unknown as FakeScript).isDestroyed = true;
      const session = seedSession(getState(), scripts);
      expect(newerJavaBridgeScripts(session, 'old')).toEqual([]);
      expect(newerJavaBridgeScripts(session, 'missing')).toEqual([]);
    });
  });
});
