import { describe, it, expect } from 'vitest';
import { applyHookStatus } from '../../src/tools/hook.js';
import type { HookEntry } from '../../src/types.js';

function hook(): HookEntry {
  return {
    id: 'h1',
    scriptId: 's1',
    sessionId: 'sess-1',
    target: 'javax.crypto.Cipher.doFinal',
    type: 'java',
    invocations: [],
    status: 'active',
    createdAt: Date.now(),
    liveness: { installed: false, firstSeenTs: null },
  };
}

describe('applyHookStatus (hook liveness)', () => {
  it('records a successful Java install with class resolution and overload count', () => {
    const h = hook();
    applyHookStatus(h, { status: 'hook_installed', classResolved: true, overloads: 7 });
    expect(h.liveness).toMatchObject({ installed: true, classResolved: true, overloadsMatched: 7 });
    expect(h.status).toBe('active');
  });

  it('marks a class-not-loaded miss as not installed, with the reason and error status', () => {
    const h = hook();
    applyHookStatus(h, { status: 'hook_error', classResolved: false, reason: 'CLASS_NOT_LOADED' });
    expect(h.liveness).toMatchObject({ installed: false, classResolved: false, reason: 'CLASS_NOT_LOADED' });
    expect(h.status).toBe('error');
  });

  it('records an ObjC install with a match count', () => {
    const h = { ...hook(), type: 'objc' as const };
    applyHookStatus(h, { status: 'hook_installed', matches: 3 });
    expect(h.liveness).toMatchObject({ installed: true, matches: 3 });
  });

  it('records a native NO_EXPORT miss', () => {
    const h = { ...hook(), type: 'native' as const };
    applyHookStatus(h, { status: 'hook_error', reason: 'NO_EXPORT' });
    expect(h.liveness).toMatchObject({ installed: false, reason: 'NO_EXPORT' });
    expect(h.status).toBe('error');
  });

  it('is a no-op for an undefined hook or a hook without a liveness record', () => {
    expect(() => applyHookStatus(undefined, { status: 'hook_installed' })).not.toThrow();
    const h = hook();
    delete h.liveness;
    expect(() => applyHookStatus(h, { status: 'hook_installed' })).not.toThrow();
  });
});
