import { describe, expect, it } from 'vitest';
// @ts-expect-error -- plain .mjs CI script without type declarations
import { findAllowScriptsMismatch } from '../../.github/scripts/check-allow-scripts.mjs';

const lockWith = (version: string) => ({ packages: { 'node_modules/frida': { version } } });

describe('findAllowScriptsMismatch', () => {
  it('passes when allowScripts approves the locked version', () => {
    const pkg = { allowScripts: { 'frida@17.26.2': true } };
    expect(findAllowScriptsMismatch(pkg, lockWith('17.26.2'))).toBeNull();
  });

  it('reports a stale key left behind by a lockfile-only bump', () => {
    const pkg = { allowScripts: { 'frida@17.24.3': true } };
    const mismatch = findAllowScriptsMismatch(pkg, lockWith('17.26.2'));
    expect(mismatch).toContain('frida@17.26.2');
    expect(mismatch).toContain('frida@17.24.3');
  });

  it('reports a missing allowScripts block', () => {
    expect(findAllowScriptsMismatch({}, lockWith('17.26.2'))).toContain('found: none');
  });

  it('rejects an approval that is not literally true', () => {
    const pkg = { allowScripts: { 'frida@17.26.2': false } };
    expect(findAllowScriptsMismatch(pkg, lockWith('17.26.2'))).not.toBeNull();
  });

  it('reports a lockfile without frida', () => {
    expect(findAllowScriptsMismatch({ allowScripts: {} }, { packages: {} })).toContain('not in package-lock.json');
  });
});
