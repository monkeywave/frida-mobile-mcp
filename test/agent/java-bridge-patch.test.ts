import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import {
  JAVA_BRIDGE_PATCH_MARKER,
  isJavaBridgeThreadDetachSkipped,
  patchJavaBridgeInCompiledBundle,
  skipJavaBridgeThreadDetach,
} from '../../src/agent/java-bridge-patch.js';

/** Upstream index.js form of Runtime._dispose (frida-java-bridge 7.0.13). */
const UPSTREAM_DISPOSE = [
  '  _dispose () {',
  '    const { vm } = this;',
  '    vm.perform(env => {',
  '      ClassFactory._disposeAll(env);',
  '      Env.dispose(env);',
  '    });',
  '    Script.nextTick(() => {',
  '      VM.dispose(vm);',
  '    });',
  '  }',
  'Script.bindWeak(runtime, () => { runtime._dispose(); });',
].join('\n');

/** The same code as esbuild emits it inside friTap's frida-compile bundle (renamed identifiers). */
const ESBUILD_DISPOSE = UPSTREAM_DISPOSE.replace('const { vm } = this;', 'const { vm: vm3 } = this;')
  .replace('VM.dispose(vm);', 'VM.dispose(vm3);')
  .replace('vm.perform(env => {', 'vm3.perform((env) => {');

function compiledBundle(modules: Array<[string, string]>): string {
  const header = modules.map(([p, c]) => `${Buffer.byteLength(c)} ${p}\n`).join('');
  return `📦\n${header}✄\n${modules.map(([, c]) => c).join('\n✄\n')}`;
}

describe('skipJavaBridgeThreadDetach', () => {
  it('comments out only the VM.dispose call and keeps the hook-reverting dispose steps', () => {
    const result = skipJavaBridgeThreadDetach(UPSTREAM_DISPOSE);
    expect(result).toMatchObject({ patched: true, status: 'patched' });
    expect(result.source).toContain(`${JAVA_BRIDGE_PATCH_MARKER} /* VM.dispose(vm); */`);
    expect(result.source).not.toMatch(/^\s*VM\.dispose\(vm\);/m);
    expect(result.source).toContain('ClassFactory._disposeAll(env);');
    expect(result.source).toContain('Env.dispose(env);');
    expect(result.source).toContain('Script.bindWeak(runtime, () => { runtime._dispose(); });');
  });

  it('is idempotent', () => {
    const once = skipJavaBridgeThreadDetach(UPSTREAM_DISPOSE).source;
    expect(skipJavaBridgeThreadDetach(once)).toEqual({ source: once, patched: true, status: 'already-patched' });
    expect(isJavaBridgeThreadDetachSkipped(once)).toBe(true);
  });

  it('handles the esbuild-renamed form', () => {
    const result = skipJavaBridgeThreadDetach(ESBUILD_DISPOSE);
    expect(result.status).toBe('patched');
    expect(result.source).toContain('/* VM.dispose(vm3); */');
  });

  it('reports pattern-not-found and leaves the source untouched when upstream changed', () => {
    const changed = 'const runtime = new Runtime();\nexport default runtime;\n';
    expect(skipJavaBridgeThreadDetach(changed)).toEqual({ source: changed, patched: false, status: 'pattern-not-found' });
  });

  it('matches the installed frida-java-bridge index.js', () => {
    const indexFile = path.resolve('node_modules', 'frida-java-bridge', 'index.js');
    expect(skipJavaBridgeThreadDetach(readFileSync(indexFile, 'utf8')).status).toBe('patched');
  });
});

describe('patchJavaBridgeInCompiledBundle', () => {
  it('patches the module and rewrites its byte size in the header', () => {
    const bundle = compiledBundle([['/agent/fritap_agent.js', `// ünïcode\n${ESBUILD_DISPOSE}`]]);
    const result = patchJavaBridgeInCompiledBundle(bundle);
    expect(result.status).toBe('patched');
    const [, sizeLine, separator, ...rest] = result.source.split('\n');
    const body = rest.join('\n');
    expect(separator).toBe('✄');
    expect(sizeLine).toBe(`${Buffer.byteLength(body)} /agent/fritap_agent.js`);
    expect(body).toContain(JAVA_BRIDGE_PATCH_MARKER);
  });

  it('keeps multi-module bundles consistent', () => {
    const bundle = compiledBundle([['/a.js', 'console.log(1);'], ['/b.js', ESBUILD_DISPOSE]]);
    const result = patchJavaBridgeInCompiledBundle(bundle);
    expect(result.status).toBe('patched');
    expect(result.source).toBe(compiledBundle([['/a.js', 'console.log(1);'], ['/b.js', skipJavaBridgeThreadDetach(ESBUILD_DISPOSE).source]]));
  });

  it('is idempotent', () => {
    const once = patchJavaBridgeInCompiledBundle(compiledBundle([['/x.js', ESBUILD_DISPOSE]])).source;
    expect(patchJavaBridgeInCompiledBundle(once)).toEqual({ source: once, patched: true, status: 'already-patched' });
  });

  it('reports pattern-not-found for bundles without the bridge or with an inconsistent header', () => {
    const noBridge = compiledBundle([['/x.js', 'console.log(1);']]);
    expect(patchJavaBridgeInCompiledBundle(noBridge)).toEqual({ source: noBridge, patched: false, status: 'pattern-not-found' });
    const badSize = `📦\n5 /x.js\n✄\n${ESBUILD_DISPOSE}`;
    expect(patchJavaBridgeInCompiledBundle(badSize).status).toBe('pattern-not-found');
    expect(patchJavaBridgeInCompiledBundle(ESBUILD_DISPOSE).status).toBe('pattern-not-found');
  });

  const realAgent = process.env.FRITAP_AGENT_PATH;
  it.skipIf(!realAgent || !existsSync(realAgent))('patches a real friTap agent bundle (FRITAP_AGENT_PATH)', () => {
    const result = patchJavaBridgeInCompiledBundle(readFileSync(realAgent!, 'utf8'));
    expect(result.status).toBe('patched');
    expect(result.source).toMatch(/\/\* VM\w*\.dispose\(vm\d*\); \*\//);
  });
});
