import { describe, it, expect } from 'vitest';
import {
  composedSourceUsesJavaBridge,
  recordJavaBridgeUsage,
  scriptUsesJavaBridge,
  sourceHooksJavaMethods,
  bundleAppModulesHookJavaMethods,
} from '../../src/agent/script-traits.js';
import { createAgentScript } from '../../src/agent/script-factory.js';

describe('script traits: Java bridge usage', () => {
  it('classic scripts use the bridge only when java is injected', () => {
    expect(composedSourceUsesJavaBridge({ source: 'x', name: 'n', bridges: ['java'], passthrough: false })).toBe(true);
    expect(composedSourceUsesJavaBridge({ source: 'frida-java-bridge', name: 'n', bridges: [], passthrough: false })).toBe(false);
    expect(composedSourceUsesJavaBridge({ source: 'x', name: 'n', bridges: ['objc'], passthrough: false })).toBe(false);
  });

  it('passthrough bundles (compiled ESM, friTap) use it when they bundle frida-java-bridge', () => {
    const bundle = '📦\n100 /agent.js\n200 /node_modules/frida-java-bridge/index.js\n';
    expect(composedSourceUsesJavaBridge({ source: bundle, name: 'n', bridges: [], passthrough: true })).toBe(true);
    expect(composedSourceUsesJavaBridge({ source: '📦\n100 /agent.js\n', name: 'n', bridges: [], passthrough: true })).toBe(false);
  });

  it('defaults to false for scripts that were never recorded', () => {
    const script = {};
    expect(scriptUsesJavaBridge(script)).toBe(false);
    recordJavaBridgeUsage(script, true);
    expect(scriptUsesJavaBridge(script)).toBe(true);
  });

  it('createAgentScript records the trait on the created script', async () => {
    const created: object[] = [];
    const session = { createScript: async () => { const s = {}; created.push(s); return s; } } as any;
    const javaScript = await createAgentScript(session, { source: 'send(1)', platform: 'android', name: 'a', kind: 'generated', useSnapshot: false });
    const nativeScript = await createAgentScript(session, { source: 'send(1)', platform: 'android', name: 'b', kind: 'generated', bridges: [], useSnapshot: false });
    // Carrying the injected bridge without hooking Java is not an unload-order hazard.
    expect(scriptUsesJavaBridge(javaScript)).toBe(false);
    expect(scriptUsesJavaBridge(nativeScript)).toBe(false);
    const hookScript = await createAgentScript(session, {
      source: "Java.use('a.B').c.implementation = function () { return 1; };",
      platform: 'android', name: 'c', kind: 'user', useSnapshot: false,
    });
    expect(scriptUsesJavaBridge(hookScript)).toBe(true);
  });
});

describe('explicit usesJavaBridge flag on passthrough sources', () => {
  it('wins over source sniffing in both directions', () => {
    const base = { name: 'n', bridges: [], passthrough: true } as const;
    expect(composedSourceUsesJavaBridge({ ...base, source: 'x', usesJavaBridge: true })).toBe(true);
    expect(composedSourceUsesJavaBridge({ ...base, source: 'frida-java-bridge', usesJavaBridge: false })).toBe(false);
  });
});

describe('Java method hook detection', () => {
  it('detects implementation replacement, registerClass and deoptimize', () => {
    expect(sourceHooksJavaMethods("Java.use('a.B').m.implementation = function () {};")).toBe(true);
    expect(sourceHooksJavaMethods("Java.use('a.B').m.overload('int').implementation=f;")).toBe(true);
    expect(sourceHooksJavaMethods("Java.registerClass({ name: 'x' });")).toBe(true);
    expect(sourceHooksJavaMethods('Java.deoptimizeEverything();')).toBe(true);
    expect(sourceHooksJavaMethods('Java.deoptimizeMethod(m);')).toBe(true);
  });

  it('ignores read-only Java use and comparisons', () => {
    expect(sourceHooksJavaMethods("Java.perform(() => send(Java.use('a.B').class.getName()));")).toBe(false);
    expect(sourceHooksJavaMethods('if (m.implementation == null) send(1);')).toBe(false);
    expect(sourceHooksJavaMethods('Java.enumerateLoadedClassesSync();')).toBe(false);
  });
});

describe('classic scripts on Android (java bridge injected by default)', () => {
  const composed = { source: 'preamble + bridge with x.implementation = y', name: 'n', bridges: ['java'] as const, passthrough: false };

  it('a native-only Interceptor script is not flagged', () => {
    const source = "Interceptor.attach(Module.getGlobalExportByName('open'), { onEnter() { send(1); } });";
    expect(composedSourceUsesJavaBridge({ ...composed, bridges: ['java'] }, { source, kind: 'user' })).toBe(false);
  });

  it('a Java-hooking script is flagged', () => {
    const source = "Java.perform(() => { Java.use('a.B').m.implementation = function () { return 0; }; });";
    expect(composedSourceUsesJavaBridge({ ...composed, bridges: ['java'] }, { source, kind: 'user' })).toBe(true);
  });

  it('an explicit hooksJavaMethods marker wins over the source scan', () => {
    expect(composedSourceUsesJavaBridge({ ...composed, bridges: ['java'] }, { source: 'x', hooksJavaMethods: true })).toBe(true);
    expect(composedSourceUsesJavaBridge({ ...composed, bridges: ['java'] }, { source: '.implementation = f', hooksJavaMethods: false })).toBe(false);
  });

  it('never flags a script without the java bridge, even if it hooks', () => {
    expect(composedSourceUsesJavaBridge({ ...composed, bridges: [] }, { source: '.implementation = f', hooksJavaMethods: true })).toBe(false);
  });
});

describe('passthrough bundles', () => {
  const bundleOf = (modules: Array<[string, string]>) =>
    `📦\n${modules.map(([p, c]) => `${Buffer.byteLength(c)} ${p}\n`).join('')}✄\n${modules.map(([, c]) => c).join('\n✄\n')}`;
  const bridgeModule: [string, string] = ['/node_modules/frida-java-bridge/index.js', 'k.implementation = f;'];

  it('ignores the embedded bridge code and checks only application modules', () => {
    const nativeOnly = bundleOf([['/agent.js', "Interceptor.attach(ptr(1), {});"], bridgeModule]);
    const hooking = bundleOf([['/agent.js', "Java.use('a.B').m.implementation = f;"], bridgeModule]);
    expect(bundleAppModulesHookJavaMethods(nativeOnly)).toBe(false);
    expect(bundleAppModulesHookJavaMethods(hooking)).toBe(true);
    const base = { name: 'n', bridges: [], passthrough: true, usesJavaBridge: true } as const;
    expect(composedSourceUsesJavaBridge({ ...base, source: nativeOnly }, { source: nativeOnly, kind: 'user' })).toBe(false);
    expect(composedSourceUsesJavaBridge({ ...base, source: hooking }, { source: hooking, kind: 'user' })).toBe(true);
  });

  it('stays conservative (true) when a bridge-embedding bundle cannot be parsed', () => {
    const broken = '📦\n999 /agent.js\n✄\nsend(1)';
    expect(bundleAppModulesHookJavaMethods(broken)).toBeNull();
    const base = { name: 'n', bridges: [], passthrough: true, usesJavaBridge: true } as const;
    expect(composedSourceUsesJavaBridge({ ...base, source: broken }, { source: broken, kind: 'user' })).toBe(true);
  });

  it('keeps generated bridge bundles (friTap agent) flagged', () => {
    const nativeOnly = bundleOf([['/agent.js', 'send(1);'], bridgeModule]);
    const base = { name: 'fritap', bridges: [], passthrough: true, usesJavaBridge: true } as const;
    expect(composedSourceUsesJavaBridge({ ...base, source: nativeOnly }, { source: nativeOnly, kind: 'generated' })).toBe(true);
  });

  it('never flags a bundle that does not embed the bridge', () => {
    const bundle = bundleOf([['/agent.js', '.implementation = f']]);
    const base = { name: 'n', bridges: [], passthrough: true, usesJavaBridge: false } as const;
    expect(composedSourceUsesJavaBridge({ ...base, source: bundle }, { source: bundle, kind: 'user' })).toBe(false);
  });
});
