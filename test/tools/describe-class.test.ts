import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import {
  registerDescribeClassTool,
  JAVA_DESCRIBE_SOURCE,
  OBJC_DESCRIBE_SOURCE,
  formatJavaModifiers,
} from '../../src/tools/describe-class.js';
import { parseJavaSignature } from '../../src/agent/java-signature.js';
import { javaEvidenceToMethod } from '../../src/tools/hook.js';
import { findRemovedApis } from '../../src/agent/lint.js';
import { initState, getState } from '../../src/state.js';
import { rateLimiter } from '../../src/helpers/rate-limiter.js';
import {
  agentOptions,
  callJson,
  makeMcpHarness,
  makeScriptingSetup,
  TEST_CONFIG,
  TARGET,
  type FakeAgentScript,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

// --- A tiny fake of java.lang.Class / reflect objects ----------------------

const PUBLIC = 0x1, PRIVATE = 0x2, STATIC = 0x8, FINAL = 0x10, VOLATILE = 0x40, SYNTHETIC = 0x1000;

const typeOf = (name: string) => ({ getName: () => name });

interface FakeClassSpec {
  name: string;
  modifiers?: number;
  isInterface?: boolean;
  superclass?: FakeClass | null;
  interfaces?: string[];
  methods?: Array<{ name: string; args: string[]; ret: string; mods?: number }>;
  ctors?: Array<{ args: string[]; mods?: number }>;
  fields?: Array<{ name: string; type: string; mods?: number }>;
  failMethods?: boolean;
}
type FakeClass = ReturnType<typeof fakeClass>;

function fakeClass(spec: FakeClassSpec) {
  return {
    getName: () => spec.name,
    getModifiers: () => spec.modifiers ?? PUBLIC,
    isInterface: () => spec.isInterface ?? false,
    getSuperclass: () => spec.superclass ?? null,
    getInterfaces: () => (spec.interfaces ?? []).map(typeOf),
    getDeclaredMethods: () => {
      if (spec.failMethods) throw new Error('NoClassDefFoundError: com.missing.Dep');
      return (spec.methods ?? []).map((m) => ({
        getName: () => m.name,
        getParameterTypes: () => m.args.map(typeOf),
        getReturnType: () => typeOf(m.ret),
        getModifiers: () => m.mods ?? PUBLIC,
      }));
    },
    getDeclaredConstructors: () => (spec.ctors ?? []).map((c) => ({
      getParameterTypes: () => c.args.map(typeOf),
      getModifiers: () => c.mods ?? PUBLIC,
    })),
    getDeclaredFields: () => (spec.fields ?? []).map((f) => ({
      getName: () => f.name,
      getType: () => typeOf(f.type),
      getModifiers: () => f.mods ?? PRIVATE,
    })),
  };
}

const OBJECT = fakeClass({ name: 'java.lang.Object', methods: [{ name: 'hashCode', args: [], ret: 'int' }] });
const BASE = fakeClass({
  name: 'com.example.BaseClient',
  superclass: OBJECT,
  methods: [{ name: 'close', args: [], ret: 'void' }],
  fields: [{ name: 'closed', type: 'boolean', mods: PRIVATE | VOLATILE }],
});
const RC4 = fakeClass({
  name: 'com.example.rc4demo.Rc4Client',
  modifiers: PUBLIC | FINAL,
  superclass: BASE,
  interfaces: ['java.lang.Runnable'],
  methods: [
    { name: 'encrypt', args: ['[B', 'java.lang.String'], ret: '[B', mods: PUBLIC | STATIC },
    { name: 'encrypt', args: ['[B'], ret: '[B' },
    { name: 'runSession', args: [], ret: 'void', mods: PRIVATE },
    { name: 'access$000', args: ['com.example.rc4demo.Rc4Client'], ret: 'void', mods: STATIC | SYNTHETIC },
  ],
  ctors: [{ args: ['java.lang.String', 'int'] }],
  fields: [{ name: 'key', type: '[B', mods: PRIVATE | FINAL }],
});

/** Run the Java agent body against a fake bridge and return what rpc.exports.describe resolves to. */
async function runJavaAgent(className: string, classes: Record<string, FakeClass>, includeInherited = false) {
  const Java = {
    available: true,
    use: (name: string) => {
      if (!classes[name]) throw new Error('ClassNotFoundException: ' + name);
      return { class: classes[name] };
    },
    enumerateClassLoaders: ({ onComplete }: { onComplete: () => void }) => onComplete(),
    ClassFactory: { get: () => ({ use: () => { throw new Error('nope'); } }) },
  };
  const javaPerform = async (fn: () => unknown) => fn();
  const rpc = { exports: {} as Record<string, () => Promise<unknown>> };
  const run = new Function('__FRIDA_MCP__', 'Java', 'javaPerform', 'rpc', JAVA_DESCRIBE_SOURCE);
  run({ options: { className, includeInherited } }, Java, javaPerform, rpc);
  return rpc.exports.describe() as Promise<any>;
}

describe('JAVA_DESCRIBE_SOURCE (agent side, fake bridge)', () => {
  it('reflects declared methods, constructors, fields, superclass and interfaces', async () => {
    const raw = await runJavaAgent('com.example.rc4demo.Rc4Client', { 'com.example.rc4demo.Rc4Client': RC4 });
    expect(raw).toMatchObject({
      found: true,
      name: 'com.example.rc4demo.Rc4Client',
      superclass: 'com.example.BaseClient',
      interfaces: ['java.lang.Runnable'],
      constructors: [{ argTypes: ['java.lang.String', 'int'], modifiers: PUBLIC }],
      fields: [{ name: 'key', type: '[B', modifiers: PRIVATE | FINAL }],
      errors: [],
    });
    expect(raw.methods).toHaveLength(4);
    expect(raw.methods[0]).toEqual({ name: 'encrypt', argTypes: ['[B', 'java.lang.String'], returnType: '[B', modifiers: PUBLIC | STATIC });
  });

  it('reports a class that is in no loader as found:false', async () => {
    expect(await runJavaAgent('com.example.Missing', {})).toEqual({ found: false });
  });

  it('walks superclasses up to java.lang.Object when include_inherited', async () => {
    const raw = await runJavaAgent('com.example.rc4demo.Rc4Client', { 'com.example.rc4demo.Rc4Client': RC4 }, true);
    expect(raw.inheritedFrom).toEqual(['com.example.BaseClient']);
    expect(raw.methods.find((m: any) => m.name === 'close')).toMatchObject({ declaringClass: 'com.example.BaseClient' });
    expect(raw.methods.find((m: any) => m.name === 'hashCode')).toBeUndefined();
    expect(raw.fields.find((f: any) => f.name === 'closed')).toMatchObject({ declaringClass: 'com.example.BaseClient' });
  });

  it('keeps going when one reflection call throws and records the error', async () => {
    const broken = fakeClass({ name: 'com.example.Broken', failMethods: true, fields: [{ name: 'x', type: 'int' }] });
    const raw = await runJavaAgent('com.example.Broken', { 'com.example.Broken': broken });
    expect(raw.methods).toEqual([]);
    expect(raw.fields).toHaveLength(1);
    expect(raw.errors[0]).toMatch(/methods of com\.example\.Broken: NoClassDefFoundError/);
  });

  it('uses only Frida 17 APIs', () => {
    expect(findRemovedApis(JAVA_DESCRIBE_SOURCE)).toEqual([]);
    expect(findRemovedApis(OBJC_DESCRIBE_SOURCE)).toEqual([]);
  });
});

describe('OBJC_DESCRIBE_SOURCE (agent side, fake bridge)', () => {
  it('lists own selectors with type encodings and the superclass', () => {
    const cls: Record<string, any> = {
      $className: 'RC4Client',
      $superClass: { $className: 'NSObject' },
      $protocols: { NSCopying: {} },
      $ownMethods: ['- encrypt:key:'],
      $methods: ['- encrypt:key:', '- description'],
      '- encrypt:key:': { types: '@32@0:8@16@24', returnType: 'pointer', argumentTypes: ['pointer', 'pointer', 'pointer', 'pointer'] },
    };
    const ObjC = { available: true, classes: { RC4Client: cls } };
    const rpc = { exports: {} as Record<string, () => any> };
    new Function('__FRIDA_MCP__', 'ObjC', 'rpc', OBJC_DESCRIBE_SOURCE)({ options: { className: 'RC4Client', includeInherited: false } }, ObjC, rpc);
    expect(rpc.exports.describe()).toMatchObject({
      found: true,
      superclass: 'NSObject',
      protocols: ['NSCopying'],
      methods: [{ selector: '- encrypt:key:', types: '@32@0:8@16@24' }],
    });
    new Function('__FRIDA_MCP__', 'ObjC', 'rpc', OBJC_DESCRIBE_SOURCE)({ options: { className: 'Nope' } }, ObjC, rpc);
    expect(rpc.exports.describe()).toEqual({ found: false });
  });
});

describe('formatJavaModifiers', () => {
  it('formats like Modifier.toString and is kind-aware for shared bits', () => {
    expect(formatJavaModifiers(PUBLIC | STATIC | FINAL, 'method')).toEqual(['public', 'static', 'final']);
    expect(formatJavaModifiers(PRIVATE | VOLATILE, 'field')).toEqual(['private', 'volatile']);
    expect(formatJavaModifiers(PUBLIC | VOLATILE | 0x80, 'method')).toEqual(['public', 'bridge', 'varargs']);
    expect(formatJavaModifiers(STATIC | SYNTHETIC, 'method')).toEqual(['static', 'synthetic']);
    expect(formatJavaModifiers(PUBLIC | 0x200 | 0x400, 'class')).toEqual(['public', 'abstract', 'interface']);
  });
});

describe('describe_class MCP tool', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];
  let scripts: FakeAgentScript[];
  let deviceManager: ReturnType<typeof makeScriptingSetup>['deviceManager'];
  let describeResult: unknown;

  beforeAll(async () => {
    const setup = makeScriptingSetup(({ name }) =>
      name?.startsWith('describe_class:') ? { exports: { describe: async () => describeResult } } : {}
    );
    scripts = setup.scripts;
    deviceManager = setup.deviceManager;
    ({ client, close } = await makeMcpHarness((server) => registerDescribeClassTool(server, deviceManager)));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
  });

  beforeEach(async () => {
    initState({ ...TEST_CONFIG });
    rateLimiter.reset();
    scripts.length = 0;
    deviceManager.detectPlatform.mockResolvedValue('android');
    describeResult = await runJavaAgent('com.example.rc4demo.Rc4Client', { 'com.example.rc4demo.Rc4Client': RC4 });
  });

  const describeScript = () => scripts.find((s) => s.name?.startsWith('describe_class:'))!;

  it('is a read-only, idempotent tool', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'describe_class')!;
    expect(tool.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false, idempotentHint: true });
  });

  it('returns methods with hook-ready signatures, constructors and fields', async () => {
    const parsed = await callJson(client, 'describe_class', { target: TARGET, class_name: 'com.example.rc4demo.Rc4Client' });
    expect(parsed.error).toBeUndefined();
    const r = parsed.result;
    expect(r).toMatchObject({
      platform: 'android',
      class_name: 'com.example.rc4demo.Rc4Client',
      kind: 'class',
      modifiers: ['public', 'final'],
      superclass: 'com.example.BaseClient',
      interfaces: ['java.lang.Runnable'],
      method_count: 4,
    });
    expect(r.methods.map((m: any) => m.signature)).toEqual([
      'access$000(com.example.rc4demo.Rc4Client)',
      'encrypt(byte[])',
      'encrypt(byte[], java.lang.String)',
      'runSession()',
    ]);
    expect(r.methods[2]).toEqual({
      name: 'encrypt',
      signature: 'encrypt(byte[], java.lang.String)',
      arg_types: ['[B', 'java.lang.String'],
      return_type: '[B',
      modifiers: ['public', 'static'],
    });
    expect(r.constructors).toEqual([{
      name: '$init', signature: '$init(java.lang.String, int)', arg_types: ['java.lang.String', 'int'], return_type: 'void', modifiers: ['public'],
    }]);
    expect(r.fields).toEqual([{ name: 'key', type: '[B', modifiers: ['private', 'final'] }]);
    expect(parsed.coverage.status).toBe('complete');
    expect(describeScript().unloadCalls).toBe(1);
  });

  it('every signature round-trips into hook_method evidence', async () => {
    const parsed = await callJson(client, 'describe_class', { target: TARGET, class_name: 'com.example.rc4demo.Rc4Client' });
    for (const m of [...parsed.result.methods, ...parsed.result.constructors]) {
      expect(parseJavaSignature(m.signature)).toMatchObject({ name: m.name, argTypes: m.arg_types });
      expect(javaEvidenceToMethod({ class: 'com.example.rc4demo.Rc4Client', signature: m.signature })).toBe(`com.example.rc4demo.Rc4Client.${m.signature}`);
    }
  });

  it('suggests hook_method with evidence for the first non-synthetic method', async () => {
    const parsed = await callJson(client, 'describe_class', { target: TARGET, class_name: 'com.example.rc4demo.Rc4Client' });
    const hook = parsed.suggested_next.find((s: any) => s.tool === 'hook_method');
    expect(hook.args.evidence).toEqual({ class: 'com.example.rc4demo.Rc4Client', signature: 'encrypt(byte[])' });
    expect(hook.args.session_id).toBe(parsed.result.session_id);
  });

  it('forwards class_name and include_inherited to the agent as options (default false)', async () => {
    await callJson(client, 'describe_class', { target: TARGET, class_name: 'a.B' });
    expect(agentOptions(describeScript().source)).toMatchObject({ className: 'a.B', includeInherited: false });
    scripts.length = 0;
    await callJson(client, 'describe_class', { target: TARGET, class_name: 'a.B', include_inherited: true });
    expect(agentOptions(describeScript().source)).toMatchObject({ includeInherited: true });
  });

  it('carries a hostile class name to the agent purely as escaped data', async () => {
    const hostile = '"}; globalThis.pwned = 1; ({"x":"';
    await callJson(client, 'describe_class', { target: TARGET, class_name: hostile });
    expect(agentOptions(describeScript().source).className).toBe(hostile);
  });

  it('reports CLASS_NOT_LOADED with watch_loads / search recovery hints', async () => {
    describeResult = { found: false };
    const parsed = await callJson(client, 'describe_class', { target: TARGET, class_name: 'com.example.Missing' });
    expect(parsed.error.code).toBe('CLASS_NOT_LOADED');
    expect(parsed.error.retryable).toBe(true);
    const tools = parsed.error.recovery_actions.map((a: any) => a.tool);
    expect(tools).toEqual(expect.arrayContaining(['watch_loads', 'search_classes_and_methods']));
  });

  it('marks coverage unknown and lists reflection errors as limitations', async () => {
    describeResult = { ...(describeResult as object), errors: ['methods of x: boom'] };
    const parsed = await callJson(client, 'describe_class', { target: TARGET, class_name: 'com.example.rc4demo.Rc4Client' });
    expect(parsed.coverage.status).toBe('unknown');
    expect(parsed.limitations.join(' ')).toMatch(/boom/);
  });

  it('selects the ObjC variant on iOS and shapes selectors', async () => {
    deviceManager.detectPlatform.mockResolvedValue('ios');
    describeResult = {
      found: true, name: 'RC4Client', superclass: 'NSObject', protocols: [], errors: [],
      methods: [{ selector: '- encrypt:key:', types: '@32@0:8@16@24', returnType: 'pointer', argumentTypes: ['pointer'] }],
    };
    const parsed = await callJson(client, 'describe_class', { target: TARGET, class_name: 'RC4Client' });
    expect(describeScript().name).toBe('describe_class:ios');
    expect(parsed.result.methods).toEqual([{ selector: '- encrypt:key:', types: '@32@0:8@16@24', return_type: 'pointer', argument_types: ['pointer'] }]);
    expect(parsed.suggested_next[0].args.method).toBe('-[RC4Client encrypt:key:]');
  });

  it('rejects a call with neither target nor session_id', async () => {
    const parsed = await callJson(client, 'describe_class', { class_name: 'a.B' });
    expect(parsed.error.message).toMatch(/provide target.*or session_id/i);
  });
});
