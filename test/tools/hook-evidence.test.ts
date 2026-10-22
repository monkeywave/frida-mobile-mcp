/**
 * Hook-by-evidence: static-analysis findings ({module, offset}, {class, signature}) become
 * hook targets, and a Java signature selects exactly one overload in the agent.
 */
import { describe, it, expect, vi } from 'vitest';
import {
  applyHookStatus,
  buildHookOptions,
  detectHookType,
  generateHookScript,
  hookEvidenceSchema,
  javaEvidenceToMethod,
  nativeEvidenceToTarget,
  resolveHookMethod,
  splitJavaMethod,
} from '../../src/tools/hook.js';
import { resolveHookFunctionTarget } from '../../src/tools/advanced/intercept.js';
import { FridaMcpError } from '../../src/helpers/errors.js';
import { findRemovedApis } from '../../src/agent/lint.js';
import type { HookEntry } from '../../src/types.js';

const FLAGS = { logArgs: true, logRetval: true, logBacktrace: false };

function expectInvalid(fn: () => unknown, message?: RegExp): void {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(FridaMcpError);
    expect((err as FridaMcpError).code).toBe('INVALID_ARGUMENT');
    if (message) expect((err as Error).message).toMatch(message);
    return;
  }
  throw new Error('expected INVALID_ARGUMENT');
}

describe('nativeEvidenceToTarget', () => {
  it('turns {module, offset} into module+0xoff (hex or decimal, string or number)', () => {
    expect(nativeEvidenceToTarget({ module: 'libfoo.so', offset: '0x1A2b' })).toBe('libfoo.so+0x1a2b');
    expect(nativeEvidenceToTarget({ module: 'libfoo.so', offset: '4660' })).toBe('libfoo.so+0x1234');
    expect(nativeEvidenceToTarget({ module: 'libfoo.so', offset: 4660 })).toBe('libfoo.so+0x1234');
  });

  it('subtracts image_base from a static address (Ghidra ELF base 0x100000)', () => {
    expect(nativeEvidenceToTarget({ module: 'libfoo.so', address: '0x101234', image_base: '0x100000' })).toBe('libfoo.so+0x1234');
    expect(nativeEvidenceToTarget({ module: 'libc++.so', address: '0x1234', image_base: 0 })).toBe('libc++.so+0x1234');
  });

  it('produces a target hook_method classifies as native', () => {
    expect(detectHookType(nativeEvidenceToTarget({ module: 'libfoo.so', offset: 1 }))).toBe('native');
  });

  it('rejects incomplete, conflicting or malformed native evidence', () => {
    expectInvalid(() => nativeEvidenceToTarget({ offset: '0x10' }), /module/);
    expectInvalid(() => nativeEvidenceToTarget({ module: 'libfoo.so' }), /offset/);
    expectInvalid(() => nativeEvidenceToTarget({ module: 'libfoo.so', address: '0x10' }), /image_base/);
    expectInvalid(() => nativeEvidenceToTarget({ module: 'libfoo.so', offset: '0x10', image_base: '0x0' }), /not both/);
    expectInvalid(() => nativeEvidenceToTarget({ module: 'libfoo.so', offset: '-1' }));
    expectInvalid(() => nativeEvidenceToTarget({ module: 'libfoo.so', offset: 'zz' }));
    expectInvalid(() => nativeEvidenceToTarget({ module: 'libfoo.so', address: '0x10', image_base: '0x100' }), /below/);
  });
});

describe('javaEvidenceToMethod', () => {
  it('normalises any signature notation to class.name(source types)', () => {
    const expected = 'com.example.Rc4Client.encrypt(byte[], java.lang.String)';
    expect(javaEvidenceToMethod({ class: 'com.example.Rc4Client', signature: 'encrypt(byte[], java.lang.String)' })).toBe(expected);
    expect(javaEvidenceToMethod({ class: 'com.example.Rc4Client', signature: 'encrypt([B,java.lang.String)' })).toBe(expected);
    expect(javaEvidenceToMethod({ class: 'com.example.Rc4Client', signature: 'encrypt([BLjava/lang/String;)[B' })).toBe(expected);
    expect(javaEvidenceToMethod({ class: 'com.example.Rc4Client', signature: 'public byte[] encrypt(byte[] d, java.lang.String k)' })).toBe(expected);
    expect(javaEvidenceToMethod({ class: 'com.example.Rc4Client', method: 'encrypt', signature: '(byte[], java.lang.String)' })).toBe(expected);
  });

  it('maps <init> to $init and allows a method without signature (all overloads)', () => {
    expect(javaEvidenceToMethod({ class: 'a.B', method: '<init>', signature: '(I)V' })).toBe('a.B.$init(int)');
    expect(javaEvidenceToMethod({ class: 'a.B', method: 'run' })).toBe('a.B.run');
  });

  it('rejects missing class/name, a name mismatch and malformed signatures', () => {
    expectInvalid(() => javaEvidenceToMethod({ signature: 'f()' }), /class/);
    expectInvalid(() => javaEvidenceToMethod({ class: 'a.B' }), /signature/);
    expectInvalid(() => javaEvidenceToMethod({ class: 'a.B', signature: '(int)' }), /method/);
    expectInvalid(() => javaEvidenceToMethod({ class: 'a.B', method: 'g', signature: 'f(int)' }), /does not match/);
    expectInvalid(() => javaEvidenceToMethod({ class: 'a.B', signature: 'f(int' }));
  });
});

describe('resolveHookMethod', () => {
  it('passes method through and requires exactly one of method / evidence', () => {
    expect(resolveHookMethod('libc.so!open', undefined)).toBe('libc.so!open');
    expectInvalid(() => resolveHookMethod(undefined, undefined));
    expectInvalid(() => resolveHookMethod('x.Y.z', { class: 'x.Y', method: 'z' }), /not both/);
  });

  it('dispatches on the evidence fields and rejects mixed evidence', () => {
    expect(resolveHookMethod(undefined, { module: 'libfoo.so', offset: '0x10' })).toBe('libfoo.so+0x10');
    expect(resolveHookMethod(undefined, { class: 'a.B', signature: 'f([B)' })).toBe('a.B.f(byte[])');
    expectInvalid(() => resolveHookMethod(undefined, { module: 'libfoo.so', offset: 1, class: 'a.B' }), /mixes/);
  });

  it('schema is strict (no stray keys such as file_offset)', () => {
    expect(() => hookEvidenceSchema.parse({ module: 'libfoo.so', file_offset: 1 })).toThrow();
    expect(hookEvidenceSchema.parse({ class: 'a.B', signature: 'f()' })).toEqual({ class: 'a.B', signature: 'f()' });
  });
});

describe('resolveHookFunctionTarget (hook_function)', () => {
  it('accepts native evidence and rejects Java evidence', () => {
    expect(resolveHookFunctionTarget(undefined, { module: 'libfoo.so', offset: '0x20' })).toBe('libfoo.so+0x20');
    expect(resolveHookFunctionTarget('libc.so!open', undefined)).toBe('libc.so!open');
    expectInvalid(() => resolveHookFunctionTarget(undefined, { class: 'a.B', signature: 'f()' }), /hook_method/);
  });
});

describe('splitJavaMethod / buildHookOptions', () => {
  it('keeps the all-overloads behaviour for a plain method', () => {
    expect(splitJavaMethod('com.example.Foo.bar')).toEqual({ className: 'com.example.Foo', methodName: 'bar' });
    expect(buildHookOptions('com.example.Foo.bar', 'java', FLAGS)).not.toHaveProperty('argTypes');
  });

  it('extracts canonical argTypes from an appended signature in any notation', () => {
    for (const method of [
      'com.example.Foo.bar(byte[], java.lang.String)',
      'com.example.Foo.bar([B,java.lang.String)',
      'com.example.Foo.bar([BLjava/lang/String;)V',
    ]) {
      expect(detectHookType(method)).toBe('java');
      expect(buildHookOptions(method, 'java', FLAGS)).toMatchObject({
        className: 'com.example.Foo',
        methodName: 'bar',
        argTypes: ['[B', 'java.lang.String'],
      });
    }
    expect(splitJavaMethod('com.example.Foo.<init>(I)V')).toEqual({ className: 'com.example.Foo', methodName: '$init', argTypes: ['int'] });
    expect(splitJavaMethod('com.example.Foo.start()').argTypes).toEqual([]);
  });

  it('rejects a malformed signature with INVALID_ARGUMENT', () => {
    expectInvalid(() => splitJavaMethod('com.example.Foo.bar(byte[]'), /Invalid Java method signature/);
  });
});

describe('applyHookStatus OVERLOAD_MISMATCH', () => {
  it('records the reason and the overloads that do exist', () => {
    const hook: HookEntry = {
      id: 'h', scriptId: 's', sessionId: 'x', target: 'a.B.f(int)', type: 'java',
      invocations: [], status: 'active', createdAt: 0, liveness: { installed: false, firstSeenTs: null },
    };
    applyHookStatus(hook, { status: 'hook_error', reason: 'OVERLOAD_MISMATCH', classResolved: true, availableOverloads: ['f(byte[])'] });
    expect(hook.liveness).toMatchObject({ installed: false, classResolved: true, reason: 'OVERLOAD_MISMATCH', availableOverloads: ['f(byte[])'] });
    expect(hook.status).toBe('error');
  });
});

/** Run JAVA_HOOK_SCRIPT against a fake Java bridge and report what it instrumented / sent. */
function runJavaHook(method: string, overloadTypes: string[][]) {
  const overloads = overloadTypes.map((types) => ({
    argumentTypes: types.map((className) => ({ className })),
    implementation: undefined as unknown,
  }));
  const cls = { bar: { overloads } };
  const sent: Array<Record<string, unknown>> = [];
  const Java = {
    available: true,
    perform: (fn: () => void) => fn(),
    use: vi.fn(() => cls),
    enumerateClassLoaders: vi.fn(),
  };
  const options = { ...buildHookOptions(method, 'java', FLAGS), platform: 'android' };
  const run = new Function('__FRIDA_MCP__', 'Java', 'send', 'recordHookError', 'Process', generateHookScript('java'));
  run({ options }, Java, (m: Record<string, unknown>) => sent.push(m), () => undefined, { getCurrentThreadId: () => 1 });
  return { hooked: overloads.map((o) => typeof o.implementation === 'function'), sent };
}

describe('JAVA_HOOK_SCRIPT overload selection (agent side)', () => {
  const OVERLOADS = [['[B'], ['[B', 'java.lang.String'], ['java.lang.String'], ['[Ljava.lang.String;']];

  it('hooks every overload when no signature is given (unchanged behaviour)', () => {
    const { hooked, sent } = runJavaHook('com.example.Foo.bar', OVERLOADS);
    expect(hooked).toEqual([true, true, true, true]);
    expect(sent.at(-1)).toMatchObject({ status: 'hook_installed', overloads: 4 });
  });

  it('hooks exactly the overload matching the signature', () => {
    const { hooked, sent } = runJavaHook('com.example.Foo.bar(byte[], java.lang.String)', OVERLOADS);
    expect(hooked).toEqual([false, true, false, false]);
    expect(sent.at(-1)).toMatchObject({ status: 'hook_installed', classResolved: true, overloads: 1 });
  });

  it('matches unqualified class names by simple name, keeping array depth', () => {
    expect(runJavaHook('com.example.Foo.bar(String)', OVERLOADS).hooked).toEqual([false, false, true, false]);
    expect(runJavaHook('com.example.Foo.bar(String[])', OVERLOADS).hooked).toEqual([false, false, false, true]);
    expect(runJavaHook('com.example.Foo.bar(Inner)', [['com.example.Outer$Inner']]).hooked).toEqual([true]);
  });

  it('reports OVERLOAD_MISMATCH with the available signatures and hooks nothing', () => {
    const { hooked, sent } = runJavaHook('com.example.Foo.bar(int)', OVERLOADS);
    expect(hooked).toEqual([false, false, false, false]);
    expect(sent.at(-1)).toMatchObject({
      status: 'hook_error',
      reason: 'OVERLOAD_MISMATCH',
      classResolved: true,
      availableOverloads: ['bar(byte[])', 'bar(byte[], java.lang.String)', 'bar(java.lang.String)', 'bar(java.lang.String[])'],
    });
  });

  it('uses only Frida 17 APIs', () => {
    expect(findRemovedApis(generateHookScript('java'))).toEqual([]);
  });
});
