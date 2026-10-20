/**
 * Frida 17.10 Interceptor instrumentation options on the native hook paths.
 *
 * Verified shape (https://frida.re/docs/javascript-api/, "Interceptor"): the options ride
 * on the target object — `Interceptor.attach({ target: addr, ...options }, callbacks)` —
 * and `Interceptor.defaults` holds process-wide defaults. The scripts are rendered here
 * exactly as the agent would see them (preamble + body) and the options wrapper is
 * executed in a sandbox to assert the call shape that reaches Interceptor.attach.
 */
import { describe, it, expect, vi } from 'vitest';
import vm from 'node:vm';
import {
  interceptorOptionsSchema,
  normalizeInterceptorOptions,
  interceptorOptionsLimitations,
  buildHookOptions,
  generateHookScript,
  INTERCEPTOR_TARGET_SNIPPET,
} from '../../src/tools/hook.js';
import { buildTraceOptions, generateTraceScript } from '../../src/tools/trace.js';
import { buildHookFunctionOptions, HOOK_FUNCTION_SCRIPT } from '../../src/tools/advanced/intercept.js';
import { RESOLVE_TARGET_SNIPPET } from '../../src/agent/address.js';
import { buildPreamble } from '../../src/agent/preamble.js';
import { findRemovedApis } from '../../src/agent/lint.js';

const FLAGS = { logArgs: true, logRetval: true, logBacktrace: false };
const OPTIONS = { scenario: 'offline', relocation: 'unchecked', scratchRegister: 'x16', redirectSpaceHint: 16 } as const;

function render(options: Record<string, unknown>, body: string): string {
  return buildPreamble({ name: 'test', platform: 'android', options, injectedBridges: [] }) + '\n' + body;
}

/** Run the in-script wrapper with a fake __FRIDA_MCP__ and return what Interceptor.attach would receive. */
function evaluateTarget(interceptorOptions: Record<string, unknown> | undefined, addr: unknown): unknown {
  const fn = new Function('__FRIDA_MCP__', 'addr', `${INTERCEPTOR_TARGET_SNIPPET}\nreturn interceptorTarget(addr);`);
  return fn({ options: interceptorOptions ? { interceptorOptions } : {} }, addr);
}

describe('interceptorOptionsSchema', () => {
  it('accepts only the documented keys and values', () => {
    expect(interceptorOptionsSchema.parse(OPTIONS)).toEqual(OPTIONS);
    expect(interceptorOptionsSchema.parse(undefined)).toBeUndefined();
    expect(() => interceptorOptionsSchema.parse({ scenario: 'sometimes' })).toThrow();
    expect(() => interceptorOptionsSchema.parse({ relocation: 'yolo' })).toThrow();
    expect(() => interceptorOptionsSchema.parse({ redirectSpaceHint: -1 })).toThrow();
    expect(() => interceptorOptionsSchema.parse({ writeRedirect: 'function () {}' })).toThrow();
    expect(() => interceptorOptionsSchema.parse({ unknown: true })).toThrow();
  });
});

describe('normalizeInterceptorOptions', () => {
  it('collapses missing or empty input to undefined', () => {
    expect(normalizeInterceptorOptions(undefined)).toBeUndefined();
    expect(normalizeInterceptorOptions({})).toBeUndefined();
    expect(normalizeInterceptorOptions({ scenario: undefined })).toBeUndefined();
  });

  it('keeps only the keys that were set', () => {
    expect(normalizeInterceptorOptions({ scenario: 'offline', relocation: undefined })).toEqual({ scenario: 'offline' });
  });
});

describe('interceptorOptionsLimitations', () => {
  it('is silent for native hooks and for absent options', () => {
    expect(interceptorOptionsLimitations('native', OPTIONS)).toEqual([]);
    expect(interceptorOptionsLimitations('java', undefined)).toEqual([]);
    expect(interceptorOptionsLimitations('objc', {})).toEqual([]);
  });

  it('notes that the options were ignored for java/objc hooks', () => {
    expect(interceptorOptionsLimitations('java', { scenario: 'offline' })[0]).toMatch(/ignored for this java hook/);
    expect(interceptorOptionsLimitations('objc', { scenario: 'offline' })[0]).toMatch(/ignored for this objc hook/);
  });
});

describe('option plumbing into __FRIDA_MCP__.options', () => {
  it('hook_method emits interceptorOptions for native targets only', () => {
    expect(buildHookOptions('libc.so!open', 'native', FLAGS, OPTIONS).interceptorOptions).toEqual(OPTIONS);
    expect(buildHookOptions('libc.so!open', 'native', FLAGS)).not.toHaveProperty('interceptorOptions');
    expect(buildHookOptions('libc.so!open', 'native', FLAGS, {})).not.toHaveProperty('interceptorOptions');
    expect(buildHookOptions('com.example.A.b', 'java', FLAGS, OPTIONS)).not.toHaveProperty('interceptorOptions');
    expect(buildHookOptions('-[A b:]', 'objc', FLAGS, OPTIONS)).not.toHaveProperty('interceptorOptions');
  });

  it('trace_method emits interceptorOptions for native patterns only', () => {
    expect(buildTraceOptions('libc.so!op*', 'native', FLAGS, OPTIONS).interceptorOptions).toEqual(OPTIONS);
    expect(buildTraceOptions('libc.so!op*', 'native', FLAGS)).not.toHaveProperty('interceptorOptions');
    expect(buildTraceOptions('com.example.*', 'java', FLAGS, OPTIONS)).not.toHaveProperty('interceptorOptions');
  });

  it('hook_function emits interceptorOptions for every target (all go through Interceptor)', () => {
    expect(buildHookFunctionOptions('libc.so!open', OPTIONS).interceptorOptions).toEqual(OPTIONS);
    expect(buildHookFunctionOptions('-[NSString length]', OPTIONS).interceptorOptions).toEqual(OPTIONS);
    expect(buildHookFunctionOptions('libc.so!open')).not.toHaveProperty('interceptorOptions');
  });
});

describe('interceptorTarget() wrapper (the form that reaches Interceptor.attach)', () => {
  const addr = { toString: () => '0x1234' };

  it('returns the bare address when no options were given (pre-17.10 call shape)', () => {
    expect(evaluateTarget(undefined, addr)).toBe(addr);
  });

  it('returns { target, ...options } when options were given (Frida 17.10 call shape)', () => {
    const result = evaluateTarget({ scenario: 'offline', relocation: 'checked' }, addr) as Record<string, unknown>;
    expect(result).toEqual({ target: addr, scenario: 'offline', relocation: 'checked' });
    expect(result.target).toBe(addr);
  });

  it('cannot let options override the target address', () => {
    // The strict schema already rejects a stray `target`; the wrapper assigns the
    // address last so even a hand-built options object cannot redirect the hook.
    expect(() => interceptorOptionsSchema.parse({ target: 'evil' })).toThrow();
    const result = evaluateTarget({ target: 'evil' }, addr) as Record<string, unknown>;
    expect(result.target).toBe(addr);
  });
});

describe('rendered native scripts', () => {
  const cases: Array<[string, (options?: Record<string, unknown>) => string]> = [
    ['hook_method native', (o) => render(buildHookOptions('libc.so!open', 'native', FLAGS, o), generateHookScript('native'))],
    ['trace_method native', (o) => render(buildTraceOptions('libc.so!op*', 'native', FLAGS, o), generateTraceScript('native'))],
    ['hook_function', (o) => render(buildHookFunctionOptions('libc.so!open', o), RESOLVE_TARGET_SNIPPET + INTERCEPTOR_TARGET_SNIPPET + HOOK_FUNCTION_SCRIPT)],
  ];

  it.each(cases)('%s: with options, the literal reaches the script and attach uses the wrapper', (_label, make) => {
    const script = make({ scenario: 'offline', relocation: 'unchecked' });
    expect(script).toContain('"interceptorOptions":{"scenario":"offline","relocation":"unchecked"}');
    expect(script).toMatch(/Interceptor\.attach\(interceptorTarget\([a-zA-Z.]+\), \{/);
    expect(script).toContain('return Object.assign({}, io, { target: addr });');
    expect(script).not.toMatch(/Interceptor\.attach\((addr|exp\.address), \{/);
    expect(findRemovedApis(script)).toEqual([]);
  });

  it.each(cases)('%s: without options, no interceptorOptions literal is emitted', (_label, make) => {
    const script = make(undefined);
    expect(script).not.toContain('interceptorOptions"');
    expect(script).toMatch(/Interceptor\.attach\(interceptorTarget\([a-zA-Z.]+\), \{/);
    expect(findRemovedApis(script)).toEqual([]);
  });

  it('java and objc hook scripts are untouched by the option', () => {
    for (const type of ['java', 'objc'] as const) {
      const script = render(buildHookOptions('x', type, FLAGS, OPTIONS), generateHookScript(type));
      expect(script).not.toContain('interceptorOptions');
      expect(script).not.toContain('interceptorTarget(');
      expect(findRemovedApis(script)).toEqual([]);
    }
  });
});

describe('preamble hookNative(lib, name, callbacks, options?)', () => {
  function runPreamble() {
    const addr = { toString: () => '0x1000' };
    const attach = vi.fn();
    const sandbox: Record<string, unknown> = {
      Interceptor: { attach },
      Process: { findModuleByName: () => ({ findExportByName: () => addr }) },
      Module: { findGlobalExportByName: () => addr },
    };
    const context = vm.createContext(sandbox);
    vm.runInContext(buildPreamble({ name: 'p', platform: 'android', options: {}, injectedBridges: [] }), context);
    const hookNative = sandbox.hookNative as (lib: string | null, name: string, cb: unknown, options?: unknown) => boolean;
    return { addr, attach, hookNative };
  }

  it('attaches with the bare address when no options are passed', () => {
    const { addr, attach, hookNative } = runPreamble();
    const callbacks = { onEnter() {} };
    expect(hookNative('libc.so', 'open', callbacks)).toBe(true);
    expect(attach).toHaveBeenCalledTimes(1);
    expect(attach.mock.calls[0][0]).toBe(addr);
    expect(attach.mock.calls[0][1]).toBe(callbacks);
  });

  it('attaches with { target, ...options } when options are passed', () => {
    const { addr, attach, hookNative } = runPreamble();
    const callbacks = { onEnter() {} };
    expect(hookNative('libc.so', 'open', callbacks, { scenario: 'offline', scratchRegister: 'x16' })).toBe(true);
    expect(attach.mock.calls[0][0]).toEqual({ target: addr, scenario: 'offline', scratchRegister: 'x16' });
    expect(attach.mock.calls[0][1]).toBe(callbacks);
  });
});
