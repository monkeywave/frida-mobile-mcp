import { describe, it, expect } from 'vitest';
import vm from 'node:vm';
import { getScriptRegistry } from '../../src/scripts/registry.js';
import { buildPreamble } from '../../src/agent/preamble.js';
import { findRemovedApis } from '../../src/agent/lint.js';

const HOSTILE = `x'); send("pwned"); //`;
const HOSTILE_OPTIONS = {
  filter: HOSTILE,
  filter_path: HOSTILE,
  filter_key: HOSTILE,
  filter_host: HOSTILE,
  class_name: HOSTILE,
  method_name: HOSTILE,
  platform: HOSTILE,
  limit: 7,
  include_methods: true,
  log_backtrace: true,
  log_data: true,
  log_keys: false,
};

const NATIVE_HOOK_TEMPLATES = ['network_inspector', 'filesystem_monitor', 'crypto_monitor', 'keychain_prefs', 'root_jailbreak_bypass', 'anti_frida_evasion'];
const UNCONDITIONAL_NATIVE_HOOK_TEMPLATES = ['network_inspector', 'filesystem_monitor', 'crypto_monitor', 'anti_frida_evasion'];

interface SentMessage {
  status?: string;
  hooks_attempted?: number;
  hooks_installed?: number;
  hooks_skipped?: number;
  hook_errors?: unknown[];
  [key: string]: unknown;
}

/**
 * Run preamble + body in a sandbox with minimal Frida stubs. No bridge is injected, so the
 * preamble installs `{ available: false }` stubs for Java and ObjC and every native lookup
 * returns null (hooks are counted as skipped). This verifies the body parses, reads its
 * options at runtime without throwing, and ends with an `init_complete` summary.
 */
function runInSandbox(name: string, body: string, options: Record<string, unknown>): SentMessage[] {
  const sent: SentMessage[] = [];
  const sandbox = {
    send: (msg: SentMessage) => { sent.push(msg); },
    Process: { platform: 'linux', findModuleByName: () => null, getModuleByName: () => { throw new Error('not found'); } },
    Module: { findGlobalExportByName: () => null },
    Interceptor: { attach: () => { throw new Error('not in sandbox'); }, replace: () => { throw new Error('not in sandbox'); } },
    Thread: { backtrace: () => [] },
    Backtracer: { ACCURATE: 'accurate' },
    DebugSymbol: { fromAddress: (a: unknown) => String(a) },
    NativeCallback: function () { return {}; },
    NativeFunction: function () { return () => 0; },
    ptr: (v: unknown) => v,
  };
  const context = vm.createContext(sandbox);
  const preamble = buildPreamble({ name: `prebuilt:${name}`, platform: 'unknown', options, injectedBridges: [] });
  vm.runInContext(`${preamble}\n${body}`, context, { filename: `${name}.js` });
  return sent;
}

describe('Script Generation', () => {
  const registry = getScriptRegistry();

  it('registry contains exactly 9 templates', () => {
    expect(registry.listAll()).toHaveLength(9);
  });

  for (const template of registry.listAll()) {
    describe(template.name, () => {
      const output = template.generate({});

      it('generate({}) returns a non-empty string wrapped in an IIFE', () => {
        expect(typeof output).toBe('string');
        expect(output.trim().length).toBeGreaterThan(0);
        expect(output).toContain('(function()');
        expect(output).toContain('send(');
      });

      it('is a constant body independent of the options passed', () => {
        expect(template.generate(HOSTILE_OPTIONS)).toBe(output);
        expect(template.generate({ class_name: 'a', method_name: 'b', filter: 'c' })).toBe(output);
      });

      it('never splices option values into the body', () => {
        const hostileOutput = template.generate(HOSTILE_OPTIONS);
        expect(hostileOutput).not.toContain(HOSTILE);
        expect(hostileOutput).not.toContain('pwned');
      });

      it('reads its options from __FRIDA_MCP__.options at runtime', () => {
        expect(output).toContain('__FRIDA_MCP__');
      });

      it('does not use any API removed in Frida 17', () => {
        expect(findRemovedApis(output)).toEqual([]);
      });

      it(`ends with reportSummary('${template.name}')`, () => {
        expect(output).toContain(`reportSummary('${template.name}')`);
      });

      it('is syntactically valid classic JavaScript', () => {
        expect(() => new vm.Script(output, { filename: `${template.name}.js` })).not.toThrow();
      });

      it('runs to init_complete in a sandbox with default options', () => {
        const sent = runInSandbox(template.name, output, {});
        const summary = sent.find((m) => m.status === 'init_complete');
        expect(summary).toBeDefined();
        expect(summary!.script).toBe(template.name);
      });

      it('runs to init_complete in a sandbox with hostile options', () => {
        const sent = runInSandbox(template.name, output, HOSTILE_OPTIONS);
        expect(sent.find((m) => m.status === 'init_complete')).toBeDefined();
        // `send("pwned")` would have produced a bare string message. The hostile value may
        // still legitimately appear as *data* (e.g. inside an "invalid regex" error message).
        expect(sent.find((m) => (m as unknown) === 'pwned')).toBeUndefined();
      });
    });
  }

  describe('templates with native hooks', () => {
    for (const name of NATIVE_HOOK_TEMPLATES) {
      it(`${name} uses hookNative`, () => {
        expect(registry.get(name)!.generate({})).toContain('hookNative(');
      });
    }

    // keychain_prefs / root_jailbreak_bypass only hook natively inside Java/ObjC branches,
    // which the bridge-less sandbox never enters; the rest hook unconditionally.
    for (const name of UNCONDITIONAL_NATIVE_HOOK_TEMPLATES) {
      it(`${name} counts native hook attempts in the summary`, () => {
        const output = registry.get(name)!.generate({});
        const sent = runInSandbox(name, output, {});
        const summary = sent.find((m) => m.status === 'init_complete')!;
        expect(summary.hooks_attempted).toBeGreaterThan(0);
        expect(summary.hooks_installed).toBe(0);
        expect(summary.hooks_skipped).toBe(summary.hooks_attempted);
      });
    }
  });

  describe('SSL Pinning Bypass - bug fix verification', () => {
    const script = registry.get('ssl_pinning_bypass')!.generate({});

    it('uses custom TrustManager instance in SSLContext.init (Bug 1 fix)', () => {
      expect(script).toContain('TrustManager.$new()');
    });

    it('contains permissive BoringSSL callback returning ssl_verify_ok (Bug 3 fix)', () => {
      expect(script.includes('ssl_verify_ok') || script.includes('permissive_verify_cb')).toBe(true);
    });

    it('does NOT pass original tm to SSLContext.init', () => {
      expect(script).not.toMatch(/this\.init\(km,\s*tm,\s*sr\)/);
    });

    it('contains NULL safety check for result pointer', () => {
      expect(script).toContain('result.isNull');
    });

    it('uses findExport + NativePointer#writeU32 instead of Module/Memory statics', () => {
      expect(script).toContain("findExport('Security', 'SecTrustEvaluate')");
      expect(script).toContain('result.writeU32(4)');
    });
  });

  describe('class_enumeration', () => {
    const template = registry.get('class_enumeration')!;
    const output = template.generate({});

    it('uses objcClassNames() for the ObjC path', () => {
      expect(output).toContain('objcClassNames()');
      expect(output).not.toContain('enumerateLoadedClassesSync');
    });

    it('reports an error (not a crash) for an invalid filter regex', () => {
      const sent = runInSandbox('class_enumeration', output, { filter: '([' });
      expect(sent.some((m) => m.status === 'error' && String(m.error).includes('Invalid filter regex'))).toBe(true);
      expect(sent.find((m) => m.status === 'init_complete')).toBeDefined();
    });
  });

  describe('method_hook', () => {
    const template = registry.get('method_hook')!;
    const output = template.generate({});

    it('uses a Java stack trace (not Thread.backtrace) inside Java implementations', () => {
      expect(output).toContain("Java.use('android.util.Log')");
      expect(output).toContain('getStackTraceString');
    });

    it('reports missing required options at runtime', () => {
      const sent = runInSandbox('method_hook', output, {});
      expect(sent.some((m) => m.status === 'error' && String(m.error).includes('class_name'))).toBe(true);
    });
  });

  describe('root_jailbreak_bypass', () => {
    it('emits a real regex for su/magisk paths (not a line comment)', () => {
      const output = registry.get('root_jailbreak_bypass')!.generate({});
      expect(output).toContain('/\\/su|\\/magisk|\\/supersu/');
      expect(output).not.toContain('match(//su');
    });
  });
});
