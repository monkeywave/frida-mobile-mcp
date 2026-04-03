import { describe, it, expect } from 'vitest';
import { getScriptRegistry } from '../../src/scripts/registry.js';

describe('Script Generation', () => {
  const registry = getScriptRegistry();

  describe('SSL Pinning Bypass - bug fix verification', () => {
    const template = registry.get('ssl_pinning_bypass')!;
    const script = template.generate({});

    it('uses custom TrustManager instance in SSLContext.init (Bug 1 fix)', () => {
      expect(script).toContain('TrustManager.$new()');
    });

    it('contains permissive BoringSSL callback returning ssl_verify_ok (Bug 3 fix)', () => {
      const hasVerifyOk = script.includes('ssl_verify_ok');
      const hasPermissiveCallback = script.includes('permissive_verify_cb');
      expect(hasVerifyOk || hasPermissiveCallback).toBe(true);
    });

    it('does NOT pass original tm to SSLContext.init', () => {
      // The fixed version should use [TrustManager.$new()], not the original tm parameter
      expect(script).not.toMatch(/this\.init\(km,\s*tm,\s*sr\)/);
    });

    it('contains NULL safety check for result pointer', () => {
      expect(script).toContain('result.isNull');
    });
  });

  describe('All 8 scripts - basic generation', () => {
    const allTemplates = registry.listAll();

    it('registry contains exactly 8 templates', () => {
      expect(allTemplates).toHaveLength(8);
    });

    for (const template of registry.listAll()) {
      describe(`${template.name}`, () => {
        const output = template.generate({});

        it('generate({}) returns non-empty string', () => {
          expect(typeof output).toBe('string');
          expect(output.trim().length).toBeGreaterThan(0);
        });

        it('contains send() call for reporting', () => {
          expect(output).toContain('send(');
        });

        it('is wrapped in IIFE', () => {
          expect(output).toContain('(function()');
        });
      });
    }
  });

  describe('Injection safety - class_enumeration', () => {
    const template = registry.get('class_enumeration')!;

    it('escapes injected filter containing single quotes and parens', () => {
      const maliciousFilter = "'); process.exit(1); ('";
      const output = template.generate({ filter: maliciousFilter });

      // Raw injection payload must not appear unescaped
      expect(output).not.toContain("'); process.exit(1); ('");
      // The single quotes should be escaped
      expect(output).toContain("\\'");
    });
  });

  describe('Injection safety - method_hook', () => {
    const template = registry.get('method_hook')!;

    it('escapes injected class_name containing single quotes', () => {
      const output = template.generate({
        class_name: "a'; malicious(); '",
        method_name: 'test',
      });

      // Raw unescaped single quotes from injection must not appear
      expect(output).not.toContain("a'; malicious(); '");
      // Escaped quotes should be present instead
      expect(output).toContain("\\'");
    });
  });

  describe('Runtime integration - scripts using hookNative', () => {
    const runtimeScripts = ['network_inspector', 'filesystem_monitor', 'crypto_monitor', 'keychain_prefs', 'root_jailbreak_bypass'];

    for (const name of runtimeScripts) {
      describe(`${name}`, () => {
        const template = registry.get(name)!;
        const output = template.generate({});

        it('includes frida-runtime preamble', () => {
          expect(output).toContain('_hookStats');
          expect(output).toContain('hookNative');
        });

        it('uses hookNative for native hooks', () => {
          expect(output).toContain('hookNative(');
        });

        it('calls reportSummary at the end', () => {
          expect(output).toContain(`reportSummary('${name}')`);
        });
      });
    }
  });

  describe('Non-runtime scripts should not contain hookNative', () => {
    const nonRuntimeScripts = ['ssl_pinning_bypass', 'class_enumeration', 'method_hook'];

    for (const name of nonRuntimeScripts) {
      it(`${name} does not include hookNative`, () => {
        const template = registry.get(name)!;
        const output = template.generate({});
        expect(output).not.toContain('hookNative(');
      });
    }
  });

  describe('Injection safety - filesystem_monitor', () => {
    const template = registry.get('filesystem_monitor')!;

    it('escapes injected filter_path containing single quotes and parens', () => {
      const maliciousPath = "'); evil(); ('";
      const output = template.generate({ filter_path: maliciousPath });

      // Raw injection payload must not appear unescaped
      expect(output).not.toContain("'); evil(); ('");
      // Escaped quotes should be present
      expect(output).toContain("\\'");
    });
  });
});
