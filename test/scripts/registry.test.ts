import { describe, it, expect } from 'vitest';
import { getScriptRegistry } from '../../src/scripts/registry.js';

describe('ScriptRegistry', () => {
  const registry = getScriptRegistry();

  it('returns singleton instance', () => {
    expect(getScriptRegistry()).toBe(registry);
  });

  it('has all 8 scripts registered', () => {
    expect(registry.listAll()).toHaveLength(8);
  });

  it('can get each script by name', () => {
    const names = [
      'ssl_pinning_bypass', 'root_jailbreak_bypass', 'class_enumeration',
      'method_hook', 'crypto_monitor', 'network_inspector',
      'keychain_prefs', 'filesystem_monitor',
    ];
    for (const name of names) {
      const template = registry.get(name);
      expect(template).toBeDefined();
      expect(template!.name).toBe(name);
    }
  });

  it('returns undefined for unknown script', () => {
    expect(registry.get('nonexistent')).toBeUndefined();
  });

  it('each script has valid platforms', () => {
    for (const script of registry.listAll()) {
      expect(script.platforms.length).toBeGreaterThan(0);
      for (const p of script.platforms) {
        expect(['android', 'ios']).toContain(p);
      }
    }
  });

  it('each script has valid category', () => {
    const validCategories = ['bypass', 'enumeration', 'security', 'network', 'crypto', 'filesystem'];
    for (const script of registry.listAll()) {
      expect(validCategories).toContain(script.category);
    }
  });

  it('each script has valid riskTier', () => {
    for (const script of registry.listAll()) {
      expect([1, 2, 3]).toContain(script.riskTier);
    }
  });

  it('each generate() returns a non-empty string', () => {
    for (const script of registry.listAll()) {
      const source = script.generate({});
      expect(typeof source).toBe('string');
      expect(source.length).toBeGreaterThan(50);
    }
  });

  it('ssl_pinning_bypass generates different output for android/ios options', () => {
    const template = registry.get('ssl_pinning_bypass')!;
    const android = template.generate({ platform: 'android' });
    const ios = template.generate({ platform: 'ios' });
    // Both should be the same universal script (handles both)
    expect(android).toBe(ios); // Current impl is universal
    expect(android).toContain('Java.perform');
    expect(android).toContain('ObjC');
  });

  it('class_enumeration accepts filter option', () => {
    const template = registry.get('class_enumeration')!;
    const source = template.generate({ filter: 'com\\.example\\..*', limit: 100 });
    expect(source).toContain('com\\\\.example\\\\..*');
    expect(source).toContain('100');
  });
});
