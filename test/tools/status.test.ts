import { describe, it, expect } from 'vitest';
import { getScriptRegistry } from '../../src/scripts/registry.js';

// Test the structural aspects we can verify without mocking Frida
describe('get_status tool structure', () => {
  it('script registry is available for status reporting', () => {
    const registry = getScriptRegistry();
    expect(registry.listAll().length).toBe(8);
  });
});
