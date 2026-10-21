import { describe, it, expect } from 'vitest';
import { escapeRegExp } from '../../src/helpers/regex.js';

describe('escapeRegExp', () => {
  it('escapes every RegExp metacharacter', () => {
    expect(escapeRegExp('.*+?^${}()|[]\\')).toBe('\\.\\*\\+\\?\\^\\$\\{\\}\\(\\)\\|\\[\\]\\\\');
  });

  it('leaves ordinary characters untouched', () => {
    expect(escapeRegExp('com_example-App1')).toBe('com_example-App1');
  });

  it('produces a pattern that matches the input literally', () => {
    const target = 'com.example.app$Inner(1)+[x]';
    const pattern = new RegExp(escapeRegExp(target));
    expect(pattern.test(target)).toBe(true);
    expect(pattern.test('comXexampleXapp$Inner(1)+[x]')).toBe(false);
  });
});
