import { describe, it, expect } from 'vitest';
import {
  compareFritapVersions,
  decidePipFritapUsage,
  isSupportedFritapAbi,
  MIN_PIP_FRITAP_VERSION,
  parseFritapVersion,
  SUPPORTED_FRITAP_AGENT_ABI_VERSIONS,
} from '../../src/fritap/compat.js';
import { describeAbiMismatch } from '../../src/fritap/tool.js';

describe('agent ABI acceptance', () => {
  it('supports ABI 2 (friTap 2.5.x) and ABI 3 (friTap >= 2.6.3)', () => {
    expect(SUPPORTED_FRITAP_AGENT_ABI_VERSIONS).toEqual([2, 3]);
    expect(isSupportedFritapAbi(2)).toBe(true);
    expect(isSupportedFritapAbi(3)).toBe(true);
    expect(isSupportedFritapAbi(1)).toBe(false);
    expect(isSupportedFritapAbi(4)).toBe(false);
  });

  it('adds no limitation for supported or unknown ABIs', () => {
    expect(describeAbiMismatch(2)).toBeNull();
    expect(describeAbiMismatch(3)).toBeNull();
    expect(describeAbiMismatch(null)).toBeNull();
  });

  it('warns for an ABI outside the supported set', () => {
    expect(describeAbiMismatch(4)).toMatch(/ABI 4 is outside the supported set \(2, 3\)/);
  });
});

describe('friTap version parsing', () => {
  it('parses plain, v-prefixed, short and post-release versions', () => {
    expect(parseFritapVersion('2.6.5')).toEqual([2, 6, 5]);
    expect(parseFritapVersion('v2.6.5')).toEqual([2, 6, 5]);
    expect(parseFritapVersion('2.6')).toEqual([2, 6, 0]);
    expect(parseFritapVersion('1.3.4.1')).toEqual([1, 3, 4]);
    expect(parseFritapVersion('2.6.5.post1')).toEqual([2, 6, 5]);
    expect(parseFritapVersion('unknown')).toBeNull();
  });

  it('compares versions numerically', () => {
    expect(compareFritapVersions('2.10.0', '2.9.9')).toBeGreaterThan(0);
    expect(compareFritapVersions('1.9.9', '2.0.0')).toBeLessThan(0);
    expect(compareFritapVersions('2.0.0', '2.0.0')).toBe(0);
    expect(compareFritapVersions('main', '2.0.0')).toBeNull();
  });
});

describe('pip-installed friTap version gate', () => {
  it('uses friTap >= 2.0.0 without a warning', () => {
    expect(MIN_PIP_FRITAP_VERSION).toBe('2.0.0');
    expect(decidePipFritapUsage('2.0.0')).toEqual({ use: true, warning: null });
    expect(decidePipFritapUsage('2.5.2')).toEqual({ use: true, warning: null });
    expect(decidePipFritapUsage('2.6.5')).toEqual({ use: true, warning: null });
  });

  it('skips Frida 15/16-era releases (< 2.0.0) with a warning', () => {
    for (const old of ['1.3.4.1', '1.0.0', '0.9']) {
      const decision = decidePipFritapUsage(old);
      expect(decision.use).toBe(false);
      expect(decision.warning).toMatch(/older than 2\.0\.0/);
    }
  });

  it('keeps using a package of unknown version but warns', () => {
    for (const unknown of [null, 'unknown', '']) {
      const decision = decidePipFritapUsage(unknown);
      expect(decision.use).toBe(true);
      expect(decision.warning).toMatch(/unknown/);
    }
  });
});
