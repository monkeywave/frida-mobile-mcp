import { describe, it, expect, beforeAll } from 'vitest';
import { buildResult, formatToolResponse } from '../../src/helpers/result-builder.js';
import { ResponseFormat } from '../../src/constants.js';
import { initState } from '../../src/state.js';
import { loadConfig } from '../../src/config.js';

// A small response limit makes oversize responses easy to trigger deterministically.
const LIMIT = 2_000;

beforeAll(() => {
  initState(loadConfig({ mobileMcp: { enabled: false }, maxResponseChars: LIMIT } as any));
});

/** A result whose `modules` array is far larger than the character limit. */
function bigResult() {
  const modules = Array.from({ length: 400 }, (_, i) => ({
    name: `libmodule_${i}.so`,
    path: `/system/lib64/libmodule_${i}.so`,
  }));
  return buildResult({ modules_count: modules.length, modules });
}

describe('formatToolResponse truncation', () => {
  it('JSON output stays parseable when the response exceeds the limit', () => {
    const { content, structuredContent } = formatToolResponse(bigResult(), ResponseFormat.JSON);
    const text = content[0].text;
    expect(text.length).toBeLessThanOrEqual(LIMIT);
    // The whole point: never a sliced, unparseable JSON body.
    const parsed = JSON.parse(text);
    expect(parsed.result.modules.length).toBeLessThan(400);
    expect(parsed.limitations.join(' ')).toMatch(/truncated/i);
    // structuredContent always carries the full, untrimmed data.
    expect((structuredContent!.result as any).modules.length).toBe(400);
  });

  it('does not mutate the caller\'s original result (structuredContent stays complete)', () => {
    const result = bigResult();
    formatToolResponse(result, ResponseFormat.JSON);
    expect((result.result as any).modules.length).toBe(400);
  });

  it('TOON output is returned within the limit with a truncation note', () => {
    const { content } = formatToolResponse(bigResult(), ResponseFormat.TOON);
    expect(content[0].text.length).toBeLessThanOrEqual(LIMIT);
    expect(content[0].text).toMatch(/truncated/i);
  });

  it('trims several large arrays together instead of emptying the result', () => {
    // Mirrors discover_crypto: multiple big arrays. The old single-array trim fell back to an
    // empty envelope; now each array is shrunk so real data survives in the text channel.
    const mk = (p: string) => Array.from({ length: 300 }, (_, i) => ({ v: `${p}_${i}_padding_padding` }));
    const result = buildResult({ java: mk('j'), native: mk('n'), candidates: mk('c') });
    const { content } = formatToolResponse(result, ResponseFormat.JSON);
    const text = content[0].text;
    expect(text.length).toBeLessThanOrEqual(LIMIT);
    const parsed = JSON.parse(text);
    // Every array kept some elements (none emptied to fall back to the minimal envelope).
    expect(parsed.result.java.length).toBeGreaterThan(0);
    expect(parsed.result.native.length).toBeGreaterThan(0);
    expect(parsed.result.candidates.length).toBeGreaterThan(0);
    expect(parsed.limitations.join(' ')).toMatch(/truncated/i);
  });

  it('leaves a small response untouched', () => {
    const small = buildResult({ ok: true, items: [1, 2, 3] });
    const { content } = formatToolResponse(small, ResponseFormat.JSON);
    const parsed = JSON.parse(content[0].text);
    expect(parsed.result).toEqual({ ok: true, items: [1, 2, 3] });
    expect(parsed.limitations).toEqual([]);
  });
});
