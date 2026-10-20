import { describe, it, expect } from 'vitest';
import { parseTarget, formatModuleOffset, RESOLVE_TARGET_SNIPPET } from '../../src/agent/address.js';
import { findRemovedApis } from '../../src/agent/lint.js';

describe('parseTarget', () => {
  it('parses module!symbol as an export', () => {
    expect(parseTarget('libssl.so!SSL_read')).toEqual({ kind: 'export', module: 'libssl.so', symbol: 'SSL_read' });
  });

  it('parses module+0xOFFSET as a module-relative offset', () => {
    expect(parseTarget('libfoo.so+0x1234')).toEqual({ kind: 'offset', module: 'libfoo.so', offset: '0x1234' });
  });

  it('normalises decimal and upper-case hex offsets', () => {
    expect(parseTarget('libfoo.so+4660')).toEqual({ kind: 'offset', module: 'libfoo.so', offset: '0x1234' });
    expect(parseTarget('libfoo.so+0X1AbC')).toEqual({ kind: 'offset', module: 'libfoo.so', offset: '0x1abc' });
  });

  it('keeps a + inside the module name (libc++.so)', () => {
    expect(parseTarget('libc++.so+0x10')).toEqual({ kind: 'offset', module: 'libc++.so', offset: '0x10' });
    expect(parseTarget('libc++.so')).toEqual({ kind: 'global', symbol: 'libc++.so' });
  });

  it('parses a bare 0x address as absolute', () => {
    expect(parseTarget('0x7FFF12345678')).toEqual({ kind: 'absolute', address: '0x7fff12345678' });
  });

  it('parses a bare name as a global export and "!name" too', () => {
    expect(parseTarget('open')).toEqual({ kind: 'global', symbol: 'open' });
    expect(parseTarget('!open')).toEqual({ kind: 'global', symbol: 'open' });
  });

  it('trims whitespace and rejects empty specs', () => {
    expect(parseTarget('  libc.so!open ')).toEqual({ kind: 'export', module: 'libc.so', symbol: 'open' });
    expect(() => parseTarget('')).toThrow('cannot be empty');
    expect(() => parseTarget('   ')).toThrow('cannot be empty');
  });
});

describe('formatModuleOffset', () => {
  it('formats numbers, bigints and strings as module+0x..', () => {
    expect(formatModuleOffset('libfoo.so', 0x1234)).toBe('libfoo.so+0x1234');
    expect(formatModuleOffset('libfoo.so', 0x1234n)).toBe('libfoo.so+0x1234');
    expect(formatModuleOffset('libfoo.so', '4660')).toBe('libfoo.so+0x1234');
    expect(formatModuleOffset('libfoo.so', '0X1234')).toBe('libfoo.so+0x1234');
  });

  it('rejects negative or malformed offsets', () => {
    expect(() => formatModuleOffset('x', -1)).toThrow('non-negative');
    expect(() => formatModuleOffset('x', 'zz')).toThrow('Invalid offset');
  });
});

// ---------------------------------------------------------------------------
// In-agent snippet: executed against a tiny fake of the Frida globals it touches.
// ---------------------------------------------------------------------------

class FakePointer {
  constructor(readonly value: bigint) {}
  add(rhs: FakePointer | number): FakePointer { return new FakePointer(this.value + BigInt(rhs instanceof FakePointer ? rhs.value : rhs)); }
  sub(rhs: FakePointer | number): FakePointer { return new FakePointer(this.value - BigInt(rhs instanceof FakePointer ? rhs.value : rhs)); }
  isNull(): boolean { return this.value === 0n; }
  compare(rhs: FakePointer): number { return this.value < rhs.value ? -1 : this.value > rhs.value ? 1 : 0; }
  toString(radix?: number): string { return radix === 16 ? this.value.toString(16) : `0x${this.value.toString(16)}`; }
}

const LIBC_BASE = 0x7f00000000n;
const OPEN_ADDR = LIBC_BASE + 0x1000n;

const fakeModule = {
  name: 'libc.so',
  base: new FakePointer(LIBC_BASE),
  size: 0x100000,
  findExportByName: (name: string) => (name === 'open' ? new FakePointer(OPEN_ADDR) : null),
  findSymbolByName: (name: string) => (name === 'static_fn' ? new FakePointer(LIBC_BASE + 0x2000n) : null),
};

const fakeGlobals = {
  ptr: (v: string | FakePointer) => (v instanceof FakePointer ? v : new FakePointer(BigInt(v))),
  Process: {
    findModuleByName: (name: string) => (name === 'libc.so' ? fakeModule : null),
    findModuleByAddress: (p: FakePointer) => (p.value >= LIBC_BASE && p.value < LIBC_BASE + 0x100000n ? fakeModule : null),
  },
  Module: { findGlobalExportByName: (name: string) => (name === 'open' ? new FakePointer(OPEN_ADDR) : null) },
  DebugSymbol: {
    fromAddress: (p: FakePointer) => ({ name: p.value === OPEN_ADDR ? 'open' : null }),
    fromName: (name: string) => (name === 'dbg_only' ? { address: new FakePointer(LIBC_BASE + 0x3000n) } : null),
  },
  Thread: { backtrace: () => [new FakePointer(OPEN_ADDR), new FakePointer(0x1234n)] },
  Backtracer: { ACCURATE: 'accurate', FUZZY: 'fuzzy' },
};

type SnippetApi = {
  parseTargetSpec: (spec: unknown) => Record<string, string> | null;
  resolveTarget: (spec: unknown) => FakePointer | null;
  describeAddress: (p: FakePointer | string) => Record<string, string | null>;
  formatFrame: (p: FakePointer) => string;
  symbolizeBacktrace: (ctx: unknown, limit?: number) => string[];
};

function loadSnippet(): SnippetApi {
  const names = Object.keys(fakeGlobals);
  const factory = new Function(
    ...names,
    `${RESOLVE_TARGET_SNIPPET}\nreturn { parseTargetSpec, resolveTarget, describeAddress, formatFrame, symbolizeBacktrace };`
  );
  return factory(...names.map((n) => (fakeGlobals as Record<string, unknown>)[n])) as SnippetApi;
}

describe('RESOLVE_TARGET_SNIPPET', () => {
  const api = loadSnippet();

  it('does not use any Frida API removed in 17', () => {
    expect(findRemovedApis(RESOLVE_TARGET_SNIPPET)).toEqual([]);
  });

  it('agrees with the host parser on every notation', () => {
    for (const spec of ['libssl.so!SSL_read', 'libfoo.so+0x1234', 'libc++.so+0x10', '0x7fff', 'open', '!open', 'libc++.so']) {
      const host = parseTarget(spec);
      const agent = api.parseTargetSpec(spec)!;
      expect(agent.kind).toBe(host.kind);
      expect(agent.module).toBe(host.module);
      expect(agent.symbol).toBe(host.symbol);
    }
    expect(api.parseTargetSpec('')).toBeNull();
  });

  it('resolves exports, module offsets, absolute addresses and globals', () => {
    expect(api.resolveTarget('libc.so!open')!.toString()).toBe('0x7f00001000');
    expect(api.resolveTarget('libc.so+0x1000')!.toString()).toBe('0x7f00001000');
    expect(api.resolveTarget('libc.so+4096')!.toString()).toBe('0x7f00001000');
    expect(api.resolveTarget('0x7f00001000')!.toString()).toBe('0x7f00001000');
    expect(api.resolveTarget('open')!.toString()).toBe('0x7f00001000');
    expect(api.resolveTarget(parseTarget('libc.so!open'))!.toString()).toBe('0x7f00001000');
  });

  it('falls back to module symbols and DebugSymbol for non-exported names', () => {
    expect(api.resolveTarget('libc.so!static_fn')!.toString()).toBe('0x7f00002000');
    expect(api.resolveTarget('dbg_only')!.toString()).toBe('0x7f00003000');
  });

  it('returns null for unknown modules, symbols and the null pointer', () => {
    expect(api.resolveTarget('libnope.so!open')).toBeNull();
    expect(api.resolveTarget('libnope.so+0x10')).toBeNull();
    expect(api.resolveTarget('libc.so!missing')).toBeNull();
    expect(api.resolveTarget('missing')).toBeNull();
    expect(api.resolveTarget('0x0')).toBeNull();
    expect(api.resolveTarget(null)).toBeNull();
  });

  it('describes an address as module+offset with the DebugSymbol name', () => {
    expect(api.describeAddress(new FakePointer(OPEN_ADDR))).toEqual({
      address: '0x7f00001000',
      module: 'libc.so',
      offset: '0x1000',
      symbol: 'open',
      rva: 'libc.so+0x1000',
    });
    expect(api.describeAddress('0x1234')).toEqual({ address: '0x1234', module: null, offset: null, symbol: null, rva: null });
  });

  it('formats backtrace frames as module+0xoff (symbol)', () => {
    expect(api.formatFrame(new FakePointer(OPEN_ADDR))).toBe('libc.so+0x1000 (open)');
    expect(api.formatFrame(new FakePointer(LIBC_BASE + 0x20n))).toBe('libc.so+0x20');
    expect(api.formatFrame(new FakePointer(0x1234n))).toBe('0x1234');
    expect(api.symbolizeBacktrace({}, 1)).toEqual(['libc.so+0x1000 (open)']);
    expect(api.symbolizeBacktrace({})).toEqual(['libc.so+0x1000 (open)', '0x1234']);
  });
});
