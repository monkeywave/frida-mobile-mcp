/**
 * Test-only harness for the find_secrets_in_memory AGENT source: runs SECRET_SCAN_SOURCE in a node
 * `vm` context against a fake, deterministic process memory map, so the in-agent scanner can be
 * checked (and benchmarked) without a device.
 */
import vm from 'node:vm';
import { AES_SBOX } from '../../src/helpers/secret-recognizers.js';

// ---------- deterministic synthetic memory ----------

/** xorshift32 PRNG — deterministic across runs and platforms. */
export function prng(seed: number): () => number {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13; s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5; s >>>= 0;
    return s & 0xff;
  };
}

const RC = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d];
const subWord = (w: number) =>
  ((AES_SBOX[(w >>> 24) & 0xff] << 24) | (AES_SBOX[(w >>> 16) & 0xff] << 16) | (AES_SBOX[(w >>> 8) & 0xff] << 8) | AES_SBOX[w & 0xff]) >>> 0;
const rotWord = (w: number) => (((w << 8) | (w >>> 24)) & 0xffffffff) >>> 0;
const beWord = (b: Uint8Array, p: number) => ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;
const putBe = (b: Uint8Array, p: number, w: number) => {
  b[p] = (w >>> 24) & 0xff; b[p + 1] = (w >>> 16) & 0xff; b[p + 2] = (w >>> 8) & 0xff; b[p + 3] = w & 0xff;
};

export function expandAes(key: Uint8Array): Uint8Array {
  const nk = key.length / 4;
  const total = 4 * (nk + 7);
  const w: number[] = [];
  for (let i = 0; i < nk; i++) w[i] = beWord(key, 4 * i);
  for (let i = nk; i < total; i++) {
    let temp = w[i - 1];
    if (i % nk === 0) temp = (subWord(rotWord(temp)) ^ ((RC[i / nk - 1] << 24) >>> 0)) >>> 0;
    else if (nk > 6 && i % nk === 4) temp = subWord(temp);
    w[i] = (w[i - nk] ^ temp) >>> 0;
  }
  const out = new Uint8Array(total * 4);
  w.forEach((v, i) => putBe(out, 4 * i, v));
  return out;
}

function gmul(a: number, b: number): number {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}
function invMixWord(w: number): number {
  const a = [(w >>> 24) & 0xff, (w >>> 16) & 0xff, (w >>> 8) & 0xff, w & 0xff];
  const m = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]];
  const b = m.map((row) => row.reduce((acc, k, i) => acc ^ gmul(a[i], k), 0));
  return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
}
/** Equivalent-inverse (decryption) schedule built from an encryption schedule. */
export function toDecryptionSchedule(enc: Uint8Array, nk: number): Uint8Array {
  const nr = nk + 6;
  const dec = new Uint8Array(enc.length);
  for (let r = 0; r <= nr; r++) {
    for (let c = 0; c < 4; c++) {
      let w = beWord(enc, (4 * (nr - r) + c) * 4);
      if (r !== 0 && r !== nr) w = invMixWord(w);
      putBe(dec, (4 * r + c) * 4, w);
    }
  }
  return dec;
}

export function permutation(rand: () => number): Uint8Array {
  const p = new Uint8Array(256);
  for (let i = 0; i < 256; i++) p[i] = i;
  for (let i = 255; i > 0; i--) {
    const j = (rand() | (rand() << 8)) % (i + 1);
    [p[i], p[j]] = [p[j], p[i]];
  }
  return p;
}
export function int32Le(perm: Uint8Array): Uint8Array {
  const out = new Uint8Array(1024);
  perm.forEach((v, i) => { out[i * 4] = v; });
  return out;
}
const ascii = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));
export function chachaState(constant: string, keyLen: number, rand: () => number): Uint8Array {
  const st = new Uint8Array(64);
  st.set(ascii(constant), 0);
  for (let i = 0; i < 48; i++) st[16 + i] = i < keyLen ? rand() : 0;
  return st;
}
function salsaState(rand: () => number): Uint8Array {
  const st = new Uint8Array(64);
  for (let i = 0; i < 64; i++) st[i] = rand();
  const sigma = ascii('expand 32-byte k');
  [0, 5, 10, 15].forEach((w, k) => st.set(sigma.subarray(k * 4, k * 4 + 4), w * 4));
  return st;
}

/** The scanner's effective chunk advance (CHUNK - OVERLAP); structures planted around it straddle. */
export const CHUNK_STEP = 1024 * 1024 - 1024;

/**
 * Builds a heap-like buffer: zero pages, low-entropy text, random noise, and every recognized
 * structure planted at fixed offsets — several deliberately straddling chunk boundaries.
 */
export function buildHeapImage(size: number, seed: number): Uint8Array {
  const rand = prng(seed);
  const buf = new Uint8Array(size);
  // Background: alternating 64 KiB bands of zeros / text / pointer-ish / noise.
  for (let band = 0; band * 65536 < size; band++) {
    const start = band * 65536;
    const end = Math.min(size, start + 65536);
    const kind = band % 4;
    for (let i = start; i < end; i++) {
      if (kind === 1) buf[i] = 0x61 + (i % 23);
      else if (kind === 2) buf[i] = (i & 7) < 4 ? rand() & 0x0f : 0;
      else if (kind === 3) buf[i] = rand();
    }
  }
  const plant = (off: number, bytes: Uint8Array) => { if (off >= 0 && off + bytes.length <= size) buf.set(bytes, off); };
  const keys = [16, 24, 32].map((n) => Uint8Array.from({ length: n }, () => rand()));
  let at = 4096;
  const place = (bytes: Uint8Array, gap = 8192) => { plant(at, bytes); at += bytes.length + gap; };
  place(permutation(rand));
  place(int32Le(permutation(rand)));
  for (const k of keys) place(expandAes(k));
  for (const k of keys) place(toDecryptionSchedule(expandAes(k), k.length / 4));
  place(chachaState('expand 32-byte k', 32, rand));
  place(chachaState('expand 16-byte k', 16, rand));
  place(salsaState(rand));
  place(ascii('-----BEGIN RSA PRIVATE KEY-----\nMIIEow'));
  place(Uint8Array.from([0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01]));
  place(ascii(' eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U '));
  // Straddlers: each structure starts a little before a chunk boundary.
  for (let k = 1; k * CHUNK_STEP < size; k++) {
    const b = k * CHUNK_STEP;
    plant(b - 1000, int32Le(permutation(rand)));
    plant(b - 100, permutation(rand));
    plant(b - 40, expandAes(keys[k % 3]));
    plant(b - 30 + 2048, ascii('xx eyJhbGciOiJub25lIn0.eyJpc3MiOiJmcmlkYSJ9. yy'));
    plant(b - 8 + 4096, chachaState('expand 32-byte k', 32, rand));
  }
  return buf;
}

// ---------- fake Frida agent runtime ----------

interface FakeRange { base: bigint; bytes: Uint8Array | null; module?: string }

class FakePtr {
  constructor(readonly value: bigint, private readonly mem: FakeMemory) {}
  add(n: number | FakePtr): FakePtr { return new FakePtr(this.value + BigInt(typeof n === 'number' ? n : n.value), this.mem); }
  sub(n: number | FakePtr): FakePtr { return new FakePtr(this.value - BigInt(typeof n === 'number' ? n : n.value), this.mem); }
  // Like NativePointer: toString() is '0x'-prefixed, toString(radix) is the bare digits.
  toString(radix?: number): string { return radix === undefined ? '0x' + this.value.toString(16) : this.value.toString(radix); }
  readByteArray(len: number): ArrayBuffer { return this.mem.read(this.value, len); }
}

export class FakeMemory {
  readonly reads: number[] = [];
  constructor(readonly ranges: FakeRange[]) {}
  ptr(v: bigint): FakePtr { return new FakePtr(v, this); }
  read(addr: bigint, len: number): ArrayBuffer {
    const r = this.ranges.find((x) => addr >= x.base && addr < x.base + BigInt(x.bytes?.length ?? 0x1000));
    if (!r || r.bytes === null) throw new Error('access violation');
    const off = Number(addr - r.base);
    this.reads.push(len);
    return r.bytes.slice(off, off + len).buffer;
  }
  rangeOf(r: FakeRange) { return { base: this.ptr(r.base), size: r.bytes?.length ?? 0x1000, protection: 'rw-' }; }
}

export interface ScanOptions {
  recognizers: string[];
  scope: string;
  maxBytes: number;
  minEntropy: number;
  maxEntropyHits: number;
  limit: number;
  entropyLens: number[];
  aesSbox: readonly number[];
}

export const ALL = ['rc4_sbox', 'aes_key_schedule', 'chacha_key', 'salsa_key', 'high_entropy_key', 'pem_der', 'jwt'];

export function defaultOptions(over: Partial<ScanOptions> = {}): ScanOptions {
  return {
    recognizers: ALL, scope: 'heap', maxBytes: 16 * 1024 * 1024, minEntropy: 3.5,
    maxEntropyHits: 15, limit: 100, entropyLens: [16, 24, 32], aesSbox: AES_SBOX, ...over,
  };
}

/** Loads `source` into a vm context wired to `mem` and returns its rpc.exports + context globals. */
export function loadScanner(source: string, mem: FakeMemory, options: ScanOptions) {
  const modules = mem.ranges.filter((r) => r.module).map((r) => ({ name: r.module!, base: mem.ptr(r.base), size: r.bytes?.length ?? 0 }));
  const ctx: Record<string, unknown> = {
    __FRIDA_MCP__: { options },
    rpc: { exports: {} as Record<string, () => Promise<unknown>> },
    ptr: (v: unknown) => (v instanceof FakePtr ? v : mem.ptr(BigInt(v as string))),
    DebugSymbol: { fromAddress: () => null },
    Process: {
      enumerateRanges: () => mem.ranges.map((r) => mem.rangeOf(r)),
      findModuleByName: (n: string) => modules.find((m) => m.name === n) ?? null,
      findModuleByAddress: (p: FakePtr) =>
        modules.find((m) => p.value >= m.base.value && p.value < m.base.value + BigInt(m.size)) ?? null,
    },
    Module: { findGlobalExportByName: () => null, findExportByName: () => null },
  };
  vm.createContext(ctx);
  vm.runInContext(source, ctx);
  return ctx as typeof ctx & { rpc: { exports: { scan: () => Promise<unknown> } } };
}

/** Standard memory map: two heap ranges, one module-backed range, one unreadable range. */
export function standardMemory(): FakeMemory {
  return new FakeMemory([
    { base: 0x7000_0000n, bytes: buildHeapImage(3 * 1024 * 1024 + 4321, 0x5eed) },
    { base: 0x7100_0000n, bytes: null },
    { base: 0x7200_0000n, bytes: buildHeapImage(600 * 1024, 0xbeef), module: 'libtarget.so' },
    { base: 0x7300_0000n, bytes: buildHeapImage(70 * 1024, 0x1234) },
  ]);
}

/** Option sets the golden test pins: defaults plus each early-stop / scope / cap path. */
export const GOLDEN_CASES: Record<string, Partial<ScanOptions>> = {
  default: {},
  precise_only: { recognizers: ['rc4_sbox', 'aes_key_schedule', 'chacha_key', 'salsa_key', 'pem_der', 'jwt'] },
  entropy_wide: { recognizers: ['high_entropy_key'], maxEntropyHits: 400, limit: 1000, minEntropy: 3.9 },
  entropy_low_threshold: { recognizers: ['high_entropy_key'], maxEntropyHits: 300, limit: 1000, minEntropy: 2.5, entropyLens: [16, 32] },
  limit_stop: { limit: 7 },
  max_bytes_stop: { maxBytes: 1500 * 1024 },
  module_scope: { scope: 'libtarget.so' },
  module_missing: { scope: 'libnope.so' },
  all_scope: { scope: 'all', recognizers: ['rc4_sbox', 'jwt', 'pem_der'] },
  // Uncapped: every entropy window across the whole map (pinned by count + sha256, not inline).
  entropy_exhaustive: { recognizers: ['high_entropy_key'], maxEntropyHits: 1e9, limit: 1e9, minEntropy: 3.0 },
};

/** Cases whose output is too large to inline in the golden file. */
export const HASHED_CASES = new Set(['entropy_exhaustive']);
