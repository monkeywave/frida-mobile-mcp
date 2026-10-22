import { describe, it, expect } from 'vitest';
import { buildPattern } from '../../src/helpers/pattern-builder.js';

const SIGMA = Uint8Array.from(Buffer.from('expand 32-byte k', 'latin1'));
const TAU = Uint8Array.from(Buffer.from('expand 16-byte k', 'latin1'));
const sigmaHex = toHex(SIGMA);

/** Build a window: context-before, secret, context-after; returns bytes + the secret offset. */
function window(before: Uint8Array, secret: Uint8Array, after: Uint8Array): { bytes: Uint8Array; offset: number } {
  const bytes = new Uint8Array(before.length + secret.length + after.length);
  bytes.set(before, 0);
  bytes.set(secret, before.length);
  bytes.set(after, before.length + secret.length);
  return { bytes, offset: before.length };
}

function fill(len: number, value: number): Uint8Array {
  return new Uint8Array(len).fill(value);
}

/** Distinct, non-repeating bytes (0,1,2,..) so an anchor over them is "unique". */
function ramp(len: number, start = 0): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = (start + i) & 0xff;
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => ('0' + b.toString(16)).slice(-2))
    .join(' ');
}

describe('buildPattern — chacha_key', () => {
  it('anchors on the sigma constant 16 bytes before the key', () => {
    const { bytes, offset } = window(SIGMA, ramp(32), fill(16, 0));
    const d = buildPattern({ windowBytes: bytes, secretOffsetInWindow: offset, size: 32, type: 'chacha_key' });

    expect(d.anchor.pattern).toBe(sigmaHex);
    expect(d.offset_to_key).toBe(16);
    expect(d.key_len).toBe(32);
    expect(d.anchor.bytes_before_key).toBe(16);
    // Fixed constant: the scan pattern is just the 16 constant bytes (no key wildcards).
    expect(d.scan_memory_pattern).toBe(sigmaHex);
    expect(d.confidence).toBe('high');
    expect(d.fritap.ms_agent_anchor.slot).toEqual({ data: 16, len: 32, label: 'CHACHA_KEY' });
  });

  it('recognises the tau (128-bit) constant', () => {
    const { bytes, offset } = window(TAU, ramp(16), fill(8, 0));
    const d = buildPattern({ windowBytes: bytes, secretOffsetInWindow: offset, size: 16, type: 'chacha_key' });
    expect(d.anchor.pattern).toBe(toHex(TAU));
    expect(d.confidence).toBe('high');
  });

  it('falls back to the known sigma constant (medium) when it is not in the window', () => {
    const { bytes, offset } = window(fill(16, 0xaa), ramp(32), fill(16, 0));
    const d = buildPattern({ windowBytes: bytes, secretOffsetInWindow: offset, size: 32, type: 'chacha_key' });
    expect(d.anchor.pattern).toBe(sigmaHex);
    expect(d.offset_to_key).toBe(16);
    expect(d.confidence).toBe('medium');
  });
});

describe('buildPattern — pem_der / jwt', () => {
  it('anchors a PEM blob on the "-----BEGIN" prefix', () => {
    const pem = Uint8Array.from(Buffer.from('-----BEGIN RSA PRIVATE KEY-----', 'latin1'));
    const { bytes, offset } = window(fill(32, 0x20), pem, fill(0, 0));
    const d = buildPattern({ windowBytes: bytes, secretOffsetInWindow: offset, size: pem.length, type: 'pem_der' });

    expect(d.anchor.pattern).toBe(toHex(Uint8Array.from(Buffer.from('-----BEGIN', 'latin1'))));
    expect(d.offset_to_key).toBe(0);
    expect(d.confidence).toBe('high');
    expect(d.scan_memory_pattern).toBe(d.anchor.pattern);
  });

  it('anchors a JWT on the "eyJ" prefix', () => {
    const jwt = Uint8Array.from(Buffer.from('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig', 'latin1'));
    const { bytes, offset } = window(fill(8, 0x2e), jwt, fill(0, 0));
    const d = buildPattern({ windowBytes: bytes, secretOffsetInWindow: offset, size: jwt.length, type: 'jwt' });
    expect(d.anchor.pattern).toBe(toHex(Uint8Array.from(Buffer.from('eyJ', 'latin1'))));
    expect(d.confidence).toBe('high');
  });
});

describe('buildPattern — aes/unknown structural anchor', () => {
  it('uses a constant run adjacent to the key as the anchor with the right offset', () => {
    const zeros = fill(16, 0x00);
    const key = ramp(16, 0x40);
    const { bytes, offset } = window(new Uint8Array([...fill(8, 0xcc), ...zeros]), key, fill(16, 0x11));
    const d = buildPattern({ windowBytes: bytes, secretOffsetInWindow: offset, size: 16, type: 'aes_key_schedule' });

    expect(d.offset_to_key).toBe(16); // the 16-byte zero run precedes the key
    expect(d.anchor.bytes_before_key).toBe(16);
    expect(d.anchor.pattern).toBe(toHex(zeros));
    // Derived anchor: scan pattern spells out the key region as wildcards ("xx ?? xx").
    expect(d.scan_memory_pattern.startsWith(toHex(zeros))).toBe(true);
    expect(d.scan_memory_pattern).toContain('??');
    expect(d.scan_memory_pattern.split(' ').filter((t) => t === '??')).toHaveLength(16);
    expect(d.confidence).toBe('medium');
  });

  it('reaches high confidence for a long, non-repeating anchor', () => {
    const { bytes, offset } = window(ramp(12, 0x30), ramp(16, 0x80), fill(8, 0));
    const d = buildPattern({ windowBytes: bytes, secretOffsetInWindow: offset, size: 16 });
    expect(d.confidence).toBe('high');
    expect(d.anchor.bytes_before_key).toBeGreaterThanOrEqual(8);
  });

  it('is low confidence when almost no stable bytes precede the key', () => {
    const { bytes, offset } = window(new Uint8Array([0x12, 0x9f]), ramp(16), fill(8, 0));
    const d = buildPattern({ windowBytes: bytes, secretOffsetInWindow: offset, size: 16, type: 'aes_key_schedule' });
    expect(d.confidence).toBe('low');
  });
});

describe('buildPattern — rc4_sbox', () => {
  it('caps confidence at medium and notes the native rc4 engine', () => {
    const zeros = fill(16, 0x00);
    const { bytes, offset } = window(zeros, ramp(256), fill(0, 0));
    const d = buildPattern({ windowBytes: bytes, secretOffsetInWindow: offset, size: 256, type: 'rc4_sbox' });
    expect(d.confidence).toBe('medium'); // would score high by length, clamped for rc4
    expect(d.note.toLowerCase()).toContain('rc4');
    expect(d.key_len).toBe(256);
  });
});

describe('buildPattern — module addressing & fritap entries', () => {
  it('computes the anchor rva and a fritap offsets entry when the module is known', () => {
    const { bytes, offset } = window(SIGMA, ramp(32), fill(16, 0));
    const d = buildPattern({
      windowBytes: bytes,
      secretOffsetInWindow: offset,
      size: 32,
      type: 'chacha_key',
      address: 'libfoo.so+0x1000',
      module: 'libfoo.so',
      moduleOffset: 0x1000,
    });

    expect(d.secret.address).toBe('libfoo.so+0x1000');
    expect(d.anchor.module).toBe('libfoo.so');
    expect(d.anchor.rva).toBe('libfoo.so+0xff0'); // key offset 0x1000 minus the 16-byte anchor
    expect(d.fritap.offsets_entry).toEqual({ 'libfoo.so': { CHACHA_KEY: { address: '0x1000', absolute: false } } });
  });

  it('honours an explicit label and omits module fields when unknown', () => {
    const { bytes, offset } = window(SIGMA, ramp(32), fill(16, 0));
    const d = buildPattern({ windowBytes: bytes, secretOffsetInWindow: offset, size: 32, type: 'chacha_key', label: 'MY_KEY' });
    expect(d.fritap.ms_agent_anchor.keylog_labels).toEqual(['MY_KEY']);
    expect(d.fritap.offsets_entry).toBeUndefined();
    expect(d.anchor.rva).toBeUndefined();
  });
});
