import { describe, it, expect } from 'vitest';
import {
  isRc4Sbox,
  isRc4SboxInt32LE,
  shannonEntropy,
  distinctBytes,
  matchesAesSchedule,
  matchesAesDecryptionSchedule,
  aesScheduleBytes,
  chachaKeyLenAt,
  matchesSalsa20StateAt,
  CHACHA_SIGMA,
  CHACHA_TAU,
  findDerKey,
  findPem,
  findJwts,
  AES_SBOX,
} from '../../src/helpers/secret-recognizers.js';

// Independent forward AES key expansion (test-only reference), kept separate from the
// recognizer's recurrence VERIFIER so a hit proves both agree, not that one fed the other.
const RC = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d];
function subWord(w: number): number {
  return ((AES_SBOX[(w >>> 24) & 0xff] << 24) | (AES_SBOX[(w >>> 16) & 0xff] << 16) | (AES_SBOX[(w >>> 8) & 0xff] << 8) | AES_SBOX[w & 0xff]) >>> 0;
}
function rotWord(w: number): number {
  return (((w << 8) | (w >>> 24)) & 0xffffffff) >>> 0;
}
function expandAes(key: Uint8Array): Uint8Array {
  const nk = key.length / 4;
  const nr = nk + 6;
  const total = 4 * (nr + 1);
  const w = new Array<number>(total);
  for (let i = 0; i < nk; i++) w[i] = ((key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3]) >>> 0;
  for (let i = nk; i < total; i++) {
    let temp = w[i - 1];
    if (i % nk === 0) temp = (subWord(rotWord(temp)) ^ ((RC[i / nk - 1] << 24) >>> 0)) >>> 0;
    else if (nk > 6 && i % nk === 4) temp = subWord(temp);
    w[i] = (w[i - nk] ^ temp) >>> 0;
  }
  const out = new Uint8Array(total * 4);
  for (let i = 0; i < total; i++) {
    out[4 * i] = (w[i] >>> 24) & 0xff;
    out[4 * i + 1] = (w[i] >>> 16) & 0xff;
    out[4 * i + 2] = (w[i] >>> 8) & 0xff;
    out[4 * i + 3] = w[i] & 0xff;
  }
  return out;
}

function identityPermutation(): Uint8Array {
  const b = new Uint8Array(256);
  for (let i = 0; i < 256; i++) b[i] = i;
  return b;
}

describe('isRc4Sbox', () => {
  it('accepts the identity permutation (pre-KSA RC4 state)', () => {
    expect(isRc4Sbox(identityPermutation(), 0)).toBe(true);
  });

  it('accepts a shuffled permutation of 0..255', () => {
    const b = identityPermutation();
    // deterministic swap shuffle — still a permutation
    for (let i = 255; i > 0; i--) {
      const j = (i * 73 + 7) % 256;
      const t = b[i];
      b[i] = b[j];
      b[j] = t;
    }
    expect(isRc4Sbox(b, 0)).toBe(true);
  });

  it('rejects a block with a duplicated byte value', () => {
    const b = identityPermutation();
    b[200] = b[100]; // introduce a duplicate -> no longer a permutation
    expect(isRc4Sbox(b, 0)).toBe(false);
  });

  it('finds an S-box at a non-zero offset inside a larger buffer', () => {
    const buf = new Uint8Array(1024);
    buf.set(identityPermutation(), 300);
    expect(isRc4Sbox(buf, 300)).toBe(true);
    expect(isRc4Sbox(buf, 0)).toBe(false); // zeros -> duplicates
  });

  it('rejects when the window runs past the buffer end', () => {
    expect(isRc4Sbox(identityPermutation(), 1)).toBe(false);
  });
});

describe('isRc4SboxInt32LE (Java int[256] S-box)', () => {
  function intPermutationLE(perm: Uint8Array): Uint8Array {
    const b = new Uint8Array(1024);
    for (let i = 0; i < 256; i++) b[i * 4] = perm[i]; // low byte = value, high 3 bytes = 0
    return b;
  }

  it('accepts a 256-int32 little-endian permutation', () => {
    expect(isRc4SboxInt32LE(intPermutationLE(identityPermutation()), 0)).toBe(true);
  });

  it('rejects when an int holds a value > 255 (non-zero high byte)', () => {
    const b = intPermutationLE(identityPermutation());
    b[1] = 0x01; // first int becomes 0x0100 = 256
    expect(isRc4SboxInt32LE(b, 0)).toBe(false);
  });

  it('rejects a duplicated value', () => {
    const perm = identityPermutation();
    perm[5] = perm[6];
    expect(isRc4SboxInt32LE(intPermutationLE(perm), 0)).toBe(false);
  });

  it('finds an int32 S-box at an offset and is not confused by a byte[] S-box', () => {
    const buf = new Uint8Array(2048);
    buf.set(intPermutationLE(identityPermutation()), 128);
    expect(isRc4SboxInt32LE(buf, 128)).toBe(true);
    expect(isRc4SboxInt32LE(identityPermutation(), 0)).toBe(false); // 256 bytes != 1024
  });
});

describe('shannonEntropy / distinctBytes', () => {
  it('is 0 for a constant buffer', () => {
    expect(shannonEntropy(new Uint8Array(32).fill(7), 0, 32)).toBe(0);
    expect(distinctBytes(new Uint8Array(32).fill(7), 0, 32)).toBe(1);
  });

  it('is 8 bits/byte for all 256 distinct values', () => {
    expect(shannonEntropy(identityPermutation(), 0, 256)).toBeCloseTo(8, 6);
  });

  it('is 4 bits/byte for 16 fully distinct bytes', () => {
    const b = new Uint8Array(16);
    for (let i = 0; i < 16; i++) b[i] = i * 16;
    expect(shannonEntropy(b, 0, 16)).toBeCloseTo(4, 6);
    expect(distinctBytes(b, 0, 16)).toBe(16);
  });
});

describe('matchesAesSchedule', () => {
  it('schedule byte lengths are 176 / 208 / 240', () => {
    expect(aesScheduleBytes(4)).toBe(176);
    expect(aesScheduleBytes(6)).toBe(208);
    expect(aesScheduleBytes(8)).toBe(240);
  });

  it("all-zero AES-128 key: first derived word is 0x62636363 (pins S-box/Rcon/packing)", () => {
    const sched = expandAes(new Uint8Array(16));
    expect(Array.from(sched.slice(16, 20))).toEqual([0x62, 0x63, 0x63, 0x63]);
    expect(matchesAesSchedule(sched, 0, 4)).toBe(true);
  });

  it('accepts a valid AES-128 schedule (FIPS-197 example key) and rejects a 1-bit corruption', () => {
    const key = Uint8Array.from([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]);
    const sched = expandAes(key);
    expect(matchesAesSchedule(sched, 0, 4)).toBe(true);
    const bad = sched.slice();
    bad[100] ^= 0x01;
    expect(matchesAesSchedule(bad, 0, 4)).toBe(false);
  });

  it('accepts a valid AES-256 schedule and rejects corruption', () => {
    const key = new Uint8Array(32);
    for (let i = 0; i < 32; i++) key[i] = (i * 37 + 11) & 0xff;
    const sched = expandAes(key);
    expect(matchesAesSchedule(sched, 0, 8)).toBe(true);
    const bad = sched.slice();
    bad[150] ^= 0x80;
    expect(matchesAesSchedule(bad, 0, 8)).toBe(false);
  });

  it('finds a schedule at an offset and rejects random bytes', () => {
    const sched = expandAes(new Uint8Array(16).fill(0x11));
    const buf = new Uint8Array(512);
    buf.set(sched, 64);
    expect(matchesAesSchedule(buf, 64, 4)).toBe(true);
    // A region of incrementing bytes should not satisfy the recurrence.
    const ramp = new Uint8Array(176);
    for (let i = 0; i < ramp.length; i++) ramp[i] = i & 0xff;
    expect(matchesAesSchedule(ramp, 0, 4)).toBe(false);
  });
});

describe('matchesAesDecryptionSchedule', () => {
  // Independent GF(2^8) multiply + InvMixColumns to build a decryption schedule from an encryption
  // one. MixColumns (in the detector) and InvMixColumns (here) are inverses, so a round-trip match
  // exercises real inverse operations, not the same code.
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
    const a0 = (w >>> 24) & 0xff, a1 = (w >>> 16) & 0xff, a2 = (w >>> 8) & 0xff, a3 = w & 0xff;
    const b0 = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
    const b1 = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
    const b2 = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
    const b3 = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
    return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0;
  }
  // dk[0]=ek[Nr], dk[Nr]=ek[0], dk[r]=InvMixColumns(ek[Nr-r]) for inner rounds.
  function toDecryptionSchedule(enc: Uint8Array, nk: 4 | 6 | 8): Uint8Array {
    const nr = nk + 6;
    const beWord = (b: Uint8Array, p: number) => ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;
    const dec = new Uint8Array(enc.length);
    for (let r = 0; r <= nr; r++) {
      for (let c = 0; c < 4; c++) {
        let w = beWord(enc, (4 * (nr - r) + c) * 4);
        if (r !== 0 && r !== nr) w = invMixWord(w);
        const p = (4 * r + c) * 4;
        dec[p] = (w >>> 24) & 0xff; dec[p + 1] = (w >>> 16) & 0xff; dec[p + 2] = (w >>> 8) & 0xff; dec[p + 3] = w & 0xff;
      }
    }
    return dec;
  }

  it('accepts a reconstructed AES-128 decryption schedule and rejects the encryption one', () => {
    const key = Uint8Array.from([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]);
    const enc = expandAes(key);
    const dec = toDecryptionSchedule(enc, 4);
    expect(matchesAesDecryptionSchedule(dec, 0, 4)).toBe(true);
    // The two schedule forms are distinct: each detector rejects the other's layout.
    expect(matchesAesDecryptionSchedule(enc, 0, 4)).toBe(false);
    expect(matchesAesSchedule(dec, 0, 4)).toBe(false);
    const bad = dec.slice();
    bad[80] ^= 0x01;
    expect(matchesAesDecryptionSchedule(bad, 0, 4)).toBe(false);
  });

  it('accepts an AES-256 decryption schedule', () => {
    const key = new Uint8Array(32);
    for (let i = 0; i < 32; i++) key[i] = (i * 53 + 7) & 0xff;
    const dec = toDecryptionSchedule(expandAes(key), 8);
    expect(matchesAesDecryptionSchedule(dec, 0, 8)).toBe(true);
  });
});

describe('chachaKeyLenAt / matchesSalsa20StateAt', () => {
  function chachaState(constant: Uint8Array, keyLen: number): Uint8Array {
    const st = new Uint8Array(64);
    st.set(constant, 0);
    for (let i = 0; i < keyLen; i++) st[16 + i] = (i * 7 + 1) & 0xff; // key bytes
    return st;
  }

  it('detects a ChaCha20 256-bit key after the sigma constant (key at +16)', () => {
    const st = chachaState(CHACHA_SIGMA, 32);
    expect(chachaKeyLenAt(st, 0)).toBe(32);
    expect(st[16]).toBe(1); // key starts here
  });

  it('detects a 128-bit key after the tau constant', () => {
    expect(chachaKeyLenAt(chachaState(CHACHA_TAU, 16), 0)).toBe(16);
  });

  it('returns 0 when no constant is present, and finds one at an offset', () => {
    expect(chachaKeyLenAt(new Uint8Array(64), 0)).toBe(0);
    const buf = new Uint8Array(256);
    buf.set(chachaState(CHACHA_SIGMA, 32), 96);
    expect(chachaKeyLenAt(buf, 96)).toBe(32);
    expect(chachaKeyLenAt(buf, 0)).toBe(0);
  });

  it('detects a Salsa20 state with the sigma constant on the diagonal', () => {
    const st = new Uint8Array(64);
    const diag = [0, 5, 10, 15];
    for (let k = 0; k < 4; k++) for (let b = 0; b < 4; b++) st[diag[k] * 4 + b] = CHACHA_SIGMA[k * 4 + b];
    expect(matchesSalsa20StateAt(st, 0)).toBe(true);
    st[5 * 4 + 1] ^= 0x01; // corrupt one constant word
    expect(matchesSalsa20StateAt(st, 0)).toBe(false);
  });
});

describe('findPem / findDerKey / findJwts', () => {
  function ascii(s: string): Uint8Array {
    const b = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
    return b;
  }

  it('locates a PEM header', () => {
    const b = ascii('junk\n-----BEGIN RSA PRIVATE KEY-----\nMIIB...');
    expect(findPem(b)).toBe(5);
    expect(findPem(ascii('no key here'))).toBe(-1);
  });

  it('locates a DER SEQUENCE + INTEGER v0 header', () => {
    const b = new Uint8Array([0x00, 0x30, 0x82, 0x04, 0xa3, 0x02, 0x01, 0x00, 0x02, 0x82]);
    expect(findDerKey(b)).toBe(1);
    expect(findDerKey(new Uint8Array([0x30, 0x82, 0x01, 0x02, 0x03]))).toBe(-1);
  });

  it('locates JWT-shaped tokens', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const b = ascii('header: Authorization Bearer ' + jwt + ' end');
    const hits = findJwts(b);
    expect(hits.length).toBe(1);
    expect(b[hits[0]]).toBe('e'.charCodeAt(0));
    expect(findJwts(ascii('eyJonly.one.part no second eyJ'))).toEqual([]);
  });
});
