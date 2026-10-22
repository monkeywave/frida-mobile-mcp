/**
 * Content-aware secret recognizers (host side).
 *
 * These are the pure, device-free reference implementations of the structure/entropy
 * recognizers used by the `find_secrets_in_memory` tool. The tool runs a faithful classic-JS
 * port of the same algorithms inside the Frida agent (see `SECRET_SCAN_SOURCE` in
 * `src/tools/secrets.ts`) — exactly the dual host/agent pattern used for address notation
 * (`parseTarget` in `src/agent/address.ts` vs. the in-agent `RESOLVE_TARGET_SNIPPET`).
 *
 * Keeping the logic here as plain functions lets us unit-test correctness against known
 * vectors (a real RC4 S-box, a real AES key schedule, high/low entropy buffers) without a
 * device; the agent port is then verified end-to-end on the emulator.
 *
 * Every function takes a byte buffer + offset so it can be slid across a memory range.
 */

/**
 * True when `bytes[off .. off+256)` is a permutation of 0..255 — the shape of an RC4 key
 * schedule (the S-box), both the identity state before KSA and the shuffled state after.
 * A full 256-byte permutation essentially never occurs by chance, so this is high precision.
 */
export function isRc4Sbox(bytes: Uint8Array, off: number): boolean {
  if (off < 0 || off + 256 > bytes.length) return false;
  const seen = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    const v = bytes[off + i];
    if (seen[v]) return false; // duplicate value -> not a permutation (fails fast)
    seen[v] = 1;
  }
  return true;
}

/**
 * True when `bytes[off .. off+1024)` is a permutation of 0..255 stored as 256 little-endian
 * int32 values (each in 0..255, i.e. three high zero bytes) — the shape of an RC4 S-box kept in
 * a Java `int[256]`, which is how many JVM/ART RC4 implementations store it (a byte[256] is
 * caught by isRc4Sbox instead). Fails fast on the first non-zero high byte or duplicate value.
 */
export function isRc4SboxInt32LE(bytes: Uint8Array, off: number): boolean {
  if (off < 0 || off + 1024 > bytes.length) return false;
  // Cheap reject first: on random memory the very first int almost never has three zero high
  // bytes, so this bails before allocating the `seen` table in the overwhelmingly common case.
  if (bytes[off + 1] !== 0 || bytes[off + 2] !== 0 || bytes[off + 3] !== 0) return false;
  const seen = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    const p = off + i * 4;
    if (bytes[p + 1] !== 0 || bytes[p + 2] !== 0 || bytes[p + 3] !== 0) return false; // not a 0..255 int
    const v = bytes[p];
    if (seen[v]) return false;
    seen[v] = 1;
  }
  return true;
}

/** Shannon entropy (bits/byte, 0..8) of `bytes[off .. off+len)`. */
export function shannonEntropy(bytes: Uint8Array, off: number, len: number): number {
  if (len <= 0 || off < 0 || off + len > bytes.length) return 0;
  const counts = new Array<number>(256).fill(0);
  for (let i = 0; i < len; i++) counts[bytes[off + i]]++;
  let e = 0;
  for (let i = 0; i < 256; i++) {
    const c = counts[i];
    if (c === 0) continue;
    const p = c / len;
    e -= p * Math.log2(p);
  }
  return e;
}

/** Count of distinct byte values in `bytes[off .. off+len)`. */
export function distinctBytes(bytes: Uint8Array, off: number, len: number): number {
  const seen = new Uint8Array(256);
  let n = 0;
  for (let i = 0; i < len; i++) {
    const v = bytes[off + i];
    if (!seen[v]) {
      seen[v] = 1;
      n++;
    }
  }
  return n;
}

// AES S-box (forward) — used by the key-expansion verifier.
// prettier-ignore
export const AES_SBOX: readonly number[] = [
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

// Round constants (rc[j]); Rcon word j is rc[j] << 24.
const AES_RC: readonly number[] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d];

function subWord(w: number): number {
  return (
    ((AES_SBOX[(w >>> 24) & 0xff] << 24) |
      (AES_SBOX[(w >>> 16) & 0xff] << 16) |
      (AES_SBOX[(w >>> 8) & 0xff] << 8) |
      AES_SBOX[w & 0xff]) >>>
    0
  );
}

function rotWord(w: number): number {
  return (((w << 8) | (w >>> 24)) & 0xffffffff) >>> 0;
}

/** Nk (key words) for a supported AES variant: 4 = AES-128, 6 = AES-192, 8 = AES-256. */
export type AesNk = 4 | 6 | 8;

/** Expanded-key length in bytes for an AES variant: 176 / 208 / 240. */
export function aesScheduleBytes(nk: AesNk): number {
  const nr = nk + 6;
  return 4 * 4 * (nr + 1);
}

/** Big-endian 32-bit word at byte offset `p`. */
function beWord(bytes: Uint8Array, p: number): number {
  return ((bytes[p] << 24) | (bytes[p + 1] << 16) | (bytes[p + 2] << 8) | bytes[p + 3]) >>> 0;
}

/**
 * True when the `total` words read via `getWord(i)` satisfy the AES forward key-expansion
 * recurrence. Words are read on demand (not pre-materialized) and the check bails at the first
 * mismatch — on random memory that is almost always `i === nk`, so only a few words are ever
 * touched. A match is effectively impossible by chance, so a success is a recovered key.
 */
function verifyForwardSchedule(getWord: (i: number) => number, total: number, nk: AesNk): boolean {
  for (let i = nk; i < total; i++) {
    let temp = getWord(i - 1);
    if (i % nk === 0) {
      const rcon = (AES_RC[i / nk - 1] << 24) >>> 0;
      temp = (subWord(rotWord(temp)) ^ rcon) >>> 0;
    } else if (nk > 6 && i % nk === 4) {
      temp = subWord(temp);
    }
    if (getWord(i) !== ((getWord(i - nk) ^ temp) >>> 0)) return false;
  }
  return true;
}

/**
 * True when `bytes[off .. off+aesScheduleBytes(nk))` is a valid AES (encryption) key schedule (the
 * aeskeyfind test). Big-endian word packing. **Mode-independent** — the same expanded schedule
 * backs CBC/CTR/GCM/XTS/… .
 */
export function matchesAesSchedule(bytes: Uint8Array, off: number, nk: AesNk): boolean {
  const total = 4 * (nk + 6 + 1);
  if (off < 0 || off + total * 4 > bytes.length) return false;
  return verifyForwardSchedule((i) => beWord(bytes, off + i * 4), total, nk);
}

// GF(2^8) xtime (·2) for AES MixColumns, and the full MixColumns on one 4-byte column/word.
function xtime(b: number): number {
  const r = (b << 1) & 0xff;
  return (b & 0x80) !== 0 ? r ^ 0x1b : r;
}
function mixColumnWord(w: number): number {
  const a0 = (w >>> 24) & 0xff;
  const a1 = (w >>> 16) & 0xff;
  const a2 = (w >>> 8) & 0xff;
  const a3 = w & 0xff;
  const b0 = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
  const b1 = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
  const b2 = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
  const b3 = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
  return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0;
}

/**
 * True when `bytes[off ..]` is a valid AES **decryption** schedule (the "equivalent inverse
 * cipher" form stored by e.g. OpenSSL `AES_set_decrypt_key`): round keys in reverse order with
 * InvMixColumns applied to the inner rounds. We reconstruct the candidate *encryption* schedule
 * (reverse the round-key order; apply MixColumns to inner round keys, the inverse of
 * InvMixColumns) and verify the forward recurrence on it. Catches decrypt-only contexts (CBC
 * decryption) where the forward schedule is absent. Big-endian word packing.
 */
export function matchesAesDecryptionSchedule(bytes: Uint8Array, off: number, nk: AesNk): boolean {
  const nr = nk + 6;
  const total = 4 * (nr + 1);
  if (off < 0 || off + total * 4 > bytes.length) return false;

  // Reconstruct encryption word i on demand: dk round key r (= words [4r..4r+3]) maps to ek round
  // key (nr - r), with MixColumns on the inner rounds (the inverse of the stored InvMixColumns).
  const ekWord = (i: number): number => {
    const r = (i / 4) | 0;
    const c = i % 4;
    const dkWord = beWord(bytes, off + (4 * (nr - r) + c) * 4);
    return r === 0 || r === nr ? dkWord : mixColumnWord(dkWord);
  };
  return verifyForwardSchedule(ekWord, total, nk);
}

// ChaCha20/Salsa20 sigma constant "expand 32-byte k" and tau "expand 16-byte k".
export const CHACHA_SIGMA = Uint8Array.from('expand 32-byte k', (c) => c.charCodeAt(0));
export const CHACHA_TAU = Uint8Array.from('expand 16-byte k', (c) => c.charCodeAt(0));

function matchesBytes(bytes: Uint8Array, off: number, needle: Uint8Array): boolean {
  if (off + needle.length > bytes.length) return false;
  for (let i = 0; i < needle.length; i++) if (bytes[off + i] !== needle[i]) return false;
  return true;
}

/**
 * ChaCha20 / XChaCha20 cipher-state detector. The 64-byte state begins with the 16-byte sigma/tau
 * constant (words 0..3, contiguous), immediately followed by the key (words 4..11). Returns the
 * key length (32 for sigma, 16 for tau) when `bytes[off..]` starts with the constant, else 0.
 * The key therefore sits at `off + 16`. An exact 16-byte constant match is as precise as the RC4 S-box.
 */
export function chachaKeyLenAt(bytes: Uint8Array, off: number): 0 | 16 | 32 {
  if (matchesBytes(bytes, off, CHACHA_SIGMA)) return 32;
  if (matchesBytes(bytes, off, CHACHA_TAU)) return 16;
  return 0;
}

/**
 * Salsa20 cipher-state detector. Unlike ChaCha, Salsa20 places the four 4-byte constant words on
 * the state diagonal — positions 0, 5, 10, 15 (byte offsets 0, 20, 40, 60) — with the 256-bit key
 * in words 1..4 and 11..14. Returns true when those four constant words are present (32-byte key).
 */
export function matchesSalsa20StateAt(bytes: Uint8Array, off: number): boolean {
  if (off < 0 || off + 64 > bytes.length) return false;
  const diag = [0, 5, 10, 15];
  for (let k = 0; k < 4; k++) {
    for (let b = 0; b < 4; b++) {
      if (bytes[off + diag[k] * 4 + b] !== CHACHA_SIGMA[k * 4 + b]) return false;
    }
  }
  return true;
}

/**
 * Offset of a DER private-key/certificate header within `bytes` at or after `from`, or -1.
 * Heuristic: SEQUENCE with a 2-byte length (`30 82 xx xx`) immediately followed by an
 * INTEGER version 0 (`02 01 00`) — the start of a PKCS#1/PKCS#8 private key or similar.
 */
export function findDerKey(bytes: Uint8Array, from = 0): number {
  for (let i = Math.max(0, from); i + 7 <= bytes.length; i++) {
    if (bytes[i] === 0x30 && bytes[i + 1] === 0x82 && bytes[i + 4] === 0x02 && bytes[i + 5] === 0x01 && bytes[i + 6] === 0x00) {
      return i;
    }
  }
  return -1;
}

const PEM_MARKER = '-----BEGIN';

/** Offset of an ASCII "-----BEGIN" PEM header within `bytes` at or after `from`, or -1. */
export function findPem(bytes: Uint8Array, from = 0): number {
  const m = PEM_MARKER;
  for (let i = Math.max(0, from); i + m.length <= bytes.length; i++) {
    let ok = true;
    for (let j = 0; j < m.length; j++) {
      if (bytes[i + j] !== m.charCodeAt(j)) {
        ok = false;
        break;
      }
    }
    if (ok) return i;
  }
  return -1;
}

/**
 * Offsets of JWT-shaped tokens (`eyJ<base64url>.eyJ<base64url>.`) in `bytes`. Scans the buffer
 * as Latin-1 text. Returns up to `limit` start offsets.
 */
export function findJwts(bytes: Uint8Array, limit = 16): number[] {
  // Latin-1 decode is 1:1 with byte offsets, so regex indices map straight back to the buffer.
  let text = '';
  for (let i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
  const re = /eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g;
  const out: number[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null && out.length < limit) {
    out.push(m.index);
  }
  return out;
}
