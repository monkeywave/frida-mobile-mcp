/**
 * Memory-pattern builder (host side, device-free, pure).
 *
 * Turns a small memory WINDOW around a recovered secret into a reusable *anchor* descriptor:
 * a stable byte signature near the key plus the offset from that anchor to the key. The anchor
 * lets a later run re-locate the same secret by shape (via `scan_memory`) or hand friTap a
 * pattern / offset for its own hooks — even across process restarts where the absolute address
 * moves but the surrounding structure does not.
 *
 * This is the pure, unit-tested core (no Frida): `generate_memory_pattern` reads the window in
 * the agent and then calls `buildPattern(...)` here — the same host/agent split used for address
 * notation (`parseTarget` in `src/agent/address.ts`) and the secret recognizers
 * (`src/helpers/secret-recognizers.ts`).
 */
import { formatModuleOffset } from '../agent/address.js';
import { distinctBytes, CHACHA_SIGMA, CHACHA_TAU } from './secret-recognizers.js';

/** Recognizer types the anchor strategy branches on (mirrors find_secrets_in_memory + chacha_key). */
export type PatternType = 'rc4_sbox' | 'aes_key_schedule' | 'high_entropy_key' | 'pem_der' | 'jwt' | 'chacha_key';

export type Confidence = 'high' | 'medium' | 'low';

export interface BuildPatternInput {
  /** Bytes read around the secret: context before, the secret, context after. */
  windowBytes: Uint8Array;
  /** Index of the secret's first byte within `windowBytes`. */
  secretOffsetInWindow: number;
  /** Key/secret length in bytes. */
  size: number;
  /** Recognizer type, picks the anchor strategy. */
  type?: PatternType;
  /** Keylog/slot label; defaults from `type`. */
  label?: string;
  /** The secret's address in friendly notation (module+0xoff or absolute) for the descriptor. */
  address?: string;
  /** Module the secret lives in, when known (enables the fritap offsets entry + anchor rva). */
  module?: string;
  /** The secret's byte offset within `module`, when known. */
  moduleOffset?: number;
}

export interface AnchorDescriptor {
  /** Anchor bytes as a `scan_memory` pattern fragment ("65 78 ..", or with `??` wildcards). */
  pattern: string;
  module?: string;
  /** Anchor's module+0xoff, when the module/offset is known. */
  rva?: string;
  /** Distance from the anchor's start to the key (== offset_to_key). */
  bytes_before_key: number;
}

export interface MsAgentValidators {
  max_zero_fraction: number;
  min_shannon_entropy_bits: number;
  min_secret_len: number;
  max_secret_len: number;
}

export interface MsAgentAnchor {
  pattern: string;
  anchor_offset_in_struct: number;
  slot: { data: number; len: number; label: string };
  validators: MsAgentValidators;
  keylog_labels: string[];
}

export interface PatternDescriptor {
  secret: { address?: string; size: number; type?: PatternType };
  anchor: AnchorDescriptor;
  offset_to_key: number;
  key_len: number;
  /** Ready for the scan_memory tool: "xx ?? xx" grammar (two-hex tokens, `??` wildcards). */
  scan_memory_pattern: string;
  fritap: {
    offsets_entry?: Record<string, Record<string, { address: string; absolute: boolean }>>;
    ms_agent_anchor: MsAgentAnchor;
  };
  confidence: Confidence;
  note: string;
}

// ChaCha/Salsa20 state layout: [16-byte constant][32-byte key][counter+nonce]. The constant
// ("sigma" for a 256-bit key, "tau" for 128-bit) sits exactly 16 bytes before the key, so it is
// the ideal fixed anchor: unique, position-locked, never part of the key itself. The constant
// bytes are shared with the recognizer (CHACHA_SIGMA/CHACHA_TAU) so the two never disagree.
const CHACHA_KEY_OFFSET = 16;

const PEM_BEGIN = asciiBytes('-----BEGIN');
const JWT_PREFIX = asciiBytes('eyJ');
// DER private-key/cert header: SEQUENCE(2-byte len) + INTEGER version 0; the length bytes vary.
const DER_TOKENS = ['30', '82', '??', '??', '02', '01', '00'];

// A homogeneous run this long adjacent to the key is taken as a padding/structural anchor.
const MIN_CONST_RUN = 4;
// When no constant run precedes the key, fall back to at most this many raw bytes as the anchor.
const MAX_RAW_ANCHOR = 16;

const DEFAULT_LABELS: Record<PatternType, string> = {
  rc4_sbox: 'RC4_KEY',
  aes_key_schedule: 'AES_KEY',
  high_entropy_key: 'SYMMETRIC_KEY',
  pem_der: 'PRIVATE_KEY',
  jwt: 'JWT',
  chacha_key: 'CHACHA_KEY',
};

/** The internal shape each anchor strategy returns before the descriptor is assembled. */
interface AnchorChoice {
  patternTokens: string[];
  /** Distance from the anchor's start to the key start (anchor is `offsetToKey` bytes before it). */
  offsetToKey: number;
  confidence: Confidence;
  note: string;
  /** Fixed-constant anchors (chacha/pem/der/jwt) locate standalone; derived ones wildcard the key. */
  fixed: boolean;
}

/**
 * Build a reusable pattern descriptor for a secret located inside `windowBytes`. Pure: given the
 * same window it always yields the same anchor, offset and confidence.
 */
export function buildPattern(input: BuildPatternInput): PatternDescriptor {
  const { windowBytes, secretOffsetInWindow, size, type } = input;
  const label = input.label ?? (type ? DEFAULT_LABELS[type] : 'SECRET_KEY');
  const keyLen = size;

  const choice = chooseAnchor(windowBytes, secretOffsetInWindow, size, type);
  const anchorPattern = choice.patternTokens.join(' ');
  // Fixed constants (sigma, PEM header, ...) are strong standalone locators; derived anchors are
  // weak alone, so they also spell out the key region as wildcards per the "xx ?? xx" grammar.
  const scanPattern = choice.fixed
    ? anchorPattern
    : [anchorPattern, wildcardTokens(keyLen)].filter((t) => t.length > 0).join(' ');

  const hasModule = input.module !== undefined && input.moduleOffset !== undefined;
  const anchorRva = hasModule
    ? formatModuleOffset(input.module as string, Math.max(0, (input.moduleOffset as number) - choice.offsetToKey))
    : undefined;

  const anchor: AnchorDescriptor = {
    pattern: anchorPattern,
    bytes_before_key: choice.offsetToKey,
  };
  if (input.module !== undefined) anchor.module = input.module;
  if (anchorRva !== undefined) anchor.rva = anchorRva;

  const msAgentAnchor: MsAgentAnchor = {
    pattern: anchorPattern,
    anchor_offset_in_struct: choice.offsetToKey,
    slot: { data: choice.offsetToKey, len: keyLen, label },
    validators: { max_zero_fraction: 0.5, min_shannon_entropy_bits: 3.5, min_secret_len: keyLen, max_secret_len: keyLen },
    keylog_labels: [label],
  };

  const descriptor: PatternDescriptor = {
    secret: { size, type },
    anchor,
    offset_to_key: choice.offsetToKey,
    key_len: keyLen,
    scan_memory_pattern: scanPattern,
    fritap: { ms_agent_anchor: msAgentAnchor },
    confidence: choice.confidence,
    note: choice.note,
  };
  if (input.address !== undefined) descriptor.secret.address = input.address;
  if (hasModule) {
    // friTap offsets JSON keys the *key* slot (not the anchor) by module -> label.
    descriptor.fritap.offsets_entry = {
      [input.module as string]: {
        [label]: { address: `0x${(input.moduleOffset as number).toString(16)}`, absolute: false },
      },
    };
  }
  return descriptor;
}

/** Dispatch to the recognizer-aware anchor strategy. */
function chooseAnchor(window: Uint8Array, secretOffset: number, size: number, type?: PatternType): AnchorChoice {
  switch (type) {
    case 'chacha_key':
      return chachaAnchor(window, secretOffset, size);
    case 'pem_der':
      return pemDerAnchor(window, secretOffset);
    case 'jwt':
      return jwtAnchor(window, secretOffset);
    case 'rc4_sbox':
      // The S-box IS the key material, so there is no fixed marker; anchor on adjacent stable
      // bytes and cap confidence at medium. friTap also ships a native rc4 ms_agent engine.
      return structuralAnchor(window, secretOffset, { maxConfidence: 'medium', rc4: true });
    default:
      // aes_key_schedule / high_entropy_key / unknown: longest low-variance run adjacent to the key.
      return structuralAnchor(window, secretOffset, {});
  }
}

/** ChaCha/Salsa: the 16-byte sigma/tau constant sits 16 bytes before the key. */
function chachaAnchor(window: Uint8Array, secretOffset: number, size: number): AnchorChoice {
  const before = sliceBytes(window, secretOffset - CHACHA_KEY_OFFSET, CHACHA_KEY_OFFSET);
  if (before.length === CHACHA_KEY_OFFSET && (bytesEqual(before, CHACHA_SIGMA) || bytesEqual(before, CHACHA_TAU))) {
    const constName = bytesEqual(before, CHACHA_SIGMA) ? 'sigma ("expand 32-byte k")' : 'tau ("expand 16-byte k")';
    return {
      patternTokens: hexTokens(before),
      offsetToKey: CHACHA_KEY_OFFSET,
      confidence: 'high',
      note: `ChaCha/Salsa ${constName} constant precedes the ${size}-byte key by 16 bytes`,
      fixed: true,
    };
  }
  // Constant not confirmed in the window; still emit the known sigma constant as the anchor.
  return {
    patternTokens: hexTokens(CHACHA_SIGMA),
    offsetToKey: CHACHA_KEY_OFFSET,
    confidence: 'medium',
    note: 'ChaCha sigma constant assumed 16 bytes before the key (not confirmed in the read window)',
    fixed: true,
  };
}

/** PEM "-----BEGIN" / DER "30 82 ?? ?? 02 01 00" header — the key blob starts at the marker. */
function pemDerAnchor(window: Uint8Array, secretOffset: number): AnchorChoice {
  const pem = indexOfBytes(window, PEM_BEGIN);
  if (pem >= 0 && pem <= secretOffset) {
    return {
      patternTokens: hexTokens(PEM_BEGIN),
      offsetToKey: secretOffset - pem,
      confidence: 'high',
      note: 'PEM "-----BEGIN" header marks the start of the key material',
      fixed: true,
    };
  }
  if (matchesTokens(window, secretOffset, DER_TOKENS)) {
    return {
      patternTokens: [...DER_TOKENS],
      offsetToKey: 0,
      confidence: 'high',
      note: 'DER SEQUENCE + INTEGER v0 header (private key/cert) at the key start',
      fixed: true,
    };
  }
  return {
    patternTokens: hexTokens(PEM_BEGIN),
    offsetToKey: 0,
    confidence: 'medium',
    note: 'No PEM/DER header found in the window; using the "-----BEGIN" marker as a default anchor',
    fixed: true,
  };
}

/** JWT "eyJ" prefix — the token starts at the marker. */
function jwtAnchor(window: Uint8Array, secretOffset: number): AnchorChoice {
  const jwt = indexOfBytes(window, JWT_PREFIX);
  const found = jwt >= 0 && jwt <= secretOffset;
  return {
    patternTokens: hexTokens(JWT_PREFIX),
    offsetToKey: found ? secretOffset - jwt : 0,
    confidence: found ? 'high' : 'medium',
    note: found ? 'JWT "eyJ" prefix marks the token start' : 'JWT "eyJ" prefix assumed at the token start',
    fixed: true,
  };
}

/**
 * Derived anchor for keys with no fixed marker (AES schedule, high-entropy, RC4, unknown):
 * prefer the longest constant run immediately before the key (padding/structure), else fall back
 * to the raw bytes just before it. The key region is wildcarded in the scan pattern.
 */
function structuralAnchor(
  window: Uint8Array,
  secretOffset: number,
  opts: { maxConfidence?: Confidence; rc4?: boolean }
): AnchorChoice {
  const runLen = constantRunBefore(window, secretOffset);
  let anchorStart: number;
  let anchorLen: number;
  let note: string;

  if (runLen >= MIN_CONST_RUN) {
    anchorLen = runLen;
    anchorStart = secretOffset - runLen;
    note = `constant 0x${byteHex(window[secretOffset - 1])} run (${runLen} bytes) adjacent to the key`;
  } else if (secretOffset > 0) {
    anchorLen = Math.min(secretOffset, MAX_RAW_ANCHOR);
    anchorStart = secretOffset - anchorLen;
    note = `non-stable ${anchorLen}-byte anchor immediately before the key (verify by re-scan)`;
  } else {
    anchorLen = 0;
    anchorStart = secretOffset;
    note = 'no bytes available before the key for an anchor; relying on the key length alone';
  }

  const anchorBytes = sliceBytes(window, anchorStart, anchorLen);
  let confidence = scoreAnchor(anchorBytes);
  if (opts.maxConfidence) confidence = clampConfidence(confidence, opts.maxConfidence);
  if (opts.rc4) note += '; RC4 S-box is itself the key material — friTap ships a native rc4 ms_agent engine';

  return {
    patternTokens: hexTokens(anchorBytes),
    offsetToKey: anchorLen,
    confidence,
    note,
    fixed: false,
  };
}

/** Length of the run of identical bytes ending immediately before the key. */
function constantRunBefore(window: Uint8Array, secretOffset: number): number {
  if (secretOffset <= 0) return 0;
  const value = window[secretOffset - 1];
  let len = 0;
  for (let i = secretOffset - 1; i >= 0 && window[i] === value; i--) len++;
  return len;
}

/**
 * Grade a derived anchor: longer and more non-repeating (more distinct bytes) ⇒ higher. A long
 * constant run (one distinct byte) is usable for the offset but not unique, so it stays medium.
 */
function scoreAnchor(anchor: Uint8Array): Confidence {
  const len = anchor.length;
  const distinct = distinctBytes(anchor, 0, len);
  if (len >= 8 && distinct >= 6) return 'high';
  if (len >= 4 && distinct >= 2) return 'medium';
  if (len >= 12) return 'medium'; // long constant padding: weak but a usable offset anchor
  return 'low';
}

const CONFIDENCE_RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };
function clampConfidence(value: Confidence, max: Confidence): Confidence {
  return CONFIDENCE_RANK[value] > CONFIDENCE_RANK[max] ? max : value;
}

// --- byte helpers ----------------------------------------------------------

function asciiBytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

function sliceBytes(bytes: Uint8Array, off: number, len: number): Uint8Array {
  if (off < 0 || len <= 0 || off + len > bytes.length) return new Uint8Array(0);
  return bytes.subarray(off, off + len);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function byteHex(b: number): string {
  return ('0' + (b & 0xff).toString(16)).slice(-2);
}

function hexTokens(bytes: Uint8Array): string[] {
  const out: string[] = [];
  for (let i = 0; i < bytes.length; i++) out.push(byteHex(bytes[i]));
  return out;
}

function wildcardTokens(n: number): string {
  if (n <= 0) return '';
  return new Array(n).fill('??').join(' ');
}

/** First index of `needle` in `haystack`, or -1. */
function indexOfBytes(haystack: Uint8Array, needle: Uint8Array): number {
  if (needle.length === 0) return -1;
  for (let i = 0; i + needle.length <= haystack.length; i++) {
    let ok = true;
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) {
        ok = false;
        break;
      }
    }
    if (ok) return i;
  }
  return -1;
}

/** True when `window[off..]` matches a token pattern ("30", "82", "??", ...). */
function matchesTokens(window: Uint8Array, off: number, tokens: string[]): boolean {
  if (off < 0 || off + tokens.length > window.length) return false;
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i] === '??') continue;
    if (window[off + i] !== parseInt(tokens[i], 16)) return false;
  }
  return true;
}
