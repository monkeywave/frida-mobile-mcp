import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../helpers/errors.js';
import { resolveInstrumentationTarget } from './hook.js';
import { responseFormatSchema } from '../constants.js';
import { getOrCreateSession, sessionResolutionLimitations } from '../helpers/session-helper.js';
import { createAgentScript } from '../agent/script-factory.js';
import type { BridgeName } from '../agent/bridges.js';
import { RESOLVE_TARGET_SNIPPET } from '../agent/address.js';
import { callRpcWithTimeout } from '../helpers/rpc-timeout.js';
import { getState } from '../state.js';
import { rateLimiter } from '../helpers/rate-limiter.js';
import { AES_SBOX } from '../helpers/secret-recognizers.js';

const NO_BRIDGES: BridgeName[] = [];

const ALL_RECOGNIZERS = ['rc4_sbox', 'aes_key_schedule', 'chacha_key', 'salsa_key', 'high_entropy_key', 'pem_der', 'jwt'] as const;
type Recognizer = (typeof ALL_RECOGNIZERS)[number];

// The precise recognizers slide byte-by-byte, so the budget trades coverage for latency. 16 MiB
// of heap scans in well under the RPC timeout and reaches the keys in practice; narrow `scope` to
// a module (or raise max_bytes) for an exhaustive sweep.
const DEFAULT_MAX_BYTES = 16 * 1024 * 1024;
const DEFAULT_LIMIT = 100; // max candidates returned
const DEFAULT_MIN_ENTROPY = 3.5; // bits/byte for a high-entropy key window
const ENTROPY_LENS = [16, 24, 32]; // candidate symmetric-key sizes
// high_entropy_key is low-precision and abundant on a real heap, so it gets its own small budget:
// without this cap it floods the candidate limit in the first megabyte and starves the precise
// recognizers (rc4_sbox / aes_key_schedule), which must keep scanning the whole scope.
const DEFAULT_MAX_ENTROPY_HITS = 15;

interface SecretCandidate {
  type: Recognizer;
  address: string;
  size: number;
  preview_hex?: string;
  preview_text?: string;
  entropy?: number;
  distinct?: number;
  note?: string;
}

interface ScanResult {
  candidates: SecretCandidate[];
  bytes_scanned: number;
  ranges_scanned: number;
  ranges_unreadable: number;
  stopped: 'complete' | 'max_bytes' | 'limit';
  error?: string;
}

export function registerSecretsTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'find_secrets_in_memory',
    {
      title: 'Find Secrets in Memory (Content-Aware)',
      description:
        'Scan live process memory for the STRUCTURE of secrets, not just names or byte patterns. Finds keys even when you never reached the code that uses them: an RC4 key schedule (256-byte permutation of 0..255, byte[] or Java int[256] — the rc4demo case), an AES key schedule (aeskeyfind-style verification, AES-128/192/256, both encryption AND decryption schedules — and it is MODE-INDEPENDENT: the same expanded key backs CBC/CTR/GCM/XTS), a ChaCha20/XChaCha20 key (located by the exact "expand 32-byte k" sigma constant, key at +16) and Salsa20 state, high-entropy 16/24/32-byte buffers (candidate symmetric keys), PEM/DER private-key headers, and JWT tokens. Raw-key-only ciphers (AES-NI with no in-memory schedule) fall back to high_entropy_key + monitor_crypto at the API boundary. Defaults to writable (heap) ranges where live keys sit. Returns candidates with a module+offset address and a hex/text preview; read the full bytes with read_memory, or hand one to generate_memory_pattern. Complements discover_crypto (name-only) and scan_memory (fixed byte-pattern only).',
      inputSchema: z.object({
        target: z.string().optional().describe('App bundle ID, process name, or PID. Optional when session_id is given.'),
        session_id: z.string().optional().describe('Reuse an existing session (from explore_app/get_status) instead of re-attaching by target.'),
        device: z.string().optional().describe('Device ID'),
        recognizers: z
          .array(z.enum(ALL_RECOGNIZERS))
          .optional()
          .describe(`Which recognizers to run (default: all). One or more of: ${ALL_RECOGNIZERS.join(', ')}.`),
        scope: z
          .string()
          .optional()
          .describe('"heap" (writable rw- ranges, default — where live keys sit), "all" (every readable range, slower), or a module name (e.g. "libfoo.so") to scan just that module.'),
        max_bytes: z.number().optional().describe(`Stop after scanning this many bytes (default: ${DEFAULT_MAX_BYTES}).`),
        min_entropy: z.number().optional().describe(`Shannon entropy (bits/byte) threshold for high_entropy_key windows (default: ${DEFAULT_MIN_ENTROPY}).`),
        max_entropy_hits: z.number().optional().describe(`Cap on noisy high_entropy_key candidates so they don't crowd out precise recognizers (default: ${DEFAULT_MAX_ENTROPY_HITS}).`),
        limit: z.number().optional().describe(`Max candidates to return (default: ${DEFAULT_LIMIT}).`),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ target, session_id, device, recognizers, scope, max_bytes, min_entropy, max_entropy_hits, limit, response_format }) => {
      try {
        const state = getState();
        rateLimiter.check('memory_read', state.config.rateLimits.memoryReadsPerMinute);
        rateLimiter.record('memory_read');

        const resolved = resolveInstrumentationTarget(target, session_id);
        const resolution = await getOrCreateSession(deviceManager, {
          target: resolved.target,
          device,
          sessionId: resolved.sessionId,
        });
        const { sessionEntry } = resolution;
        const sessionLimitations = sessionResolutionLimitations(resolution);

        const selected = recognizers && recognizers.length > 0 ? recognizers : [...ALL_RECOGNIZERS];
        const scopeValue = scope ?? 'heap';
        const maxBytes = max_bytes ?? DEFAULT_MAX_BYTES;
        const minEntropy = min_entropy ?? DEFAULT_MIN_ENTROPY;
        const maxCandidates = limit ?? DEFAULT_LIMIT;

        const script = await createAgentScript(sessionEntry.session, {
          sessionEntry,
          source: SECRET_SCAN_SOURCE,
          platform: sessionEntry.platform,
          name: 'find_secrets:' + scopeValue,
          kind: 'generated',
          options: {
            recognizers: selected,
            scope: scopeValue,
            maxBytes,
            minEntropy,
            maxEntropyHits: max_entropy_hits ?? DEFAULT_MAX_ENTROPY_HITS,
            limit: maxCandidates,
            entropyLens: ENTROPY_LENS,
            aesSbox: AES_SBOX,
          },
          bridges: NO_BRIDGES,
        });
        await script.load();
        let result: ScanResult;
        try {
          result = await callRpcWithTimeout(script.exports.scan() as Promise<ScanResult>, 'Secret scan', 180_000);
        } finally {
          await script.unload();
        }

        if (result.error) {
          throw new FridaMcpError('SCAN_ERROR', result.error, [
            { tool: 'find_secrets_in_memory', args: { session_id: sessionEntry.id, scope: 'heap' }, reason: 'Retry on the heap scope' },
          ]);
        }

        const first = result.candidates[0];
        const truncated = result.stopped !== 'complete';
        return formatToolResponse(
          buildResult(
            {
              session_id: sessionEntry.id,
              scope: scopeValue,
              recognizers: selected,
              candidate_count: result.candidates.length,
              candidates: result.candidates,
              bytes_scanned: result.bytes_scanned,
              ranges_scanned: result.ranges_scanned,
              ranges_unreadable: result.ranges_unreadable,
              stopped: result.stopped,
            },
            first
              ? [
                  { tool: 'read_memory', args: { session_id: sessionEntry.id, address: first.address, size: first.size }, reason: `Read the full bytes of the top candidate (${first.type})` },
                  { tool: 'monitor_crypto', args: { session_id: sessionEntry.id }, reason: 'Confirm by watching the key flow through a crypto call' },
                ]
              : [
                  { tool: 'find_secrets_in_memory', args: { session_id: sessionEntry.id, scope: 'all' }, reason: 'Nothing on the heap — widen to all readable ranges' },
                  { tool: 'trigger_and_wait', args: { session_id: sessionEntry.id }, reason: 'Drive the app so the secret gets allocated, then re-scan' },
                ],
            truncated
              ? { coverage: { status: 'unknown', note: `stopped early (${result.stopped})` }, limitations: [...sessionLimitations, `Scan stopped early (${result.stopped}); raise max_bytes/limit or narrow scope to a module to scan more.`] }
              : { coverage: { status: 'complete' }, limitations: sessionLimitations },
          ),
          response_format,
        );
      } catch (err) {
        if (err instanceof FridaMcpError) return formatToolResponse(err.toErrorResponse(), response_format);
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    },
  );
}

/**
 * In-agent content recognizers — a faithful classic-JS port of src/helpers/secret-recognizers.ts
 * (same dual host/agent pattern as address.ts). Options (recognizers, scope, caps, aesSbox) arrive
 * as the JSON literal __FRIDA_MCP__.options; no value is spliced into code. Uses only the Frida 17
 * instance API (NativePointer#readByteArray, Process.enumerateRanges), never removed statics.
 */
export const SECRET_SCAN_SOURCE =
  RESOLVE_TARGET_SNIPPET +
  `
(function () { // closure scope: the per-byte hot loop reads locals, not global-object properties
  var CHUNK = 1024 * 1024;   // read ranges in 1 MiB slices
  var OVERLAP = 1024;        // re-scan the tail so a structure straddling a chunk boundary isn't missed;
                             // MUST be >= the largest recognized structure (the int32[] RC4 S-box = 1024 bytes),
                             // otherwise a structure whose start lands in the last <structSize> bytes of a chunk
                             // core is bailed on this chunk and never re-reached in the next.
  var ENTROPY_STRIDE = 8;    // step for high-entropy windows (keys are usually >=8-aligned)
  var PREVIEW = 64;          // bytes of hex preview per candidate

  function hexSlice(bytes, off, len) {
    var out = '';
    var end = Math.min(off + len, bytes.length);
    for (var i = off; i < end; i++) out += ('0' + bytes[i].toString(16)).slice(-2);
    return out;
  }
  function textSlice(bytes, off, len) {
    var out = '';
    var end = Math.min(off + len, bytes.length);
    for (var i = off; i < end; i++) { var c = bytes[i]; out += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.'; }
    return out;
  }

  var SBOX = __FRIDA_MCP__.options.aesSbox;
  var RC = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d];
  function subWord(w) {
    return ((SBOX[(w >>> 24) & 0xff] << 24) | (SBOX[(w >>> 16) & 0xff] << 16) | (SBOX[(w >>> 8) & 0xff] << 8) | SBOX[w & 0xff]) >>> 0;
  }
  function rotWord(w) { return (((w << 8) | (w >>> 24)) & 0xffffffff) >>> 0; }
  function aesScheduleBytes(nk) { var nr = nk + 6; return 4 * 4 * (nr + 1); }
  function beWord(bytes, p) { return ((bytes[p] << 24) | (bytes[p+1] << 16) | (bytes[p+2] << 8) | bytes[p+3]) >>> 0; }
  // Reads words on demand via getWord and bails at the first mismatch (almost always i===nk on
  // random memory), so no per-offset array is built and only a few words are touched.
  function verifyForwardSchedule(getWord, total, nk) {
    for (var i = nk; i < total; i++) {
      var temp = getWord(i - 1);
      if (i % nk === 0) { var rcon = (RC[(i / nk) - 1] << 24) >>> 0; temp = (subWord(rotWord(temp)) ^ rcon) >>> 0; }
      else if (nk > 6 && i % nk === 4) { temp = subWord(temp); }
      if (getWord(i) !== ((getWord(i - nk) ^ temp) >>> 0)) return false;
    }
    return true;
  }
  function matchesAesSchedule(bytes, off, nk) {
    var total = 4 * (nk + 6 + 1);
    if (off + total * 4 > bytes.length) return false;
    return verifyForwardSchedule(function (i) { return beWord(bytes, off + i * 4); }, total, nk);
  }
  function xtime(b) { var r = (b << 1) & 0xff; return (b & 0x80) !== 0 ? (r ^ 0x1b) : r; }
  function mixColumnWord(w) {
    var a0 = (w >>> 24) & 0xff, a1 = (w >>> 16) & 0xff, a2 = (w >>> 8) & 0xff, a3 = w & 0xff;
    var b0 = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
    var b1 = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
    var b2 = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
    var b3 = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0;
  }
  // Decryption (equivalent-inverse) schedule: reverse round-key order + MixColumns the inner rounds
  // to reconstruct the encryption schedule, then verify the forward recurrence.
  function matchesAesDecryptionSchedule(bytes, off, nk) {
    var nr = nk + 6, total = 4 * (nr + 1);
    if (off + total * 4 > bytes.length) return false;
    function ekWord(i) {
      var r = (i / 4) | 0, c = i % 4;
      var dkWord = beWord(bytes, off + (4 * (nr - r) + c) * 4);
      return (r === 0 || r === nr) ? dkWord : mixColumnWord(dkWord);
    }
    return verifyForwardSchedule(ekWord, total, nk);
  }
  var SIGMA = [0x65,0x78,0x70,0x61,0x6e,0x64,0x20,0x33,0x32,0x2d,0x62,0x79,0x74,0x65,0x20,0x6b]; // "expand 32-byte k"
  var TAU   = [0x65,0x78,0x70,0x61,0x6e,0x64,0x20,0x31,0x36,0x2d,0x62,0x79,0x74,0x65,0x20,0x6b]; // "expand 16-byte k"
  function matchesConst(bytes, off, cst) {
    if (off + cst.length > bytes.length) return false;
    for (var i = 0; i < cst.length; i++) if (bytes[off + i] !== cst[i]) return false;
    return true;
  }
  // ChaCha20/XChaCha20 state: contiguous 16-byte sigma/tau constant, key at +16. Returns 32|16|0.
  function chachaKeyLenAt(bytes, off) {
    if (matchesConst(bytes, off, SIGMA)) return 32;
    if (matchesConst(bytes, off, TAU)) return 16;
    return 0;
  }
  // Salsa20 state: the four constant words sit on the diagonal (positions 0,5,10,15).
  function matchesSalsa20At(bytes, off) {
    if (off + 64 > bytes.length) return false;
    var diag = [0, 5, 10, 15];
    for (var k = 0; k < 4; k++) for (var b = 0; b < 4; b++) {
      if (bytes[off + diag[k] * 4 + b] !== SIGMA[k * 4 + b]) return false;
    }
    return true;
  }
  // Candidate first bytes are located with the native TypedArray#indexOf (a memchr), not a JS loop.
  function findDerKey(bytes, from) {
    for (var i = bytes.indexOf(0x30, from); i >= 0 && i + 7 <= bytes.length; i = bytes.indexOf(0x30, i + 1)) {
      if (bytes[i+1] === 0x82 && bytes[i+4] === 0x02 && bytes[i+5] === 0x01 && bytes[i+6] === 0x00) return i;
    }
    return -1;
  }
  var PEM = '-----BEGIN';
  function findPem(bytes, from) {
    for (var i = bytes.indexOf(0x2d, from); i >= 0 && i + PEM.length <= bytes.length; i = bytes.indexOf(0x2d, i + 1)) {
      var ok = true;
      for (var j = 0; j < PEM.length; j++) { if (bytes[i + j] !== PEM.charCodeAt(j)) { ok = false; break; } }
      if (ok) return i;
    }
    return -1;
  }
  var RC4_HIST = new Uint16Array(256);
  // ---- Hot path ------------------------------------------------------------------------------
  // scanChunk visits every byte offset of every chunk, and Frida's QuickJS pays dearly for each
  // function call and allocation. So the per-offset loop is inlined over the typed array, allocates
  // nothing, and guards every exact recognizer above with a cheap NECESSARY condition — the exact
  // check (unchanged) only runs where its guard holds, so results are identical while almost every
  // offset is rejected in a handful of byte reads.
  var AES_NKS = [4, 6, 8];
  var SB1 = new Uint8Array(256);  // SBOX[x] ^ Rcon[1]: top byte of SubWord(RotWord(.)) ^ Rcon at i = nk
  var XT = new Uint8Array(256);   // xtime(x)
  var XT3 = new Uint8Array(256);  // xtime(x) ^ x  (multiply by 3)
  for (var xi = 0; xi < 256; xi++) { SB1[xi] = SBOX[xi] ^ 0x01; XT[xi] = xtime(xi); XT3[xi] = XT[xi] ^ xi; }

  // Byte offset of word i of the reconstructed ENCRYPTION schedule inside a decryption schedule
  // (the ekWord() mapping of matchesAesDecryptionSchedule) and whether that word is MixColumns'd.
  function decWordPos(nk, i) { var nr = nk + 6; return (4 * (nr - (i >> 2)) + (i & 3)) * 4; }
  function decWordMixed(nk, i) { var r = i >> 2; return r !== 0 && r !== nk + 6; }
  // First-step taps (i = nk): w[nk] == w[0] ^ SubWord(RotWord(w[nk-1])) ^ Rcon. The guard compares
  // only the TOP byte of each side (rejects 255/256 of offsets); the full recurrence verifies.
  // Forward: top(w[nk]) at 4nk, top(w[0]) at 0, byte 1 of w[nk-1] at 4(nk-1)+1.
  // Decryption: w[nk] is always an inner (mixed) word, w[0] never is; w[nk-1] is mixed for nk 6/8.
  var D4A = decWordPos(4, 4), D4B = decWordPos(4, 0), D4C = decWordPos(4, 3) + 1;
  var D6A = decWordPos(6, 6), D6B = decWordPos(6, 0), D6C = decWordPos(6, 5);
  var D8A = decWordPos(8, 8), D8B = decWordPos(8, 0), D8C = decWordPos(8, 7);
  if (!decWordMixed(4, 4) || decWordMixed(4, 3) || !decWordMixed(6, 5) || !decWordMixed(8, 7) || !decWordMixed(8, 8)) {
    throw new Error('AES decryption tap layout changed');
  }
  var AES_MAX_BYTES = aesScheduleBytes(8); // every nk is in bounds when off + this <= length

  // Exact-check fallbacks for the last <AES_MAX_BYTES> bytes of a chunk (per-nk bounds apply).
  function aesForwardNkAt(bytes, off, len) {
    for (var n = 0; n < 3; n++) {
      var nk = AES_NKS[n];
      if (off + aesScheduleBytes(nk) <= len && matchesAesSchedule(bytes, off, nk)) return n;
    }
    return -1;
  }
  function aesDecryptionNkAt(bytes, off, len) {
    for (var n = 0; n < 3; n++) {
      var nk = AES_NKS[n];
      if (off + aesScheduleBytes(nk) <= len && matchesAesDecryptionSchedule(bytes, off, nk)) return n;
    }
    return -1;
  }
  // Index into AES_NKS of the schedule at off (decryption form adds 3), or -1. Same precedence as
  // before: encryption AES-128/192/256 first, decryption forms only when no encryption form matches.
  function aesScheduleAt(bytes, off, len) {
    if (off + AES_MAX_BYTES > len) {
      var f = aesForwardNkAt(bytes, off, len);
      if (f >= 0) return f;
      var d = aesDecryptionNkAt(bytes, off, len);
      return d >= 0 ? d + 3 : -1;
    }
    var b0 = bytes[off], p, m, c;
    if ((bytes[off + 16] ^ b0) === SB1[bytes[off + 13]] && matchesAesSchedule(bytes, off, 4)) return 0;
    if ((bytes[off + 24] ^ b0) === SB1[bytes[off + 21]] && matchesAesSchedule(bytes, off, 6)) return 1;
    if ((bytes[off + 32] ^ b0) === SB1[bytes[off + 29]] && matchesAesSchedule(bytes, off, 8)) return 2;
    p = off + D4A; m = XT[bytes[p]] ^ XT3[bytes[p + 1]] ^ bytes[p + 2] ^ bytes[p + 3];
    if ((m ^ bytes[off + D4B]) === SB1[bytes[off + D4C]] && matchesAesDecryptionSchedule(bytes, off, 4)) return 3;
    p = off + D6A; m = XT[bytes[p]] ^ XT3[bytes[p + 1]] ^ bytes[p + 2] ^ bytes[p + 3];
    p = off + D6C; c = bytes[p] ^ XT[bytes[p + 1]] ^ XT3[bytes[p + 2]] ^ bytes[p + 3];
    if ((m ^ bytes[off + D6B]) === SB1[c] && matchesAesDecryptionSchedule(bytes, off, 6)) return 4;
    p = off + D8A; m = XT[bytes[p]] ^ XT3[bytes[p + 1]] ^ bytes[p + 2] ^ bytes[p + 3];
    p = off + D8C; c = bytes[p] ^ XT[bytes[p + 1]] ^ XT3[bytes[p + 2]] ^ bytes[p + 3];
    if ((m ^ bytes[off + D8B]) === SB1[c] && matchesAesDecryptionSchedule(bytes, off, 8)) return 5;
    return -1;
  }

  // Per-chunk guard tables, filled in one pass so each offset's six guards are plain lookups:
  // T[j] = SB1[b_j]; MT[j] = top byte of MixColumns(word at j); MS[j] = SB1[byte 1 of MixColumns(word at j)].
  var AES_T = null, AES_MT = null, AES_MS = null;
  function fillAesGuardTables(bytes) {
    var len = bytes.length;
    if (AES_T === null || AES_T.length < len) { AES_T = new Uint8Array(len); AES_MT = new Uint8Array(len); AES_MS = new Uint8Array(len); }
    var T = AES_T, MT = AES_MT, MS = AES_MS;
    var a0 = bytes[0], a1 = bytes[1], a2 = bytes[2], a3;
    for (var j = 0; j + 3 < len; j++) {
      a3 = bytes[j + 3];
      T[j] = SB1[a0];
      MT[j] = XT[a0] ^ XT3[a1] ^ a2 ^ a3;
      MS[j] = SB1[a0 ^ XT[a1] ^ XT3[a2] ^ a3];
      a0 = a1; a1 = a2; a2 = a3;
    }
    for (; j < len; j++) T[j] = SB1[bytes[j]];
  }

  var STAMP = new Uint32Array(256); // generation-stamped "seen" set, reused instead of new Uint8Array(256)
  var stampGen = 0;
  function nextStamp() {
    if (++stampGen >= 0xfffffff0) { STAMP.fill(0); stampGen = 1; }
    return stampGen;
  }
  // Same answers as isRc4Sbox / isRc4SboxInt32LE in secret-recognizers.ts, without allocating a seen-array per call.
  function isRc4SboxFast(bytes, off) {
    if (off + 256 > bytes.length) return false;
    var g = nextStamp();
    for (var i = 0; i < 256; i++) { var v = bytes[off + i]; if (STAMP[v] === g) return false; STAMP[v] = g; }
    return true;
  }
  function isRc4SboxInt32LEFast(bytes, off) {
    if (off + 1024 > bytes.length) return false;
    if (bytes[off + 1] !== 0 || bytes[off + 2] !== 0 || bytes[off + 3] !== 0) return false;
    var g = nextStamp();
    for (var i = 0; i < 256; i++) {
      var p = off + i * 4;
      if (bytes[p + 1] !== 0 || bytes[p + 2] !== 0 || bytes[p + 3] !== 0) return false;
      var v = bytes[p];
      if (STAMP[v] === g) return false;
      STAMP[v] = g;
    }
    return true;
  }

  // Strided entropy windows over an incremental histogram: advancing by ENTROPY_STRIDE removes and
  // adds STRIDE bytes instead of recounting L; any other jump rebuilds. Shannon is computed from the
  // same counts in the same 0..255 order as shannonEntropy() in secret-recognizers.ts, so the float
  // result is bit-identical.
  var ENT_HIST = new Uint16Array(256);
  function EntropyWindow(bytes, len) { this.bytes = bytes; this.len = len; this.start = -1; this.distinct = 0; }
  EntropyWindow.prototype.moveTo = function (off) {
    var b = this.bytes, L = this.len, i;
    if (this.start >= 0 && off - this.start === ENTROPY_STRIDE && ENTROPY_STRIDE <= L) {
      for (i = this.start; i < off; i++) if (--ENT_HIST[b[i]] === 0) this.distinct--;
      for (i = this.start + L; i < off + L; i++) if (ENT_HIST[b[i]]++ === 0) this.distinct++;
    } else {
      ENT_HIST.fill(0);
      this.distinct = 0;
      for (i = off; i < off + L; i++) if (ENT_HIST[b[i]]++ === 0) this.distinct++;
    }
    this.start = off;
  };
  EntropyWindow.prototype.entropy = function () {
    var e = 0, L = this.len;
    for (var k = 0; k < 256; k++) { var c = ENT_HIST[k]; if (!c) continue; var p = c / L; e -= p * (Math.log(p) / Math.LN2); }
    return e;
  };

  // A JWT match starts at "eyJ" and lies inside one maximal run of base64url/'.' bytes. So instead
  // of materializing the whole ~1 MiB chunk as a string, each run is turned into a (small) string
  // from its first "eyJ" onward and fed to the same regex — no match can start earlier in the run,
  // so matches and their order are unchanged.
  var JWT_CHAR = new Uint8Array(256);
  for (var jc = 0; jc < 256; jc++) {
    JWT_CHAR[jc] = ((jc >= 0x30 && jc <= 0x39) || (jc >= 0x41 && jc <= 0x5a) || (jc >= 0x61 && jc <= 0x7a) || jc === 0x2d || jc === 0x5f || jc === 0x2e) ? 1 : 0;
  }
  function latin1(bytes, from, to) {
    var s = '';
    for (var i = from; i < to; i += 4096) s += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(to, i + 4096)));
    return s;
  }
  // Calls onMatch(index, text) for each regex match in bytes[0, end) in order; stops when it returns true.
  function forEachJwt(bytes, end, onMatch) {
    for (var i = bytes.indexOf(0x65); i >= 0 && i + 3 <= end; i = bytes.indexOf(0x65, i + 1)) {
      if (bytes[i + 1] !== 0x79 || bytes[i + 2] !== 0x4a) continue;
      var e = i + 3;
      while (e < end && JWT_CHAR[bytes[e]]) e++;
      var re = /eyJ[A-Za-z0-9_-]{5,}\\.eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*/g;
      var text = latin1(bytes, i, e), mm;
      while ((mm = re.exec(text)) !== null) { if (onMatch(i + mm.index, mm[0])) return; }
      i = e - 1; // the run is done; resume after it
    }
  }

  // Exact per-offset recognizers in the original order (RC4 byte[], RC4 int32[], AES enc then dec,
  // ChaCha, Salsa). Only called for offsets a guard flagged. Returns true once the limit is reached.
  function emitOffsetHits(bytes, off, len, w, push, addr) {
    if (w.rc4) {
      if (isRc4SboxFast(bytes, off)) {
        if (push({ type: 'rc4_sbox', address: addr(off), size: 256, preview_hex: hexSlice(bytes, off, PREVIEW), note: '256-byte permutation of 0..255 (RC4 S-box, byte[])' })) return true;
      }
      if (isRc4SboxInt32LEFast(bytes, off)) {
        if (push({ type: 'rc4_sbox', address: addr(off), size: 1024, preview_hex: hexSlice(bytes, off, PREVIEW), note: 'permutation of 0..255 as int32[] (RC4 S-box, Java int[256])' })) return true;
      }
    }
    if (w.aes) {
      var an = aesScheduleAt(bytes, off, len);
      if (an >= 0) {
        var nk = AES_NKS[an % 3];
        var kind = an < 3 ? ' encryption key schedule' : ' decryption (equivalent-inverse) key schedule';
        if (push({ type: 'aes_key_schedule', address: addr(off), size: aesScheduleBytes(nk), preview_hex: hexSlice(bytes, off, PREVIEW), note: 'valid AES-' + (nk * 32) + kind })) return true;
      }
    }
    if (bytes[off] !== 0x65) return false; // both ChaCha constants and the Salsa diagonal start with 'e'
    if (w.chacha) {
      var ckl = chachaKeyLenAt(bytes, off);
      if (ckl !== 0 && off + 16 + ckl <= len) {
        if (push({ type: 'chacha_key', address: addr(off + 16), size: ckl, preview_hex: hexSlice(bytes, off + 16, ckl), note: 'ChaCha20 ' + (ckl * 8) + '-bit key (after "expand ' + ckl + '-byte k" constant at ' + addr(off) + ')' })) return true;
      }
    }
    if (w.salsa && matchesSalsa20At(bytes, off)) {
      if (push({ type: 'salsa_key', address: addr(off), size: 64, preview_hex: hexSlice(bytes, off, PREVIEW), note: 'Salsa20 state (sigma constant on the diagonal; 256-bit key in words 1-4 and 11-14)' })) return true;
    }
    return false;
  }

  // JS guard pass (used when the native guard pass is unavailable): flags the offsets in
  // [0, coreLen) where any per-offset recognizer could match, in ascending order.
  function forEachCandidateJs(bytes, coreLen, w, visit) {
    var len = bytes.length;
    // Sliding 256-byte histogram: [off, off+256) is an RC4 byte S-box exactly when all 256 values
    // are distinct — O(1) per offset instead of re-checking 256 bytes.
    var hist = RC4_HIST, distinct = 0, h;
    if (w.rc4) { hist.fill(0); for (h = 0; h < 256 && h < len; h++) if (hist[bytes[h]]++ === 0) distinct++; }
    if (w.aes) fillAesGuardTables(bytes);
    var T = AES_T, MT = AES_MT, MS = AES_MS, aesFastEnd = len - AES_MAX_BYTES, b0, cand;
    var wantRc4 = w.rc4, wantAes = w.aes, wantCS = w.chacha || w.salsa;
    for (var off = 0; off < coreLen; off++) {
      b0 = bytes[off];
      cand = false;
      if (wantRc4) {
        if (distinct === 256 && off + 256 <= len) cand = true;
        if (--hist[b0] === 0) distinct--;
        if (off + 256 < len && hist[bytes[off + 256]]++ === 0) distinct++;
        // int32[256]: the first two LE ints are 0..255 and differ (else not a permutation).
        if (bytes[off + 3] === 0 && bytes[off + 7] === 0 && b0 !== bytes[off + 4]) cand = true;
      }
      // Six first-step guards (enc 128/192/256, dec 128/192/256) as table lookups; near the chunk
      // end, where bounds differ per nk, every offset goes to the exact check.
      if (!cand && wantAes && (off > aesFastEnd ||
          (bytes[off + 16] ^ b0) === T[off + 13] || (bytes[off + 24] ^ b0) === T[off + 21] || (bytes[off + 32] ^ b0) === T[off + 29] ||
          (MT[off + D4A] ^ bytes[off + D4B]) === T[off + D4C] || (MT[off + D6A] ^ bytes[off + D6B]) === MS[off + D6C] ||
          (MT[off + D8A] ^ bytes[off + D8B]) === MS[off + D8C])) cand = true;
      if (!cand && wantCS && b0 === 0x65) cand = true;
      if (cand && visit(off)) return;
    }
  }

  // Native guard pass: a CModule flags candidate offsets ~100x faster than QuickJS runs the per-byte
  // loop. Its guards are STRONGER than the JS pass (full first AES recurrence word, full int32
  // header, the 4-byte "expa" constant prefix) but still only necessary conditions — the exact JS
  // recognizers decide every hit. Falls back to the JS pass when CModule is unavailable or fails.
  var GUARD_C = [
    'typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;',
    'static u32 be(const u8 *p) { return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3]; }',
    'static u32 subw(const u8 *sb, u32 w) { return ((u32)sb[w >> 24] << 24) | ((u32)sb[(w >> 16) & 255] << 16) | ((u32)sb[(w >> 8) & 255] << 8) | sb[w & 255]; }',
    'static u32 mixw(const u8 *xt, u32 w) {',
    '  u32 a0 = w >> 24, a1 = (w >> 16) & 255, a2 = (w >> 8) & 255, a3 = w & 255;',
    '  u32 b0 = xt[a0] ^ xt[a1] ^ a1 ^ a2 ^ a3, b1 = a0 ^ xt[a1] ^ xt[a2] ^ a2 ^ a3;',
    '  u32 b2 = a0 ^ a1 ^ xt[a2] ^ xt[a3] ^ a3, b3 = xt[a0] ^ a0 ^ a1 ^ a2 ^ xt[a3];',
    '  return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;',
    '}',
    '/* First key-expansion step (i = nk): w[nk] == w[0] ^ SubWord(RotWord(w[nk-1])) ^ Rcon[1]. */',
    'static int first_step(const u8 *sb, u32 wnk, u32 w0, u32 wprev) { return wnk == (w0 ^ subw(sb, (wprev << 8) | (wprev >> 24)) ^ 0x01000000u); }',
    '/* Each AES guard first compares only the top byte of that step (rejects 255/256), then the full word. */',
    'static int fwd_guard(const u8 *sb1, const u8 *sb, const u8 *q, u32 nk) {',
    '  if ((q[4 * nk] ^ q[0]) != sb1[q[4 * nk - 3]]) return 0;',
    '  return first_step(sb, be(q + 4 * nk), be(q), be(q + 4 * nk - 4));',
    '}',
    '/* Decryption form: w[nk] at a (always through MixColumns), w[0] at z (raw), w[nk-1] at c (mixed when cmix). */',
    'static int dec_guard(const u8 *sb1, const u8 *sb, const u8 *xt, const u8 *xt3, const u8 *q, u32 a, u32 z, u32 c, int cmix) {',
    '  const u8 *pa = q + a, *pc = q + c;',
    '  u8 top = xt[pa[0]] ^ xt3[pa[1]] ^ pa[2] ^ pa[3];',
    '  u8 prev1 = cmix ? (u8)(pc[0] ^ xt[pc[1]] ^ xt3[pc[2]] ^ pc[3]) : pc[1];',
    '  if ((u8)(top ^ q[z]) != sb1[prev1]) return 0;',
    '  return first_step(sb, mixw(xt, be(pa)), be(q + z), cmix ? mixw(xt, be(pc)) : be(pc));',
    '}',
    'u32 secret_candidates(const u8 *b, u32 len, u32 core, u32 flags, const u8 *tab, const u32 *tap, u32 *out) {',
    '  const u8 *sb1 = tab, *xt = tab + 256, *xt3 = tab + 512, *sb = tab + 768;',
    '  u16 hist[256]; u32 distinct = 0, n = 0, i, off;',
    '  for (i = 0; i < 256; i++) hist[i] = 0;',
    '  if (flags & 1) for (i = 0; i < 256 && i < len; i++) if (hist[b[i]]++ == 0) distinct++;',
    '  for (off = 0; off < core; off++) {',
    '    const u8 *q = b + off; u8 b0 = q[0]; int c = 0;',
    '    if (flags & 1) {',
    '      if (distinct == 256 && off + 256 <= len) c = 1;',
    '      if (--hist[b0] == 0) distinct--;',
    '      if (off + 256 < len && hist[q[256]]++ == 0) distinct++;',
    '      if (off + 1024 <= len && (q[1] | q[2] | q[3] | q[5] | q[6] | q[7]) == 0 && b0 != q[4]) c = 1;',
    '    }',
    '    if (!c && (flags & 2)) {',
    '      if (off + tap[9] > len) c = 1;',
    '      else if (fwd_guard(sb1, sb, q, 4) || fwd_guard(sb1, sb, q, 6) || fwd_guard(sb1, sb, q, 8) ||',
    '               dec_guard(sb1, sb, xt, xt3, q, tap[0], tap[1], tap[2], 0) ||',
    '               dec_guard(sb1, sb, xt, xt3, q, tap[3], tap[4], tap[5], 1) ||',
    '               dec_guard(sb1, sb, xt, xt3, q, tap[6], tap[7], tap[8], 1)) c = 1;',
    '    }',
    '    if (!c && (flags & 4) && off + 4 <= len && b0 == 0x65 && q[1] == 0x78 && q[2] == 0x70 && q[3] == 0x61) c = 1;',
    '    if (c) out[n++] = off;',
    '  }',
    '  return n;',
    '}',
  ].join('\\n');
  var NATIVE_GUARDS; // undefined = not tried yet, null = unavailable
  function nativeGuards() {
    if (NATIVE_GUARDS !== undefined) return NATIVE_GUARDS;
    NATIVE_GUARDS = null;
    if (typeof CModule !== 'function' || typeof NativeFunction !== 'function') return null;
    try {
      var cm = new CModule(GUARD_C);
      var tab = Memory.alloc(1024), tap = Memory.alloc(40);
      var t = new Uint8Array(1024); t.set(SB1, 0); t.set(XT, 256); t.set(XT3, 512); t.set(SBOX, 768);
      tab.writeByteArray(t.buffer);
      // Word (not byte) positions of the decryption taps: w[nk], w[0], w[nk-1] per nk.
      tap.writeByteArray(new Uint32Array([D4A, D4B, D4C - 1, D6A, D6B, D6C, D8A, D8B, D8C, AES_MAX_BYTES]).buffer);
      NATIVE_GUARDS = {
        cm: cm, tab: tab, tap: tap, buf: Memory.alloc(CHUNK), out: Memory.alloc(CHUNK * 4),
        fn: new NativeFunction(cm.secret_candidates, 'uint32', ['pointer', 'uint32', 'uint32', 'uint32', 'pointer', 'pointer', 'pointer']),
      };
    } catch (e) { NATIVE_GUARDS = null; }
    return NATIVE_GUARDS;
  }
  // Candidate offsets from the native pass, or null when it is unavailable for this chunk.
  function nativeCandidates(bytes, coreLen, w) {
    var ng = nativeGuards();
    if (ng === null || bytes.length > CHUNK) return null;
    try {
      ng.buf.writeByteArray(bytes.buffer.byteLength === bytes.length ? bytes.buffer : bytes.slice().buffer);
      var flags = (w.rc4 ? 1 : 0) | (w.aes ? 2 : 0) | (w.chacha || w.salsa ? 4 : 0);
      var n = ng.fn(ng.buf, bytes.length, coreLen, flags, ng.tab, ng.tap, ng.out);
      return n === 0 ? new Uint32Array(0) : new Uint32Array(ng.out.readByteArray(n * 4));
    } catch (e) { NATIVE_GUARDS = null; return null; }
  }

  function scanChunk(bytes, coreLen, base, pos, want, opts, out, limit, counters) {
    function addr(off) { var a = base.add(pos + off); var d = describeAddress(a); return d.rva !== null ? d.rva : a.toString(); }
    function push(c) { out.push(c); return out.length >= limit; }

    // rc4_sbox + aes_key_schedule + chacha/salsa: every start offset within the core is guarded
    // (native or JS pass); the exact recognizers run only on flagged offsets, in ascending order.
    var len = bytes.length;
    var w = { rc4: !!want.rc4_sbox, aes: !!want.aes_key_schedule, chacha: !!want.chacha_key, salsa: !!want.salsa_key };
    var limitHit = false;
    function visit(off) { if (out.length >= limit) return true; limitHit = emitOffsetHits(bytes, off, len, w, push, addr); return limitHit; }
    if ((w.rc4 || w.aes || w.chacha || w.salsa) && out.length < limit) {
      var cands = nativeCandidates(bytes, coreLen, w);
      if (cands !== null) { for (var ci = 0; ci < cands.length; ci++) if (visit(cands[ci])) break; }
      else forEachCandidateJs(bytes, coreLen, w, visit);
    }
    if (limitHit) return;
    // pem_der: substring scans
    if (want.pem_der) {
      var p = 0;
      while (p < coreLen && out.length < limit) {
        var pem = findPem(bytes, p);
        if (pem < 0 || pem >= coreLen) break;
        if (push({ type: 'pem_der', address: addr(pem), size: PREVIEW, preview_text: textSlice(bytes, pem, PREVIEW), note: 'PEM header' })) return;
        p = pem + 1;
      }
      var q = 0;
      while (q < coreLen && out.length < limit) {
        var der = findDerKey(bytes, q);
        if (der < 0 || der >= coreLen) break;
        if (push({ type: 'pem_der', address: addr(der), size: PREVIEW, preview_hex: hexSlice(bytes, der, PREVIEW), note: 'DER SEQUENCE + INTEGER v0 (private key/cert header)' })) return;
        q = der + 1;
      }
    }
    // jwt: matched per base64url run (see forEachJwt) — the chunk is never turned into one big string.
    if (want.jwt && out.length < limit) {
      var stopJwt = false;
      forEachJwt(bytes, Math.min(coreLen + OVERLAP, len), function (index, text) {
        if (index >= coreLen || out.length >= limit) return true;
        stopJwt = push({ type: 'jwt', address: addr(index), size: text.length, preview_text: text.slice(0, 160), note: 'JWT token' });
        return stopJwt;
      });
      if (stopJwt) return;
    }
    // high_entropy_key: strided windows, bounded by its own budget so it cannot crowd out the
    // precise recognizers above or halt the whole scan (the real-heap flooding seen on-device).
    if (want.high_entropy_key && counters.entropyHits < opts.maxEntropyHits) {
      var lens = opts.entropyLens || [16, 24, 32];
      var entEnd = Math.min(coreLen + OVERLAP, len);
      for (var li = 0; li < lens.length && counters.entropyHits < opts.maxEntropyHits; li++) {
        var L = lens[li];
        var win = new EntropyWindow(bytes, L);
        for (var o2 = 0; o2 + L <= entEnd && counters.entropyHits < opts.maxEntropyHits && out.length < limit; o2 += ENTROPY_STRIDE) {
          if (o2 >= coreLen) break;
          win.moveTo(o2);
          var dc = win.distinct;
          if (dc < L * 0.75) continue; // cheap pre-filter before the log-heavy entropy calc
          var ent = win.entropy();
          if (ent >= opts.minEntropy) {
            counters.entropyHits++;
            push({ type: 'high_entropy_key', address: addr(o2), size: L, preview_hex: hexSlice(bytes, o2, L), entropy: Math.round(ent * 100) / 100, distinct: dc, note: L + '-byte high-entropy buffer (candidate key)' });
            o2 += L - ENTROPY_STRIDE; // skip past this window to avoid overlapping duplicates
          }
        }
      }
    }
  }

  function selectRanges(scope) {
    if (scope === 'all') return Process.enumerateRanges('r--');
    if (scope === 'heap' || !scope) return Process.enumerateRanges('rw-');
    var mod = Process.findModuleByName(scope);
    if (!mod) return { error: 'module_not_found: ' + scope };
    return [{ base: mod.base, size: mod.size }];
  }

  rpc.exports.scan = async function () {
    var o = __FRIDA_MCP__.options;
    var sel = o.recognizers || [];
    var want = {};
    for (var si = 0; si < sel.length; si++) want[sel[si]] = true;
    var limit = o.limit;
    var out = [];
    var counters = { entropyHits: 0 };
    var bytesScanned = 0, rangesScanned = 0, rangesUnreadable = 0;
    var stopped = 'complete';

    var ranges = selectRanges(o.scope);
    if (ranges && ranges.error) return { candidates: [], bytes_scanned: 0, ranges_scanned: 0, ranges_unreadable: 0, stopped: 'complete', error: ranges.error };

    for (var r = 0; r < ranges.length; r++) {
      if (out.length >= limit) { stopped = 'limit'; break; }
      if (bytesScanned >= o.maxBytes) { stopped = 'max_bytes'; break; }
      var base = ranges[r].base, size = ranges[r].size;
      var pos = 0, readAny = false;
      while (pos < size) {
        if (out.length >= limit) { stopped = 'limit'; break; }
        if (bytesScanned >= o.maxBytes) { stopped = 'max_bytes'; break; }
        var readLen = Math.min(CHUNK, size - pos);
        var buf = null;
        try { buf = base.add(pos).readByteArray(readLen); } catch (e) { buf = null; }
        if (buf === null) { break; }
        readAny = true;
        var bytes = new Uint8Array(buf);
        // Core = the part we advance past; the trailing OVERLAP is only re-read for straddlers.
        var isLast = (pos + readLen) >= size;
        var coreLen = isLast ? bytes.length : Math.max(1, bytes.length - OVERLAP);
        scanChunk(bytes, coreLen, base, pos, want, o, out, limit, counters);
        bytesScanned += coreLen;
        pos += coreLen;
      }
      if (readAny) rangesScanned++; else rangesUnreadable++;
    }
    return { candidates: out.slice(0, limit), bytes_scanned: bytesScanned, ranges_scanned: rangesScanned, ranges_unreadable: rangesUnreadable, stopped: stopped };
  };
})();
`;
