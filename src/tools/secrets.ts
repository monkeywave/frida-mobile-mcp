import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../helpers/errors.js';
import { resolveInstrumentationTarget } from './hook.js';
import { responseFormatSchema } from '../constants.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
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
        const { sessionEntry } = await getOrCreateSession(deviceManager, {
          target: resolved.target,
          device,
          sessionId: resolved.sessionId,
        });

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
              ? { coverage: { status: 'unknown', note: `stopped early (${result.stopped})` }, limitations: [`Scan stopped early (${result.stopped}); raise max_bytes/limit or narrow scope to a module to scan more.`] }
              : { coverage: { status: 'complete' } },
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
const SECRET_SCAN_SOURCE =
  RESOLVE_TARGET_SNIPPET +
  `
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

  function isRc4Sbox(bytes, off) {
    if (off + 256 > bytes.length) return false;
    var seen = new Uint8Array(256);
    for (var i = 0; i < 256; i++) { var v = bytes[off + i]; if (seen[v]) return false; seen[v] = 1; }
    return true;
  }
  // RC4 S-box stored as a Java int[256] (little-endian int32 values, each 0..255).
  function isRc4SboxInt32LE(bytes, off) {
    if (off + 1024 > bytes.length) return false;
    if (bytes[off + 1] !== 0 || bytes[off + 2] !== 0 || bytes[off + 3] !== 0) return false; // cheap reject before allocating
    var seen = new Uint8Array(256);
    for (var i = 0; i < 256; i++) {
      var p = off + i * 4;
      if (bytes[p + 1] !== 0 || bytes[p + 2] !== 0 || bytes[p + 3] !== 0) return false;
      var v = bytes[p];
      if (seen[v]) return false;
      seen[v] = 1;
    }
    return true;
  }
  function shannon(bytes, off, len) {
    var counts = new Array(256); for (var i = 0; i < 256; i++) counts[i] = 0;
    for (var j = 0; j < len; j++) counts[bytes[off + j]]++;
    var e = 0;
    for (var k = 0; k < 256; k++) { var c = counts[k]; if (!c) continue; var p = c / len; e -= p * (Math.log(p) / Math.LN2); }
    return e;
  }
  function distinctCount(bytes, off, len) {
    var seen = new Uint8Array(256), n = 0;
    for (var i = 0; i < len; i++) { var v = bytes[off + i]; if (!seen[v]) { seen[v] = 1; n++; } }
    return n;
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
  function findDerKey(bytes, from) {
    for (var i = from; i + 7 <= bytes.length; i++) {
      if (bytes[i] === 0x30 && bytes[i+1] === 0x82 && bytes[i+4] === 0x02 && bytes[i+5] === 0x01 && bytes[i+6] === 0x00) return i;
    }
    return -1;
  }
  var PEM = '-----BEGIN';
  function findPem(bytes, from) {
    for (var i = from; i + PEM.length <= bytes.length; i++) {
      var ok = true;
      for (var j = 0; j < PEM.length; j++) { if (bytes[i + j] !== PEM.charCodeAt(j)) { ok = false; break; } }
      if (ok) return i;
    }
    return -1;
  }
  function scanChunk(bytes, coreLen, base, pos, want, opts, out, limit, counters) {
    function addr(off) { var a = base.add(pos + off); var d = describeAddress(a); return d.rva !== null ? d.rva : a.toString(); }
    function push(c) { out.push(c); return out.length >= limit; }

    // rc4_sbox + aes_key_schedule: slide byte-by-byte (fail-fast), only start offsets within the core
    var nks = [4, 6, 8];
    for (var off = 0; off < coreLen && out.length < limit; off++) {
      if (want.rc4_sbox && isRc4Sbox(bytes, off)) {
        if (push({ type: 'rc4_sbox', address: addr(off), size: 256, preview_hex: hexSlice(bytes, off, PREVIEW), note: '256-byte permutation of 0..255 (RC4 S-box, byte[])' })) return;
      }
      if (want.rc4_sbox && isRc4SboxInt32LE(bytes, off)) {
        if (push({ type: 'rc4_sbox', address: addr(off), size: 1024, preview_hex: hexSlice(bytes, off, PREVIEW), note: 'permutation of 0..255 as int32[] (RC4 S-box, Java int[256])' })) return;
      }
      if (want.aes_key_schedule) {
        var hitAes = false;
        for (var n = 0; n < nks.length; n++) {
          if (matchesAesSchedule(bytes, off, nks[n])) {
            if (push({ type: 'aes_key_schedule', address: addr(off), size: aesScheduleBytes(nks[n]), preview_hex: hexSlice(bytes, off, PREVIEW), note: 'valid AES-' + (nks[n] * 32) + ' encryption key schedule' })) return;
            hitAes = true; break;
          }
        }
        if (!hitAes) {
          for (var dn = 0; dn < nks.length; dn++) {
            if (matchesAesDecryptionSchedule(bytes, off, nks[dn])) {
              if (push({ type: 'aes_key_schedule', address: addr(off), size: aesScheduleBytes(nks[dn]), preview_hex: hexSlice(bytes, off, PREVIEW), note: 'valid AES-' + (nks[dn] * 32) + ' decryption (equivalent-inverse) key schedule' })) return;
              break;
            }
          }
        }
      }
      if (want.chacha_key) {
        var ckl = chachaKeyLenAt(bytes, off);
        if (ckl !== 0 && off + 16 + ckl <= bytes.length) {
          if (push({ type: 'chacha_key', address: addr(off + 16), size: ckl, preview_hex: hexSlice(bytes, off + 16, ckl), note: 'ChaCha20 ' + (ckl * 8) + '-bit key (after "expand ' + ckl + '-byte k" constant at ' + addr(off) + ')' })) return;
        }
      }
      if (want.salsa_key && matchesSalsa20At(bytes, off)) {
        if (push({ type: 'salsa_key', address: addr(off), size: 64, preview_hex: hexSlice(bytes, off, PREVIEW), note: 'Salsa20 state (sigma constant on the diagonal; 256-bit key in words 1-4 and 11-14)' })) return;
      }
    }
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
    // jwt: cheap byte pre-scan for the "eyJ" prefix before building the latin-1 string (the vast
    // majority of heap chunks contain no JWT, so the ~1 MiB string is almost never materialized).
    if (want.jwt) {
      var jwtEnd = Math.min(coreLen + OVERLAP, bytes.length);
      var hasPrefix = false;
      for (var jp = 0; jp + 3 <= jwtEnd; jp++) {
        if (bytes[jp] === 0x65 && bytes[jp + 1] === 0x79 && bytes[jp + 2] === 0x4a) { hasPrefix = true; break; }
      }
      if (hasPrefix) {
        var text = '';
        for (var t = 0; t < jwtEnd; t++) text += String.fromCharCode(bytes[t]);
        var re = /eyJ[A-Za-z0-9_-]{5,}\\.eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*/g;
        var mm;
        while ((mm = re.exec(text)) !== null && out.length < limit) {
          if (mm.index >= coreLen) break;
          if (push({ type: 'jwt', address: addr(mm.index), size: mm[0].length, preview_text: mm[0].slice(0, 160), note: 'JWT token' })) return;
        }
      }
    }
    // high_entropy_key: strided windows, bounded by its own budget so it cannot crowd out the
    // precise recognizers above or halt the whole scan (the real-heap flooding seen on-device).
    if (want.high_entropy_key && counters.entropyHits < opts.maxEntropyHits) {
      var lens = opts.entropyLens || [16, 24, 32];
      for (var li = 0; li < lens.length && counters.entropyHits < opts.maxEntropyHits; li++) {
        var L = lens[li];
        for (var o2 = 0; o2 + L <= Math.min(coreLen + OVERLAP, bytes.length) && counters.entropyHits < opts.maxEntropyHits && out.length < limit; o2 += ENTROPY_STRIDE) {
          if (o2 >= coreLen) break;
          var dc = distinctCount(bytes, o2, L);
          if (dc < L * 0.75) continue; // cheap pre-filter before the log-heavy entropy calc
          var ent = shannon(bytes, o2, L);
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
`;
