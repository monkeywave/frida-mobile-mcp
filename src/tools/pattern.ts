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
import { parseTarget, RESOLVE_TARGET_SNIPPET } from '../agent/address.js';
import { callRpcWithTimeout } from '../helpers/rpc-timeout.js';
import { getState } from '../state.js';
import { rateLimiter } from '../helpers/rate-limiter.js';
import { buildPattern, type PatternType } from '../helpers/pattern-builder.js';

const NO_BRIDGES: BridgeName[] = [];

const PATTERN_TYPES = ['rc4_sbox', 'aes_key_schedule', 'high_entropy_key', 'pem_der', 'jwt', 'chacha_key'] as const;
const DEFAULT_CONTEXT_BYTES = 64;
// Keep the window well under read_memory's own ceiling; an anchor only needs its local context.
const MAX_CONTEXT_BYTES = 4096;

const ADDRESS_NOTATIONS =
  '"0x7fff12345678" (absolute), "libfoo.so+0x1234" (module-relative), "libssl.so!SSL_read" (export), or "open" (global export)';

interface WindowResult {
  data: string;
  window_start: string;
  secret_offset: number;
  address: string;
  rva: string | null;
  module: string | null;
  module_offset: string | null;
}

export function registerPatternTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'generate_memory_pattern',
    {
      title: 'Generate Memory Pattern (Anchor + Offset)',
      description:
        'Turn a secret you already located (e.g. from find_secrets_in_memory) into a reusable anchor pattern: a stable byte signature near the key plus the offset from it to the key. ' +
        'Reads a small window around the address, then derives a recognizer-aware anchor (ChaCha sigma constant, PEM/DER/JWT header, or the longest stable run adjacent to the key). ' +
        'Returns a scan_memory pattern to re-locate the secret by shape across restarts, plus a friTap offsets entry and an ms_agent anchor to hand to capture_tls. This finds no new secret — give it one you have.',
      inputSchema: z.object({
        target: z.string().optional().describe('App bundle ID, process name, or PID. Optional when session_id is given.'),
        session_id: z.string().optional().describe('Reuse an existing session (from explore_app/find_secrets_in_memory) instead of re-attaching by target.'),
        device: z.string().optional().describe('Device ID'),
        address: z.string().describe(`The secret's address, any notation: ${ADDRESS_NOTATIONS}.`),
        size: z.number().int().positive().describe('Secret/key length in bytes (e.g. 32 for a ChaCha key, 256 for an RC4 S-box).'),
        type: z
          .enum(PATTERN_TYPES)
          .optional()
          .describe(`Recognizer type, selects the anchor strategy: ${PATTERN_TYPES.join(', ')}. Omit for a generic adjacent-run anchor.`),
        context_bytes: z
          .number()
          .int()
          .min(0)
          .max(MAX_CONTEXT_BYTES)
          .optional()
          .describe(`Bytes to read before and after the secret when hunting for an anchor (default: ${DEFAULT_CONTEXT_BYTES}).`),
        label: z.string().optional().describe('Keylog/slot label for the pattern (default derived from type, e.g. "RC4_KEY").'),
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
    async ({ target, session_id, device, address, size, type, context_bytes, label, response_format }) => {
      try {
        const state = getState();
        rateLimiter.check('memory_read', state.config.rateLimits.memoryReadsPerMinute);
        rateLimiter.record('memory_read');

        const resolved = resolveInstrumentationTarget(target, session_id);
        const parsedTarget = parseTarget(address); // validates the notation host-side
        const contextBytes = context_bytes ?? DEFAULT_CONTEXT_BYTES;

        const { sessionEntry } = await getOrCreateSession(deviceManager, {
          target: resolved.target,
          device,
          sessionId: resolved.sessionId,
        });

        const script = await createAgentScript(sessionEntry.session, {
          sessionEntry,
          source: PATTERN_WINDOW_SOURCE,
          platform: sessionEntry.platform,
          name: 'generate_memory_pattern:' + address,
          kind: 'generated',
          options: { target: parsedTarget, address, size, contextBytes },
          bridges: NO_BRIDGES,
        });
        await script.load();
        let win: WindowResult;
        try {
          win = await callRpcWithTimeout(script.exports.readWindow() as Promise<WindowResult>, 'Pattern window read');
        } finally {
          await script.unload();
        }

        const windowBytes = hexToBytes(win.data);
        const descriptor = buildPattern({
          windowBytes,
          secretOffsetInWindow: win.secret_offset,
          size,
          type: type as PatternType | undefined,
          label,
          address: win.rva ?? win.address,
          module: win.module ?? undefined,
          moduleOffset: win.module_offset !== null ? Number(win.module_offset) : undefined,
        });

        const captureArgs: Record<string, unknown> = { session_id: sessionEntry.id };
        if (descriptor.fritap.offsets_entry) captureArgs.offsets = descriptor.fritap.offsets_entry;

        return formatToolResponse(
          buildResult(
            descriptor,
            [
              { tool: 'scan_memory', args: { session_id: sessionEntry.id, pattern: descriptor.scan_memory_pattern }, reason: 'Re-locate this secret by pattern' },
              { tool: 'capture_tls', args: captureArgs, reason: 'Hand the pattern to friTap' },
            ],
            {
              coverage: { status: 'unknown', note: 'anchor derived from a single memory snapshot; confirm across a restart' },
              limitations:
                descriptor.confidence === 'low'
                  ? ['Low-confidence anchor (short or no stable bytes near the key); re-scan to verify it is distinctive.']
                  : [],
            }
          ),
          response_format
        );
      } catch (err) {
        if (err instanceof FridaMcpError) return formatToolResponse(err.toErrorResponse(), response_format);
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

/**
 * In-agent window reader (classic JS, Frida 17 instance API only). Resolves the secret, then reads
 * `contextBytes` on each side via NativePointer#readByteArray. If the leading context is unmapped
 * it retries from the secret itself (secret_offset 0). Options arrive as the __FRIDA_MCP__ literal.
 */
const PATTERN_WINDOW_SOURCE =
  RESOLVE_TARGET_SNIPPET +
  `
  function toHex(buf) {
    var bytes = new Uint8Array(buf), out = '';
    for (var i = 0; i < bytes.length; i++) out += ('0' + bytes[i].toString(16)).slice(-2);
    return out;
  }

  rpc.exports.readWindow = function () {
    var o = __FRIDA_MCP__.options;
    var base = resolveTarget(o.target);
    if (base === null) throw new Error('target not found: ' + o.address);

    var before = o.contextBytes;
    var secretOffset = before;
    var start = base.sub(before);
    var total = before + o.size + o.contextBytes;
    var buf = null;
    try { buf = start.readByteArray(total); } catch (e) { buf = null; }
    if (buf === null) {
      // Leading context is unmapped: read from the secret itself so there is still a window.
      start = base;
      secretOffset = 0;
      total = o.size + o.contextBytes;
      try { buf = start.readByteArray(total); } catch (e2) { buf = null; }
    }
    if (buf === null) throw new Error('memory at ' + base + ' is not readable');

    var d = describeAddress(base);
    return {
      data: toHex(buf),
      window_start: start.toString(),
      secret_offset: secretOffset,
      address: base.toString(),
      rva: d.rva,
      module: d.module,
      module_offset: d.offset,
    };
  };
`;
