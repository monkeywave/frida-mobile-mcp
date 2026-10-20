import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, MemoryWriteDisabledError, wrapFridaError } from '../helpers/errors.js';
import { validateMemoryAddress } from '../helpers/sanitize.js';
import { audit } from '../helpers/logger.js';
import { rateLimiter } from '../helpers/rate-limiter.js';
import { responseFormatSchema } from '../constants.js';
import { createAgentScript } from '../agent/script-factory.js';
import { callRpcWithTimeout } from '../helpers/rpc-timeout.js';
import { parseTarget, RESOLVE_TARGET_SNIPPET, type ParsedTarget } from '../agent/address.js';

const MAX_SCAN_MATCHES = 100;

const ADDRESS_NOTATIONS = '"0x7fff12345678" (absolute), "libfoo.so+0x1234" or "libfoo.so+4660" (module-relative offset), "libssl.so!SSL_read" (module export), or "!open" / "open" (global export)';

const READ_MEMORY_SOURCE = RESOLVE_TARGET_SNIPPET + `
  rpc.exports.read = function() {
    var o = __FRIDA_MCP__.options;
    var base = resolveTarget(o.target);
    if (base === null) throw new Error('target not found: ' + o.address);
    var buf = base.readByteArray(o.size);
    if (buf === null) throw new Error('memory at ' + base + ' is not readable');
    var hex = Array.from(new Uint8Array(buf)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join('');
    return { data: hex, address: base.toString(), rva: describeAddress(base).rva };
  };
`;

const WRITE_MEMORY_SOURCE = RESOLVE_TARGET_SNIPPET + `
  function hexToBytes(hexData) {
    var bytes = [];
    for (var i = 0; i < hexData.length; i += 2) {
      bytes.push(parseInt(hexData.substr(i, 2), 16));
    }
    return bytes;
  }

  function isWritable(address) {
    var range = Process.findRangeByAddress(address);
    return range !== null && range.protection.indexOf('w') !== -1;
  }

  rpc.exports.write = function() {
    var o = __FRIDA_MCP__.options;
    var address = resolveTarget(o.target);
    if (address === null) throw new Error('target not found: ' + o.address);
    var bytes = hexToBytes(o.hexData);
    var range = Process.findRangeByAddress(address);
    var originalProtection = range ? range.protection : null;
    var reprotected = false;

    if (!isWritable(address)) {
      if (!Memory.protect(address, bytes.length, 'rw-')) {
        return { error: 'protect_failed', message: 'Memory.protect(rw-) failed for ' + address + ' (' + (originalProtection || 'unmapped') + ')' };
      }
      reprotected = true;
    }
    try {
      address.writeByteArray(bytes);
    } finally {
      if (reprotected && originalProtection) Memory.protect(address, bytes.length, originalProtection);
    }
    return { ok: true, address: address.toString(), reprotected: reprotected, original_protection: originalProtection };
  };
`;

const SCAN_MEMORY_SOURCE = `
  function scanRanges() {
    var o = __FRIDA_MCP__.options;
    if (o.moduleName) {
      var mod = Process.findModuleByName(o.moduleName);
      if (!mod) return { error: 'module_not_found', message: 'Module not found: ' + o.moduleName };
      return { ranges: [{ base: mod.base, size: mod.size }] };
    }
    return { ranges: Process.enumerateRanges('r--') };
  }

  rpc.exports.scan = async function() {
    var o = __FRIDA_MCP__.options;
    var limit = o.limit;
    var results = [];
    var errors = [];
    var selected = scanRanges();
    if (selected.error) return selected;
    var ranges = selected.ranges;

    for (var i = 0; i < ranges.length && results.length < limit; i++) {
      try {
        await Memory.scan(ranges[i].base, ranges[i].size, o.pattern, {
          onMatch: function(address, size) {
            results.push({ address: address.toString(), size: size });
            if (results.length >= limit) return 'stop';
          },
          onError: function(reason) {
            if (errors.length < 10) errors.push({ base: ranges[i].base.toString(), reason: String(reason) });
          },
          onComplete: function() {}
        });
      } catch (e) {
        if (errors.length < 10) errors.push({ base: ranges[i].base.toString(), reason: String(e && e.message ? e.message : e) });
      }
    }
    return { results: results, errors: errors };
  };
`;

type ReadResult = { data: string; address: string; rva: string | null };

type WriteResult =
  | { ok: true; address: string; reprotected: boolean; original_protection: string | null }
  | { error: string; message: string };

/**
 * Validate a memory target spec and the transfer size. Only absolute addresses can be
 * checked on the host; module-relative and symbolic targets are resolved in the agent.
 */
function validateMemoryTarget(address: string, size: number): ParsedTarget {
  const target = parseTarget(address);
  validateMemoryAddress(target.kind === 'absolute' ? address : '0', size);
  return target;
}

function nextChunkAddress(resolvedAddress: string, size: number): string {
  return `0x${(BigInt(resolvedAddress) + BigInt(size)).toString(16)}`;
}

type ScanResult =
  | { results: Array<{ address: string; size: number }>; errors: Array<{ base: string; reason: string }> }
  | { error: string; message: string };

export function registerMemoryTools(server: McpServer): void {
  server.registerTool(
    'read_memory',
    {
      title: 'Read Process Memory',
      description: `Read raw memory from a target process. Requires an active session. Address in any notation: ${ADDRESS_NOTATIONS}. Max 4MB per read. Returns hex-encoded bytes plus the resolved absolute address and module+offset (rva).`,
      inputSchema: z.object({
        session_id: z.string().describe('Session ID'),
        address: z.string().describe(`Memory address: ${ADDRESS_NOTATIONS}`),
        size: z.number().describe('Number of bytes to read'),
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
    async ({ session_id, address, size, response_format }) => {
      try {
        const state = getState();
        const session = state.getSession(session_id);
        if (!session) {
          throw new FridaMcpError('SESSION_NOT_FOUND', `Session "${session_id}" not found.`, [{ tool: 'get_status', reason: 'List sessions' }]);
        }

        rateLimiter.check('memory_read', state.config.rateLimits.memoryReadsPerMinute);
        rateLimiter.record('memory_read');

        const target = validateMemoryTarget(address, size);

        const script = await createAgentScript(session.session, {
          sessionEntry: session,
          source: READ_MEMORY_SOURCE,
          platform: session.platform,
          name: 'read_memory:read',
          kind: 'generated',
          options: { target, address, size },
          bridges: [],
        });
        await script.load();
        let readResult: ReadResult;
        try {
          readResult = await callRpcWithTimeout(script.exports.read() as Promise<ReadResult>, 'Memory read');
        } finally {
          await script.unload();
        }
        const hexData = readResult.data;

        audit({
          timestamp: new Date().toISOString(),
          sessionId: session_id,
          tool: 'read_memory',
          params: { address, resolved: readResult.address, size },
          status: 'success',
        });

        return formatToolResponse(
          buildResult(
            {
              address: readResult.address,
              rva: readResult.rva,
              target: address,
              size,
              data: hexData,
              data_length: hexData.length / 2,
            },
            [
              { tool: 'read_memory', args: { session_id, address: nextChunkAddress(readResult.address, size), size }, reason: 'Read next chunk' },
              { tool: 'scan_memory', reason: 'Search for patterns in memory' },
            ]
          ),
          response_format
        );
      } catch (err) {
        if (err instanceof FridaMcpError) return formatToolResponse(err.toErrorResponse(), response_format);
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );

  server.registerTool(
    'write_memory',
    {
      title: 'Write Process Memory',
      description: `Write raw bytes to process memory. DISABLED by default for safety - enable via config (memoryWriteEnabled: true). Provide hex-encoded data. Address in any notation: ${ADDRESS_NOTATIONS}.`,
      inputSchema: z.object({
        session_id: z.string().describe('Session ID'),
        address: z.string().describe(`Memory address: ${ADDRESS_NOTATIONS}`),
        data: z.string().describe('Hex-encoded bytes to write (e.g., "90909090")'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async ({ session_id, address, data, response_format }) => {
      try {
        const state = getState();
        if (!state.config.memoryWriteEnabled) {
          throw new MemoryWriteDisabledError();
        }

        const session = state.getSession(session_id);
        if (!session) {
          throw new FridaMcpError('SESSION_NOT_FOUND', `Session "${session_id}" not found.`, [{ tool: 'get_status', reason: 'List sessions' }]);
        }

        const bytes = Buffer.from(data, 'hex');
        const target = validateMemoryTarget(address, bytes.length);

        const script = await createAgentScript(session.session, {
          sessionEntry: session,
          source: WRITE_MEMORY_SOURCE,
          platform: session.platform,
          name: 'write_memory:write',
          kind: 'generated',
          options: { target, address, hexData: data },
          bridges: [],
        });
        await script.load();
        let writeResult: WriteResult;
        try {
          writeResult = await callRpcWithTimeout(script.exports.write() as Promise<WriteResult>, 'Memory write');
        } finally {
          await script.unload();
        }
        if ('error' in writeResult) {
          throw new FridaMcpError('MEMORY_PROTECT_FAILED', writeResult.message, [
            { tool: 'read_memory', args: { session_id, address, size: bytes.length }, reason: 'Inspect the target range' },
          ]);
        }

        audit({
          timestamp: new Date().toISOString(),
          sessionId: session_id,
          tool: 'write_memory',
          params: { address, resolved: writeResult.address, size: bytes.length },
          status: 'success',
        });

        return formatToolResponse(
          buildResult(
            {
              address: writeResult.address,
              target: address,
              bytes_written: bytes.length,
              reprotected: writeResult.reprotected,
              original_protection: writeResult.original_protection,
              message: `Wrote ${bytes.length} bytes to ${writeResult.address} (${address})`,
            },
            [
              { tool: 'read_memory', args: { session_id, address: writeResult.address, size: bytes.length }, reason: 'Verify the write' },
            ]
          ),
          response_format
        );
      } catch (err) {
        if (err instanceof FridaMcpError) return formatToolResponse(err.toErrorResponse(), response_format);
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );

  server.registerTool(
    'scan_memory',
    {
      title: 'Scan Process Memory',
      description: 'Scan process memory for a byte pattern. Pattern format: "48 89 5c 24 ?? 57" where ?? is a wildcard. Optionally limit scan to a specific module.',
      inputSchema: z.object({
        session_id: z.string().describe('Session ID'),
        pattern: z.string().describe('Byte pattern with ?? wildcards (e.g., "48 89 5c 24 ?? 57")'),
        module: z.string().optional().describe('Module name to limit scan scope (e.g., "libssl.so")'),
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
    async ({ session_id, pattern, module: moduleName, response_format }) => {
      try {
        const state = getState();
        const session = state.getSession(session_id);
        if (!session) {
          throw new FridaMcpError('SESSION_NOT_FOUND', `Session "${session_id}" not found.`, [{ tool: 'get_status', reason: 'List sessions' }]);
        }

        const script = await createAgentScript(session.session, {
          sessionEntry: session,
          source: SCAN_MEMORY_SOURCE,
          platform: session.platform,
          name: 'scan_memory:scan',
          kind: 'generated',
          options: { pattern, moduleName: moduleName || null, limit: MAX_SCAN_MATCHES },
          bridges: [],
        });
        await script.load();
        let scanResult: ScanResult;
        try {
          scanResult = await callRpcWithTimeout(script.exports.scan() as Promise<ScanResult>, 'Memory scan', 60_000);
        } finally {
          await script.unload();
        }

        if ('error' in scanResult) {
          throw new FridaMcpError('SCAN_ERROR', scanResult.message, []);
        }
        const results = scanResult.results;

        return formatToolResponse(
          buildResult(
            {
              pattern,
              module: moduleName || 'all readable ranges',
              matches: results.length,
              results: results,
              truncated: results.length >= MAX_SCAN_MATCHES,
              scan_errors: scanResult.errors,
            },
            results.length > 0
              ? [{ tool: 'read_memory', args: { session_id, address: results[0].address, size: 64 }, reason: 'Read memory at first match' }]
              : []
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
