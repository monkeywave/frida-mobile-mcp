import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, MemoryWriteDisabledError, wrapFridaError } from '../helpers/errors.js';
import { validateMemoryAddress } from '../helpers/sanitize.js';
import { audit } from '../helpers/logger.js';
import { rateLimiter } from '../helpers/rate-limiter.js';

export function registerMemoryTools(server: McpServer): void {
  server.tool(
    'read_memory',
    'Read raw memory from a target process. Requires an active session. Address as hex string (e.g., "0x7fff12345678"). Max 4MB per read. Returns hex-encoded bytes.',
    {
      session_id: z.string().describe('Session ID'),
      address: z.string().describe('Memory address as hex string (e.g., "0x12345678")'),
      size: z.number().describe('Number of bytes to read'),
    },
    async ({ session_id, address, size }) => {
      try {
        const state = getState();
        const session = state.getSession(session_id);
        if (!session) {
          throw new FridaMcpError('SESSION_NOT_FOUND', `Session "${session_id}" not found.`, [{ tool: 'get_status', reason: 'List sessions' }]);
        }

        rateLimiter.check('memory_read', state.config.rateLimits.memoryReadsPerMinute);
        rateLimiter.record('memory_read');

        validateMemoryAddress(address, size);

        const script = await session.session.createScript(`
          rpc.exports.read = function(addr, sz) {
            var ptr_addr = ptr(addr);
            var buf = ptr_addr.readByteArray(sz);
            return buf ? Array.from(new Uint8Array(buf)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join('') : '';
          };
        `);
        await script.load();
        const hexData = await script.exports.read(address, size) as string;
        await script.unload();

        audit({
          timestamp: new Date().toISOString(),
          sessionId: session_id,
          tool: 'read_memory',
          params: { address, size },
          status: 'success',
        });

        return formatToolResponse(
          buildResult(
            {
              address,
              size,
              data: hexData,
              data_length: hexData.length / 2,
            },
            [
              { tool: 'read_memory', args: { session_id, address: `0x${(BigInt(address) + BigInt(size)).toString(16)}`, size }, reason: 'Read next chunk' },
              { tool: 'scan_memory', reason: 'Search for patterns in memory' },
            ]
          )
        );
      } catch (err) {
        if (err instanceof FridaMcpError) return formatToolResponse(err.toErrorResponse());
        return formatToolResponse(wrapFridaError(err).toErrorResponse());
      }
    }
  );

  server.tool(
    'write_memory',
    'Write raw bytes to process memory. DISABLED by default for safety - enable via config (memoryWriteEnabled: true). Provide hex-encoded data.',
    {
      session_id: z.string().describe('Session ID'),
      address: z.string().describe('Memory address as hex string'),
      data: z.string().describe('Hex-encoded bytes to write (e.g., "90909090")'),
    },
    async ({ session_id, address, data }) => {
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
        validateMemoryAddress(address, bytes.length);

        const script = await session.session.createScript(`
          rpc.exports.write = function(addr, hexData) {
            var ptr_addr = ptr(addr);
            var bytes = [];
            for (var i = 0; i < hexData.length; i += 2) {
              bytes.push(parseInt(hexData.substr(i, 2), 16));
            }
            ptr_addr.writeByteArray(bytes);
            return true;
          };
        `);
        await script.load();
        await script.exports.write(address, data);
        await script.unload();

        audit({
          timestamp: new Date().toISOString(),
          sessionId: session_id,
          tool: 'write_memory',
          params: { address, size: bytes.length },
          status: 'success',
        });

        return formatToolResponse(
          buildResult(
            {
              address,
              bytes_written: bytes.length,
              message: `Wrote ${bytes.length} bytes to ${address}`,
            },
            [
              { tool: 'read_memory', args: { session_id, address, size: bytes.length }, reason: 'Verify the write' },
            ]
          )
        );
      } catch (err) {
        if (err instanceof FridaMcpError) return formatToolResponse(err.toErrorResponse());
        return formatToolResponse(wrapFridaError(err).toErrorResponse());
      }
    }
  );

  server.tool(
    'scan_memory',
    'Scan process memory for a byte pattern. Pattern format: "48 89 5c 24 ?? 57" where ?? is a wildcard. Optionally limit scan to a specific module.',
    {
      session_id: z.string().describe('Session ID'),
      pattern: z.string().describe('Byte pattern with ?? wildcards (e.g., "48 89 5c 24 ?? 57")'),
      module: z.string().optional().describe('Module name to limit scan scope (e.g., "libssl.so")'),
    },
    async ({ session_id, pattern, module: moduleName }) => {
      try {
        const state = getState();
        const session = state.getSession(session_id);
        if (!session) {
          throw new FridaMcpError('SESSION_NOT_FOUND', `Session "${session_id}" not found.`, [{ tool: 'get_status', reason: 'List sessions' }]);
        }

        const script = await session.session.createScript(`
          rpc.exports.scan = function(pattern, moduleName) {
            var results = [];
            var ranges;
            if (moduleName) {
              var mod = Process.findModuleByName(moduleName);
              if (!mod) return { error: 'Module not found: ' + moduleName };
              ranges = [{ base: mod.base, size: mod.size }];
            } else {
              ranges = Process.enumerateRanges('r--');
            }

            for (var i = 0; i < ranges.length && results.length < 100; i++) {
              try {
                Memory.scan(ranges[i].base, ranges[i].size, pattern, {
                  onMatch: function(address, size) {
                    results.push({ address: address.toString(), size: size });
                    if (results.length >= 100) return 'stop';
                  },
                  onComplete: function() {}
                });
              } catch(e) {}
            }
            return results;
          };
        `);
        await script.load();
        const results = await script.exports.scan(pattern, moduleName || null) as Array<{ address: string; size: number }> | { error: string };
        await script.unload();

        if ('error' in results) {
          throw new FridaMcpError('SCAN_ERROR', results.error, []);
        }

        return formatToolResponse(
          buildResult(
            {
              pattern,
              module: moduleName || 'all readable ranges',
              matches: results.length,
              results: results,
              truncated: results.length >= 100,
            },
            results.length > 0
              ? [{ tool: 'read_memory', args: { session_id, address: results[0].address, size: 64 }, reason: 'Read memory at first match' }]
              : []
          )
        );
      } catch (err) {
        if (err instanceof FridaMcpError) return formatToolResponse(err.toErrorResponse());
        return formatToolResponse(wrapFridaError(err).toErrorResponse());
      }
    }
  );
}
