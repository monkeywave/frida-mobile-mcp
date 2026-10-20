/**
 * Native analysis tools that speak the vocabulary of static RE tools (Ghidra/ReVa, IDA MCP, REA):
 * every address is reported both as an absolute pointer and as `module+0xoff`, and every
 * target input accepts `module!symbol`, `module+0xoff`, `0xaddr` or a global `symbol`.
 *
 *   resolve_address          - translate between absolute addresses and module+offset (+symbol)
 *   analyze_native_function  - function bounds, basic blocks/edges (ControlFlowGraph, Frida 17.12+)
 *                              and the first instructions
 *   dump_module_memory       - write a module image (base-relative, gaps zero-filled) to the host
 *   list_threads             - threads with optional symbolised backtraces
 */
import { z } from 'zod';
import { toolOutputSchema } from '../../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type frida from 'frida';
import { promises as fs } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import path from 'node:path';
import { getState } from '../../state.js';
import type { SessionEntry } from '../../types.js';
import { buildResult, formatToolResponse } from '../../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../../helpers/errors.js';
import { validateFilePath } from '../../helpers/sanitize.js';
import { audit } from '../../helpers/logger.js';
import { responseFormatSchema } from '../../constants.js';
import { createAgentScript } from '../../agent/script-factory.js';
import { RESOLVE_TARGET_SNIPPET } from '../../agent/address.js';
import { callRpcWithTimeout } from '../../helpers/rpc-timeout.js';

// ---------------------------------------------------------------------------
// Agent sources (classic JS; RESOLVE_TARGET_SNIPPET is prepended at load time)
// ---------------------------------------------------------------------------

const RESOLVE_ADDRESS_SOURCE = `
  rpc.exports.run = function () {
    var o = __FRIDA_MCP__.options;
    var parsed = parseTargetSpec(o.target);
    var p = resolveTarget(parsed);
    if (p === null) return { error: 'not_found', message: 'Could not resolve native target: ' + o.target };
    var d = describeAddress(p);
    d.target = o.target;
    d.kind = parsed.kind;
    var mod = Process.findModuleByAddress(p);
    d.module_base = mod ? mod.base.toString() : null;
    d.module_path = mod ? mod.path : null;
    var range = Process.findRangeByAddress(p);
    d.protection = range ? range.protection : null;
    return d;
  };
`;

const ANALYZE_FUNCTION_SOURCE = `
  function relativeTo(p) {
    var mod = Process.findModuleByAddress(p);
    return mod ? mod.name + '+0x' + p.sub(mod.base).toString(16) : null;
  }

  function summariseInstruction(insn) {
    return {
      address: insn.address.toString(),
      rva: relativeTo(insn.address),
      size: insn.size,
      mnemonic: insn.mnemonic,
      op_str: insn.opStr,
      text: insn.toString()
    };
  }

  function isReturn(insn) {
    var m = insn.mnemonic || '';
    var ops = insn.opStr || '';
    var groups = insn.groups || [];
    if (groups.indexOf('return') !== -1 || groups.indexOf('ret') !== -1) return true;
    if (m.indexOf('ret') === 0) return true;
    if (m === 'bx' && ops === 'lr') return true;
    if (m.indexOf('pop') === 0 && /\\bpc\\b/.test(ops)) return true;
    return false;
  }

  function parseLinear(entry, maxCount, stopAtReturn, limitEnd) {
    var out = [];
    var cursor = entry;
    for (var i = 0; i < maxCount; i++) {
      if (limitEnd !== null && cursor.compare(limitEnd) >= 0) break;
      var insn;
      try { insn = Instruction.parse(cursor); } catch (e) { break; }
      out.push(insn);
      cursor = insn.next;
      if (stopAtReturn && isReturn(insn)) break;
    }
    return out;
  }

  function summariseBlock(block, index) {
    var entry = {
      index: index,
      start: block.start.toString(),
      end: block.end.toString(),
      size: block.end.sub(block.start).toInt32(),
      rva: relativeTo(block.start),
      instruction_count: null,
      successors: block.successors.map(function (s) { return s.start.toString(); }),
      predecessors: block.predecessors.map(function (s) { return s.start.toString(); })
    };
    try { entry.instruction_count = block.instructions.length; } catch (e) {}
    return entry;
  }

  function buildGraph(entry, maxBlocks) {
    var cfg = new ControlFlowGraph(entry);
    var all = cfg.blocks.slice();
    all.sort(function (a, b) { return a.start.compare(b.start); });
    var kept = all.slice(0, maxBlocks);
    var edges = [];
    kept.forEach(function (b) {
      b.successors.forEach(function (s) { edges.push({ from: b.start.toString(), to: s.start.toString() }); });
    });
    return {
      source: 'ControlFlowGraph',
      entry_block: cfg.entryBlock.start.toString(),
      block_count: all.length,
      truncated: all.length > kept.length,
      blocks: kept.map(summariseBlock),
      edges: edges
    };
  }

  function buildLinearGraph(entry, maxInstructions) {
    var insns = parseLinear(entry, maxInstructions, true, null);
    var last = insns[insns.length - 1];
    var end = last ? last.next : entry;
    return {
      source: 'linear',
      entry_block: entry.toString(),
      block_count: 1,
      truncated: insns.length >= maxInstructions,
      blocks: [{ index: 0, start: entry.toString(), end: end.toString(), size: end.sub(entry).toInt32(), rva: relativeTo(entry), instruction_count: insns.length, successors: [], predecessors: [] }],
      edges: []
    };
  }

  rpc.exports.run = function () {
    var o = __FRIDA_MCP__.options;
    var entry = resolveTarget(o.target);
    if (entry === null) return { error: 'not_found', message: 'Could not resolve native target: ' + o.target };

    var result = { target: o.target, arch: Process.arch, entry: describeAddress(entry), range: null, graph: null, instructions: [], limitations: [] };

    var range = null;
    try { range = Process.findFunctionRange(entry); } catch (e) { result.limitations.push('findFunctionRange failed: ' + String(e && e.message ? e.message : e)); }
    if (range) {
      result.range = { base: range.base.toString(), size: range.size, end: range.base.add(range.size).toString(), rva: relativeTo(range.base) };
    } else {
      result.limitations.push('function bounds could not be determined (no symbol size information); instructions are bounded by count only');
    }

    if (typeof ControlFlowGraph === 'function') {
      try { result.graph = buildGraph(entry, o.maxBlocks); } catch (e) { result.limitations.push('ControlFlowGraph failed: ' + String(e && e.message ? e.message : e)); }
    } else {
      result.limitations.push('ControlFlowGraph API not available in this Frida runtime (requires frida-server >= 17.12)');
    }
    if (result.graph === null) {
      result.graph = buildLinearGraph(entry, o.maxLinearInstructions);
      result.limitations.push('basic blocks approximated by linear disassembly from the entry until the first return (max ' + o.maxLinearInstructions + ' instructions)');
    }

    var limitEnd = range ? range.base.add(range.size) : null;
    result.instructions = parseLinear(entry, o.maxInstructions, false, limitEnd).map(summariseInstruction);
    return result;
  };
`;

const DUMP_MODULE_SOURCE = `
  rpc.exports.describe = function () {
    var o = __FRIDA_MCP__.options;
    var mod = Process.findModuleByName(o.moduleName);
    if (mod === null) return { error: 'module_not_found', message: 'Module not found: ' + o.moduleName };
    var ranges = mod.enumerateRanges('r--').map(function (r) {
      return { base: r.base.toString(), size: r.size, protection: r.protection, file: r.file ? { path: r.file.path, offset: r.file.offset } : null };
    });
    return { name: mod.name, path: mod.path, base: mod.base.toString(), size: mod.size, ranges: ranges };
  };

  rpc.exports.readChunk = function (address, size) {
    try { return ptr(address).readByteArray(size); } catch (e) { return null; }
  };
`;

const LIST_THREADS_SOURCE = `
  rpc.exports.run = function () {
    var o = __FRIDA_MCP__.options;
    return Process.enumerateThreads().map(function (t) {
      var pc = t.context && t.context.pc ? t.context.pc : null;
      var entry = { id: t.id, name: t.name || null, state: t.state, pc: pc ? pc.toString() : null, location: pc ? formatFrame(pc) : null };
      if (o.backtraces) entry.backtrace = symbolizeBacktrace(t.context, o.frames);
      return entry;
    });
  };
`;

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested in test/tools/native.test.ts)
// ---------------------------------------------------------------------------

export const DUMP_CHUNK_SIZE = 1024 * 1024;
export const DEFAULT_DUMP_MAX_BYTES = 64 * 1024 * 1024;
export const MAX_DUMP_BYTES = 1024 * 1024 * 1024;

/**
 * Directories a dump may be written into: the current working directory, the OS temp
 * directory and ~/.config/frida-mobile-mcp/dumps. Anything else is rejected so a tool call
 * can never overwrite arbitrary host files.
 */
export function defaultDumpRoots(): string[] {
  return [process.cwd(), tmpdir(), path.join(homedir(), '.config', 'frida-mobile-mcp', 'dumps')].map((p) => path.resolve(p));
}

function isWithin(root: string, candidate: string): boolean {
  return candidate === root || candidate.startsWith(root + path.sep);
}

/** Validate `outPath` (absolute, no traversal, under an allowed root) and return it resolved. */
export function resolveDumpOutputPath(outPath: string, roots: string[] = defaultDumpRoots()): string {
  try {
    validateFilePath(outPath);
  } catch (err) {
    throw new FridaMcpError('INVALID_PATH', err instanceof Error ? err.message : String(err), []);
  }
  if (!path.isAbsolute(outPath)) {
    throw new FridaMcpError('INVALID_PATH', 'out_path must be an absolute path', []);
  }
  const resolved = path.resolve(outPath);
  const allowed = roots.map((r) => path.resolve(r));
  if (!allowed.some((root) => isWithin(root, resolved))) {
    throw new FridaMcpError(
      'INVALID_PATH',
      `out_path must be inside one of: ${allowed.join(', ')}`,
      [{ action: 'retry', reason: 'Choose a path under the current directory, the temp directory or ~/.config/frida-mobile-mcp/dumps' }]
    );
  }
  return resolved;
}

export interface MemoryRangeSpec {
  base: string;
  size: number;
}

export interface DumpChunk {
  /** Absolute address to read from. */
  address: bigint;
  length: number;
  /** Offset inside the output file (= address - module base). */
  fileOffset: number;
}

export interface DumpPlan {
  /** Number of bytes the image file covers, starting at the module base. */
  imageSize: number;
  truncated: boolean;
  chunks: DumpChunk[];
}

/**
 * Plan the reads for a module image: the file is laid out base-relative (file offset 0 is
 * the module base) so it can be imported with `base` as the image base; only readable
 * ranges are read, gaps stay zero-filled. Ranges are clamped to the module and to maxBytes.
 */
export function planDumpChunks(
  moduleBase: bigint,
  moduleSize: number,
  ranges: MemoryRangeSpec[],
  maxBytes: number,
  chunkSize: number = DUMP_CHUNK_SIZE
): DumpPlan {
  const imageSize = Math.min(moduleSize, maxBytes);
  const imageEnd = moduleBase + BigInt(imageSize);
  const chunks: DumpChunk[] = [];
  for (const range of ranges) {
    const start = bigMax(BigInt(range.base), moduleBase);
    const end = bigMin(BigInt(range.base) + BigInt(range.size), imageEnd);
    for (let cursor = start; cursor < end; cursor += BigInt(chunkSize)) {
      const length = Number(bigMin(cursor + BigInt(chunkSize), end) - cursor);
      chunks.push({ address: cursor, length, fileOffset: Number(cursor - moduleBase) });
    }
  }
  return { imageSize, truncated: moduleSize > imageSize, chunks };
}

function bigMax(a: bigint, b: bigint): bigint {
  return a > b ? a : b;
}

function bigMin(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}

export function hex(value: bigint): string {
  return `0x${value.toString(16)}`;
}

/** frida-node resolves an rpc export returning an ArrayBuffer as a Buffer; normalise defensively. */
export function toBuffer(value: unknown): Buffer | null {
  if (value === null || value === undefined) return null;
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof ArrayBuffer) return Buffer.from(value);
  if (Array.isArray(value) && value.length === 2) return toBuffer(value[1]);
  return null;
}

// ---------------------------------------------------------------------------
// Session / script plumbing
// ---------------------------------------------------------------------------

function requireSession(sessionId: string): SessionEntry {
  const session = getState().getSession(sessionId);
  if (!session) {
    throw new FridaMcpError('SESSION_NOT_FOUND', `Session "${sessionId}" not found.`, [{ tool: 'get_status', reason: 'List sessions' }]);
  }
  return session;
}

interface NativeScriptSpec {
  name: string;
  source: string;
  options?: Record<string, unknown>;
}

/** Load a native-only agent script (no bridges), run `fn`, always unload. */
async function withNativeScript<T>(session: SessionEntry, spec: NativeScriptSpec, fn: (script: frida.Script) => Promise<T>): Promise<T> {
  const script = await createAgentScript(session.session, {
    sessionEntry: session,
    source: RESOLVE_TARGET_SNIPPET + spec.source,
    platform: session.platform,
    name: spec.name,
    kind: 'generated',
    options: spec.options,
    bridges: [],
  });
  await script.load();
  try {
    return await fn(script);
  } finally {
    await script.unload();
  }
}

async function runNativeRpc<T>(session: SessionEntry, spec: NativeScriptSpec, label: string, timeoutMs?: number): Promise<T> {
  return withNativeScript(session, spec, (script) => callRpcWithTimeout(script.exports.run() as Promise<T>, label, timeoutMs));
}

interface AgentError {
  error: string;
  message: string;
}

function isAgentError(value: unknown): value is AgentError {
  return typeof value === 'object' && value !== null && 'error' in value && 'message' in value;
}

function throwIfAgentError(value: unknown, sessionId: string): void {
  if (!isAgentError(value)) return;
  const code = value.error === 'module_not_found' ? 'MODULE_NOT_FOUND' : 'TARGET_NOT_FOUND';
  throw new FridaMcpError(code, value.message, [
    { tool: 'enumerate_modules', args: { session_id: sessionId }, reason: 'List loaded modules to find the exact name' },
    { tool: 'enumerate_exports', args: { session_id: sessionId }, reason: 'List exports of the module' },
  ]);
}

// ---------------------------------------------------------------------------
// Result shapes
// ---------------------------------------------------------------------------

export interface AddressDescription {
  address: string;
  module: string | null;
  offset: string | null;
  symbol: string | null;
  rva: string | null;
}

interface ResolvedAddress extends AddressDescription {
  target: string;
  kind: string;
  module_base: string | null;
  module_path: string | null;
  protection: string | null;
}

interface ModuleImage {
  name: string;
  path: string;
  base: string;
  size: number;
  ranges: Array<MemoryRangeSpec & { protection: string; file: { path: string; offset: number } | null }>;
}

interface DumpedRange extends MemoryRangeSpec {
  file_offset: number;
  bytes_read: number;
  unreadable_bytes: number;
}

const TARGET_DESCRIPTION =
  'Native target: "module!symbol" (export or ELF/Mach-O symbol), "module+0xOFFSET" (Ghidra/IDA style RVA, e.g. "libfoo.so+0x1234"), "0xADDRESS" (absolute), or a bare global export name';

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

export function registerNativeAnalysisTools(server: McpServer): void {
  registerResolveAddress(server);
  registerAnalyzeNativeFunction(server);
  registerDumpModuleMemory(server);
  registerListThreads(server);
}

function registerResolveAddress(server: McpServer): void {
  server.registerTool(
    'resolve_address',
    {
      title: 'Resolve Native Address',
      description:
        'Translate between absolute process addresses and static-analysis coordinates. Give "0x7f..." to get module+0xoffset (+ nearest symbol); give "libfoo.so+0x1234" or "libfoo.so!func" to get the absolute runtime address. Use it to hand addresses between Frida and Ghidra/IDA.',
      inputSchema: z.object({
        session_id: z.string().describe('Session ID'),
        target: z.string().describe(TARGET_DESCRIPTION),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ session_id, target, response_format }) => {
      try {
        const session = requireSession(session_id);
        const resolved = await runNativeRpc<ResolvedAddress | AgentError>(
          session,
          { name: 'resolve_address:run', source: RESOLVE_ADDRESS_SOURCE, options: { target } },
          'Address resolution'
        );
        throwIfAgentError(resolved, session_id);
        const result = resolved as ResolvedAddress;
        return formatToolResponse(buildResult({ session_id, ...result }, [
          { tool: 'analyze_native_function', args: { session_id, target: result.rva ?? result.address }, reason: 'Disassemble and build the control-flow graph' },
          { tool: 'hook_method', args: { target: session.target, method: result.rva ?? result.address }, reason: 'Hook this address' },
          { tool: 'read_memory', args: { session_id, address: result.address, size: 64 }, reason: 'Read bytes at this address' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}

function registerAnalyzeNativeFunction(server: McpServer): void {
  server.registerTool(
    'analyze_native_function',
    {
      title: 'Analyze Native Function',
      description:
        'Static-style analysis of a native function at runtime: function range (Process.findFunctionRange), basic blocks and edges (Frida 17.12+ ControlFlowGraph; falls back to linear disassembly until the first return and says so in `limitations`), and the first instructions. All addresses are reported as absolute and as module+0xoffset for cross-referencing with Ghidra/IDA.',
      inputSchema: z.object({
        session_id: z.string().describe('Session ID'),
        target: z.string().describe(TARGET_DESCRIPTION),
        max_blocks: z.number().int().min(1).max(2000).optional().default(200).describe('Maximum basic blocks to return (default 200)'),
        max_instructions: z.number().int().min(1).max(256).optional().default(32).describe('Instructions to disassemble from the entry (default 32)'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ session_id, target, max_blocks, max_instructions, response_format }) => {
      try {
        const session = requireSession(session_id);
        const analysis = await runNativeRpc<Record<string, unknown> | AgentError>(
          session,
          {
            name: 'analyze_native_function:run',
            source: ANALYZE_FUNCTION_SOURCE,
            options: { target, maxBlocks: max_blocks ?? 200, maxInstructions: max_instructions ?? 32, maxLinearInstructions: 400 },
          },
          'Function analysis',
          30_000
        );
        throwIfAgentError(analysis, session_id);
        return formatToolResponse(buildResult({ session_id, ...(analysis as Record<string, unknown>) }, [
          { tool: 'hook_method', args: { target: session.target, method: target }, reason: 'Hook this function to observe calls' },
          { tool: 'dump_module_memory', reason: 'Dump the containing module for offline analysis in Ghidra/IDA' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}

function registerDumpModuleMemory(server: McpServer): void {
  server.registerTool(
    'dump_module_memory',
    {
      title: 'Dump Module Memory',
      description:
        'Dump a loaded module from process memory to a file on the host (e.g. an unpacked/decrypted library). The file is laid out base-relative: file offset 0 is the module base, readable ranges are copied in 1 MiB chunks, unreadable gaps are zero-filled, so it can be imported into Ghidra/IDA as a raw binary at the returned `base`. out_path must be absolute and inside the current directory, the OS temp directory or ~/.config/frida-mobile-mcp/dumps.',
      inputSchema: z.object({
        session_id: z.string().describe('Session ID'),
        module_name: z.string().describe('Module name as listed by enumerate_modules (e.g. "libfoo.so")'),
        out_path: z.string().describe('Absolute output file path on the host (under cwd, the temp dir or ~/.config/frida-mobile-mcp/dumps)'),
        max_bytes: z.number().int().min(1).max(MAX_DUMP_BYTES).optional().default(DEFAULT_DUMP_MAX_BYTES).describe('Maximum image size to write (default 64 MiB)'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ session_id, module_name, out_path, max_bytes, response_format }) => {
      try {
        const session = requireSession(session_id);
        const outputPath = resolveDumpOutputPath(out_path);
        const dump = await withNativeScript(
          session,
          { name: 'dump_module_memory:run', source: DUMP_MODULE_SOURCE, options: { moduleName: module_name } },
          async (script) => {
            const image = await callRpcWithTimeout(script.exports.describe() as Promise<ModuleImage | AgentError>, 'Module lookup');
            throwIfAgentError(image, session_id);
            return dumpModuleImage(script, image as ModuleImage, outputPath, max_bytes ?? DEFAULT_DUMP_MAX_BYTES);
          }
        );
        audit({ timestamp: new Date().toISOString(), sessionId: session_id, tool: 'dump_module_memory', params: { module_name, out_path: outputPath, bytes: dump.bytes }, status: 'success' });
        return formatToolResponse(buildResult({ session_id, module: module_name, ...dump }, [
          { tool: 'enumerate_exports', args: { session_id, module_name }, reason: 'Export names to apply in the static tool' },
          { tool: 'resolve_address', args: { session_id, target: `${module_name}+0x0` }, reason: 'Translate offsets found in the dump back to runtime addresses' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}

interface DumpResult {
  path: string;
  bytes: number;
  base: string;
  end: string;
  module_size: number;
  module_path: string;
  truncated: boolean;
  ranges: DumpedRange[];
}

/** Read the planned chunks through the loaded script and write them base-relative into `outputPath`. */
async function dumpModuleImage(script: frida.Script, image: ModuleImage, outputPath: string, maxBytes: number): Promise<DumpResult> {
  const base = BigInt(image.base);
  const plan = planDumpChunks(base, image.size, image.ranges, maxBytes);
  const stats = new Map<string, DumpedRange>();
  for (const range of image.ranges) {
    stats.set(range.base, { base: range.base, size: range.size, file_offset: Number(BigInt(range.base) - base), bytes_read: 0, unreadable_bytes: 0 });
  }

  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  const handle = await fs.open(outputPath, 'w');
  try {
    for (const chunk of plan.chunks) {
      const raw = await callRpcWithTimeout(script.exports.readChunk(hex(chunk.address), chunk.length), 'Memory read', 30_000);
      const buffer = toBuffer(raw);
      const owner = findOwningRange(stats, chunk.address);
      if (buffer) {
        await handle.write(buffer, 0, buffer.length, chunk.fileOffset);
        if (owner) owner.bytes_read += buffer.length;
      } else if (owner) {
        owner.unreadable_bytes += chunk.length;
      }
    }
    await handle.truncate(plan.imageSize);
  } finally {
    await handle.close();
  }

  return {
    path: outputPath,
    bytes: plan.imageSize,
    base: image.base,
    end: hex(base + BigInt(image.size)),
    module_size: image.size,
    module_path: image.path,
    truncated: plan.truncated,
    ranges: [...stats.values()],
  };
}

function findOwningRange(stats: Map<string, DumpedRange>, address: bigint): DumpedRange | undefined {
  for (const range of stats.values()) {
    const start = BigInt(range.base);
    if (address >= start && address < start + BigInt(range.size)) return range;
  }
  return undefined;
}

function registerListThreads(server: McpServer): void {
  server.registerTool(
    'list_threads',
    {
      title: 'List Threads',
      description:
        'List the threads of the target process (id, name, state, current pc as module+0xoffset). With backtraces: true each thread also gets a symbolised backtrace (up to 8 frames) captured from its register context.',
      inputSchema: z.object({
        session_id: z.string().describe('Session ID'),
        backtraces: z.boolean().optional().default(false).describe('Capture an 8-frame backtrace per thread (slower; default false)'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ session_id, backtraces, response_format }) => {
      try {
        const session = requireSession(session_id);
        const threads = await runNativeRpc<unknown[]>(
          session,
          { name: 'list_threads:run', source: LIST_THREADS_SOURCE, options: { backtraces: backtraces ?? false, frames: 8 } },
          'Thread enumeration',
          30_000
        );
        return formatToolResponse(buildResult({ session_id, thread_count: threads.length, threads }, [
          { tool: 'resolve_address', reason: 'Resolve a frame address to module+offset / symbol' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}
