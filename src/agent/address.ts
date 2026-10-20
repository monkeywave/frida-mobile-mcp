/**
 * Native address vocabulary shared with static RE tools (Ghidra/ReVa, IDA MCP, REA).
 *
 * Target notations accepted everywhere a native address is expected:
 *   module!symbol      export (or ELF/Mach-O symbol) of a module      "libssl.so!SSL_read"
 *   module+0xOFFSET    module-relative offset (RVA), hex or decimal   "libfoo.so+0x1234", "libfoo.so+4660"
 *   0xADDRESS          absolute address in the process                "0x7f1234567890"
 *   symbol             global export, searched across all modules     "open"
 *
 * The host-side parser (parseTarget) and the in-agent JavaScript (RESOLVE_TARGET_SNIPPET)
 * share the same regular expressions so both sides agree on the grammar. Addresses reported
 * back to the agent are always given as absolute pointer AND `module+0xoff` so they can be
 * handed to a static analysis tool with the right image base.
 */

export type TargetKind = 'export' | 'offset' | 'absolute' | 'global';

export interface ParsedTarget {
  kind: TargetKind;
  /** Module name for `export` and `offset` targets. */
  module?: string;
  /** Symbol name for `export` and `global` targets. */
  symbol?: string;
  /** Module-relative offset as a normalised hex string (`0x1234`) for `offset` targets. */
  offset?: string;
  /** Absolute address as a normalised hex string for `absolute` targets. */
  address?: string;
}

/** Bare absolute address: 0x-prefixed hex. */
const ABSOLUTE_PATTERN = /^0[xX][0-9a-fA-F]+$/;
/** `module+offset` where offset is hex (0x..) or decimal; the module name may itself contain '+' (libc++.so). */
const OFFSET_PATTERN = /^(.+?)\+(0[xX][0-9a-fA-F]+|\d+)$/;
/** `module!symbol`; an empty module part ("!open") means a global export lookup. */
const EXPORT_PATTERN = /^([^!]*)!(.+)$/;

/**
 * Parse a native target spec into its components. Throws on an empty or malformed spec.
 */
export function parseTarget(spec: string): ParsedTarget {
  const text = (spec ?? '').trim();
  if (text.length === 0) {
    throw new Error('Native target cannot be empty');
  }
  if (ABSOLUTE_PATTERN.test(text)) {
    return { kind: 'absolute', address: normaliseHex(text) };
  }
  const exportMatch = EXPORT_PATTERN.exec(text);
  if (exportMatch) {
    const [, module, symbol] = exportMatch;
    return module.length === 0 ? { kind: 'global', symbol } : { kind: 'export', module, symbol };
  }
  const offsetMatch = OFFSET_PATTERN.exec(text);
  if (offsetMatch) {
    const [, module, offset] = offsetMatch;
    return { kind: 'offset', module, offset: normaliseOffset(offset) };
  }
  return { kind: 'global', symbol: text };
}

/** Format a module-relative address the way Ghidra/IDA users read it: `libfoo.so+0x1234`. */
export function formatModuleOffset(module: string, offset: number | bigint | string): string {
  return `${module}+${normaliseOffset(offset)}`;
}

function normaliseHex(hex: string): string {
  return `0x${hex.slice(2).toLowerCase()}`;
}

function normaliseOffset(offset: number | bigint | string): string {
  if (typeof offset === 'number' || typeof offset === 'bigint') {
    if (offset < 0) throw new Error('Offset must be non-negative');
    return `0x${offset.toString(16)}`;
  }
  const text = offset.trim();
  if (ABSOLUTE_PATTERN.test(text)) return normaliseHex(text);
  if (/^\d+$/.test(text)) return `0x${BigInt(text).toString(16)}`;
  throw new Error(`Invalid offset: ${offset}`);
}

/**
 * In-agent helpers (classic JavaScript, Frida 17 APIs only). Append after the preamble
 * (which provides findExport) and before the tool body.
 *
 *   parseTargetSpec(spec)  -> { kind, module, symbol, offset, address } (same grammar as parseTarget)
 *   resolveTarget(spec)    -> NativePointer | null; accepts a spec string or a parsed object
 *   describeAddress(p)     -> { address, module, offset, symbol, rva }
 *   formatFrame(p)         -> 'module+0xoff (symbol)' for backtraces
 *   symbolizeBacktrace(ctx, limit?) -> string[] via Thread.backtrace(ctx, Backtracer.ACCURATE)
 */
export const RESOLVE_TARGET_SNIPPET = `
var __ABSOLUTE_PATTERN = ${ABSOLUTE_PATTERN.toString()};
var __OFFSET_PATTERN = ${OFFSET_PATTERN.toString()};
var __EXPORT_PATTERN = ${EXPORT_PATTERN.toString()};

function parseTargetSpec(spec) {
  var text = String(spec === null || spec === undefined ? '' : spec).trim();
  if (text.length === 0) return null;
  if (__ABSOLUTE_PATTERN.test(text)) return { kind: 'absolute', address: text };
  var exportMatch = __EXPORT_PATTERN.exec(text);
  if (exportMatch) {
    if (exportMatch[1].length === 0) return { kind: 'global', symbol: exportMatch[2] };
    return { kind: 'export', module: exportMatch[1], symbol: exportMatch[2] };
  }
  var offsetMatch = __OFFSET_PATTERN.exec(text);
  if (offsetMatch) return { kind: 'offset', module: offsetMatch[1], offset: offsetMatch[2] };
  return { kind: 'global', symbol: text };
}

function __nonNullPointer(p) {
  return p !== null && p !== undefined && !p.isNull() ? p : null;
}

function __resolveModuleSymbol(moduleName, symbol) {
  var mod = Process.findModuleByName(moduleName);
  if (mod === null) return null;
  var exported = __nonNullPointer(mod.findExportByName(symbol));
  if (exported) return exported;
  try { return __nonNullPointer(mod.findSymbolByName(symbol)); } catch (e) { return null; }
}

function __resolveGlobalSymbol(symbol) {
  var exported = __nonNullPointer(Module.findGlobalExportByName(symbol));
  if (exported) return exported;
  try {
    var ds = DebugSymbol.fromName(symbol);
    return ds ? __nonNullPointer(ds.address) : null;
  } catch (e) { return null; }
}

function resolveTarget(spec) {
  var parsed = typeof spec === 'string' ? parseTargetSpec(spec) : spec;
  if (!parsed || !parsed.kind) return null;
  try {
    switch (parsed.kind) {
      case 'absolute':
        return __nonNullPointer(ptr(parsed.address));
      case 'offset': {
        var mod = Process.findModuleByName(parsed.module);
        if (mod === null) return null;
        return mod.base.add(ptr(parsed.offset));
      }
      case 'export':
        return __resolveModuleSymbol(parsed.module, parsed.symbol);
      case 'global':
        return __resolveGlobalSymbol(parsed.symbol);
      default:
        return null;
    }
  } catch (e) {
    return null;
  }
}

function __symbolNameAt(p) {
  try {
    var ds = DebugSymbol.fromAddress(p);
    return ds && ds.name ? ds.name : null;
  } catch (e) {
    return null;
  }
}

function describeAddress(address) {
  var p = ptr(address);
  var out = { address: p.toString(), module: null, offset: null, symbol: __symbolNameAt(p), rva: null };
  var mod = Process.findModuleByAddress(p);
  if (mod !== null) {
    var off = '0x' + p.sub(mod.base).toString(16);
    out.module = mod.name;
    out.offset = off;
    out.rva = mod.name + '+' + off;
  }
  return out;
}

function formatFrame(address) {
  var d = describeAddress(address);
  var where = d.rva !== null ? d.rva : d.address;
  return d.symbol !== null ? where + ' (' + d.symbol + ')' : where;
}

function symbolizeBacktrace(context, limit) {
  try {
    var frames = Thread.backtrace(context, Backtracer.ACCURATE);
    if (typeof limit === 'number') frames = frames.slice(0, limit);
    return frames.map(formatFrame);
  } catch (e) {
    return ['<backtrace unavailable: ' + String(e && e.message ? e.message : e) + '>'];
  }
}
`;
