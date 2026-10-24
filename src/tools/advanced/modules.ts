import { z } from 'zod';
import { toolOutputSchema } from '../../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import { getState } from '../../state.js';
import { buildResult, formatToolResponse, pagedCoverage } from '../../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../../helpers/errors.js';
import { responseFormatSchema, type ResponseFormat } from '../../constants.js';
import { createAgentScript } from '../../agent/script-factory.js';
import { callRpcWithTimeout } from '../../helpers/rpc-timeout.js';
import type { SessionEntry, SuggestedAction, ToolResult, ErrorResponse } from '../../types.js';

// ---------------------------------------------------------------------------
// Pagination / filter constants
// ---------------------------------------------------------------------------

const DEFAULT_LIMIT = 200;
const MAX_LIMIT = 500;

/** Platforms on which Frida implements Module#enumerateSymbols(). */
const SYMBOL_PLATFORMS: ReadonlySet<SessionEntry['platform']> = new Set(['android', 'ios', 'linux', 'macos']);

const ADDRESS_VOCABULARY =
  'Addresses are absolute runtime pointers; subtract the module base to get the Ghidra/IDA offset ' +
  '(or use resolve_address with a "module+0xoff" target).';

// ---------------------------------------------------------------------------
// Agent sources (classic JS, Frida 17 Module *instance* API only)
// ---------------------------------------------------------------------------

/** Shared in-agent helpers: module lookup + offset/limit paging (keeps the RPC payload bounded). */
const AGENT_HELPERS_SOURCE = `
  function __mcpFindModule(o) {
    var mod = Process.findModuleByName(o.moduleName);
    if (mod === null) return { error: 'module_not_found', message: 'Module not found: ' + o.moduleName };
    return mod;
  }
  function __mcpPage(items, o) {
    var offset = o.offset || 0;
    var limit = o.limit || ${DEFAULT_LIMIT};
    return { total: items.length, offset: offset, limit: limit, items: items.slice(offset, offset + limit) };
  }
`;

const ENUMERATE_MODULES_SOURCE = `
  rpc.exports.run = function() {
    return Process.enumerateModules().map(function(m) {
      return { name: m.name, base: m.base.toString(), end: m.base.add(m.size).toString(), size: m.size, path: m.path };
    });
  };
`;

const ENUMERATE_EXPORTS_SOURCE = AGENT_HELPERS_SOURCE + `
  rpc.exports.run = function() {
    var o = __FRIDA_MCP__.options;
    var mod = __mcpFindModule(o);
    if (mod.error) return mod;
    var exports = mod.enumerateExports().map(function(e) {
      var entry = { type: e.type, name: e.name, address: e.address.toString() };
      if (typeof e.size === 'number') entry.size = e.size;
      return entry;
    });
    return __mcpPage(exports, o);
  };
`;

const ENUMERATE_IMPORTS_SOURCE = AGENT_HELPERS_SOURCE + `
  rpc.exports.run = function() {
    var o = __FRIDA_MCP__.options;
    var mod = __mcpFindModule(o);
    if (mod.error) return mod;
    var imports = mod.enumerateImports().map(function(i) {
      var entry = { name: i.name };
      if (i.type !== undefined) entry.type = i.type;
      if (i.module !== undefined) entry.module = i.module;
      if (i.address !== undefined && i.address !== null) entry.address = i.address.toString();
      if (i.slot !== undefined && i.slot !== null) entry.slot = i.slot.toString();
      return entry;
    });
    return __mcpPage(imports, o);
  };
`;

const ENUMERATE_SYMBOLS_SOURCE = AGENT_HELPERS_SOURCE + `
  rpc.exports.run = function() {
    var o = __FRIDA_MCP__.options;
    var mod = __mcpFindModule(o);
    if (mod.error) return mod;
    var re = null;
    if (o.filter) {
      try { re = new RegExp(o.filter, 'i'); } catch (e) { return { error: 'invalid_filter', message: String(e) }; }
    }
    var symbols = [];
    mod.enumerateSymbols().forEach(function(s) {
      if (re !== null && !re.test(s.name)) return;
      var entry = { name: s.name, type: s.type, isGlobal: s.isGlobal, address: s.address.toString() };
      if (typeof s.size === 'number') entry.size = s.size;
      if (s.section) entry.section = { id: s.section.id, protection: s.section.protection };
      symbols.push(entry);
    });
    return __mcpPage(symbols, o);
  };
`;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

interface ModuleEntry {
  name: string;
  base: string;
  end: string;
  size: number;
  path: string;
}

interface ExportEntry {
  type: string;
  name: string;
  address: string;
  size?: number;
}

interface ImportEntry {
  type?: string;
  name: string;
  module?: string;
  address?: string;
  slot?: string;
}

interface SymbolEntry {
  name: string;
  type: string;
  isGlobal: boolean;
  address: string;
  size?: number;
  section?: { id: string; protection: string };
}

interface AgentError {
  error: string;
  message: string;
}

interface AgentPage<T> {
  total: number;
  offset: number;
  limit: number;
  items: T[];
}

interface PaginationArgs {
  offset: number;
  limit: number;
}

type ToolResponse = ReturnType<typeof formatToolResponse>;

// ---------------------------------------------------------------------------
// Host-side helpers
// ---------------------------------------------------------------------------

const paginationSchema = {
  offset: z.number().int().min(0).default(0).describe('Number of entries to skip (default 0)'),
  limit: z.number().int().min(1).max(MAX_LIMIT).default(DEFAULT_LIMIT)
    .describe(`Maximum entries to return (default ${DEFAULT_LIMIT}, max ${MAX_LIMIT})`),
};

function requireSession(sessionId: string): SessionEntry {
  const session = getState().getSession(sessionId);
  if (!session) throw new FridaMcpError('SESSION_NOT_FOUND', 'Session not found.', []);
  return session;
}

/** Throws INVALID_FILTER when the user-supplied pattern is not a valid case-insensitive regex. */
function compileFilter(filter: string | undefined): RegExp | null {
  if (!filter) return null;
  try {
    return new RegExp(filter, 'i');
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new FridaMcpError('INVALID_FILTER', `Invalid filter regex "${filter}": ${detail}`, [
      { action: 'retry', reason: 'Provide a valid JavaScript regular expression (matched case-insensitively)' },
    ]);
  }
}

function assertSymbolsSupported(session: SessionEntry, sessionId: string, moduleName: string): void {
  if (SYMBOL_PLATFORMS.has(session.platform)) return;
  throw new FridaMcpError(
    'SYMBOLS_UNSUPPORTED',
    `enumerateSymbols() is only available on Linux/Android/iOS/macOS (session platform: ${session.platform})`,
    [
      { tool: 'enumerate_exports', args: { session_id: sessionId, module_name: moduleName }, reason: 'List exported functions instead' },
      { tool: 'enumerate_imports', args: { session_id: sessionId, module_name: moduleName }, reason: 'List imported functions instead' },
    ],
    { platform: session.platform }
  );
}

/** Create a native-only (no bridges) agent script, run its `run` export once and unload it. */
async function runAgentOnce<T>(
  session: SessionEntry,
  name: string,
  source: string,
  label: string,
  options: Record<string, unknown> = {}
): Promise<T> {
  const script = await createAgentScript(session.session, {
    sessionEntry: session,
    source,
    platform: session.platform,
    name,
    kind: 'generated',
    options,
    bridges: [],
  });
  await script.load();
  try {
    return await callRpcWithTimeout(script.exports.run() as Promise<T>, label);
  } finally {
    await script.unload();
  }
}

function isAgentError(value: unknown): value is AgentError {
  return typeof value === 'object' && value !== null && typeof (value as AgentError).error === 'string';
}

/** Translate the agent's error envelope into a FridaMcpError, or return the page untouched. */
function unwrapAgentPage<T>(result: AgentPage<T> | AgentError, sessionId: string, moduleName: string): AgentPage<T> {
  if (!isAgentError(result)) return result;
  if (result.error === 'invalid_filter') {
    throw new FridaMcpError('INVALID_FILTER', result.message, [
      { action: 'retry', reason: 'Provide a valid JavaScript regular expression' },
    ]);
  }
  throw new FridaMcpError('MODULE_NOT_FOUND', result.message, [
    { tool: 'enumerate_modules', args: { session_id: sessionId, filter: moduleName }, reason: 'List loaded modules to find the exact name' },
  ], { module: moduleName });
}

/** Run a module-scoped enumeration script and return one page of entries. */
async function enumerateModulePage<T>(
  sessionId: string,
  moduleName: string,
  toolName: string,
  source: string,
  label: string,
  options: PaginationArgs & { filter?: string | null }
): Promise<AgentPage<T>> {
  const session = requireSession(sessionId);
  const page = await runAgentOnce<AgentPage<T> | AgentError>(
    session, `${toolName}:run`, source, label, { moduleName, ...options }
  );
  return unwrapAgentPage(page, sessionId, moduleName);
}

function pageMeta<T>(page: AgentPage<T>): { offset: number; limit: number; truncated: boolean } {
  return { offset: page.offset, limit: page.limit, truncated: page.offset + page.items.length < page.total };
}

/** Offset of the next page, or undefined on the last page. */
function nextPageOffset<T>(page: AgentPage<T>): number | undefined {
  const nextOffset = page.offset + page.items.length;
  return nextOffset < page.total ? nextOffset : undefined;
}

/** suggested_next entries for a list of named, addressed entries inside a module. */
function suggestForEntry(moduleName: string, entry: { name: string } | undefined): SuggestedAction[] {
  if (!entry) return [];
  return [
    { tool: 'hook_method', args: { method: `${moduleName}!${entry.name}` }, reason: 'Hook this function by module!name' },
    { tool: 'resolve_address', args: { target: `${moduleName}!${entry.name}` }, reason: 'Resolve to an absolute address and module+0xoff offset' },
    { tool: 'analyze_native_function', args: { target: `${moduleName}!${entry.name}` }, reason: 'Inspect the function prologue / disassembly' },
  ];
}

/** Uniform try/catch + formatting wrapper so each tool handler only builds its result. */
async function respond(
  responseFormat: ResponseFormat | undefined,
  build: () => Promise<ToolResult>
): Promise<ToolResponse> {
  let payload: ToolResult | ErrorResponse;
  try {
    payload = await build();
  } catch (err) {
    payload = wrapFridaError(err).toErrorResponse();
  }
  return formatToolResponse(payload, responseFormat);
}

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
};

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

async function enumerateModules(sessionId: string, filter: string | undefined): Promise<ToolResult> {
  const pattern = compileFilter(filter);
  const session = requireSession(sessionId);
  const all = await runAgentOnce<ModuleEntry[]>(session, 'enumerate_modules:run', ENUMERATE_MODULES_SOURCE, 'Module enumeration');
  const modules = pattern ? all.filter((m) => pattern.test(m.name) || pattern.test(m.path)) : all;
  const first = modules[0]?.name;
  return buildResult({ session_id: sessionId, module_count: modules.length, filter: filter ?? null, modules }, [
    { tool: 'enumerate_exports', args: { session_id: sessionId, module_name: first }, reason: 'List exports of a module' },
    { tool: 'enumerate_imports', args: { session_id: sessionId, module_name: first }, reason: 'List imports of a module' },
    { tool: 'enumerate_symbols', args: { session_id: sessionId, module_name: first }, reason: 'List debug/ELF symbols of a module (Linux/Android/iOS/macOS)' },
  ], { coverage: { status: 'complete', scope: filter ? `loaded modules matching ${filter}` : 'loaded modules' } });
}

async function enumerateExports(sessionId: string, moduleName: string, paging: PaginationArgs): Promise<ToolResult> {
  const page = await enumerateModulePage<ExportEntry>(
    sessionId, moduleName, 'enumerate_exports', ENUMERATE_EXPORTS_SOURCE, 'Export enumeration', paging
  );
  const pageInfo = pageMeta(page);
  return buildResult(
    { session_id: sessionId, module: moduleName, export_count: page.total, exports: page.items, ...pageInfo },
    suggestForEntry(moduleName, page.items[0]),
    { coverage: pagedCoverage(`module ${moduleName} exports`, pageInfo.truncated, nextPageOffset(page)) }
  );
}

async function enumerateImports(sessionId: string, moduleName: string, paging: PaginationArgs): Promise<ToolResult> {
  const page = await enumerateModulePage<ImportEntry>(
    sessionId, moduleName, 'enumerate_imports', ENUMERATE_IMPORTS_SOURCE, 'Import enumeration', paging
  );
  const first = page.items[0];
  const suggestions: SuggestedAction[] = first?.module
    ? suggestForEntry(first.module, first)
    : [{ tool: 'enumerate_modules', args: { session_id: sessionId }, reason: 'Find the module that provides an import' }];
  const pageInfo = pageMeta(page);
  return buildResult(
    { session_id: sessionId, module: moduleName, import_count: page.total, imports: page.items, ...pageInfo },
    suggestions,
    { coverage: pagedCoverage(`module ${moduleName} imports`, pageInfo.truncated, nextPageOffset(page)) }
  );
}

async function enumerateSymbols(
  sessionId: string, moduleName: string, filter: string | undefined, paging: PaginationArgs
): Promise<ToolResult> {
  compileFilter(filter);
  assertSymbolsSupported(requireSession(sessionId), sessionId, moduleName);
  const page = await enumerateModulePage<SymbolEntry>(
    sessionId, moduleName, 'enumerate_symbols', ENUMERATE_SYMBOLS_SOURCE, 'Symbol enumeration', { ...paging, filter: filter ?? null }
  );
  const pageInfo = pageMeta(page);
  const scope = `module ${moduleName} symbols${filter ? ` matching ${filter}` : ''}`;
  return buildResult(
    { session_id: sessionId, module: moduleName, filter: filter ?? null, symbol_count: page.total, symbols: page.items, ...pageInfo },
    suggestForEntry(moduleName, page.items[0]),
    { coverage: pagedCoverage(scope, pageInfo.truncated, nextPageOffset(page)) }
  );
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

export function registerAdvancedModuleTools(server: McpServer): void {
  server.registerTool(
    'enumerate_modules',
    {
      title: 'Enumerate Modules',
      description:
        'List loaded modules (shared libraries) in the target process with name, base, end (base+size), size and path. ' +
        'Optional case-insensitive regex `filter` matches against name or path. ' +
        'Use base/end to rebase a Ghidra/IDA project; ' + ADDRESS_VOCABULARY,
      inputSchema: z.object({
        session_id: z.string().describe('Session ID'),
        filter: z.string().optional().describe('Case-insensitive regex matched against module name or path (e.g. "libssl|libcrypto")'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: readOnlyAnnotations,
    },
    ({ session_id, filter, response_format }) =>
      respond(response_format, () => enumerateModules(session_id, filter))
  );

  server.registerTool(
    'enumerate_exports',
    {
      title: 'Enumerate Module Exports',
      description:
        'List exports (functions and variables) of a specific module, paginated with offset/limit. ' +
        'Hook results with hook_method using "module!name". ' + ADDRESS_VOCABULARY,
      inputSchema: z.object({
        session_id: z.string().describe('Session ID'),
        module_name: z.string().describe('Module name (e.g., "libssl.so")'),
        ...paginationSchema,
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: readOnlyAnnotations,
    },
    ({ session_id, module_name, offset, limit, response_format }) =>
      respond(response_format, () => enumerateExports(session_id, module_name, { offset, limit }))
  );

  server.registerTool(
    'enumerate_imports',
    {
      title: 'Enumerate Module Imports',
      description:
        'List imports of a specific module (functions it calls in other libraries), paginated with offset/limit. ' +
        'Each entry carries the providing `module` when known, so "module!name" can be hooked directly. ' + ADDRESS_VOCABULARY,
      inputSchema: z.object({
        session_id: z.string().describe('Session ID'),
        module_name: z.string().describe('Module name (e.g., "libssl.so")'),
        ...paginationSchema,
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: readOnlyAnnotations,
    },
    ({ session_id, module_name, offset, limit, response_format }) =>
      respond(response_format, () => enumerateImports(session_id, module_name, { offset, limit }))
  );

  server.registerTool(
    'enumerate_symbols',
    {
      title: 'Enumerate Module Symbols',
      description:
        'List symbols (including non-exported/debug symbols) of a specific module. Only available on Linux, Android, iOS and macOS. ' +
        'Filtering (case-insensitive regex on the symbol name) and offset/limit paging happen inside the agent, so large symbol tables stay cheap. ' +
        ADDRESS_VOCABULARY,
      inputSchema: z.object({
        session_id: z.string().describe('Session ID'),
        module_name: z.string().describe('Module name (e.g., "libssl.so")'),
        filter: z.string().optional().describe('Case-insensitive regex matched against the symbol name (e.g. "^SSL_")'),
        ...paginationSchema,
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: readOnlyAnnotations,
    },
    ({ session_id, module_name, filter, offset, limit, response_format }) =>
      respond(response_format, () => enumerateSymbols(session_id, module_name, filter, { offset, limit }))
  );
}
