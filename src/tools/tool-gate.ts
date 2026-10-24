/**
 * Registration seam for every tool: `gateServer()` wraps an `McpServer` so that each
 * `registerTool` call passes through a single policy. The policy decides whether a tool is
 * exposed at all (tool profile + exclude globs), trims its schema for the `compact` schema
 * profile, stamps `_meta.effects` / `_meta.provenance` on the definition and wraps the handler.
 *
 * Used by `registerAllTools` so the catalog can be trimmed when the server runs next to a
 * large companion server (e.g. REA) in the same client context.
 */
import type { McpServer } from '@modelcontextprotocol/server';
import { log } from '../helpers/logger.js';
import { escapeRegExp } from '../helpers/regex.js';
import type { ToolEffects } from './effects.js';
import type { RuntimeConfig, SchemaProfile, ToolProfile } from '../config.js';

/** Any tool handler; the gate does not care about its argument types. */
type ToolHandler = (...args: any[]) => unknown;

export interface ToolPolicy {
  toolProfile: ToolProfile;
  /** Glob patterns (`*` wildcard) of tool names that are never registered. */
  toolsExclude: string[];
  schemaProfile: SchemaProfile;
  effects: Record<string, ToolEffects>;
  /** Optional handler decorator (e.g. an evidence store). */
  wrapHandler?: (name: string, cb: ToolHandler) => ToolHandler;
}

/**
 * Tools kept by the `core` profile. Names that are not registered by this build (e.g. tools
 * added later) are simply absent; the core filter never registers anything by itself.
 */
export const CORE_TOOLS: readonly string[] = [
  'get_status',
  'frida_help',
  'list_devices',
  'select_device',
  'list_applications',
  'get_app_info',
  'explore_app',
  'detect_app_technologies',
  'search_classes_and_methods',
  'describe_class',
  'hook_method',
  'trace_method',
  'get_messages',
  'trigger_and_wait',
  'execute_script',
  'validate_script',
  'run_prebuilt_script',
  'discover_crypto',
  'monitor_crypto',
  'find_secrets_in_memory',
  'read_memory',
  'scan_memory',
  'bypass_ssl_pinning',
  'capture_tls',
  'enumerate_modules',
  'enumerate_exports',
  'hook_function',
  'mobile_action',
  'stop_instrumentation',
  'unload_script',
  'get_evidence',
  'export_evidence_bundle',
];

const CORE_TOOL_SET = new Set(CORE_TOOLS);

/** Provenance marker for tools whose output comes from the analysed app/device. */
export const TARGET_PROVENANCE = { untrusted_content: true, source: 'analysis_target' } as const;

/** Max length of a compact-profile description. */
export const COMPACT_DESCRIPTION_MAX = 160;

/** Anchored RegExp for a glob where `*` matches any run of characters. */
export function globToRegExp(glob: string): RegExp {
  return new RegExp(`^${glob.split('*').map(escapeRegExp).join('.*')}$`);
}

/** The exposure half of a tool policy (what `isToolExposed` needs). */
export type ExposurePolicy = Pick<ToolPolicy, 'toolProfile' | 'toolsExclude'>;

/**
 * Exposure policy of a runtime config (`FRIDA_MCP_TOOL_PROFILE` / `FRIDA_MCP_TOOLS_EXCLUDE`).
 * Missing fields (a plain `FridaMcpConfig`) mean the full catalog.
 */
export function policyFromConfig(config: Partial<RuntimeConfig>): ExposurePolicy {
  return { toolProfile: config.toolProfile ?? 'full', toolsExclude: config.toolsExclude ?? [] };
}

/** Whether the policy lets `name` be registered. */
export function isToolExposed(name: string, policy: ExposurePolicy): boolean {
  if (policy.toolProfile === 'core' && !CORE_TOOL_SET.has(name)) return false;
  return !policy.toolsExclude.some((glob) => globToRegExp(glob).test(name));
}

/** First sentence of `text`, capped at `max` characters (ellipsis when cut). */
export function firstSentence(text: string, max: number): string {
  const trimmed = text.trim();
  const match = /^.*?[.!?](?=\s|$)/s.exec(trimmed);
  const sentence = match ? match[0] : trimmed;
  return sentence.length <= max ? sentence : `${sentence.slice(0, max - 3).trimEnd()}...`;
}

/** `inputSchema` (a ZodObject; every tool passes `z.object`) without `response_format`. */
function withoutResponseFormat(inputSchema: unknown): unknown {
  const zodObject = inputSchema as { shape: Record<string, unknown>; omit: (mask: Record<string, true>) => unknown };
  return 'response_format' in zodObject.shape ? zodObject.omit({ response_format: true }) : inputSchema;
}

interface ToolConfig {
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  annotations?: { idempotentHint?: boolean };
  _meta?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Rewrite a tool definition according to the policy: stamp `_meta.effects` (with `idempotent`
 * derived from the tool's `idempotentHint` annotation) and `_meta.provenance`, and, for the
 * `compact` schema profile, shorten the description and drop `response_format` and `outputSchema`.
 */
export function applyPolicyToConfig(name: string, config: ToolConfig, policy: ToolPolicy): ToolConfig {
  const effects = policy.effects[name];
  const idempotent = config.annotations?.idempotentHint === true;
  const meta: Record<string, unknown> = { ...config._meta, effects: { ...effects, idempotent } };
  if (effects?.targetDerived) meta.provenance = TARGET_PROVENANCE;
  const next: ToolConfig = { ...config, _meta: meta };
  if (policy.schemaProfile === 'compact') {
    if (config.description) next.description = firstSentence(config.description, COMPACT_DESCRIPTION_MAX);
    if ('inputSchema' in config) next.inputSchema = withoutResponseFormat(config.inputSchema);
    delete next.outputSchema;
  }
  return next;
}

/** Stamp `_meta.provenance` onto successful results of target-derived tools. */
function stampProvenance(cb: ToolHandler): ToolHandler {
  return async (...args: unknown[]) => {
    const result = (await cb(...args)) as { isError?: boolean; _meta?: Record<string, unknown> } | undefined;
    if (!result || typeof result !== 'object' || result.isError) return result;
    return { ...result, _meta: { ...result._meta, provenance: TARGET_PROVENANCE } };
  };
}

function wrapToolHandler(name: string, cb: ToolHandler, policy: ToolPolicy): ToolHandler {
  const wrapped = policy.wrapHandler ? policy.wrapHandler(name, cb) : cb;
  return policy.effects[name]?.targetDerived ? stampProvenance(wrapped) : wrapped;
}

/**
 * Proxy over `server` whose `registerTool` applies `policy`. Every other property is read
 * from the real server and functions are bound to it, so SDK private fields keep working.
 */
export function gateServer(server: McpServer, policy: ToolPolicy): McpServer {
  const registerTool = (name: string, config: ToolConfig, cb: ToolHandler): unknown => {
    if (!isToolExposed(name, policy)) {
      log('debug', `Tool "${name}" hidden by tool profile/exclude policy`);
      // No caller uses registerTool's return value (grep "= server.registerTool"), so a
      // hidden tool has no RegisteredTool handle.
      return undefined as any;
    }
    const register = server.registerTool.bind(server) as unknown as (n: string, c: ToolConfig, h: ToolHandler) => unknown;
    return register(name, applyPolicyToConfig(name, config, policy), wrapToolHandler(name, cb, policy));
  };

  return new Proxy(server, {
    get(target, prop) {
      if (prop === 'registerTool') return registerTool;
      const value = Reflect.get(target, prop, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}
