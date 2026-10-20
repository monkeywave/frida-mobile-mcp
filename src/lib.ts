/**
 * Library entry point for `frida-mobile-mcp`.
 *
 * Embed the Frida tool set in your own MCP server with `registerFridaTools`, or run the full
 * server with `createServer`. Everything exported here is part of the public API.
 */
import { McpServer } from '@modelcontextprotocol/server';
import { initState, getState, type ServerState } from './state.js';
import { loadConfig, getActiveConfig, type RuntimeConfig } from './config.js';
import { initLogger, log } from './helpers/logger.js';
import { getPackageVersion } from './helpers/version.js';
import { DeviceManager } from './device/manager.js';
import { registerAllTools } from './tools/register-all.js';
import { getScriptRegistry } from './scripts/registry.js';
import type { ScriptTemplate } from './types.js';

export { createServer } from './server.js';
export { initState, getState, ServerState } from './state.js';
export {
  loadConfig,
  getActiveConfig,
  getConfigPath,
  DEFAULT_CONFIG,
  parseSchemaProfile,
  parseMaxResponseChars,
} from './config.js';
export type { RuntimeConfig, SchemaProfile } from './config.js';
export { DeviceManager, platformFromSystemParameters } from './device/manager.js';
export { resolveDevice, deviceToInfo, deviceToDetailedInfo } from './device/resolver.js';
export { getScriptRegistry } from './scripts/registry.js';
export {
  composeAgentSource,
  createAgentScript,
  defaultBridgesFor,
  isFridaCompileBundle,
  looksLikeEsModule,
  FRIDA_COMPILE_BUNDLE_MARKER,
} from './agent/script-factory.js';
export type {
  AgentPlatform,
  AgentScriptOptions,
  ComposedAgentSource,
  ScriptKind,
  ScriptRuntime,
} from './agent/script-factory.js';
export { findRemovedApis, REMOVED_API_PATTERNS } from './agent/lint.js';
export type { RemovedApiPattern } from './agent/lint.js';
export {
  areBridgesBuilt,
  getBridgesDir,
  loadBridgeManifest,
  loadBridgeSource,
  BRIDGE_NAMES,
} from './agent/bridges.js';
export type { BridgeName, BridgeManifest, BridgeManifestEntry } from './agent/bridges.js';
export { CHARACTER_LIMIT, getCharacterLimit, ResponseFormat, responseFormatSchema } from './constants.js';
export { startHttpServer, isLoopbackHost } from './transport/http.js';
export type { HttpServerHandle, HttpTransportOptions } from './transport/http.js';
export { createStdioTransport } from './transport/stdio.js';
export { getPackageVersion } from './helpers/version.js';
export type * from './types.js';

/** Public shape of the prebuilt script template registry. */
export interface ScriptRegistryLike {
  register(template: ScriptTemplate): void;
  get(name: string): ScriptTemplate | undefined;
  listAll(): ScriptTemplate[];
}

/** The prebuilt script template registry (ssl_pinning_bypass, root_jailbreak_bypass, ...). */
export const scriptRegistry: ScriptRegistryLike = getScriptRegistry();

export interface RegisterFridaToolsOptions {
  /** Device manager shared by the tools; defaults to one built on the global server state. */
  deviceManager?: DeviceManager;
  /** Configuration used when the global state still has to be initialised. */
  config?: RuntimeConfig;
  /** Also register the `frida://` resources (default: true). */
  resources?: boolean;
  /** Also register the workflow prompts (default: true). */
  prompts?: boolean;
}

/** Server identity shared by `createServer` and per-session HTTP servers. */
export const SERVER_INFO = { name: 'frida-mobile-mcp', version: getPackageVersion() } as const;

export const SERVER_CAPABILITIES = {
  capabilities: { tools: {}, resources: {}, prompts: {} },
} as const;

/**
 * Return the process-global state, initialising it (and the logger) on first use so that
 * library consumers do not have to call `loadConfig`/`initState` themselves.
 */
export function ensureState(config?: RuntimeConfig): ServerState {
  try {
    return getState();
  } catch {
    const resolved = config ?? getActiveConfig() ?? loadConfig();
    initLogger({
      auditPath: resolved.auditLogPath,
      level: process.env.FRIDA_MCP_DEBUG === '1' ? 'debug' : 'info',
    });
    return initState(resolved);
  }
}

/**
 * Register every Frida tool (plus resources and prompts) on an existing `McpServer`.
 * Returns the `DeviceManager` the tools share. Safe to call for several servers in one
 * process: the Frida state is global, the MCP server is not.
 */
export function registerFridaTools(server: McpServer, options: RegisterFridaToolsOptions = {}): DeviceManager {
  const state = ensureState(options.config);
  const deviceManager = options.deviceManager ?? new DeviceManager(state.deviceManager, state.config);

  registerAllTools(server, deviceManager, { resources: options.resources, prompts: options.prompts });


  log('debug', 'Frida tools registered on MCP server');
  return deviceManager;
}



/**
 * Build a fresh `McpServer` with every Frida tool registered, sharing the global state.
 * The HTTP transport uses this once per MCP session because a server can only be
 * connected to a single transport.
 */
export function createSessionServer(options: RegisterFridaToolsOptions = {}): McpServer {
  const server = new McpServer({ ...SERVER_INFO }, SERVER_CAPABILITIES);
  registerFridaTools(server, options);
  return server;
}
