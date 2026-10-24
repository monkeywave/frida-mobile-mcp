/**
 * Single place that knows every tool, resource and prompt this server exposes.
 * Used by both the CLI server (src/server.ts) and the library entry (src/lib.ts).
 */
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { registerStatusTool } from './status.js';
import { registerHelpTool } from './help.js';
import { registerExploreTool } from './explore.js';
import { registerAppInfoTool } from './app-info.js';
import { registerHookTool } from './hook.js';
import { registerTraceTool } from './trace.js';
import { registerScriptTool } from './script.js';
import { registerPrebuiltTool } from './prebuilt.js';
import { registerSearchTool } from './search.js';
import { registerDescribeClassTool } from './describe-class.js';
import { registerDiscoverTool } from './discover.js';
import { registerSecretsTool } from './secrets.js';
import { registerCoverageTool } from './coverage.js';
import { registerCryptoOracleTool } from './crypto-oracle.js';
import { registerPatternTool } from './pattern.js';
import { registerDriveTool } from './drive.js';
import { registerWatchTool } from './watch.js';
import { registerTriggerTool } from './trigger.js';
import { registerMemoryTools } from './memory.js';
import { registerSslTool } from './ssl.js';
import { registerMessagesTool } from './messages.js';
import { registerCleanupTool } from './cleanup.js';
import { registerMobileTool } from './mobile.js';
import { registerDetectTool } from './detect.js';
import { registerValidateTool } from './validate.js';
import { registerRecipesTool } from './recipes.js';
import { registerLibraryTools } from './library.js';
import { registerEvidenceTools } from './evidence.js';
import { evidenceWrapHandler } from '../helpers/evidence-hook.js';
import { registerFritapTool } from '../fritap/tool.js';
import { registerAdvancedDeviceTools } from './advanced/device.js';
import { registerAdvancedProcessTools } from './advanced/process.js';
import { registerAdvancedSessionTools } from './advanced/session.js';
import { registerAdvancedModuleTools } from './advanced/modules.js';
import { registerAdvancedInterceptTools } from './advanced/intercept.js';
import { registerNativeAnalysisTools } from './advanced/native.js';
import { registerFridaServerTools } from './advanced/server.js';
import { registerAdbTools } from './advanced/adb.js';
import { registerInjectTools } from './advanced/inject.js';
import { registerResources } from '../resources.js';
import { registerPrompts } from '../prompts.js';
import { getActiveConfig, type SchemaProfile, type ToolProfile } from '../config.js';
import { TOOL_EFFECTS } from './effects.js';
import { getState } from '../state.js';
import { gateServer, policyFromConfig, type ToolPolicy } from './tool-gate.js';

export interface RegisterAllOptions {
  /** Also register the `frida://` resources (default: true). */
  resources?: boolean;
  /** Also register the workflow prompts (default: true). */
  prompts?: boolean;
  /** Tool exposure profile (default: active config, else `full`). */
  toolProfile?: ToolProfile;
  /** Tool-name globs never registered (default: active config, else none). */
  toolsExclude?: string[];
  /** Schema verbosity applied by the gate (default: active config, else `full`). */
  schemaProfile?: SchemaProfile;
  /** Optional decorator applied to every registered tool handler. */
  wrapHandler?: ToolPolicy['wrapHandler'];
  /**
   * Persist every tool result in the evidence store and write a central audit line
   * (default: true; the store itself is enabled by `initEvidenceStore`).
   */
  evidence?: boolean;
}

/** Tier 1: high-level, task-oriented tools. */
export function registerTier1Tools(server: McpServer, deviceManager: DeviceManager): void {
  registerStatusTool(server, deviceManager);
  registerHelpTool(server);
  registerExploreTool(server, deviceManager);
  registerAppInfoTool(server, deviceManager);
  registerHookTool(server, deviceManager);
  registerTraceTool(server, deviceManager);
  registerScriptTool(server, deviceManager);
  registerPrebuiltTool(server, deviceManager);
  registerSearchTool(server, deviceManager);
  registerDescribeClassTool(server, deviceManager);
  registerDiscoverTool(server, deviceManager);
  registerSecretsTool(server, deviceManager);
  registerCoverageTool(server, deviceManager);
  registerCryptoOracleTool(server, deviceManager);
  registerPatternTool(server, deviceManager);
  registerDriveTool(server, deviceManager);
  registerWatchTool(server, deviceManager);
  registerMemoryTools(server);
  registerSslTool(server, deviceManager);
  registerFritapTool(server, deviceManager);
  registerMessagesTool(server);
  registerCleanupTool(server);
  registerMobileTool(server);
  registerTriggerTool(server);
  registerDetectTool(server, deviceManager);
  registerValidateTool(server);
  registerRecipesTool(server);
  registerLibraryTools(server, deviceManager);
  registerEvidenceTools(server);
}

/** Tier 2: advanced primitives (devices, processes, sessions, modules, native analysis). */
export function registerTier2Tools(server: McpServer, deviceManager: DeviceManager): void {
  registerAdvancedDeviceTools(server, deviceManager);
  registerAdvancedProcessTools(server, deviceManager);
  registerAdvancedSessionTools(server, deviceManager);
  registerAdvancedModuleTools(server);
  registerAdvancedInterceptTools(server);
  registerNativeAnalysisTools(server);
  registerFridaServerTools(server);
  registerAdbTools(server);
  registerInjectTools(server, deviceManager);
}

/**
 * The handler decorator for the policy: the evidence hook (unless `options.evidence === false`)
 * wrapped around the caller's own `wrapHandler`, if any.
 */
function composeWrapHandler(options: RegisterAllOptions): ToolPolicy['wrapHandler'] {
  const custom = options.wrapHandler;
  if (options.evidence === false) return custom;
  if (!custom) return evidenceWrapHandler;
  return (name, cb) => evidenceWrapHandler(name, custom(name, cb));
}

/** Tool policy from explicit options, then the active runtime config, then full/[]/full. */
function buildToolPolicy(options: RegisterAllOptions = {}): ToolPolicy {
  const config = getActiveConfig();
  const exposure = policyFromConfig(config ?? {});
  return {
    toolProfile: options.toolProfile ?? exposure.toolProfile,
    toolsExclude: options.toolsExclude ?? exposure.toolsExclude,
    schemaProfile: options.schemaProfile ?? config?.schemaProfile ?? 'full',
    effects: TOOL_EFFECTS,
    wrapHandler: composeWrapHandler(options),
  };
}

/** Remember the applied exposure policy so get_status reports what was really hidden. */
function recordAppliedExposure(policy: ToolPolicy): void {
  try {
    getState().toolExposure = { toolProfile: policy.toolProfile, toolsExclude: [...policy.toolsExclude] };
  } catch {
    // State is not initialised (some unit tests register tools without it); nothing to record.
  }
}

export function registerAllTools(server: McpServer, deviceManager: DeviceManager, options: RegisterAllOptions = {}): void {
  // Every tool registration goes through the policy gate; resources and prompts do not.
  const policy = buildToolPolicy(options);
  const gated = gateServer(server, policy);
  recordAppliedExposure(policy);
  registerTier1Tools(gated, deviceManager);
  registerTier2Tools(gated, deviceManager);
  if (options.resources !== false) registerResources(server, deviceManager);
  if (options.prompts !== false) registerPrompts(server);
}
