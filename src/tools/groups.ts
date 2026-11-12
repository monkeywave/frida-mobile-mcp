/**
 * Tool groups: lets a host MCP server register only part of the Frida tool set.
 *
 * - `core`: tools that work on any Frida target, desktop processes included
 *   (attach/spawn, hooks, tracing, scripts, memory, native analysis, evidence, ...).
 * - `mobile`: Android/iOS-only tools (adb, frida-server management, app ids,
 *   mobile-mcp driving, mobile prebuilt scripts and recipes).
 * - `fritap`: the friTap TLS key extraction / traffic capture tool.
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

export type ToolGroup = 'core' | 'mobile' | 'fritap';

/** Every group, in registration order. */
export const ALL_TOOL_GROUPS: readonly ToolGroup[] = ['core', 'mobile', 'fritap'];

type Registrar = (server: McpServer, deviceManager: DeviceManager) => void;

const CORE_REGISTRARS: readonly Registrar[] = [
  registerStatusTool,
  (server) => registerHelpTool(server),
  registerExploreTool,
  registerHookTool,
  registerTraceTool,
  registerScriptTool,
  registerSearchTool,
  registerDescribeClassTool,
  registerDiscoverTool,
  registerSecretsTool,
  registerCoverageTool,
  registerCryptoOracleTool,
  registerPatternTool,
  registerWatchTool,
  (server) => registerMemoryTools(server),
  (server) => registerMessagesTool(server),
  (server) => registerCleanupTool(server),
  (server) => registerTriggerTool(server),
  (server) => registerValidateTool(server),
  registerLibraryTools,
  (server) => registerEvidenceTools(server),
  registerAdvancedDeviceTools,
  registerAdvancedProcessTools,
  registerAdvancedSessionTools,
  (server) => registerAdvancedModuleTools(server),
  (server) => registerAdvancedInterceptTools(server),
  (server) => registerNativeAnalysisTools(server),
  registerInjectTools,
];

const MOBILE_REGISTRARS: readonly Registrar[] = [
  registerAppInfoTool,
  registerPrebuiltTool,
  registerDriveTool,
  registerSslTool,
  (server) => registerMobileTool(server),
  registerDetectTool,
  (server) => registerRecipesTool(server),
  (server) => registerFridaServerTools(server),
  (server) => registerAdbTools(server),
];

const FRITAP_REGISTRARS: readonly Registrar[] = [registerFritapTool];

/** The tool registrars of each group. */
export const TOOL_GROUPS: Readonly<Record<ToolGroup, readonly Registrar[]>> = {
  core: CORE_REGISTRARS,
  mobile: MOBILE_REGISTRARS,
  fritap: FRITAP_REGISTRARS,
};

function assertKnownGroups(groups: readonly string[]): void {
  const unknown = groups.filter((group) => !ALL_TOOL_GROUPS.includes(group as ToolGroup));
  if (unknown.length > 0) {
    throw new Error(`Unknown tool group(s): ${unknown.join(', ')}. Valid groups: ${ALL_TOOL_GROUPS.join(', ')}`);
  }
}

/**
 * Register the tools of the selected groups (default: all). Duplicates are ignored and
 * groups are always registered in `ALL_TOOL_GROUPS` order. Throws on an unknown group name.
 */
export function registerToolGroups(
  server: McpServer,
  deviceManager: DeviceManager,
  groups: readonly ToolGroup[] = ALL_TOOL_GROUPS,
): void {
  assertKnownGroups(groups);
  const selected = new Set(groups);
  for (const group of ALL_TOOL_GROUPS) {
    if (!selected.has(group)) continue;
    for (const register of TOOL_GROUPS[group]) register(server, deviceManager);
  }
}
