/**
 * Single place that knows every tool, resource and prompt this server exposes.
 * Used by both the CLI server (src/server.ts) and the library entry (src/lib.ts).
 */
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { registerStatusTool } from './status.js';
import { registerHelpTool } from './help.js';
import { registerExploreTool } from './explore.js';
import { registerHookTool } from './hook.js';
import { registerTraceTool } from './trace.js';
import { registerScriptTool } from './script.js';
import { registerPrebuiltTool } from './prebuilt.js';
import { registerSearchTool } from './search.js';
import { registerDiscoverTool } from './discover.js';
import { registerWatchTool } from './watch.js';
import { registerTriggerTool } from './trigger.js';
import { registerMemoryTools } from './memory.js';
import { registerSslTool } from './ssl.js';
import { registerMessagesTool } from './messages.js';
import { registerCleanupTool } from './cleanup.js';
import { registerMobileTool } from './mobile.js';
import { registerDetectTool } from './detect.js';
import { registerValidateTool } from './validate.js';
import { registerFritapTool } from '../fritap/tool.js';
import { registerAdvancedDeviceTools } from './advanced/device.js';
import { registerAdvancedProcessTools } from './advanced/process.js';
import { registerAdvancedSessionTools } from './advanced/session.js';
import { registerAdvancedModuleTools } from './advanced/modules.js';
import { registerAdvancedInterceptTools } from './advanced/intercept.js';
import { registerNativeAnalysisTools } from './advanced/native.js';
import { registerResources } from '../resources.js';
import { registerPrompts } from '../prompts.js';

export interface RegisterAllOptions {
  /** Also register the `frida://` resources (default: true). */
  resources?: boolean;
  /** Also register the workflow prompts (default: true). */
  prompts?: boolean;
}

/** Tier 1: high-level, task-oriented tools. */
export function registerTier1Tools(server: McpServer, deviceManager: DeviceManager): void {
  registerStatusTool(server, deviceManager);
  registerHelpTool(server);
  registerExploreTool(server, deviceManager);
  registerHookTool(server, deviceManager);
  registerTraceTool(server, deviceManager);
  registerScriptTool(server, deviceManager);
  registerPrebuiltTool(server, deviceManager);
  registerSearchTool(server, deviceManager);
  registerDiscoverTool(server, deviceManager);
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
}

/** Tier 2: advanced primitives (devices, processes, sessions, modules, native analysis). */
export function registerTier2Tools(server: McpServer, deviceManager: DeviceManager): void {
  registerAdvancedDeviceTools(server, deviceManager);
  registerAdvancedProcessTools(server, deviceManager);
  registerAdvancedSessionTools(server, deviceManager);
  registerAdvancedModuleTools(server);
  registerAdvancedInterceptTools(server);
  registerNativeAnalysisTools(server);
}

export function registerAllTools(server: McpServer, deviceManager: DeviceManager, options: RegisterAllOptions = {}): void {
  registerTier1Tools(server, deviceManager);
  registerTier2Tools(server, deviceManager);
  if (options.resources !== false) registerResources(server, deviceManager);
  if (options.prompts !== false) registerPrompts(server);
}
