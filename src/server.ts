import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { initState, getState } from './state.js';
import { loadConfig } from './config.js';
import { initLogger, logStartupBanner, log } from './helpers/logger.js';
import { DeviceManager } from './device/manager.js';
import { registerStatusTool } from './tools/status.js';
import { registerHelpTool } from './tools/help.js';
import { registerExploreTool } from './tools/explore.js';
import { registerHookTool } from './tools/hook.js';
import { registerTraceTool } from './tools/trace.js';
import { registerScriptTool } from './tools/script.js';
import { registerPrebuiltTool } from './tools/prebuilt.js';
import { registerSearchTool } from './tools/search.js';
import { registerMemoryTools } from './tools/memory.js';
import { registerSslTool } from './tools/ssl.js';
import { registerMessagesTool } from './tools/messages.js';
import { registerCleanupTool } from './tools/cleanup.js';
import { registerMobileTool } from './tools/mobile.js';
import { registerDetectTool } from './tools/detect.js';
import { registerAdvancedDeviceTools } from './tools/advanced/device.js';
import { registerAdvancedProcessTools } from './tools/advanced/process.js';
import { registerAdvancedSessionTools } from './tools/advanced/session.js';
import { registerAdvancedModuleTools } from './tools/advanced/modules.js';
import { registerAdvancedInterceptTools } from './tools/advanced/intercept.js';
import { registerResources } from './resources.js';
import { registerPrompts } from './prompts.js';
import type { FridaMcpConfig } from './types.js';

export function createServer(configOverrides?: Partial<FridaMcpConfig>): McpServer {
  // Load config
  const config = loadConfig(configOverrides);

  // Init logger
  initLogger({
    auditPath: config.auditLogPath,
    level: process.env.FRIDA_MCP_DEBUG === '1' ? 'debug' : 'info',
  });

  // Init state
  const state = initState(config);

  // Create device manager
  const deviceManager = new DeviceManager(state.deviceManager, config);

  // Create MCP server
  const server = new McpServer(
    {
      name: 'frida-mobile-mcp',
      version: '0.1.0',
    },
    {
      capabilities: {
        tools: {},
        resources: {},
        prompts: {},
      },
    }
  );

  // Register Tier 1 tools
  registerStatusTool(server, deviceManager);
  registerHelpTool(server);
  registerExploreTool(server, deviceManager);
  registerHookTool(server, deviceManager);
  registerTraceTool(server, deviceManager);
  registerScriptTool(server, deviceManager);
  registerPrebuiltTool(server, deviceManager);
  registerSearchTool(server, deviceManager);
  registerMemoryTools(server);
  registerSslTool(server, deviceManager);
  registerMessagesTool(server);
  registerCleanupTool(server);
  registerMobileTool(server);
  registerDetectTool(server, deviceManager);

  // Register Tier 2 advanced tools
  registerAdvancedDeviceTools(server, deviceManager);
  registerAdvancedProcessTools(server, deviceManager);
  registerAdvancedSessionTools(server, deviceManager);
  registerAdvancedModuleTools(server);
  registerAdvancedInterceptTools(server);

  // Register resources and prompts
  registerResources(server, deviceManager);
  registerPrompts(server);

  log('info', 'MCP server initialized with all tools registered');

  return server;
}
