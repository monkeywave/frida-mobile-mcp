import { McpServer } from '@modelcontextprotocol/server';
import { getState } from './state.js';
import { loadConfig } from './config.js';
import { log } from './helpers/logger.js';
import { initRuntime } from './lib.js';
import { getPackageVersion } from './helpers/version.js';
import { DeviceManager } from './device/manager.js';
import { registerAllTools } from './tools/register-all.js';
import type { FridaMcpConfig } from './types.js';

export function createServer(configOverrides?: Partial<FridaMcpConfig>): McpServer {
  // Load config
  const config = loadConfig(configOverrides);

  // Init logger, evidence store and state
  const state = initRuntime(config);

  // Create device manager
  const deviceManager = new DeviceManager(state.deviceManager, config);

  // Create MCP server
  const server = new McpServer(
    {
      name: 'frida-mobile-mcp',
      version: getPackageVersion(),
    },
    {
      capabilities: {
        tools: {},
        resources: {},
        prompts: {},
      },
    }
  );

  // Register every tool, resource and prompt (single source of truth: tools/register-all.ts)
  registerAllTools(server, deviceManager);

  log('info', 'MCP server initialized with all tools registered');

  return server;
}
