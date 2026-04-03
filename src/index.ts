#!/usr/bin/env node

import { program } from 'commander';
import { createRequire } from 'module';
import { createServer } from './server.js';
import { createStdioTransport } from './transport/stdio.js';
import { logStartupBanner, log } from './helpers/logger.js';
import { getState } from './state.js';

const require = createRequire(import.meta.url);
const { version } = require('../package.json');

program
  .name('frida-mobile-mcp')
  .description('Mobile Frida MCP Server - AI-powered mobile app exploration and testing')
  .version(version)
  .option('--transport <type>', 'Transport type: stdio or http', 'stdio')
  .option('--port <number>', 'HTTP port (when using http transport)', '3000')
  .option('--device <id>', 'Frida device ID to use')
  .option('--allow-custom-scripts', 'Allow execution of custom Frida scripts')
  .option('--allow-memory-write', 'Allow memory write operations')
  .option('--no-mobile-mcp', 'Disable mobile-mcp integration')
  .option('--debug', 'Enable debug logging');

program.parse();

const opts = program.opts();

async function main(): Promise<void> {
  logStartupBanner();

  // Wire --debug flag to environment variable (checked by logger)
  if (opts.debug) {
    process.env.FRIDA_MCP_DEBUG = '1';
  }

  const configOverrides: Record<string, unknown> = {};
  if (opts.allowCustomScripts) {
    configOverrides.allowCustomScripts = true;
  }
  if (opts.allowMemoryWrite) {
    configOverrides.memoryWriteEnabled = true;
  }
  if (opts.mobileMcp === false) {
    configOverrides.mobileMcp = { enabled: false };
  }

  const server = createServer(configOverrides as any);

  if (opts.transport === 'stdio') {
    const transport = createStdioTransport();
    await server.connect(transport);
    log('info', 'frida-mobile-mcp server running on stdio transport');
  } else if (opts.transport === 'http') {
    // HTTP transport will be implemented in Phase 6
    console.error(`HTTP transport not yet implemented. Use --transport stdio`);
    process.exit(1);
  } else {
    console.error(`Unknown transport: ${opts.transport}`);
    process.exit(1);
  }

  // Resolve initial device if specified
  if (opts.device) {
    process.env.FRIDA_DEVICE_ID = opts.device;
  }

  // Handle graceful shutdown
  const shutdown = async () => {
    log('info', 'Shutting down frida-mobile-mcp server...');
    try {
      const state = getState();
      await state.cleanup();
    } catch { /* ignore cleanup errors */ }
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
