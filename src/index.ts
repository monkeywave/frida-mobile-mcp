#!/usr/bin/env node

import { Command } from 'commander';
import frida from 'frida';
import { createServer } from './server.js';
import { createSessionServer } from './lib.js';
import { createStdioTransport } from './transport/stdio.js';
import { startHttpServer, type HttpServerHandle } from './transport/http.js';
import { logStartupBanner, log } from './helpers/logger.js';
import { getPackageVersion } from './helpers/version.js';
import { getState } from './state.js';
import { getActiveConfig, type RuntimeConfig } from './config.js';
import { runDoctor } from './cli/doctor.js';
import { runSetup, CLIENT_NAMES, type ClientName } from './cli/setup.js';

interface ServeOptions {
  transport: string;
  host: string;
  port: string;
  httpToken?: string;
  device?: string;
  allowCustomScripts?: boolean;
  allowMemoryWrite?: boolean;
  mobileMcp: boolean;
  debug?: boolean;
  listDevices?: boolean;
}

interface SetupCliOptions {
  client: string;
  device?: string;
  allowCustomScripts?: boolean;
  allowMemoryWrite?: boolean;
  print?: boolean;
}

const program = new Command();

program
  .name('frida-mobile-mcp')
  .description('Mobile Frida MCP Server - AI-powered mobile app exploration and testing')
  .version(getPackageVersion());

program
  .command('serve', { isDefault: true })
  .description('Run the MCP server (default command)')
  .option('--transport <type>', 'Transport type: stdio or http', 'stdio')
  .option('--host <host>', 'HTTP bind address (http transport)', '127.0.0.1')
  .option('--port <number>', 'HTTP port, 0 picks a free port (http transport)', '3000')
  .option('--http-token <token>', 'Bearer token for the http transport (or FRIDA_MCP_HTTP_TOKEN)')
  .option('--device <id>', 'Frida device ID to use')
  .option('--allow-custom-scripts', 'Allow execution of custom Frida scripts')
  .option('--allow-memory-write', 'Allow memory write operations')
  .option('--no-mobile-mcp', 'Disable mobile-mcp integration')
  .option('--debug', 'Enable debug logging')
  .option('--list-devices', 'List Frida devices and exit')
  .action((opts: ServeOptions) => runWithErrorHandling(() => serve(opts)));

program
  .command('doctor')
  .description('Check Node, frida-node, adb, devices, frida-server and bridge bundles')
  .action(() => runWithErrorHandling(async () => process.exit(await runDoctor())));

program
  .command('setup')
  .description('Add this server to an MCP client configuration')
  .requiredOption('--client <name>', `Client: ${CLIENT_NAMES.join(', ')}`)
  .option('--device <id>', 'Default Frida device ID (FRIDA_DEVICE_ID)')
  .option('--allow-custom-scripts', 'Pass --allow-custom-scripts to the server')
  .option('--allow-memory-write', 'Pass --allow-memory-write to the server')
  .option('--print', 'Print the configuration instead of writing it')
  .action((opts: SetupCliOptions) => runWithErrorHandling(async () => process.exit(setup(opts))));

function runWithErrorHandling(task: () => Promise<void>): Promise<void> {
  return task().catch((err) => {
    console.error('Fatal error:', err instanceof Error ? err.message : err);
    process.exit(1);
  });
}

function setup(opts: SetupCliOptions): number {
  return runSetup({
    client: opts.client as ClientName,
    device: opts.device,
    allowCustomScripts: opts.allowCustomScripts,
    allowMemoryWrite: opts.allowMemoryWrite,
    print: opts.print,
  });
}

async function listDevices(): Promise<void> {
  const devices = await frida.enumerateDevices();
  console.log(['ID', 'TYPE', 'NAME'].join('\t'));
  for (const device of devices) {
    console.log([device.id, device.type, device.name].join('\t'));
  }
}

function configOverridesFrom(opts: ServeOptions): Partial<RuntimeConfig> {
  const overrides: Partial<RuntimeConfig> = {};
  if (opts.allowCustomScripts) overrides.allowCustomScripts = true;
  if (opts.allowMemoryWrite) overrides.memoryWriteEnabled = true;
  if (opts.mobileMcp === false) overrides.mobileMcp = { enabled: false } as RuntimeConfig['mobileMcp'];
  if (opts.httpToken) overrides.httpToken = opts.httpToken;
  return overrides;
}

/** `FRIDA_MCP_REMOTE=host[:port]`: register the remote frida-server and select it when nothing else is. */
async function addRemoteDeviceFromConfig(config: RuntimeConfig | null): Promise<void> {
  const address = config?.remoteDevice;
  if (!address) return;
  try {
    const state = getState();
    const device = await state.deviceManager.addRemoteDevice(address);
    if (!state.selectedDevice && !process.env.FRIDA_DEVICE_ID) {
      state.selectedDevice = device;
    }
    log('info', `Added remote frida-server ${address} as device "${device.id}"`);
  } catch (err) {
    log('warn', `Could not add remote frida-server ${address}: ${String(err)}`);
  }
}

function parsePort(value: string): number {
  const port = Number.parseInt(value, 10);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`Invalid --port "${value}": expected an integer between 0 and 65535`);
  }
  return port;
}

async function startHttp(opts: ServeOptions): Promise<HttpServerHandle> {
  const handle = await startHttpServer({
    host: opts.host,
    port: parsePort(opts.port),
    token: getActiveConfig()?.httpToken,
    createSessionServer,
  });
  console.error(JSON.stringify({ event: 'listening', url: handle.url, transport: 'http' }));
  return handle;
}

function installShutdownHandlers(closeTransport: () => Promise<void>): void {
  let shuttingDown = false;
  const shutdown = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    log('info', 'Shutting down frida-mobile-mcp server...');
    try {
      await closeTransport();
      await getState().cleanup();
    } catch { /* ignore cleanup errors */ }
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

async function serve(opts: ServeOptions): Promise<void> {
  if (opts.listDevices) {
    await listDevices();
    return;
  }
  if (opts.debug) process.env.FRIDA_MCP_DEBUG = '1';
  if (opts.device) process.env.FRIDA_DEVICE_ID = opts.device;
  if (opts.transport !== 'stdio' && opts.transport !== 'http') {
    throw new Error(`Unknown transport: ${opts.transport} (expected stdio or http)`);
  }

  const server = createServer(configOverridesFrom(opts));
  // The banner reads logger state (audit path), so it must come after createServer() initialised it.
  logStartupBanner();
  await addRemoteDeviceFromConfig(getActiveConfig());

  if (opts.transport === 'stdio') {
    await server.connect(createStdioTransport());
    log('info', 'frida-mobile-mcp server running on stdio transport');
    installShutdownHandlers(() => server.close());
    return;
  }

  const handle = await startHttp(opts);
  log('info', `frida-mobile-mcp server listening on ${handle.url}`);
  installShutdownHandlers(() => handle.close());
}

program.parseAsync().catch((err) => {
  console.error('Fatal error:', err instanceof Error ? err.message : err);
  process.exit(1);
});
