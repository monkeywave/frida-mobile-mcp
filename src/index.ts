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
import { addRemoteDeviceForState } from './device/manager.js';
import { getActiveConfig, isToolProfile, parseToolsExclude, TOOL_PROFILES, type RuntimeConfig, type ToolProfile } from './config.js';
import { runDoctor } from './cli/doctor.js';
import { runSetup, CLIENT_NAMES, type ClientName } from './cli/setup.js';
import {
  runGadget,
  GADGET_INTERACTIONS,
  GADGET_PLATFORMS,
  type GadgetInteraction,
  type GadgetPlatform,
} from './cli/gadget.js';

interface ServeOptions {
  transport: string;
  host: string;
  port: string;
  httpToken?: string;
  device?: string;
  remote?: string;
  remoteToken?: string;
  remoteCert?: string;
  allowCustomScripts?: boolean;
  allowMemoryWrite?: boolean;
  allowNativeInjection?: boolean;
  allowAdbShell?: boolean;
  toolProfile?: string;
  excludeTools?: string;
  mobileMcp: boolean;
  debug?: boolean;
  listDevices?: boolean;
}

interface SetupCliOptions {
  client: string;
  device?: string;
  allowCustomScripts?: boolean;
  allowMemoryWrite?: boolean;
  allowNativeInjection?: boolean;
  allowAdbShell?: boolean;
  print?: boolean;
}

interface GadgetCliOptions {
  interaction: string;
  platform: string;
  address: string;
  port?: string;
  onPortConflict: string;
  onLoad: string;
  script?: string;
  onChange: string;
  runtime?: string;
  out?: string;
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
  .option('--remote <host[:port]>', 'Add a remote frida-server at startup (or FRIDA_MCP_REMOTE)')
  .option('--remote-token <token>', 'Auth token of the remote frida-server (or FRIDA_MCP_REMOTE_TOKEN)')
  .option('--remote-cert <path>', 'TLS certificate (PEM) of the remote frida-server (or FRIDA_MCP_REMOTE_CERT)')
  .option('--allow-custom-scripts', 'Allow execution of custom Frida scripts')
  .option('--allow-memory-write', 'Allow memory write operations')
  .option('--allow-native-injection', 'Allow native library injection (inject_library)')
  .option('--allow-adb-shell', 'Allow raw adb shell commands (adb_shell)')
  .option('--tool-profile <profile>', 'Tools to expose: full or core (or FRIDA_MCP_TOOL_PROFILE)')
  .option('--exclude-tools <globs>', 'Comma-separated tool-name globs to hide, e.g. "adb_*" (or FRIDA_MCP_TOOLS_EXCLUDE)')
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
  .option('--allow-native-injection', 'Pass --allow-native-injection to the server')
  .option('--allow-adb-shell', 'Pass --allow-adb-shell to the server')
  .option('--print', 'Print the configuration instead of writing it')
  .action((opts: SetupCliOptions) => runWithErrorHandling(async () => process.exit(setup(opts))));

program
  .command('gadget')
  .description('Generate a frida-gadget config.json and print APK/IPA repackaging guidance')
  .option('--interaction <type>', `Gadget interaction: ${GADGET_INTERACTIONS.join(', ')}`, 'listen')
  .option('--platform <os>', `Target platform for the guidance: ${GADGET_PLATFORMS.join(', ')}`, 'android')
  .option('--address <addr>', 'listen: bind address', '127.0.0.1')
  .option('--port <number>', 'listen: TCP port', '27042')
  .option('--on-port-conflict <mode>', 'listen: fail or pick-next', 'fail')
  .option('--on-load <mode>', 'listen: resume or wait', 'wait')
  .option('--script <path>', 'script: on-device path to the agent script the gadget runs')
  .option('--on-change <mode>', 'script: ignore or reload', 'reload')
  .option('--runtime <engine>', 'GumJS runtime override: qjs or v8')
  .option('--out <path>', 'Write the config to this path instead of the platform default')
  .option('--print', 'Print the config instead of writing it')
  .action((opts: GadgetCliOptions) => runWithErrorHandling(async () => process.exit(gadget(opts))));

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
    allowNativeInjection: opts.allowNativeInjection,
    allowAdbShell: opts.allowAdbShell,
    print: opts.print,
  });
}

function gadget(opts: GadgetCliOptions): number {
  return runGadget({
    interaction: opts.interaction as GadgetInteraction,
    platform: opts.platform as GadgetPlatform,
    address: opts.address,
    port: opts.port !== undefined ? parsePort(opts.port) : undefined,
    onPortConflict: opts.onPortConflict as 'fail' | 'pick-next',
    onLoad: opts.onLoad as 'resume' | 'wait',
    scriptPath: opts.script,
    onChange: opts.onChange as 'ignore' | 'reload',
    runtime: opts.runtime as 'qjs' | 'v8' | undefined,
    out: opts.out,
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

/** Unlike the env variable (which falls back with a warning), a bad CLI flag is a hard error. */
function parseToolProfileFlag(value: string): ToolProfile {
  const normalized = value.trim().toLowerCase();
  if (!isToolProfile(normalized)) {
    throw new Error(`Invalid --tool-profile "${value}": expected ${TOOL_PROFILES.join(' or ')}`);
  }
  return normalized;
}

function configOverridesFrom(opts: ServeOptions): Partial<RuntimeConfig> {
  const overrides: Partial<RuntimeConfig> = {};
  if (opts.allowCustomScripts) overrides.allowCustomScripts = true;
  if (opts.allowMemoryWrite) overrides.memoryWriteEnabled = true;
  if (opts.allowNativeInjection) overrides.allowNativeInjection = true;
  if (opts.allowAdbShell) overrides.allowAdbShell = true;
  if (opts.toolProfile !== undefined) overrides.toolProfile = parseToolProfileFlag(opts.toolProfile);
  if (opts.excludeTools !== undefined) overrides.toolsExclude = parseToolsExclude(opts.excludeTools);
  if (opts.mobileMcp === false) overrides.mobileMcp = { enabled: false } as RuntimeConfig['mobileMcp'];
  if (opts.httpToken) overrides.httpToken = opts.httpToken;
  if (opts.remote) overrides.remoteDevice = opts.remote;
  if (opts.remoteToken) overrides.remoteToken = opts.remoteToken;
  if (opts.remoteCert) overrides.remoteCertificate = opts.remoteCert;
  return overrides;
}

/** `FRIDA_MCP_REMOTE=host[:port]`: register the remote frida-server and select it when nothing else is. */
async function addRemoteDeviceFromConfig(config: RuntimeConfig | null): Promise<void> {
  const address = config?.remoteDevice;
  if (!address) return;
  try {
    const state = getState();
    const device = await addRemoteDeviceForState(state, address, {
      token: config?.remoteToken,
      certificate: config?.remoteCertificate,
    });
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
