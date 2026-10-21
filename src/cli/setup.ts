/**
 * `frida-mobile-mcp setup` - registers this package as an MCP server in a
 * client's configuration (Claude Code, Claude Desktop, Cursor, VS Code,
 * Windsurf, Codex).
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';

export const CLIENT_NAMES = [
  'claude-code',
  'claude-desktop',
  'cursor',
  'vscode',
  'windsurf',
  'codex',
] as const;

export type ClientName = (typeof CLIENT_NAMES)[number];

export interface SetupOptions {
  client: ClientName;
  device?: string;
  allowCustomScripts?: boolean;
  allowMemoryWrite?: boolean;
  print?: boolean;
}

export interface ServerEntry {
  command: 'npx';
  args: string[];
  env?: Record<string, string>;
}

export interface SetupEnv {
  platform: NodeJS.Platform;
  home: string;
  cwd: string;
  appData?: string;
}

export interface SetupIo {
  readFile(p: string): string | null;
  writeFile(p: string, text: string): void;
  copyFile(src: string, dst: string): void;
  mkdirp(p: string): void;
  exists(p: string): boolean;
  which(bin: string): string | null;
  run(cmd: string, args: string[]): { code: number | null; output: string };
  log(line: string): void;
  env: SetupEnv;
}

const PACKAGE_NAME = 'frida-mobile-mcp';
const DEFAULT_SERVER_NAME = 'frida';
const DEVICE_ENV_VAR = 'FRIDA_DEVICE_ID';

type JsonObject = Record<string, unknown>;

// ---------------------------------------------------------------------------
// Server entry
// ---------------------------------------------------------------------------

export function buildServerEntry(
  opts: Pick<SetupOptions, 'device' | 'allowCustomScripts' | 'allowMemoryWrite'>,
): ServerEntry {
  const entry: ServerEntry = { command: 'npx', args: ['-y', PACKAGE_NAME, ...permissionFlags(opts)] };
  if (opts.device) {
    entry.env = { [DEVICE_ENV_VAR]: opts.device };
  }
  return entry;
}

function permissionFlags(opts: Pick<SetupOptions, 'allowCustomScripts' | 'allowMemoryWrite'>): string[] {
  const flags: string[] = [];
  if (opts.allowCustomScripts) flags.push('--allow-custom-scripts');
  if (opts.allowMemoryWrite) flags.push('--allow-memory-write');
  return flags;
}

// ---------------------------------------------------------------------------
// Client config locations
// ---------------------------------------------------------------------------

export function configPathFor(client: ClientName, env: SetupEnv): string | null {
  switch (client) {
    case 'claude-code':
      return null;
    case 'claude-desktop':
      return claudeDesktopConfigPath(env);
    case 'cursor':
      return `${env.home}/.cursor/mcp.json`;
    case 'windsurf':
      return `${env.home}/.codeium/windsurf/mcp_config.json`;
    case 'vscode':
      return `${env.cwd}/.vscode/mcp.json`;
    case 'codex':
      return `${env.home}/.codex/config.toml`;
  }
}

function claudeDesktopConfigPath(env: SetupEnv): string {
  switch (env.platform) {
    case 'darwin':
      return `${env.home}/Library/Application Support/Claude/claude_desktop_config.json`;
    case 'win32':
      return `${env.appData ?? env.home + '\\AppData\\Roaming'}\\Claude\\claude_desktop_config.json`;
    default:
      return `${env.home}/.config/Claude/claude_desktop_config.json`;
  }
}

export function serversKeyFor(client: ClientName): 'mcpServers' | 'servers' {
  return client === 'vscode' ? 'servers' : 'mcpServers';
}

// ---------------------------------------------------------------------------
// Renderers
// ---------------------------------------------------------------------------

export function mergeJsonConfig(
  existingText: string | null,
  key: 'mcpServers' | 'servers',
  entry: ServerEntry,
  serverName = DEFAULT_SERVER_NAME,
): string {
  const config = parseExistingConfig(existingText);
  const servers = isPlainObject(config[key]) ? (config[key] as JsonObject) : {};
  config[key] = { ...servers, [serverName]: entry };
  return JSON.stringify(config, null, 2) + '\n';
}

function parseExistingConfig(text: string | null): JsonObject {
  if (text === null || text.trim() === '') return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error(`Existing config is not valid JSON: ${(err as Error).message}`);
  }
  if (!isPlainObject(parsed)) {
    throw new Error('Existing config is not a JSON object');
  }
  return parsed;
}

function isPlainObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function renderCodexToml(entry: ServerEntry, serverName = DEFAULT_SERVER_NAME): string {
  const lines = [
    `[mcp_servers.${serverName}]`,
    `command = ${tomlString(entry.command)}`,
    `args = [${entry.args.map(tomlString).join(', ')}]`,
  ];
  if (entry.env && Object.keys(entry.env).length > 0) {
    lines.push(`[mcp_servers.${serverName}.env]`);
    for (const [name, value] of Object.entries(entry.env)) {
      lines.push(`${name} = ${tomlString(value)}`);
    }
  }
  return lines.join('\n') + '\n';
}

function tomlString(value: string): string {
  return JSON.stringify(value);
}

export function claudeCodeCommand(entry: ServerEntry, serverName = DEFAULT_SERVER_NAME): string[] {
  const envArgs = Object.entries(entry.env ?? {}).flatMap(([name, value]) => ['-e', `${name}=${value}`]);
  return ['claude', 'mcp', 'add', '--scope', 'user', ...envArgs, serverName, '--', entry.command, ...entry.args];
}

function shellJoin(args: string[]): string {
  return args.map((arg) => (/\s/.test(arg) ? `"${arg.replace(/[\\"$`]/g, '\\$&')}"` : arg)).join(' ');
}

// ---------------------------------------------------------------------------
// Default IO (real filesystem / processes)
// ---------------------------------------------------------------------------

export function defaultSetupIo(): SetupIo {
  const platform = process.platform;
  return {
    readFile: (p) => (fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : null),
    writeFile: (p, text) => fs.writeFileSync(p, text, 'utf8'),
    copyFile: (src, dst) => fs.copyFileSync(src, dst),
    mkdirp: (p) => fs.mkdirSync(p, { recursive: true }),
    exists: (p) => fs.existsSync(p),
    which: (bin) => findOnPath(bin, platform),
    run: runProcess,
    log: (line) => console.log(line),
    env: { platform, home: os.homedir(), cwd: process.cwd(), appData: process.env.APPDATA },
  };
}

function findOnPath(bin: string, platform: NodeJS.Platform): string | null {
  const dirs = (process.env.PATH ?? '').split(path.delimiter).filter(Boolean);
  for (const dir of dirs) {
    for (const ext of executableExtensions(platform)) {
      const candidate = path.join(dir, bin + ext);
      if (isExecutableFile(candidate)) return candidate;
    }
  }
  return null;
}

function executableExtensions(platform: NodeJS.Platform): string[] {
  if (platform !== 'win32') return [''];
  const pathExt = process.env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD';
  return ['', ...pathExt.split(';').filter(Boolean)];
}

function isExecutableFile(candidate: string): boolean {
  try {
    const stat = fs.statSync(candidate);
    if (!stat.isFile()) return false;
    fs.accessSync(candidate, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function runProcess(cmd: string, args: string[]): { code: number | null; output: string } {
  const result = spawnSync(cmd, args, { encoding: 'utf8', shell: process.platform === 'win32' });
  const output = [result.stdout, result.stderr].filter(Boolean).join('');
  return { code: result.error ? 1 : result.status, output };
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

export function runSetup(opts: SetupOptions, io: SetupIo = defaultSetupIo()): number {
  if (!isKnownClient(opts.client)) {
    io.log(`Unknown client "${String(opts.client)}". Valid clients: ${CLIENT_NAMES.join(', ')}`);
    return 2;
  }
  const entry = buildServerEntry(opts);
  switch (opts.client) {
    case 'codex':
      return setupCodex(entry, io);
    case 'claude-code':
      return setupClaudeCode(entry, opts.print === true, io);
    default:
      return setupJsonClient(opts.client, entry, opts.print === true, io);
  }
}

function isKnownClient(client: unknown): client is ClientName {
  return (CLIENT_NAMES as readonly unknown[]).includes(client);
}

function setupCodex(entry: ServerEntry, io: SetupIo): number {
  const target = configPathFor('codex', io.env);
  io.log(`Add the following to ${target}:`);
  io.log('');
  io.log(renderCodexToml(entry).trimEnd());
  return 0;
}

function setupClaudeCode(entry: ServerEntry, print: boolean, io: SetupIo): number {
  const [bin, ...args] = claudeCodeCommand(entry);
  const binPath = print ? null : io.which(bin);
  if (binPath === null) {
    if (!print) io.log(`"${bin}" was not found on PATH. Run this command manually:`);
    io.log(shellJoin([bin, ...args]));
    return 0;
  }
  const result = io.run(binPath, args);
  if (result.output.trim()) io.log(result.output.trimEnd());
  return result.code ?? 1;
}

function setupJsonClient(client: ClientName, entry: ServerEntry, print: boolean, io: SetupIo): number {
  const target = configPathFor(client, io.env);
  if (target === null) {
    io.log(`Client "${client}" has no config file to write.`);
    return 2;
  }
  let merged: string;
  try {
    merged = mergeJsonConfig(io.readFile(target), serversKeyFor(client), entry);
  } catch (err) {
    io.log(`Cannot update ${target}: ${(err as Error).message}`);
    return 1;
  }
  return print ? printJsonConfig(target, merged, io) : writeJsonConfig(target, merged, io);
}

function printJsonConfig(target: string, merged: string, io: SetupIo): number {
  io.log(`Target: ${target}`);
  io.log(merged.trimEnd());
  return 0;
}

function writeJsonConfig(target: string, merged: string, io: SetupIo): number {
  const backup = `${target}.bak`;
  io.mkdirp(path.dirname(target));
  const hadExisting = io.exists(target);
  if (hadExisting) io.copyFile(target, backup);
  io.writeFile(target, merged);
  io.log(hadExisting ? `Wrote ${target} (backup: ${backup})` : `Wrote ${target}`);
  return 0;
}
