import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { EvidenceStoreConfig, FridaMcpConfig } from './types.js';

/** Tool schema verbosity: `compact` trims descriptions for small context windows. */
export type SchemaProfile = 'full' | 'compact';

const SCHEMA_PROFILES: readonly SchemaProfile[] = ['full', 'compact'];

/** Tool exposure: `core` registers only the curated core tool set (see src/tools/tool-gate.ts). */
export type ToolProfile = 'full' | 'core';

export const TOOL_PROFILES: readonly ToolProfile[] = ['full', 'core'];

/** Evidence store defaults (`evidence` in config.json); the path defaults to `~/.config/frida-mobile-mcp/evidence`. */
export const EVIDENCE_DEFAULTS = { enabled: true, maxMb: 200, maxEntries: 5000, maxEntryKb: 2048 } as const;

/**
 * Runtime configuration: the persisted `FridaMcpConfig` plus process-level settings that
 * are only ever supplied through environment variables or CLI flags.
 */
export interface RuntimeConfig extends FridaMcpConfig {
  /** Tool schema profile consumed by tool registration (`FRIDA_MCP_SCHEMA_PROFILE`). */
  schemaProfile: SchemaProfile;
  /** Which tools are registered at all (`FRIDA_MCP_TOOL_PROFILE`, `--tool-profile`). */
  toolProfile: ToolProfile;
  /** Glob patterns of tool names never registered (`FRIDA_MCP_TOOLS_EXCLUDE`, `--exclude-tools`). */
  toolsExclude: string[];
  /** Overrides the default response character limit (`FRIDA_MCP_MAX_RESPONSE_CHARS`). */
  maxResponseChars?: number;
  /** `host[:port]` of a remote frida-server added at startup (`FRIDA_MCP_REMOTE`). */
  remoteDevice?: string;
  /** Auth token of the remote frida-server (`frida-server --token`, `FRIDA_MCP_REMOTE_TOKEN`). */
  remoteToken?: string;
  /** Path to the remote frida-server's TLS certificate (PEM) (`FRIDA_MCP_REMOTE_CERT`). */
  remoteCertificate?: string;
  /** Bearer token required by the HTTP transport (`FRIDA_MCP_HTTP_TOKEN`). */
  httpToken?: string;
}

const DEFAULT_CONFIG: RuntimeConfig = {
  allowCustomScripts: false,
  memoryWriteEnabled: false,
  allowAdbShell: false,
  allowNativeInjection: false,
  allowedDevices: [],
  maxSessions: 4,
  sessionTimeoutMinutes: 30,
  maxMessageBuffer: 1000,
  auditLogPath: join(homedir(), '.config', 'frida-mobile-mcp', 'audit.jsonl'),
  mobileMcp: {
    enabled: true,
    command: 'npx',
    args: ['-y', '@mobilenext/mobile-mcp@latest'],
  },
  rateLimits: {
    scriptsPerMinute: 10,
    memoryReadsPerMinute: 60,
    sessionsPerMinute: 5,
  },
  schemaProfile: 'full',
  toolProfile: 'full',
  toolsExclude: [],
  snapshots: false,
  evidence: { ...EVIDENCE_DEFAULTS },
};

export function getConfigPath(): string {
  return join(homedir(), '.config', 'frida-mobile-mcp', 'config.json');
}

function loadConfigFile(): Partial<RuntimeConfig> {
  const configPath = getConfigPath();
  if (!existsSync(configPath)) {
    return {};
  }
  try {
    const raw = readFileSync(configPath, 'utf-8');
    return JSON.parse(raw) as Partial<RuntimeConfig>;
  } catch {
    console.error(`[frida-mobile-mcp] Warning: Failed to parse config at ${configPath}, using defaults`);
    return {};
  }
}

function mergeConfig(base: RuntimeConfig, override: Partial<RuntimeConfig>): RuntimeConfig {
  return {
    ...base,
    ...override,
    mobileMcp: {
      ...base.mobileMcp,
      ...(override.mobileMcp ?? {}),
    },
    rateLimits: {
      ...base.rateLimits,
      ...(override.rateLimits ?? {}),
    },
    evidence: {
      ...base.evidence,
      ...(override.evidence ?? {}),
    },
  };
}

function isSchemaProfile(value: string): value is SchemaProfile {
  return (SCHEMA_PROFILES as readonly string[]).includes(value);
}

/** Parse `FRIDA_MCP_SCHEMA_PROFILE`; anything but a known profile falls back to the current value. */
export function parseSchemaProfile(value: string | undefined, fallback: SchemaProfile): SchemaProfile {
  if (!value) return fallback;
  const normalized = value.trim().toLowerCase();
  if (isSchemaProfile(normalized)) return normalized;
  console.error(
    `[frida-mobile-mcp] Warning: FRIDA_MCP_SCHEMA_PROFILE="${value}" is not one of ${SCHEMA_PROFILES.join('|')}, using "${fallback}"`
  );
  return fallback;
}

export function isToolProfile(value: string): value is ToolProfile {
  return (TOOL_PROFILES as readonly string[]).includes(value);
}

/** Parse `FRIDA_MCP_TOOL_PROFILE`; anything but a known profile falls back to the current value. */
export function parseToolProfile(value: string | undefined, fallback: ToolProfile): ToolProfile {
  if (!value) return fallback;
  const normalized = value.trim().toLowerCase();
  if (isToolProfile(normalized)) return normalized;
  console.error(
    `[frida-mobile-mcp] Warning: FRIDA_MCP_TOOL_PROFILE="${value}" is not one of ${TOOL_PROFILES.join('|')}, using "${fallback}"`
  );
  return fallback;
}

/** Parse a comma-separated glob list (`FRIDA_MCP_TOOLS_EXCLUDE`); entries are trimmed, empties dropped. */
export function parseToolsExclude(value: string | undefined): string[] | undefined {
  if (value === undefined) return undefined;
  return value.split(',').map((entry) => entry.trim()).filter((entry) => entry.length > 0);
}

/**
 * Parse a positive numeric env value; unset values yield undefined silently, non-positive or
 * non-numeric values warn (naming `envName`) and yield undefined so the caller keeps its default.
 * With `integer`, the value is parsed as a base-10 integer (trailing garbage is dropped).
 */
export function parsePositiveNumber(
  envName: string,
  value: string | undefined,
  { integer = false }: { integer?: boolean } = {}
): number | undefined {
  if (!value) return undefined;
  const parsed = integer ? Number.parseInt(value, 10) : Number(value.trim());
  if (!Number.isFinite(parsed) || parsed <= 0) {
    const expected = integer ? 'a positive integer' : 'a positive number';
    console.error(`[frida-mobile-mcp] Warning: ${envName}="${value}" is not ${expected}, ignoring`);
    return undefined;
  }
  return parsed;
}

/** Parse `FRIDA_MCP_MAX_RESPONSE_CHARS`; non-positive or non-numeric values are ignored. */
export function parseMaxResponseChars(value: string | undefined): number | undefined {
  return parsePositiveNumber('FRIDA_MCP_MAX_RESPONSE_CHARS', value, { integer: true });
}

/** `1` or `true` (any case) enable a boolean env flag; MCPB hosts render booleans as `true`. */
export function isEnabledFlag(value: string | undefined): boolean {
  const normalized = value?.trim().toLowerCase();
  return normalized === '1' || normalized === 'true';
}

/**
 * Parse an explicit on/off env flag: `1`/`true` -> true, `0`/`false` -> false, anything else
 * (including unset) -> undefined so the caller keeps its current value.
 */
export function parseBooleanFlag(value: string | undefined): boolean | undefined {
  const normalized = value?.trim().toLowerCase();
  if (normalized === '1' || normalized === 'true') return true;
  if (normalized === '0' || normalized === 'false') return false;
  return undefined;
}

function nonEmpty(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function applyEnvOverrides(config: RuntimeConfig): RuntimeConfig {
  const env = process.env;
  if (isEnabledFlag(env.FRIDA_MCP_ALLOW_CUSTOM_SCRIPTS)) {
    config.allowCustomScripts = true;
  }
  if (isEnabledFlag(env.FRIDA_MCP_MEMORY_WRITE)) {
    config.memoryWriteEnabled = true;
  }
  if (isEnabledFlag(env.FRIDA_MCP_ALLOW_ADB_SHELL)) {
    config.allowAdbShell = true;
  }
  if (isEnabledFlag(env.FRIDA_MCP_ALLOW_NATIVE_INJECTION)) {
    config.allowNativeInjection = true;
  }
  config.schemaProfile = parseSchemaProfile(env.FRIDA_MCP_SCHEMA_PROFILE, config.schemaProfile);
  config.toolProfile = parseToolProfile(env.FRIDA_MCP_TOOL_PROFILE, config.toolProfile);
  config.toolsExclude = parseToolsExclude(env.FRIDA_MCP_TOOLS_EXCLUDE) ?? config.toolsExclude;
  config.maxResponseChars = parseMaxResponseChars(env.FRIDA_MCP_MAX_RESPONSE_CHARS) ?? config.maxResponseChars;
  config.remoteDevice = nonEmpty(env.FRIDA_MCP_REMOTE) ?? config.remoteDevice;
  config.remoteToken = nonEmpty(env.FRIDA_MCP_REMOTE_TOKEN) ?? config.remoteToken;
  config.remoteCertificate = nonEmpty(env.FRIDA_MCP_REMOTE_CERT) ?? config.remoteCertificate;
  config.httpToken = nonEmpty(env.FRIDA_MCP_HTTP_TOKEN) ?? config.httpToken;
  config.snapshots = parseBooleanFlag(env.FRIDA_MCP_SNAPSHOTS) ?? config.snapshots;
  config.evidence = applyEvidenceEnvOverrides(config.evidence ?? {}, env);
  return config;
}

/** Parse `FRIDA_MCP_EVIDENCE_MAX_MB`; non-positive or non-numeric values are ignored. */
export function parseEvidenceMaxMb(value: string | undefined): number | undefined {
  return parsePositiveNumber('FRIDA_MCP_EVIDENCE_MAX_MB', value);
}

/** `FRIDA_MCP_EVIDENCE=0|1`, `FRIDA_MCP_EVIDENCE_PATH`, `FRIDA_MCP_EVIDENCE_MAX_MB`. */
function applyEvidenceEnvOverrides(evidence: EvidenceStoreConfig, env: NodeJS.ProcessEnv): EvidenceStoreConfig {
  return {
    ...evidence,
    enabled: parseBooleanFlag(env.FRIDA_MCP_EVIDENCE) ?? evidence.enabled,
    path: nonEmpty(env.FRIDA_MCP_EVIDENCE_PATH) ?? evidence.path,
    maxMb: parseEvidenceMaxMb(env.FRIDA_MCP_EVIDENCE_MAX_MB) ?? evidence.maxMb,
  };
}

let activeConfig: RuntimeConfig | null = null;

export function loadConfig(cliOverrides?: Partial<RuntimeConfig>): RuntimeConfig {
  const fileConfig = loadConfigFile();
  let config = mergeConfig(DEFAULT_CONFIG, fileConfig);
  if (cliOverrides) {
    config = mergeConfig(config, cliOverrides);
  }
  activeConfig = applyEnvOverrides(config);
  return activeConfig;
}

/** The configuration produced by the most recent `loadConfig()` call, or null before startup. */
export function getActiveConfig(): RuntimeConfig | null {
  return activeConfig;
}

export { DEFAULT_CONFIG };
