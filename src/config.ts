import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { FridaMcpConfig } from './types.js';

/** Tool schema verbosity: `compact` trims descriptions for small context windows. */
export type SchemaProfile = 'full' | 'compact';

const SCHEMA_PROFILES: readonly SchemaProfile[] = ['full', 'compact'];

/**
 * Runtime configuration: the persisted `FridaMcpConfig` plus process-level settings that
 * are only ever supplied through environment variables or CLI flags.
 */
export interface RuntimeConfig extends FridaMcpConfig {
  /** Tool schema profile consumed by tool registration (`FRIDA_MCP_SCHEMA_PROFILE`). */
  schemaProfile: SchemaProfile;
  /** Overrides the default response character limit (`FRIDA_MCP_MAX_RESPONSE_CHARS`). */
  maxResponseChars?: number;
  /** `host[:port]` of a remote frida-server added at startup (`FRIDA_MCP_REMOTE`). */
  remoteDevice?: string;
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
  snapshots: false,
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

/** Parse `FRIDA_MCP_MAX_RESPONSE_CHARS`; non-positive or non-numeric values are ignored. */
export function parseMaxResponseChars(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    console.error(`[frida-mobile-mcp] Warning: FRIDA_MCP_MAX_RESPONSE_CHARS="${value}" is not a positive integer, ignoring`);
    return undefined;
  }
  return parsed;
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
  config.maxResponseChars = parseMaxResponseChars(env.FRIDA_MCP_MAX_RESPONSE_CHARS) ?? config.maxResponseChars;
  config.remoteDevice = nonEmpty(env.FRIDA_MCP_REMOTE) ?? config.remoteDevice;
  config.httpToken = nonEmpty(env.FRIDA_MCP_HTTP_TOKEN) ?? config.httpToken;
  config.snapshots = parseBooleanFlag(env.FRIDA_MCP_SNAPSHOTS) ?? config.snapshots;
  return config;
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
