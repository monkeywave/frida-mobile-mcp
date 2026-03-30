import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { FridaMcpConfig } from './types.js';

const DEFAULT_CONFIG: FridaMcpConfig = {
  allowCustomScripts: false,
  memoryWriteEnabled: false,
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
};

function getConfigPath(): string {
  return join(homedir(), '.config', 'frida-mobile-mcp', 'config.json');
}

function loadConfigFile(): Partial<FridaMcpConfig> {
  const configPath = getConfigPath();
  if (!existsSync(configPath)) {
    return {};
  }
  try {
    const raw = readFileSync(configPath, 'utf-8');
    return JSON.parse(raw) as Partial<FridaMcpConfig>;
  } catch {
    console.error(`[frida-mobile-mcp] Warning: Failed to parse config at ${configPath}, using defaults`);
    return {};
  }
}

function mergeConfig(base: FridaMcpConfig, override: Partial<FridaMcpConfig>): FridaMcpConfig {
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

export function loadConfig(cliOverrides?: Partial<FridaMcpConfig>): FridaMcpConfig {
  const fileConfig = loadConfigFile();
  let config = mergeConfig(DEFAULT_CONFIG, fileConfig);
  if (cliOverrides) {
    config = mergeConfig(config, cliOverrides);
  }

  // Env var overrides
  if (process.env.FRIDA_MCP_ALLOW_CUSTOM_SCRIPTS === '1') {
    config.allowCustomScripts = true;
  }
  if (process.env.FRIDA_MCP_MEMORY_WRITE === '1') {
    config.memoryWriteEnabled = true;
  }

  return config;
}

export { DEFAULT_CONFIG };
