import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

let auditLogPath: string | null = null;
let logLevel: LogLevel = 'info';

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

export function initLogger(options: { auditPath?: string; level?: LogLevel }): void {
  if (options.auditPath) {
    auditLogPath = options.auditPath;
    try {
      mkdirSync(dirname(auditLogPath), { recursive: true });
    } catch { /* dir may already exist */ }
  }
  if (options.level) {
    logLevel = options.level;
  }
}

export function log(level: LogLevel, message: string, data?: Record<string, unknown>): void {
  if (LOG_LEVELS[level] < LOG_LEVELS[logLevel]) return;

  const entry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...data,
  };

  // Always write to stderr (stdout is MCP transport)
  console.error(`[frida-mobile-mcp] [${level.toUpperCase()}] ${message}`);

  if (data && level === 'debug') {
    console.error(JSON.stringify(data, null, 2));
  }
}

export interface AuditEntry {
  timestamp: string;
  sessionId?: string;
  tool: string;
  params: Record<string, unknown>;
  status: 'success' | 'error';
  durationMs?: number;
  scriptHash?: string;
}

export function audit(entry: AuditEntry): void {
  if (!auditLogPath) return;

  try {
    const line = JSON.stringify(entry) + '\n';
    appendFileSync(auditLogPath, line, 'utf-8');
  } catch (err) {
    console.error(`[frida-mobile-mcp] [ERROR] Failed to write audit log: ${err}`);
  }
}

export function logStartupBanner(): void {
  console.error('');
  console.error('=== frida-mobile-mcp: Mobile Frida MCP Server ===');
  console.error('WARNING: This server allows AI agents to inject code into mobile applications.');
  console.error('Only use with applications you own or have explicit authorization to test.');
  if (auditLogPath) {
    console.error(`Audit log: ${auditLogPath}`);
  }
  console.error('');
}
