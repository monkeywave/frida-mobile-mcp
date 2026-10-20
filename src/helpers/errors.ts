import type { ErrorCategory, ErrorResponse, RecoveryAction } from '../types.js';

/** Optional classification overrides; defaults are derived from the error code. */
export interface ErrorMeta {
  category?: ErrorCategory;
  retryable?: boolean;
  remediation?: string;
}

/**
 * Error code -> category/retryable defaults (REA/ReVa error envelope conventions).
 * Codes not listed here fall back to `provider` / not retryable.
 */
const ERROR_CLASSIFICATION: Record<string, { category: ErrorCategory; retryable: boolean }> = {
  INVALID_ARGUMENT: { category: 'request', retryable: false },
  INVALID_REQUEST: { category: 'request', retryable: false },
  SESSION_NOT_FOUND: { category: 'request', retryable: false },
  SCRIPT_NOT_FOUND: { category: 'request', retryable: false },
  HOOK_NOT_FOUND: { category: 'request', retryable: false },
  PROCESS_NOT_FOUND: { category: 'request', retryable: false },
  CUSTOM_SCRIPTS_DISABLED: { category: 'authorization', retryable: false },
  MEMORY_WRITE_DISABLED: { category: 'authorization', retryable: false },
  DEVICE_NOT_ALLOWED: { category: 'authorization', retryable: false },
  DEVICE_NOT_FOUND: { category: 'capability', retryable: false },
  MOBILE_MCP_UNAVAILABLE: { category: 'capability', retryable: false },
  FRITAP_AGENT_UNAVAILABLE: { category: 'capability', retryable: false },
  PLATFORM_UNSUPPORTED: { category: 'capability', retryable: false },
  RPC_TIMEOUT: { category: 'timeout', retryable: true },
  FRIDA_TIMEOUT: { category: 'timeout', retryable: true },
  RATE_LIMIT_EXCEEDED: { category: 'resource', retryable: true },
  RATE_LIMITED: { category: 'resource', retryable: true },
  SESSION_LIMIT_REACHED: { category: 'resource', retryable: true },
  SESSION_LOST: { category: 'provider', retryable: false },
  SCRIPT_ERROR: { category: 'provider', retryable: false },
  FRIDA_ERROR: { category: 'provider', retryable: false },
};

export function classifyErrorCode(code: string): { category: ErrorCategory; retryable: boolean } {
  return ERROR_CLASSIFICATION[code] ?? { category: 'provider', retryable: false };
}

export class FridaMcpError extends Error {
  code: string;
  category: ErrorCategory;
  retryable: boolean;
  remediation?: string;
  recoveryActions: RecoveryAction[];
  context: Record<string, unknown>;

  constructor(
    code: string,
    message: string,
    recoveryActions: RecoveryAction[] = [],
    context: Record<string, unknown> = {},
    meta: ErrorMeta = {}
  ) {
    super(message);
    this.name = 'FridaMcpError';
    this.code = code;
    this.recoveryActions = recoveryActions;
    this.context = context;
    const defaults = classifyErrorCode(code);
    this.category = meta.category ?? defaults.category;
    this.retryable = meta.retryable ?? defaults.retryable;
    this.remediation = meta.remediation ?? remediationFromRecoveryActions(recoveryActions);
  }

  toErrorResponse(): ErrorResponse {
    return {
      error: {
        code: this.code,
        category: this.category,
        message: this.message,
        retryable: this.retryable,
        ...(this.remediation ? { remediation: this.remediation } : {}),
        recovery_actions: this.recoveryActions,
        context: this.context,
      },
    };
  }
}

/** The first `user_intervention` recovery action doubles as the human-readable remediation. */
function remediationFromRecoveryActions(actions: RecoveryAction[]): string | undefined {
  const intervention = actions.find((a) => a.action === 'user_intervention' && a.message);
  return intervention?.message;
}

export class DeviceNotFoundError extends FridaMcpError {
  constructor(requested?: string, available?: string[]) {
    super(
      'DEVICE_NOT_FOUND',
      requested
        ? `Device "${requested}" not found or disconnected.`
        : 'No USB device detected.',
      [
        { tool: 'get_status', reason: 'Check available devices' },
        {
          action: 'user_intervention',
          message: 'Connect a device and ensure frida-server is running on it',
        },
      ],
      { requested_device: requested, available_devices: available }
    );
  }
}

export class ProcessNotFoundError extends FridaMcpError {
  constructor(target: string) {
    super(
      'PROCESS_NOT_FOUND',
      `Process "${target}" not found on the device.`,
      [
        { tool: 'get_status', reason: 'List running processes' },
        { tool: 'explore_app', args: { target }, reason: 'Try launching the app first' },
      ],
      { target }
    );
  }
}

export class SessionLostError extends FridaMcpError {
  constructor(sessionId: string, reason?: string) {
    super(
      'SESSION_LOST',
      `Session "${sessionId}" detached${reason ? `: ${reason}` : ''}.`,
      [
        { tool: 'get_status', reason: 'Check current session state' },
        { tool: 'explore_app', reason: 'Re-attach to the target app' },
      ],
      { session_id: sessionId, reason }
    );
  }
}

export class ScriptError extends FridaMcpError {
  constructor(message: string, scriptSource?: string) {
    super(
      'SCRIPT_ERROR',
      `Script error: ${message}`,
      [
        { tool: 'frida_help', args: { topic: 'examples' }, reason: 'See script examples' },
      ],
      { script_preview: scriptSource?.slice(0, 200) }
    );
  }
}

export class CustomScriptDisabledError extends FridaMcpError {
  constructor() {
    super(
      'CUSTOM_SCRIPTS_DISABLED',
      'Custom script execution is disabled. Use pre-built scripts or enable allowCustomScripts in config.',
      [
        { tool: 'run_prebuilt_script', reason: 'Use a pre-built script instead' },
        { tool: 'frida_help', args: { topic: 'scripts' }, reason: 'See available pre-built scripts' },
        {
          action: 'user_intervention',
          message: 'Set allowCustomScripts: true in ~/.config/frida-mobile-mcp/config.json',
        },
      ],
      {},
      {
        category: 'authorization',
        remediation: 'Enable custom scripts by setting allowCustomScripts: true in ~/.config/frida-mobile-mcp/config.json (or pass --allow-custom-scripts), then retry. Prefer run_prebuilt_script when a built-in script covers the task.',
      }
    );
  }
}

export class MemoryWriteDisabledError extends FridaMcpError {
  constructor() {
    super(
      'MEMORY_WRITE_DISABLED',
      'Memory write operations are disabled by default for safety.',
      [
        { tool: 'read_memory', reason: 'Read memory instead (always allowed)' },
        {
          action: 'user_intervention',
          message: 'Set memoryWriteEnabled: true in ~/.config/frida-mobile-mcp/config.json',
        },
      ]
    );
  }
}

export class MobileMcpUnavailableError extends FridaMcpError {
  constructor(reason: string) {
    super(
      'MOBILE_MCP_UNAVAILABLE',
      `mobile-mcp is not available: ${reason}`,
      [
        {
          action: 'user_intervention',
          message: 'Install mobile-mcp: npm install -g @mobilenext/mobile-mcp',
        },
        { tool: 'get_status', reason: 'All Frida tools continue to work normally' },
      ],
      { reason }
    );
  }
}

export class RateLimitError extends FridaMcpError {
  constructor(tool: string, limit: number) {
    super(
      'RATE_LIMIT_EXCEEDED',
      `Rate limit exceeded for ${tool}. Maximum ${limit} calls per minute.`,
      [
        { action: 'user_intervention', message: 'Wait a moment and try again' },
      ],
      { tool, limit },
      { category: 'resource', retryable: true, remediation: `Wait up to a minute and retry; the limit is ${limit} ${tool} calls per minute.` }
    );
  }
}

export class FritapAgentUnavailableError extends FridaMcpError {
  constructor(reason: string, searched: string[] = []) {
    super(
      'FRITAP_AGENT_UNAVAILABLE',
      `friTap agent bundle (fritap_agent.js) not found: ${reason}`,
      [
        {
          action: 'user_intervention',
          message: 'Install friTap (pip install friTap) or set FRITAP_AGENT_PATH=/path/to/fritap_agent.js, or call capture_tls with allow_download: true',
        },
        { tool: 'bypass_ssl_pinning', reason: 'Pinning bypass works without friTap' },
        { tool: 'run_prebuilt_script', args: { script_name: 'network_inspector' }, reason: 'HTTP-level monitoring without friTap' },
      ],
      { reason, searched },
      {
        category: 'capability',
        remediation: 'Run `pip install friTap` (the bundle is friTap/fritap_agent.js inside the package), or set FRITAP_AGENT_PATH to a frida-compile bundle, or allow the tool to download the pinned release with allow_download: true.',
      }
    );
  }
}

export function wrapFridaError(err: unknown): FridaMcpError {
  if (err instanceof FridaMcpError) return err;

  const message = err instanceof Error ? err.message : String(err);

  if (message.includes('unable to find device')) {
    return new DeviceNotFoundError();
  }
  if (message.includes('unable to find process')) {
    return new ProcessNotFoundError(message);
  }
  if (message.includes('detached')) {
    return new SessionLostError('unknown', message);
  }
  if (message.includes('script')) {
    return new ScriptError(message);
  }

  return new FridaMcpError('FRIDA_ERROR', message, [
    { tool: 'get_status', reason: 'Check current state' },
  ]);
}
