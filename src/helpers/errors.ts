import type { ErrorResponse, RecoveryAction } from '../types.js';

export class FridaMcpError extends Error {
  code: string;
  recoveryActions: RecoveryAction[];
  context: Record<string, unknown>;

  constructor(
    code: string,
    message: string,
    recoveryActions: RecoveryAction[] = [],
    context: Record<string, unknown> = {}
  ) {
    super(message);
    this.name = 'FridaMcpError';
    this.code = code;
    this.recoveryActions = recoveryActions;
    this.context = context;
  }

  toErrorResponse(): ErrorResponse {
    return {
      error: {
        code: this.code,
        message: this.message,
        recovery_actions: this.recoveryActions,
        context: this.context,
      },
    };
  }
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
      ]
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
      { tool, limit }
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
