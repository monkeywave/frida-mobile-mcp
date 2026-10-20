import { describe, it, expect } from 'vitest';
import {
  FridaMcpError,
  DeviceNotFoundError,
  ProcessNotFoundError,
  SessionLostError,
  ScriptError,
  CustomScriptDisabledError,
  MemoryWriteDisabledError,
  MobileMcpUnavailableError,
  RateLimitError,
  FritapAgentUnavailableError,
  wrapFridaError,
} from '../../src/helpers/errors.js';

describe('FridaMcpError', () => {
  it('creates error with code and message', () => {
    const err = new FridaMcpError('TEST_CODE', 'test message');
    expect(err.code).toBe('TEST_CODE');
    expect(err.message).toBe('test message');
    expect(err.recoveryActions).toEqual([]);
  });

  it('converts to error response format', () => {
    const err = new FridaMcpError('TEST', 'msg', [{ tool: 'get_status', reason: 'check' }]);
    const response = err.toErrorResponse();
    expect(response.error.code).toBe('TEST');
    expect(response.error.recovery_actions).toHaveLength(1);
    expect(response.error.recovery_actions[0].tool).toBe('get_status');
  });
});

describe('Specialized Errors', () => {
  it('DeviceNotFoundError has correct code and recovery actions', () => {
    const err = new DeviceNotFoundError('usb', ['local']);
    expect(err.code).toBe('DEVICE_NOT_FOUND');
    expect(err.recoveryActions.length).toBeGreaterThan(0);
    expect(err.context.available_devices).toEqual(['local']);
  });

  it('ProcessNotFoundError suggests explore_app', () => {
    const err = new ProcessNotFoundError('com.example');
    expect(err.code).toBe('PROCESS_NOT_FOUND');
    expect(err.recoveryActions.some(a => a.tool === 'explore_app')).toBe(true);
  });

  it('CustomScriptDisabledError suggests run_prebuilt_script', () => {
    const err = new CustomScriptDisabledError();
    expect(err.code).toBe('CUSTOM_SCRIPTS_DISABLED');
    expect(err.recoveryActions.some(a => a.tool === 'run_prebuilt_script')).toBe(true);
  });

  it('MemoryWriteDisabledError suggests read_memory', () => {
    const err = new MemoryWriteDisabledError();
    expect(err.code).toBe('MEMORY_WRITE_DISABLED');
    expect(err.recoveryActions.some(a => a.tool === 'read_memory')).toBe(true);
  });

  it('RateLimitError includes tool and limit', () => {
    const err = new RateLimitError('script', 10);
    expect(err.code).toBe('RATE_LIMIT_EXCEEDED');
    expect(err.message).toContain('10');
  });
});

describe('wrapFridaError', () => {
  it('passes through FridaMcpError unchanged', () => {
    const original = new CustomScriptDisabledError();
    expect(wrapFridaError(original)).toBe(original);
  });

  it('wraps unknown errors with FRIDA_ERROR code', () => {
    const wrapped = wrapFridaError(new Error('random error'));
    expect(wrapped.code).toBe('FRIDA_ERROR');
    expect(wrapped.message).toBe('random error');
  });

  it('classifies device not found errors', () => {
    const wrapped = wrapFridaError(new Error('unable to find device with id'));
    expect(wrapped.code).toBe('DEVICE_NOT_FOUND');
  });
});

describe('Error envelope classification (REA/ReVa conventions)', () => {
  it('maps RATE_LIMIT_EXCEEDED to resource and retryable', () => {
    const res = new RateLimitError('script', 10).toErrorResponse();
    expect(res.error.category).toBe('resource');
    expect(res.error.retryable).toBe(true);
    expect(res.error.remediation).toContain('retry');
    expect(res.error.recovery_actions.length).toBeGreaterThan(0);
  });

  it('maps CUSTOM_SCRIPTS_DISABLED to authorization with remediation text', () => {
    const res = new CustomScriptDisabledError().toErrorResponse();
    expect(res.error.category).toBe('authorization');
    expect(res.error.retryable).toBe(false);
    expect(res.error.remediation).toContain('allowCustomScripts');
  });

  it('maps DEVICE_NOT_FOUND to capability', () => {
    const res = new DeviceNotFoundError('usb').toErrorResponse();
    expect(res.error.category).toBe('capability');
    expect(res.error.retryable).toBe(false);
  });

  it('maps timeouts to timeout/retryable', () => {
    expect(new FridaMcpError('RPC_TIMEOUT', 'x').category).toBe('timeout');
    expect(new FridaMcpError('RPC_TIMEOUT', 'x').retryable).toBe(true);
    expect(new FridaMcpError('FRIDA_TIMEOUT', 'x').category).toBe('timeout');
    expect(new FridaMcpError('FRIDA_TIMEOUT', 'x').retryable).toBe(true);
  });

  it('maps SESSION_NOT_FOUND and INVALID_ARGUMENT to request', () => {
    expect(new FridaMcpError('SESSION_NOT_FOUND', 'x').category).toBe('request');
    expect(new FridaMcpError('INVALID_ARGUMENT', 'x').category).toBe('request');
  });

  it('falls back to provider for unknown codes', () => {
    const err = new FridaMcpError('SOMETHING_ELSE', 'x');
    expect(err.category).toBe('provider');
    expect(err.retryable).toBe(false);
  });

  it('derives remediation from a user_intervention recovery action', () => {
    const err = new MemoryWriteDisabledError();
    expect(err.remediation).toContain('memoryWriteEnabled');
    expect(err.toErrorResponse().error.remediation).toContain('memoryWriteEnabled');
  });

  it('accepts explicit overrides', () => {
    const err = new FridaMcpError('FRIDA_ERROR', 'x', [], {}, { category: 'timeout', retryable: true, remediation: 'retry' });
    const res = err.toErrorResponse();
    expect(res.error.category).toBe('timeout');
    expect(res.error.retryable).toBe(true);
    expect(res.error.remediation).toBe('retry');
  });

  it('omits remediation when none is known', () => {
    const res = new FridaMcpError('FRIDA_ERROR', 'x').toErrorResponse();
    expect('remediation' in res.error).toBe(false);
  });

  it('FritapAgentUnavailableError is a capability error with pip remediation', () => {
    const err = new FritapAgentUnavailableError('not installed', ['/a', '/b']);
    expect(err.code).toBe('FRITAP_AGENT_UNAVAILABLE');
    expect(err.category).toBe('capability');
    expect(err.remediation).toContain('pip install friTap');
    expect(err.context.searched).toEqual(['/a', '/b']);
  });
});
