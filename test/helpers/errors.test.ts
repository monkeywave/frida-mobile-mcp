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
