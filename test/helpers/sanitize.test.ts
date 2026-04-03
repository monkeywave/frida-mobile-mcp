import { describe, it, expect } from 'vitest';
import {
  validateScriptSource,
  validateProcessTarget,
  validateMemoryAddress,
  validateFilePath,
  validateTextInput,
  escapeForScript,
} from '../../src/helpers/sanitize.js';

describe('validateScriptSource', () => {
  it('throws on empty string', () => {
    expect(() => validateScriptSource('')).toThrow('Script source cannot be empty');
  });

  it('throws on whitespace-only string', () => {
    expect(() => validateScriptSource('   ')).toThrow('Script source cannot be empty');
  });

  it('passes for a normal script string', () => {
    expect(() => validateScriptSource('console.log("hello");')).not.toThrow();
  });

  it('throws when script exceeds 256KB', () => {
    const oversized = 'a'.repeat(256 * 1024 + 1);
    expect(() => validateScriptSource(oversized)).toThrow('exceeds maximum size of 256KB');
  });

  it('passes for script exactly at 256KB boundary', () => {
    const atLimit = 'a'.repeat(256 * 1024);
    expect(() => validateScriptSource(atLimit)).not.toThrow();
  });
});

describe('validateProcessTarget', () => {
  it('passes for a valid PID', () => {
    expect(() => validateProcessTarget(1234)).not.toThrow();
  });

  it('throws for PID 0', () => {
    expect(() => validateProcessTarget(0)).toThrow('PID must be a positive integer');
  });

  it('throws for negative PID', () => {
    expect(() => validateProcessTarget(-5)).toThrow('PID must be a positive integer');
  });

  it('throws for non-integer PID', () => {
    expect(() => validateProcessTarget(3.14)).toThrow('PID must be a positive integer');
  });

  it('throws for empty string target', () => {
    expect(() => validateProcessTarget('')).toThrow('Process target cannot be empty');
  });

  it('throws for string containing null byte', () => {
    expect(() => validateProcessTarget('com.example\0.app')).toThrow(
      'Process target cannot contain null bytes',
    );
  });

  it('throws for string exceeding 256 characters', () => {
    const longName = 'a'.repeat(257);
    expect(() => validateProcessTarget(longName)).toThrow(
      'Process name exceeds maximum length of 256',
    );
  });

  it('passes for a normal process name', () => {
    expect(() => validateProcessTarget('com.example.app')).not.toThrow();
  });

  it('passes for a process name exactly at 256 characters', () => {
    const atLimit = 'a'.repeat(256);
    expect(() => validateProcessTarget(atLimit)).not.toThrow();
  });
});

describe('validateMemoryAddress', () => {
  it('passes for a valid hex address string with valid size', () => {
    expect(() => validateMemoryAddress('1A2B3C', 64)).not.toThrow();
  });

  it('passes for a valid numeric address with valid size', () => {
    expect(() => validateMemoryAddress(4096, 128)).not.toThrow();
  });

  it('throws for NaN address (invalid hex string)', () => {
    expect(() => validateMemoryAddress('not_hex', 64)).toThrow(
      'Memory address must be a non-negative integer or hex string',
    );
  });

  it('throws for size of 0', () => {
    expect(() => validateMemoryAddress('1000', 0)).toThrow(
      'Memory read size must be a positive integer',
    );
  });

  it('throws for negative size', () => {
    expect(() => validateMemoryAddress('1000', -1)).toThrow(
      'Memory read size must be a positive integer',
    );
  });

  it('throws for non-integer size', () => {
    expect(() => validateMemoryAddress('1000', 1.5)).toThrow(
      'Memory read size must be a positive integer',
    );
  });

  it('throws when size exceeds 4MB', () => {
    const overLimit = 4 * 1024 * 1024 + 1;
    expect(() => validateMemoryAddress('1000', overLimit)).toThrow(
      'Memory read size exceeds maximum of 4MB',
    );
  });

  it('passes for size exactly at 4MB boundary', () => {
    const atLimit = 4 * 1024 * 1024;
    expect(() => validateMemoryAddress('1000', atLimit)).not.toThrow();
  });
});

describe('validateFilePath', () => {
  it('throws for empty string', () => {
    expect(() => validateFilePath('')).toThrow('File path cannot be empty');
  });

  it('throws for whitespace-only string', () => {
    expect(() => validateFilePath('   ')).toThrow('File path cannot be empty');
  });

  it('throws for path containing null byte', () => {
    expect(() => validateFilePath('/tmp/file\0.txt')).toThrow(
      'File path cannot contain null bytes',
    );
  });

  it('throws for path with directory traversal (..)', () => {
    expect(() => validateFilePath('/tmp/../etc/passwd')).toThrow(
      'File path cannot contain directory traversal (..)',
    );
  });

  it('passes for a normal file path', () => {
    expect(() => validateFilePath('/tmp/data/output.txt')).not.toThrow();
  });

  it('passes for a relative path without traversal', () => {
    expect(() => validateFilePath('data/output.txt')).not.toThrow();
  });
});

describe('validateTextInput', () => {
  it('returns the same string for normal input', () => {
    const result = validateTextInput('hello world');
    expect(result).toBe('hello world');
  });

  it('passes for input exactly at 4096 characters', () => {
    const atLimit = 'x'.repeat(4096);
    expect(validateTextInput(atLimit)).toBe(atLimit);
  });

  it('throws when input exceeds 4096 characters', () => {
    const oversized = 'x'.repeat(4097);
    expect(() => validateTextInput(oversized)).toThrow(
      'Text input exceeds maximum length of 4096',
    );
  });
});

describe('escapeForScript', () => {
  it('escapes backslashes', () => {
    expect(escapeForScript('path\\to\\file')).toBe('path\\\\to\\\\file');
  });

  it('escapes single quotes', () => {
    expect(escapeForScript("it's")).toBe("it\\'s");
  });

  it('escapes newlines', () => {
    expect(escapeForScript('line1\nline2')).toBe('line1\\nline2');
  });

  it('escapes carriage returns', () => {
    expect(escapeForScript('line1\rline2')).toBe('line1\\rline2');
  });

  it('escapes a combination of special characters', () => {
    expect(escapeForScript("it's a\nnew\\path\r")).toBe("it\\'s a\\nnew\\\\path\\r");
  });

  it('prevents script injection via escaped single quotes', () => {
    const malicious = "'); process.exit(1); ('";
    const escaped = escapeForScript(malicious);
    expect(escaped).toBe("\\'); process.exit(1); (\\'");
    // Every single quote in the output is preceded by a backslash, preventing injection
    expect(escaped.match(/(?<!\\)'/g)).toBeNull();
  });

  it('returns empty string unchanged', () => {
    expect(escapeForScript('')).toBe('');
  });
});
