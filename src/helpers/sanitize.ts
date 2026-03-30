const MAX_SCRIPT_SIZE = 256 * 1024; // 256KB
const MAX_MEMORY_READ = 4 * 1024 * 1024; // 4MB
const MAX_PROCESS_NAME_LENGTH = 256;
const MAX_TEXT_INPUT_LENGTH = 4096;

export function validateScriptSource(source: string): void {
  if (!source || source.trim().length === 0) {
    throw new Error('Script source cannot be empty');
  }
  if (Buffer.byteLength(source, 'utf-8') > MAX_SCRIPT_SIZE) {
    throw new Error(`Script exceeds maximum size of ${MAX_SCRIPT_SIZE / 1024}KB`);
  }
}

export function validateProcessTarget(target: string | number): void {
  if (typeof target === 'number') {
    if (!Number.isInteger(target) || target <= 0) {
      throw new Error('PID must be a positive integer');
    }
    return;
  }
  if (typeof target === 'string') {
    if (target.length === 0) {
      throw new Error('Process target cannot be empty');
    }
    if (target.length > MAX_PROCESS_NAME_LENGTH) {
      throw new Error(`Process name exceeds maximum length of ${MAX_PROCESS_NAME_LENGTH}`);
    }
    if (target.includes('\0')) {
      throw new Error('Process target cannot contain null bytes');
    }
  }
}

export function validateMemoryAddress(address: string | number, size: number): void {
  const addr = typeof address === 'string' ? parseInt(address, 16) : address;
  if (isNaN(addr) || addr < 0) {
    throw new Error('Memory address must be a non-negative integer or hex string');
  }
  if (!Number.isInteger(size) || size <= 0) {
    throw new Error('Memory read size must be a positive integer');
  }
  if (size > MAX_MEMORY_READ) {
    throw new Error(`Memory read size exceeds maximum of ${MAX_MEMORY_READ / (1024 * 1024)}MB`);
  }
}

export function validateFilePath(path: string): void {
  if (!path || path.trim().length === 0) {
    throw new Error('File path cannot be empty');
  }
  if (path.includes('\0')) {
    throw new Error('File path cannot contain null bytes');
  }
  // Resolve and check for directory traversal
  if (path.includes('..')) {
    throw new Error('File path cannot contain directory traversal (..)');
  }
}

export function validateTextInput(text: string): string {
  if (text.length > MAX_TEXT_INPUT_LENGTH) {
    throw new Error(`Text input exceeds maximum length of ${MAX_TEXT_INPUT_LENGTH}`);
  }
  return text;
}

export function escapeForScript(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/\r/g, '\\r');
}

export function sanitizeForLog(params: Record<string, unknown>): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(params)) {
    if (key === 'source' && typeof value === 'string') {
      // Truncate script source in logs
      sanitized[key] = value.slice(0, 200) + (value.length > 200 ? '...' : '');
    } else if (key === 'data' && typeof value === 'string' && value.length > 200) {
      sanitized[key] = value.slice(0, 200) + '...';
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}
