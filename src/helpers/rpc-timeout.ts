/**
 * Bounded wait for an agent rpc export call.
 *
 * Java.perform / ObjC enumeration inside the target may never call back (VM not ready,
 * process suspended, hostile app). Wrapping the `script.exports.x()` promise here turns a
 * hang into a clear RPC_TIMEOUT error instead of blocking the tool call forever.
 */
import { FridaMcpError } from './errors.js';

export const DEFAULT_RPC_TIMEOUT_MS = 15_000;

export class RpcTimeoutError extends FridaMcpError {
  constructor(label: string, timeoutMs: number) {
    super(
      'RPC_TIMEOUT',
      `${label} did not complete within ${timeoutMs / 1000}s. The runtime may not be ready yet (process suspended or VM still initializing).`,
      [
        { action: 'retry', reason: 'Retry once the app has finished launching' },
        { tool: 'get_status', reason: 'Check session state' },
      ],
      { label, timeout_ms: timeoutMs }
    );
  }
}

export function callRpcWithTimeout<T>(
  call: Promise<T>,
  label: string,
  timeoutMs: number = DEFAULT_RPC_TIMEOUT_MS
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new RpcTimeoutError(label, timeoutMs)), timeoutMs);
  });
  return Promise.race([call, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  }) as Promise<T>;
}
