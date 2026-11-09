/**
 * Read/write direction of a friTap plaintext record.
 *
 * ABI-3 agents (friTap >= 2.6.3) may set an explicit `direction` on the datalog payload; it wins.
 * Otherwise the direction is derived from the hooked function label, like friTap's
 * `direction_for_function` (friTap/constants.py): explicit read/write sets first, then substring
 * hints, and 'write' for anything still unclassified (friTap's own default).
 */
import { READ_LABEL_HINTS, SSL_READ_FUNCTIONS, SSL_WRITE_FUNCTIONS, WRITE_LABEL_HINTS } from './constants.js';

export type RecordDirection = 'read' | 'write';

const EXPLICIT_DIRECTION_ALIASES: Readonly<Record<string, RecordDirection>> = {
  read: 'read', recv: 'read', receive: 'read', in: 'read', inbound: 'read', incoming: 'read',
  write: 'write', send: 'write', out: 'write', outbound: 'write', outgoing: 'write',
};

/** Normalise an agent-supplied direction value; null when absent or unrecognised. */
export function normaliseExplicitDirection(value: unknown): RecordDirection | null {
  if (typeof value !== 'string') return null;
  const key = value.trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(EXPLICIT_DIRECTION_ALIASES, key) ? EXPLICIT_DIRECTION_ALIASES[key] : null;
}

/** Strip a call-signature suffix: "SSL_read(ssl, buf, n)" -> "SSL_read". */
export function baseFunctionLabel(functionName: string): string {
  return functionName.split('(', 1)[0].trim();
}

const MAX_MEMOISED_LABELS = 256;

/** Memoise a pure label -> value function in a bounded map (cleared when full); labels repeat on every record. */
export function memoiseByLabel<T>(compute: (label: string) => T): (label: string) => T {
  const cache = new Map<string, T>();
  return (label) => {
    if (cache.has(label)) return cache.get(label) as T;
    const value = compute(label);
    if (cache.size >= MAX_MEMOISED_LABELS) cache.clear();
    cache.set(label, value);
    return value;
  };
}

/** Direction from the hooked function label alone (ABI-2 style payloads). */
export const directionFromFunctionName = memoiseByLabel(classifyDirection);

function classifyDirection(functionName: string): RecordDirection {
  const base = baseFunctionLabel(functionName);
  if (SSL_READ_FUNCTIONS.has(base)) return 'read';
  if (SSL_WRITE_FUNCTIONS.has(base)) return 'write';
  const lowered = base.toLowerCase();
  if (READ_LABEL_HINTS.some((hint) => lowered.includes(hint))) return 'read';
  if (WRITE_LABEL_HINTS.some((hint) => lowered.includes(hint))) return 'write';
  return 'write';
}

/** Direction of a datalog record: the agent's explicit `direction` when usable, else the function label. */
export function resolveRecordDirection(functionName: string, explicitDirection?: unknown): RecordDirection {
  return normaliseExplicitDirection(explicitDirection) ?? directionFromFunctionName(functionName);
}
