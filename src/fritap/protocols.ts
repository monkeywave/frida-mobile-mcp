/**
 * capture_tls `protocols` parameter -> friTap's `protocol_select` config value.
 * friTap accepts a comma list of concrete protocols ("tls,rc4") or a meta selection
 * ("auto" = hook what is detected, "all" = install every protocol's hooks).
 */
import { FridaMcpError } from '../helpers/errors.js';

export const FRITAP_PROTOCOL_CHOICES = ['tls', 'rc4', 'auto', 'all'] as const;

export const DEFAULT_PROTOCOL_SELECT = 'tls';
const META_PROTOCOLS: ReadonlySet<string> = new Set(['auto', 'all']);

function dedupe(protocols: readonly string[] | undefined): string[] {
  return [...new Set(protocols ?? [])];
}

function assertNoMetaMix(unique: readonly string[]): void {
  if (unique.length <= 1) return;
  const meta = unique.filter((p) => META_PROTOCOLS.has(p));
  if (meta.length === 0) return;
  throw new FridaMcpError(
    'INVALID_ARGUMENT',
    `protocols: "${meta.join('", "')}" selects hooks by itself and cannot be combined with other protocols; pass it alone.`
  );
}

/** Throw INVALID_ARGUMENT when a meta selection (auto/all) is mixed with anything else. */
export function validateFritapProtocols(protocols: readonly string[] | undefined): void {
  assertNoMetaMix(dedupe(protocols));
}

/** Comma-joined, de-duplicated `protocol_select` value; 'tls' when nothing is selected. */
export function toProtocolSelect(protocols: readonly string[] | undefined): string {
  const unique = dedupe(protocols);
  assertNoMetaMix(unique);
  return unique.length === 0 ? DEFAULT_PROTOCOL_SELECT : unique.join(',');
}
