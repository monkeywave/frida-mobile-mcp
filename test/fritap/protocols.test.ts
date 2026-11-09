import { describe, it, expect } from 'vitest';
import { toProtocolSelect, validateFritapProtocols } from '../../src/fritap/protocols.js';
import { FridaMcpError } from '../../src/helpers/errors.js';

function invalidArgument(fn: () => unknown): FridaMcpError {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(FridaMcpError);
    expect((err as FridaMcpError).code).toBe('INVALID_ARGUMENT');
    return err as FridaMcpError;
  }
  throw new Error('expected INVALID_ARGUMENT');
}

describe('toProtocolSelect', () => {
  it('defaults to tls', () => {
    expect(toProtocolSelect(undefined)).toBe('tls');
    expect(toProtocolSelect([])).toBe('tls');
  });

  it('joins concrete protocols with commas, de-duplicated', () => {
    expect(toProtocolSelect(['tls'])).toBe('tls');
    expect(toProtocolSelect(['tls', 'rc4'])).toBe('tls,rc4');
    expect(toProtocolSelect(['rc4', 'tls', 'rc4'])).toBe('rc4,tls');
  });

  it('passes meta selections alone', () => {
    expect(toProtocolSelect(['auto'])).toBe('auto');
    expect(toProtocolSelect(['all'])).toBe('all');
    expect(toProtocolSelect(['all', 'all'])).toBe('all');
  });

  it('rejects mixing auto/all with other protocols', () => {
    expect(invalidArgument(() => toProtocolSelect(['auto', 'tls'])).message).toMatch(/"auto"/);
    expect(invalidArgument(() => validateFritapProtocols(['tls', 'all'])).message).toMatch(/"all"/);
    invalidArgument(() => validateFritapProtocols(['auto', 'all']));
  });
});
