import { describe, it, expect } from 'vitest';
import { libraryFamilyFromFunction, resolveRecordLibrary } from '../../src/fritap/library-family.js';

describe('libraryFamilyFromFunction', () => {
  it.each([
    ['SSL_read', 'openssl/boringssl'],
    ['SSL_write_ex', 'openssl/boringssl'],
    ['SSL_read(ssl, buf, n)', 'openssl/boringssl'],
    ['PR_Write', 'nss'],
    ['gnutls_record_recv', 'gnutls'],
    ['wolfSSL_write', 'wolfssl'],
    ['mbedtls_ssl_read', 'mbedtls'],
    ['SSLRead', 'secure_transport'],
    ['DecryptMessage', 'schannel'],
    ['Go_Conn_Write', 'go_tls'],
    ['readApplicationData', 'java_sslengine'],
    ['quiche_conn_stream_recv', 'quiche'],
    ['QuicSpdyStream_WriteHeaders', 'chromium_quic'],
    ['SealedSessionCipher.decrypt', 'signal'],
  ])('maps %s to %s', (fn, family) => {
    expect(libraryFamilyFromFunction(fn)).toBe(family);
  });

  it('returns null for unknown or empty labels', () => {
    expect(libraryFamilyFromFunction('custom_hook')).toBeNull();
    expect(libraryFamilyFromFunction('')).toBeNull();
    expect(libraryFamilyFromFunction('toString')).toBeNull();
  });
});

describe('resolveRecordLibrary', () => {
  it('prefers the agent-supplied library', () => {
    expect(resolveRecordLibrary('libssl.so', 'SSL_read')).toEqual({ name: 'libssl.so', source: 'agent' });
  });

  it('falls back to the function family when the agent sends no library', () => {
    expect(resolveRecordLibrary(undefined, 'SSL_write')).toEqual({ name: 'openssl/boringssl', source: 'function' });
    expect(resolveRecordLibrary('', 'PR_Read')).toEqual({ name: 'nss', source: 'function' });
    expect(resolveRecordLibrary(null, 'SSL_read')).toEqual({ name: 'openssl/boringssl', source: 'function' });
  });

  it('returns null when neither is usable', () => {
    expect(resolveRecordLibrary(42, 'custom_hook')).toBeNull();
  });
});
