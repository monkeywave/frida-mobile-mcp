/**
 * TLS library attribution of a friTap plaintext record.
 *
 * friTap v2.6.5 sets `library` on datalog payloads only for QUIC records; the SSL_read/SSL_write
 * hooks (OpenSSL/BoringSSL via Conscrypt, NSS, GnuTLS, ...) send just the hooked `function`
 * label. The hooked module is not part of the message, so the library family is derived from
 * that label instead (every family uses its own API names). Exact module names are not guessed
 * from library_detected: several modules of one family are usually loaded (e.g. Conscrypt's
 * libssl.so next to Cronet's stable_cronet_libssl.so), so a guess could misattribute records.
 */
import { baseFunctionLabel, memoiseByLabel } from './direction.js';

/** Library family per hooked function label (mirrors the labels in friTap/constants.py SSL_READ/SSL_WRITE at v2.6.5). */
const FAMILY_BY_FUNCTION: Readonly<Record<string, string>> = {
  SSL_read: 'openssl/boringssl', SSL_read_ex: 'openssl/boringssl', SSL_write: 'openssl/boringssl', SSL_write_ex: 'openssl/boringssl',
  wolfSSL_read: 'wolfssl', wolfSSL_write: 'wolfssl',
  gnutls_record_recv: 'gnutls', gnutls_record_send: 'gnutls',
  mbedtls_ssl_read: 'mbedtls', mbedtls_ssl_write: 'mbedtls',
  s2n_recv: 's2n', s2n_send: 's2n',
  matrixSslReceivedData: 'matrixssl', matrixSslEncodeWritebuf: 'matrixssl',
  NSS_read: 'nss', NSS_write: 'nss', PR_Read: 'nss', PR_Recv: 'nss', PR_Write: 'nss', PR_Send: 'nss',
  readApplicationData: 'java_sslengine', writeApplicationData: 'java_sslengine',
  Full_read: 'raw_socket', Full_write: 'raw_socket',
  SSLRead: 'secure_transport', SSLWrite: 'secure_transport',
  DecryptMessage: 'schannel', EncryptMessage: 'schannel',
  Go_Conn_Read: 'go_tls', Go_Conn_Write: 'go_tls',
  ssh_packet_read_poll2: 'openssh', ssh_packet_send2: 'openssh',
  mtproto_decrypt: 'mtproto', mtproto_encrypt: 'mtproto',
};

/** Prefix rules for label families with many functions (QUIC stacks, Signal). */
const FAMILY_BY_PREFIX: ReadonlyArray<readonly [string, string]> = [
  ['quiche_', 'quiche'],
  ['msquic_', 'msquic'],
  ['Quic', 'chromium_quic'],
  ['neqo_', 'neqo'],
  ['SessionCipher.', 'signal'],
  ['GroupCipher.', 'signal'],
  ['SealedSessionCipher.', 'signal'],
];

/** Library family of a hooked function label; null when the label is not a known friTap hook. */
export const libraryFamilyFromFunction = memoiseByLabel(classifyLibraryFamily);

function classifyLibraryFamily(functionName: string): string | null {
  const base = baseFunctionLabel(functionName);
  if (Object.prototype.hasOwnProperty.call(FAMILY_BY_FUNCTION, base)) return FAMILY_BY_FUNCTION[base];
  const rule = FAMILY_BY_PREFIX.find(([prefix]) => base.startsWith(prefix));
  return rule ? rule[1] : null;
}

/** Where a record's library label came from. */
export type RecordLibrarySource = 'agent' | 'function';

export interface RecordLibrary {
  name: string;
  source: RecordLibrarySource;
}

/** Library of a datalog record: the agent's `library` when set, else the family of its function label. */
export function resolveRecordLibrary(agentLibrary: unknown, functionName: string): RecordLibrary | null {
  if (typeof agentLibrary === 'string' && agentLibrary) return { name: agentLibrary, source: 'agent' };
  const family = libraryFamilyFromFunction(functionName);
  return family ? { name: family, source: 'function' } : null;
}
