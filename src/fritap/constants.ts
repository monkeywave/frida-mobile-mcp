/** Function names friTap reports for the read side of a record (mirrors friTap/constants.py SSL_READ at v2.6.5). */
export const SSL_READ_FUNCTIONS: ReadonlySet<string> = new Set([
  // OpenSSL / BoringSSL / LibreSSL / Cronet / GoTLS (legacy label)
  'SSL_read', 'SSL_read_ex',
  'wolfSSL_read', 'gnutls_record_recv', 'mbedtls_ssl_read', 's2n_recv',
  'matrixSslReceivedData',
  // NSS
  'NSS_read', 'PR_Read', 'PR_Recv',
  // Java (BouncyCastle / Conscrypt) and the raw-socket full-capture tracer
  'readApplicationData', 'Full_read',
  // Apple SecureTransport, Windows Schannel (SSPI), Go crypto/tls
  'SSLRead', 'DecryptMessage', 'Go_Conn_Read',
  // QUIC stream/datagram receive
  'quiche_stream_recv', 'quiche_conn_stream_recv', 'quiche_dgram_recv',
  'msquic_stream_recv',
  'QuicSpdyStream_Readv', 'QuicStream_Readv', 'QuicStreamSequencer_Readv',
  'QuicSpdyStream_OnDataFramePayload', 'QuicSpdyStream_OnHeadersDecoded', 'QuicStreamSequencer_OnStreamFrame',
  // Neqo (Firefox HTTP/3), OpenSSH, Telegram MTProto, Signal
  'neqo_read_response_data', 'neqo_http3conn_read_response_data',
  'ssh_packet_read_poll2',
  'mtproto_decrypt',
  'SessionCipher.decrypt', 'GroupCipher.decrypt', 'SealedSessionCipher.decrypt',
]);

/** Function names friTap reports for the write side of a record (mirrors friTap/constants.py SSL_WRITE at v2.6.5). */
export const SSL_WRITE_FUNCTIONS: ReadonlySet<string> = new Set([
  'SSL_write', 'SSL_write_ex',
  'wolfSSL_write', 'gnutls_record_send', 'mbedtls_ssl_write', 's2n_send',
  'matrixSslEncodeWritebuf',
  'NSS_write', 'PR_Write', 'PR_Send',
  'writeApplicationData', 'Full_write',
  'SSLWrite', 'EncryptMessage', 'Go_Conn_Write',
  // QUIC stream/datagram send
  'quiche_stream_send', 'quiche_conn_stream_send', 'quiche_dgram_send',
  'msquic_stream_send',
  'QuicSpdyStream_WriteOrBufferBody', 'QuicSpdyStream_WriteHeaders',
  'QuicChromiumClientStream_WriteHeaders',
  'QuicSpdySession_WriteHeadersOnHeadersStream',
  // Neqo (Firefox HTTP/3), OpenSSH, Telegram MTProto
  'neqo_send_request_body', 'neqo_http3conn_send_request_body',
  'ssh_packet_send2',
  'mtproto_encrypt',
]);

/** Substrings marking an unlisted function label as receive-side (fallback; the explicit sets win). */
export const READ_LABEL_HINTS: readonly string[] = ['read', 'recv', 'receive', 'decrypt'];
/** Substrings marking an unlisted function label as send-side (fallback; the explicit sets win). */
export const WRITE_LABEL_HINTS: readonly string[] = ['write', 'send', 'encrypt'];

/**
 * sha256 of the friTap agent bundle (`friTap/fritap_agent.js`) per git tag. A downloaded bundle
 * runs inside the target process, so it is verified against this map before being cached.
 * Other tags can be pinned at runtime with `FRITAP_AGENT_SHA256` (bare hash for the selected
 * `FRITAP_VERSION` tag); with no pin a download is accepted with a warning.
 */
export const PINNED_AGENT_SHA256: Readonly<Record<string, string>> = {
  'v2.5.2': 'f3c04f5521fa650bf3da7beed3725498968b900d8f1b9cdcb3c7fcffe69f0bb3',
  'v2.6.5': 'aaacf799749625fa75d2704f2022d57a1e7988615eb61ba1728c7a6dea0997a9',
};
