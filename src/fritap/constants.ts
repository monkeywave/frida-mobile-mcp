/** Function names friTap reports for the read side of a record (mirrors friTap/constants.py SSL_READ). */
export const SSL_READ_FUNCTIONS: ReadonlySet<string> = new Set([
  'SSL_read', 'wolfSSL_read', 'readApplicationData', 'NSS_read', 'Full_read',
  'gnutls_record_recv', 'PR_Read', 'mbedtls_ssl_read', 's2n_recv',
  'quiche_stream_recv', 'quiche_dgram_recv', 'msquic_stream_recv',
  'QuicSpdyStream_Readv', 'QuicSpdyStream_OnDataFramePayload', 'QuicStreamSequencer_OnStreamFrame',
  'neqo_read_response_data', 'ssh_packet_read_poll2', 'mtproto_decrypt',
]);

/** Function names friTap reports for the write side of a record (mirrors friTap/constants.py SSL_WRITE). */
export const SSL_WRITE_FUNCTIONS: ReadonlySet<string> = new Set([
  'SSL_write', 'wolfSSL_write', 'writeApplicationData', 'NSS_write', 'Full_write',
  'gnutls_record_send', 'PR_Write', 'mbedtls_ssl_write', 's2n_send',
  'quiche_stream_send', 'quiche_dgram_send', 'msquic_stream_send',
  'QuicSpdyStream_WriteOrBufferBody', 'neqo_send_request_body', 'ssh_packet_send2', 'mtproto_encrypt',
]);

/**
 * sha256 of the friTap agent bundle (`friTap/fritap_agent.js`) per git tag. A downloaded bundle
 * runs inside the target process, so it is verified against this map before being cached.
 * Other tags can be pinned at runtime with `FRITAP_AGENT_SHA256` (bare hash for the selected
 * `FRITAP_VERSION` tag); with no pin a download is accepted with a warning.
 */
export const PINNED_AGENT_SHA256: Readonly<Record<string, string>> = {
  'v2.5.2': 'f3c04f5521fa650bf3da7beed3725498968b900d8f1b9cdcb3c7fcffe69f0bb3',
};
