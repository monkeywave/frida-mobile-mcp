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
