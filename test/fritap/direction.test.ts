import { describe, it, expect } from 'vitest';
import {
  baseFunctionLabel,
  directionFromFunctionName,
  normaliseExplicitDirection,
  resolveRecordDirection,
} from '../../src/fritap/direction.js';

describe('directionFromFunctionName (ABI-2 payloads: function label only)', () => {
  it.each([
    'SSL_read', 'SSL_read_ex', 'SSLRead', 'PR_Recv', 'PR_Read', 'Go_Conn_Read', 'DecryptMessage',
    'gnutls_record_recv', 'readApplicationData', 'QuicSpdyStream_OnHeadersDecoded', 'SessionCipher.decrypt',
  ])('classifies %s as read', (fn) => {
    expect(directionFromFunctionName(fn)).toBe('read');
  });

  it.each([
    'SSL_write', 'SSL_write_ex', 'SSLWrite', 'PR_Send', 'PR_Write', 'Go_Conn_Write', 'EncryptMessage',
    'gnutls_record_send', 'writeApplicationData', 'QuicSpdyStream_WriteHeaders', 'mtproto_encrypt',
  ])('classifies %s as write', (fn) => {
    expect(directionFromFunctionName(fn)).toBe('write');
  });

  it('falls back to read hints for unlisted labels', () => {
    expect(directionFromFunctionName('custom_lib_recv_plain')).toBe('read');
    expect(directionFromFunctionName('MyTls_ReadRecord')).toBe('read');
    expect(directionFromFunctionName('blob_receive')).toBe('read');
    expect(directionFromFunctionName('aes_decrypt_block')).toBe('read');
  });

  it('falls back to write hints for unlisted labels', () => {
    expect(directionFromFunctionName('custom_lib_send_plain')).toBe('write');
    expect(directionFromFunctionName('aes_encrypt_block')).toBe('write');
  });

  it('defaults unclassifiable labels to write (friTap behaviour)', () => {
    expect(directionFromFunctionName('something_else')).toBe('write');
    expect(directionFromFunctionName('')).toBe('write');
  });

  it('ignores a call-signature suffix', () => {
    expect(baseFunctionLabel('SSL_read(ssl, buf, n)')).toBe('SSL_read');
    expect(directionFromFunctionName('SSL_read_ex(ssl, buf, n, out)')).toBe('read');
  });
});

describe('resolveRecordDirection (ABI-3 payloads: explicit direction)', () => {
  it('prefers an explicit direction over the function label', () => {
    expect(resolveRecordDirection('SSL_write', 'read')).toBe('read');
    expect(resolveRecordDirection('SSL_read', 'write')).toBe('write');
    expect(resolveRecordDirection('signal_hook', 'read')).toBe('read');
  });

  it('normalises direction spellings', () => {
    expect(normaliseExplicitDirection(' READ ')).toBe('read');
    expect(normaliseExplicitDirection('incoming')).toBe('read');
    expect(normaliseExplicitDirection('recv')).toBe('read');
    expect(normaliseExplicitDirection('outgoing')).toBe('write');
    expect(normaliseExplicitDirection('send')).toBe('write');
  });

  it('falls back to the function label for missing or unknown directions', () => {
    expect(resolveRecordDirection('SSLRead', null)).toBe('read');
    expect(resolveRecordDirection('SSLRead', undefined)).toBe('read');
    expect(resolveRecordDirection('SSLRead', 'sideways')).toBe('read');
    expect(resolveRecordDirection('SSL_write_ex', 42)).toBe('write');
    expect(normaliseExplicitDirection('__proto__')).toBeNull();
  });
});
