import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../../src/helpers/logger.js', () => ({
  log: vi.fn(),
  initLogger: vi.fn(),
  audit: vi.fn(),
}));

import { FritapCapture, MAX_TRACKED_LIBRARIES, OTHER_LIBRARIES, UNKNOWN_LIBRARY } from '../../src/fritap/capture.js';

const DATALOG = {
  contentType: 'datalog',
  ss_family: 'AF_INET',
  src_addr: 2130706433,
  src_port: 443,
  dst_addr: 167772161,
  dst_port: 1234,
  ssl_session_id: 'abc',
  protocol: 'tls',
};
const BYTES = Buffer.from('hello');

describe('FritapCapture ABI-3 records', () => {
  let capture: FritapCapture;

  beforeEach(() => {
    capture = new FritapCapture({});
  });

  afterEach(() => {
    capture.close();
  });

  it('labels SSLRead / SSL_read_ex as read (previously mislabelled write)', () => {
    expect(capture.handleSend({ ...DATALOG, function: 'SSLRead' }, BYTES)?.payload.direction).toBe('read');
    expect(capture.handleSend({ ...DATALOG, function: 'SSL_read_ex' }, BYTES)?.payload.direction).toBe('read');
    expect(capture.handleSend({ ...DATALOG, function: 'SSL_write_ex' }, BYTES)?.payload.direction).toBe('write');
  });

  it('prefers the agent-supplied direction and carries library', () => {
    const record = capture.handleSend({ ...DATALOG, function: 'mtproto_hook', direction: 'read', library: 'libssl.so' }, BYTES);
    expect(record?.payload.direction).toBe('read');
    expect(record?.payload.library).toBe('libssl.so');
  });

  it('omits library on ABI-2 payloads', () => {
    const record = capture.handleSend({ ...DATALOG, function: 'SSL_read' }, BYTES);
    expect(record?.payload).not.toHaveProperty('library');
  });

  it('attributes SSL_read/SSL_write records without an agent library to openssl/boringssl (friTap v2.6.5 TLS hooks)', () => {
    const read = capture.handleSend({ ...DATALOG, function: 'SSL_read' }, BYTES);
    capture.handleSend({ ...DATALOG, function: 'SSL_write' }, Buffer.from('ab'));
    expect(read?.payload.library_family).toBe('openssl/boringssl');
    expect(capture.stats.per_library).toEqual({ 'openssl/boringssl': { read: 1, write: 1, bytes: 7 } });
  });

  it('does not add library_family when the agent names the library', () => {
    const record = capture.handleSend({ ...DATALOG, function: 'quiche_stream_recv', library: 'libquiche.so' }, BYTES);
    expect(record?.payload.library).toBe('libquiche.so');
    expect(record?.payload).not.toHaveProperty('library_family');
  });

  it('turns caller_stack into its own record kind', () => {
    const record = capture.handleSend({
      contentType: 'caller_stack', ssl_session_id: 's1', java_frames: ['com.sdk.Net.call'], native_frames: [{ module: 'libssl.so' }],
    }, null);
    expect(record).toEqual({
      type: 'fritap_caller_stack',
      payload: { ssl_session_id: 's1', java_frames: ['com.sdk.Net.call'], native_frames: [{ module: 'libssl.so' }] },
    });
  });

  it('turns platform_report into its own record kind', () => {
    const record = capture.handleSend({ contentType: 'platform_report', platform: 'Android', target: 'android', probe: true, abi: 3 }, null);
    expect(record).toEqual({ type: 'fritap_platform_report', payload: { platform: 'Android', target: 'android', probe: true, abi: 3 } });
  });

  it('keeps other unknown message types as fritap_event', () => {
    const payload = { contentType: 'ipsec_esp_keys', spi: '1' };
    expect(capture.handleSend(payload, null)).toEqual({ type: 'fritap_event', payload });
  });

  it('summarises records per library and direction', () => {
    capture.handleSend({ ...DATALOG, function: 'SSL_read', library: 'libssl.so' }, BYTES);
    capture.handleSend({ ...DATALOG, function: 'SSL_write', library: 'libssl.so' }, Buffer.from('ab'));
    capture.handleSend({ ...DATALOG, function: 'SSL_write', library: 'libssl.so' }, Buffer.from('c'));
    capture.handleSend({ ...DATALOG, function: 'PR_Recv' }, BYTES);
    capture.handleSend({ ...DATALOG, function: 'custom_hook_recv' }, BYTES);
    expect(capture.stats.per_library).toEqual({
      'libssl.so': { read: 1, write: 2, bytes: 8 },
      nss: { read: 1, write: 0, bytes: 5 },
      [UNKNOWN_LIBRARY]: { read: 1, write: 0, bytes: 5 },
    });
    expect(capture.stats.records).toBe(5);
  });

  it('keeps hostile library names as plain keys', () => {
    capture.handleSend({ ...DATALOG, function: 'SSL_read', library: '__proto__' }, BYTES);
    expect(Object.keys(capture.stats.per_library)).toEqual(['__proto__']);
    expect(({} as Record<string, unknown>).read).toBeUndefined();
  });

  it('folds libraries beyond the tracking cap into "other"', () => {
    for (let i = 0; i < MAX_TRACKED_LIBRARIES + 3; i++) {
      capture.handleSend({ ...DATALOG, function: 'SSL_read', library: `lib${i}.so` }, BYTES);
    }
    const keys = Object.keys(capture.stats.per_library);
    expect(keys.length).toBe(MAX_TRACKED_LIBRARIES + 1);
    expect(capture.stats.per_library[OTHER_LIBRARIES]).toEqual({ read: 3, write: 0, bytes: 15 });
  });
});
