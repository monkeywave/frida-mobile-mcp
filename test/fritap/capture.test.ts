import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

vi.mock('frida', () => ({
  default: {
    getDeviceManager: () => ({}),
    Cancellable: { withTimeout: () => ({ isCancelled: false }) },
  },
}));

vi.mock('../../src/helpers/logger.js', () => ({
  log: vi.fn(),
  initLogger: vi.fn(),
  audit: vi.fn(),
}));

import {
  FritapCapture,
  MAX_RECORD_HEX_BYTES,
  MAX_RECORD_PREVIEW_CHARS,
  utf8Preview,
} from '../../src/fritap/capture.js';

const PCAP_GLOBAL_HEADER_LEN = 24;

const DATALOG_READ = {
  contentType: 'datalog',
  function: 'SSL_read',
  ss_family: 'AF_INET',
  src_addr: 2130706433,
  src_port: 443,
  dst_addr: 167772161,
  dst_port: 1234,
  ssl_session_id: 'abc',
  protocol: 'tls',
};

const HTTP_BYTES = Buffer.from('GET / HTTP/1.1\r\n\x00\x01');

describe('FritapCapture without file sinks', () => {
  let capture: FritapCapture;

  beforeEach(() => {
    capture = new FritapCapture({});
  });

  afterEach(() => {
    capture.close();
  });

  it('exposes null paths', () => {
    expect(capture.keylogPath).toBeNull();
    expect(capture.pcapPath).toBeNull();
  });

  it('turns keylog messages into fritap_keylog records', () => {
    const record = capture.handleSend({ contentType: 'keylog', keylog: 'CLIENT_RANDOM aa bb', protocol: 'tls' }, null);
    expect(record).toEqual({ type: 'fritap_keylog', payload: { keylog: 'CLIENT_RANDOM aa bb', protocol: 'tls' } });
    expect(capture.stats.keylog_lines).toBe(1);
  });

  it('defaults the keylog protocol to tls', () => {
    const record = capture.handleSend({ contentType: 'keylog', keylog: 'CLIENT_RANDOM cc dd' }, null);
    expect(record?.payload.protocol).toBe('tls');
  });

  it('turns SSL_read datalog messages into read records', () => {
    const record = capture.handleSend(DATALOG_READ, HTTP_BYTES);
    expect(record?.type).toBe('fritap_datalog');
    const payload = record!.payload;
    expect(payload.function).toBe('SSL_read');
    expect(payload.direction).toBe('read');
    expect(payload.protocol).toBe('tls');
    expect(payload.src).toBe('127.0.0.1:443');
    expect(payload.dst).toBe('10.0.0.1:1234');
    expect(payload.transport).toBe('tcp');
    expect(payload.length).toBe(18);
    expect(payload.hex).toBe(HTTP_BYTES.toString('hex'));
    expect(payload.utf8_preview).toBe('GET / HTTP/1.1\r\n..');
    expect((payload.utf8_preview as string).startsWith('GET / HTTP/1.1')).toBe(true);
    expect(payload.truncated).toBe(false);
    expect(payload.ssl_session_id).toBe('abc');
    expect(capture.stats.records).toBe(1);
    expect(capture.stats.bytes).toBe(18);
  });

  it('maps SSL_write and unknown functions to write', () => {
    expect(capture.handleSend({ ...DATALOG_READ, function: 'SSL_write' }, HTTP_BYTES)?.payload.direction).toBe('write');
    expect(capture.handleSend({ ...DATALOG_READ, function: 'something_else' }, HTTP_BYTES)?.payload.direction).toBe('write');
    expect(capture.handleSend({ ...DATALOG_READ, function: undefined }, HTTP_BYTES)?.payload.direction).toBe('write');
    expect(capture.stats.records).toBe(3);
    expect(capture.stats.bytes).toBe(3 * HTTP_BYTES.length);
  });

  it('truncates the hex of large records and bounds the preview', () => {
    const big = Buffer.alloc(1000, 0x41);
    const record = capture.handleSend(DATALOG_READ, big);
    const payload = record!.payload;
    expect(payload.length).toBe(1000);
    expect((payload.hex as string).length).toBe(MAX_RECORD_HEX_BYTES * 2);
    expect((payload.hex as string).length).toBe(1024);
    expect(payload.truncated).toBe(true);
    expect((payload.utf8_preview as string).length).toBeLessThanOrEqual(MAX_RECORD_PREVIEW_CHARS);
    expect(capture.stats.bytes).toBe(1000);
  });

  it('returns a zero-length record for datalog without data', () => {
    const record = capture.handleSend(DATALOG_READ, null);
    expect(record?.type).toBe('fritap_datalog');
    expect(record?.payload.length).toBe(0);
    expect(record?.payload.hex).toBe('');
    expect(record?.payload.truncated).toBe(false);
    expect(capture.stats.records).toBe(1);
    expect(capture.stats.bytes).toBe(0);
  });

  it('turns console messages into fritap_console records', () => {
    expect(capture.handleSend({ contentType: 'console', console: '[*] hooks installed' }, null)).toEqual({
      type: 'fritap_console',
      payload: { level: 'console', message: '[*] hooks installed' },
    });
  });

  it('reads console_dev text from the console_dev field', () => {
    expect(capture.handleSend({ contentType: 'console_dev', console_dev: 'dev text' }, null)).toEqual({
      type: 'fritap_console',
      payload: { level: 'console_dev', message: 'dev text' },
    });
  });

  it('JSON-stringifies non-string console text', () => {
    const record = capture.handleSend({ contentType: 'console', console: { a: 1 } }, null);
    expect(record?.payload.message).toBe('{"a":1}');
  });

  it('records detected libraries once', () => {
    const payload = { contentType: 'library_detected', library: 'libssl.so', path: '/x' };
    const record = capture.handleSend(payload, null);
    expect(record).toEqual({ type: 'fritap_event', payload });
    capture.handleSend(payload, null);
    capture.handleSend({ contentType: 'library_detected', library: 'libcrypto.so', path: '/y' }, null);
    expect(capture.stats.libraries_detected).toEqual(['libssl.so', 'libcrypto.so']);
  });

  it('wraps unknown contentTypes as fritap_event', () => {
    const payload = { contentType: 'something_new', detail: 1 };
    expect(capture.handleSend(payload, null)).toEqual({ type: 'fritap_event', payload });
  });

  it('returns null for noise payloads', () => {
    expect(capture.handleSend({ foo: 'bar' }, null)).toBeNull();
    expect(capture.handleSend('config_batch', null)).toBeNull();
    expect(capture.handleSend(['a'], null)).toBeNull();
    expect(capture.handleSend(null, null)).toBeNull();
    expect(capture.handleSend(42, null)).toBeNull();
  });

  it('counts errors and wraps them as fritap_error records', () => {
    expect(capture.handleError('boom', 'stack')).toEqual({
      type: 'fritap_error',
      payload: { description: 'boom', stack: 'stack' },
    });
    expect(capture.stats.errors).toBe(1);
    expect(capture.handleError('again').payload.stack).toBeNull();
    expect(capture.stats.errors).toBe(2);
  });
});

describe('FritapCapture with file sinks', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fritap-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('appends keylog lines to the keylog file', () => {
    const keylogPath = path.join(tmpDir, 'keys.log');
    const capture = new FritapCapture({ keylogPath });
    expect(capture.keylogPath).toBe(keylogPath);

    capture.handleSend({ contentType: 'keylog', keylog: 'CLIENT_RANDOM aa bb' }, null);
    capture.handleSend({ contentType: 'keylog', keylog: 'CLIENT_RANDOM cc dd' }, null);
    expect(fs.readFileSync(keylogPath, 'utf8')).toBe('CLIENT_RANDOM aa bb\nCLIENT_RANDOM cc dd\n');
    expect(capture.stats.keylog_lines).toBe(2);

    capture.close();
    expect(() => capture.close()).not.toThrow();
    expect(fs.readFileSync(keylogPath, 'utf8')).toBe('CLIENT_RANDOM aa bb\nCLIENT_RANDOM cc dd\n');
  });

  it('ignores keylog messages without a keylog string', () => {
    const keylogPath = path.join(tmpDir, 'keys.log');
    const capture = new FritapCapture({ keylogPath });
    expect(capture.handleSend({ contentType: 'keylog' }, null)).toBeNull();
    expect(capture.handleSend({ contentType: 'keylog', keylog: 7 }, null)).toBeNull();
    expect(capture.handleSend({ contentType: 'keylog', keylog: '' }, null)).toBeNull();
    capture.close();
    expect(fs.readFileSync(keylogPath, 'utf8')).toBe('');
    expect(capture.stats.keylog_lines).toBe(0);
  });

  it('writes datalog records to the pcap file', () => {
    const pcapPath = path.join(tmpDir, 'out.pcap');
    const capture = new FritapCapture({ pcapPath });
    expect(capture.pcapPath).toBe(pcapPath);
    expect(fs.statSync(pcapPath).size).toBe(PCAP_GLOBAL_HEADER_LEN);

    capture.handleSend(DATALOG_READ, HTTP_BYTES);
    const sizeAfterRecord = fs.statSync(pcapPath).size;
    expect(sizeAfterRecord).toBeGreaterThan(PCAP_GLOBAL_HEADER_LEN);
    expect(sizeAfterRecord).toBe(PCAP_GLOBAL_HEADER_LEN + 16 + 20 + 20 + HTTP_BYTES.length);

    const empty = capture.handleSend(DATALOG_READ, null);
    expect(empty?.type).toBe('fritap_datalog');
    expect(empty?.payload.length).toBe(0);
    expect(fs.statSync(pcapPath).size).toBe(sizeAfterRecord);

    capture.close();
    expect(fs.statSync(pcapPath).size).toBe(sizeAfterRecord);
  });
});

describe('utf8Preview', () => {
  it('keeps umlauts and newlines and replaces control bytes', () => {
    expect(utf8Preview(Buffer.from('Grüße\nwelt\r\n\tx\x00y'))).toBe('Grüße\nwelt\r\n\tx.y');
  });

  it('replaces every NUL byte with a dot', () => {
    expect(utf8Preview(Buffer.from([0x61, 0x00, 0x00, 0x62]))).toBe('a..b');
  });

  it('limits the preview to the first bytes', () => {
    const preview = utf8Preview(Buffer.alloc(MAX_RECORD_PREVIEW_CHARS + 100, 0x41));
    expect(preview.length).toBe(MAX_RECORD_PREVIEW_CHARS);
  });
});
