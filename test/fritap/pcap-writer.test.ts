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
  LINKTYPE_RAW,
  PcapWriter,
  decodeFritapAddress,
  endpointsFromDatalog,
  type DatalogEndpoints,
} from '../../src/fritap/pcap-writer.js';

const GLOBAL_HEADER_LEN = 24;
const RECORD_HEADER_LEN = 16;
const IPV4_LEN = 20;
const IPV6_LEN = 40;
const TCP_LEN = 20;
const UDP_LEN = 8;

const IPV4_TCP: DatalogEndpoints = {
  ssFamily: 'AF_INET',
  srcAddr: '127.0.0.1',
  srcPort: 443,
  dstAddr: '10.0.0.1',
  dstPort: 51234,
  transport: 'tcp',
};

const IPV4_UDP: DatalogEndpoints = { ...IPV4_TCP, transport: 'udp' };

const IPV6_TCP: DatalogEndpoints = {
  ssFamily: 'AF_INET6',
  srcAddr: '2001:0db8:0000:0000:0000:0000:0000:0001',
  srcPort: 443,
  dstAddr: '2001:0db8:0000:0000:0000:0000:0000:0002',
  dstPort: 51234,
  transport: 'tcp',
};

describe('decodeFritapAddress', () => {
  it('decodes AF_INET big-endian uint32 values', () => {
    expect(decodeFritapAddress('AF_INET', 2130706433)).toBe('127.0.0.1');
    expect(decodeFritapAddress('AF_INET', 3232235777)).toBe('192.168.1.1');
  });

  it('passes dotted-quad strings through and falls back to 0.0.0.0', () => {
    expect(decodeFritapAddress('AF_INET', '10.0.0.1')).toBe('10.0.0.1');
    expect(decodeFritapAddress('AF_INET', 'junk')).toBe('0.0.0.0');
  });

  it('expands 32-char hex AF_INET6 addresses into groups', () => {
    expect(decodeFritapAddress('AF_INET6', '20010DB8000000000000000000000001')).toBe(
      '2001:0db8:0000:0000:0000:0000:0000:0001'
    );
  });

  it('passes other AF_INET6 strings through and falls back to ::', () => {
    expect(decodeFritapAddress('AF_INET6', 'short')).toBe('short');
    expect(decodeFritapAddress('AF_INET6', 5)).toBe('::');
  });
});

describe('endpointsFromDatalog', () => {
  const payload = { ss_family: 'AF_INET', src_addr: 2130706433, src_port: 443, dst_addr: 167772161, dst_port: 51234 };

  it('decodes the 4-tuple and defaults to tcp', () => {
    expect(endpointsFromDatalog(payload)).toEqual({
      ssFamily: 'AF_INET',
      srcAddr: '127.0.0.1',
      srcPort: 443,
      dstAddr: '10.0.0.1',
      dstPort: 51234,
      transport: 'tcp',
    });
  });

  it('honours transport udp', () => {
    expect(endpointsFromDatalog({ ...payload, transport: 'udp' }).transport).toBe('udp');
  });

  it('defaults a missing ss_family to AF_INET', () => {
    const { ss_family: _omit, ...withoutFamily } = payload;
    expect(endpointsFromDatalog(withoutFamily).ssFamily).toBe('AF_INET');
  });

  it('clamps out-of-range ports to 0', () => {
    expect(endpointsFromDatalog({ ...payload, src_port: 70000 }).srcPort).toBe(0);
    expect(endpointsFromDatalog({ ...payload, dst_port: 'x' }).dstPort).toBe(0);
  });
});

describe('PcapWriter', () => {
  let tmpDir: string;
  let file: string;
  let writer: PcapWriter | null;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fritap-'));
    file = path.join(tmpDir, 'out.pcap');
    writer = null;
  });

  afterEach(() => {
    writer?.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function readRecord(index: number): { header: Buffer; packet: Buffer } {
    const content = fs.readFileSync(file);
    let offset = GLOBAL_HEADER_LEN;
    for (let i = 0; i < index; i += 1) {
      offset += RECORD_HEADER_LEN + content.readUInt32LE(offset + 8);
    }
    const header = content.subarray(offset, offset + RECORD_HEADER_LEN);
    const length = header.readUInt32LE(8);
    const packet = content.subarray(offset + RECORD_HEADER_LEN, offset + RECORD_HEADER_LEN + length);
    return { header, packet };
  }

  it('writes a 24-byte global header with magic, version 2.4 and LINKTYPE_RAW', () => {
    writer = new PcapWriter(file);
    const content = fs.readFileSync(file);
    expect(content.length).toBe(GLOBAL_HEADER_LEN);
    expect(content.readUInt32LE(0)).toBe(0xa1b2c3d4);
    expect(content.readUInt16LE(4)).toBe(2);
    expect(content.readUInt16LE(6)).toBe(4);
    expect(content.readUInt32LE(20)).toBe(LINKTYPE_RAW);
    expect(content.readUInt32LE(20)).toBe(101);
    expect(writer.isOpen).toBe(true);
    expect(writer.path).toBe(file);
  });

  it('writes an IPv4/TCP record with the right headers', () => {
    writer = new PcapWriter(file);
    const data = Buffer.from('hello');
    writer.writeRecord(IPV4_TCP, data);

    const content = fs.readFileSync(file);
    expect(content.length).toBe(GLOBAL_HEADER_LEN + RECORD_HEADER_LEN + IPV4_LEN + TCP_LEN + data.length);

    const { header, packet } = readRecord(0);
    expect(header.readUInt32LE(8)).toBe(45);
    expect(header.readUInt32LE(12)).toBe(45);

    expect(packet[0]).toBe(0x45);
    expect(packet[9]).toBe(6);
    expect(packet.readUInt16BE(2)).toBe(IPV4_LEN + TCP_LEN + data.length);
    expect([...packet.subarray(12, 16)]).toEqual([127, 0, 0, 1]);
    expect([...packet.subarray(16, 20)]).toEqual([10, 0, 0, 1]);

    const tcp = packet.subarray(IPV4_LEN);
    expect(tcp.readUInt16BE(0)).toBe(443);
    expect(tcp.readUInt16BE(2)).toBe(51234);
    expect(tcp.readUInt32BE(4)).toBe(1);
    expect(tcp.readUInt16BE(12)).toBe(0x5018);
    expect(packet.subarray(IPV4_LEN + TCP_LEN).toString()).toBe('hello');
  });

  it('uses a record timestamp from the given milliseconds', () => {
    writer = new PcapWriter(file);
    writer.writeRecord(IPV4_TCP, Buffer.from('x'), 1_700_000_000_123);
    const { header } = readRecord(0);
    expect(header.readUInt32LE(0)).toBe(1_700_000_000);
    expect(header.readUInt32LE(4)).toBe(123_000);
  });

  it('advances the TCP sequence per flow and restarts on the reverse flow', () => {
    writer = new PcapWriter(file);
    writer.writeRecord(IPV4_TCP, Buffer.from('hello'));
    writer.writeRecord(IPV4_TCP, Buffer.from('world!'));
    const reverse: DatalogEndpoints = {
      ...IPV4_TCP,
      srcAddr: IPV4_TCP.dstAddr,
      srcPort: IPV4_TCP.dstPort,
      dstAddr: IPV4_TCP.srcAddr,
      dstPort: IPV4_TCP.srcPort,
    };
    writer.writeRecord(reverse, Buffer.from('ok'));

    expect(readRecord(0).packet.readUInt32BE(IPV4_LEN + 4)).toBe(1);
    expect(readRecord(1).packet.readUInt32BE(IPV4_LEN + 4)).toBe(6);
    const third = readRecord(2).packet;
    expect(third.readUInt32BE(IPV4_LEN + 4)).toBe(1);
    expect([...third.subarray(12, 16)]).toEqual([10, 0, 0, 1]);
    expect(third.readUInt16BE(IPV4_LEN)).toBe(51234);
  });

  it('writes an IPv4/UDP record with an 8-byte UDP header', () => {
    writer = new PcapWriter(file);
    const data = Buffer.from('datagram');
    writer.writeRecord(IPV4_UDP, data);

    const { header, packet } = readRecord(0);
    expect(header.readUInt32LE(8)).toBe(IPV4_LEN + UDP_LEN + data.length);
    expect(packet[9]).toBe(17);
    const udp = packet.subarray(IPV4_LEN);
    expect(udp.readUInt16BE(0)).toBe(443);
    expect(udp.readUInt16BE(2)).toBe(51234);
    expect(udp.readUInt16BE(4)).toBe(UDP_LEN + data.length);
    expect(packet.subarray(IPV4_LEN + UDP_LEN).toString()).toBe('datagram');
  });

  it('writes an IPv6/TCP record with a 40-byte IPv6 header', () => {
    writer = new PcapWriter(file);
    const data = Buffer.from('v6');
    writer.writeRecord(IPV6_TCP, data);

    const { header, packet } = readRecord(0);
    expect(header.readUInt32LE(8)).toBe(IPV6_LEN + TCP_LEN + data.length);
    expect(packet[0] >> 4).toBe(6);
    expect(packet.readUInt16BE(4)).toBe(TCP_LEN + data.length);
    expect(packet[6]).toBe(6);
    expect([...packet.subarray(8, 24)]).toEqual([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    expect([...packet.subarray(24, 40)]).toEqual([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    expect(packet.readUInt16BE(IPV6_LEN)).toBe(443);
    expect(packet.subarray(IPV6_LEN + TCP_LEN).toString()).toBe('v6');
  });

  it('close is idempotent and writeRecord after close is a no-op', () => {
    writer = new PcapWriter(file);
    writer.writeRecord(IPV4_TCP, Buffer.from('hello'));
    const sizeBefore = fs.statSync(file).size;

    expect(writer.isOpen).toBe(true);
    writer.close();
    expect(writer.isOpen).toBe(false);
    expect(() => writer!.close()).not.toThrow();

    expect(() => writer!.writeRecord(IPV4_TCP, Buffer.from('ignored'))).not.toThrow();
    expect(fs.statSync(file).size).toBe(sizeBefore);
  });
});
