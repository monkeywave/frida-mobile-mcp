/**
 * Minimal pcap writer for friTap datalog records.
 *
 * friTap's Python side (pcap.py) does the same thing: every decrypted record becomes one
 * synthetic IPv4/IPv6 + TCP (or UDP) packet with the 4-tuple from the datalog payload.
 * There is no handshake and no real traffic; the file is only a container that lets
 * Wireshark show the plaintext as TCP streams ("Follow TCP stream").
 *
 * Link type 101 (LINKTYPE_RAW): the packet starts with the IP header.
 */
import { closeSync, openSync, writeSync } from 'node:fs';

export const LINKTYPE_RAW = 101;
const PCAP_MAGIC = 0xa1b2c3d4;
const SNAPLEN = 262_144;

export interface DatalogEndpoints {
  ssFamily: 'AF_INET' | 'AF_INET6';
  srcAddr: string;
  srcPort: number;
  dstAddr: string;
  dstPort: number;
  transport: 'tcp' | 'udp';
}

/** Decode friTap's address encoding: AF_INET is a big-endian uint32, AF_INET6 a 32-char hex string. */
export function decodeFritapAddress(ssFamily: string, raw: unknown): string {
  if (ssFamily === 'AF_INET6') {
    if (typeof raw === 'string' && /^[0-9a-fA-F]{32}$/.test(raw)) {
      const groups: string[] = [];
      for (let i = 0; i < 32; i += 4) groups.push(raw.slice(i, i + 4).toLowerCase());
      return groups.join(':');
    }
    return typeof raw === 'string' ? raw : '::';
  }
  if (typeof raw === 'number') {
    const n = raw >>> 0;
    return `${(n >>> 24) & 0xff}.${(n >>> 16) & 0xff}.${(n >>> 8) & 0xff}.${n & 0xff}`;
  }
  if (typeof raw === 'string' && /^\d+\.\d+\.\d+\.\d+$/.test(raw)) return raw;
  return '0.0.0.0';
}

export function endpointsFromDatalog(payload: Record<string, unknown>): DatalogEndpoints {
  const ssFamily = payload.ss_family === 'AF_INET6' ? 'AF_INET6' : 'AF_INET';
  return {
    ssFamily,
    srcAddr: decodeFritapAddress(ssFamily, payload.src_addr),
    srcPort: toPort(payload.src_port),
    dstAddr: decodeFritapAddress(ssFamily, payload.dst_addr),
    dstPort: toPort(payload.dst_port),
    transport: payload.transport === 'udp' ? 'udp' : 'tcp',
  };
}

function toPort(value: unknown): number {
  return typeof value === 'number' && value >= 0 && value <= 0xffff ? value : 0;
}

export class PcapWriter {
  private fd: number | null;
  private readonly seq = new Map<string, number>();

  constructor(public readonly path: string) {
    this.fd = openSync(path, 'w');
    writeSync(this.fd, buildGlobalHeader());
  }

  get isOpen(): boolean {
    return this.fd !== null;
  }

  writeRecord(endpoints: DatalogEndpoints, data: Buffer, timestampMs: number = Date.now()): void {
    if (this.fd === null) return;
    const packet = buildPacket(endpoints, data, this.nextSeq(endpoints, data.length));
    const header = Buffer.alloc(16);
    header.writeUInt32LE(Math.floor(timestampMs / 1000), 0);
    header.writeUInt32LE((timestampMs % 1000) * 1000, 4);
    header.writeUInt32LE(packet.length, 8);
    header.writeUInt32LE(packet.length, 12);
    writeSync(this.fd, Buffer.concat([header, packet]));
  }

  close(): void {
    if (this.fd === null) return;
    try { closeSync(this.fd); } catch { /* already closed */ }
    this.fd = null;
  }

  /** Per-flow sequence numbers so Wireshark can reassemble the stream. */
  private nextSeq(e: DatalogEndpoints, length: number): number {
    const key = `${e.srcAddr}:${e.srcPort}>${e.dstAddr}:${e.dstPort}`;
    const current = this.seq.get(key) ?? 1;
    this.seq.set(key, (current + length) >>> 0);
    return current;
  }
}

function buildGlobalHeader(): Buffer {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(PCAP_MAGIC, 0);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeInt32LE(0, 8);
  header.writeUInt32LE(0, 12);
  header.writeUInt32LE(SNAPLEN, 16);
  header.writeUInt32LE(LINKTYPE_RAW, 20);
  return header;
}

function buildPacket(e: DatalogEndpoints, data: Buffer, seq: number): Buffer {
  const transport = e.transport === 'udp' ? buildUdpHeader(e, data.length) : buildTcpHeader(e, seq);
  const payloadLength = transport.length + data.length;
  const ip = e.ssFamily === 'AF_INET6' ? buildIpv6Header(e, payloadLength) : buildIpv4Header(e, payloadLength);
  return Buffer.concat([ip, transport, data]);
}

function buildIpv4Header(e: DatalogEndpoints, payloadLength: number): Buffer {
  const header = Buffer.alloc(20);
  header[0] = 0x45;
  header.writeUInt16BE(20 + payloadLength, 2);
  header[8] = 64;
  header[9] = e.transport === 'udp' ? 17 : 6;
  ipv4ToBytes(e.srcAddr).copy(header, 12);
  ipv4ToBytes(e.dstAddr).copy(header, 16);
  header.writeUInt16BE(ipv4Checksum(header), 10);
  return header;
}

function buildIpv6Header(e: DatalogEndpoints, payloadLength: number): Buffer {
  const header = Buffer.alloc(40);
  header[0] = 0x60;
  header.writeUInt16BE(payloadLength, 4);
  header[6] = e.transport === 'udp' ? 17 : 6;
  header[7] = 64;
  ipv6ToBytes(e.srcAddr).copy(header, 8);
  ipv6ToBytes(e.dstAddr).copy(header, 24);
  return header;
}

function buildTcpHeader(e: DatalogEndpoints, seq: number): Buffer {
  const header = Buffer.alloc(20);
  header.writeUInt16BE(e.srcPort, 0);
  header.writeUInt16BE(e.dstPort, 2);
  header.writeUInt32BE(seq >>> 0, 4);
  header.writeUInt32BE(0, 8);
  header.writeUInt16BE(0x5018, 12); // data offset 5 words, PSH|ACK
  header.writeUInt16BE(0xffff, 14);
  return header;
}

function buildUdpHeader(e: DatalogEndpoints, dataLength: number): Buffer {
  const header = Buffer.alloc(8);
  header.writeUInt16BE(e.srcPort, 0);
  header.writeUInt16BE(e.dstPort, 2);
  header.writeUInt16BE(8 + dataLength, 4);
  return header;
}

function ipv4ToBytes(addr: string): Buffer {
  const parts = addr.split('.').map((p) => Number.parseInt(p, 10));
  return Buffer.from(parts.length === 4 && parts.every((p) => p >= 0 && p <= 255) ? parts : [0, 0, 0, 0]);
}

function ipv6ToBytes(addr: string): Buffer {
  const out = Buffer.alloc(16);
  const groups = addr.split(':');
  if (groups.length !== 8) return out;
  groups.forEach((g, i) => out.writeUInt16BE(Number.parseInt(g || '0', 16) & 0xffff, i * 2));
  return out;
}

function ipv4Checksum(header: Buffer): number {
  let sum = 0;
  for (let i = 0; i < header.length; i += 2) sum += header.readUInt16BE(i);
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}
