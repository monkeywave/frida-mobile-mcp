/**
 * Sinks for one running friTap capture: NSS key log file, optional pcap, and the
 * normalised message records that get buffered on the session (get_messages).
 */
import { closeSync, openSync, writeSync } from 'node:fs';
import { resolveRecordDirection, type RecordDirection } from './direction.js';
import { resolveRecordLibrary } from './library-family.js';
import { endpointsFromDatalog, PcapWriter } from './pcap-writer.js';
import { log } from '../helpers/logger.js';

/** Max bytes of a plaintext record kept as hex in the message buffer. */
export const MAX_RECORD_HEX_BYTES = 512;
/** Max characters of the utf8 preview. */
export const MAX_RECORD_PREVIEW_CHARS = 256;

export type FritapMessageType =
  | 'fritap_keylog'
  | 'fritap_datalog'
  | 'fritap_console'
  | 'fritap_event'
  | 'fritap_caller_stack'
  | 'fritap_platform_report'
  | 'fritap_error';

/** Library key for records with neither an agent `library` nor a known hooked function label. */
export const UNKNOWN_LIBRARY = 'unknown';
/** Bucket for libraries beyond MAX_TRACKED_LIBRARIES (names come from the target, so the map is bounded). */
export const OTHER_LIBRARIES = 'other';
export const MAX_TRACKED_LIBRARIES = 64;

/** Plaintext record counts of one TLS library, split by direction. */
export interface FritapLibraryStats {
  read: number;
  write: number;
  bytes: number;
}

export interface FritapRecord {
  type: FritapMessageType;
  payload: Record<string, unknown>;
}

export interface FritapCaptureStats {
  keylog_lines: number;
  records: number;
  bytes: number;
  libraries_detected: string[];
  errors: number;
  /**
   * Plaintext records per library and direction: the datalog `library` when the agent sets it
   * (QUIC records), else the library family of the hooked function (e.g. SSL_read ->
   * 'openssl/boringssl'), else 'unknown'.
   */
  per_library: Record<string, FritapLibraryStats>;
}

export interface FritapCaptureOptions {
  keylogPath?: string;
  pcapPath?: string;
}

export class FritapCapture {
  readonly stats: FritapCaptureStats = {
    keylog_lines: 0, records: 0, bytes: 0, libraries_detected: [], errors: 0,
    // Null prototype: library names come from the target process (e.g. "__proto__" must stay a plain key).
    per_library: Object.create(null) as Record<string, FritapLibraryStats>,
  };
  private keylogFd: number | null = null;
  private pcap: PcapWriter | null = null;
  private closed = false;

  constructor(readonly options: FritapCaptureOptions) {
    if (options.keylogPath) this.keylogFd = openSync(options.keylogPath, 'a');
    if (options.pcapPath) this.pcap = new PcapWriter(options.pcapPath);
  }

  get keylogPath(): string | null { return this.options.keylogPath ?? null; }
  get pcapPath(): string | null { return this.options.pcapPath ?? null; }

  /** Turn an agent `send()` into a buffered record (or null for noise), writing sinks on the way. */
  handleSend(payload: unknown, data: Buffer | null): FritapRecord | null {
    if (!isObject(payload)) return null;
    switch (payload.contentType) {
      case 'keylog':
        return this.handleKeylog(payload);
      case 'datalog':
        return this.handleDatalog(payload, data);
      case 'console':
      case 'console_dev':
      case 'console_debug':
      case 'console_info':
      case 'console_warn':
      case 'console_error':
        return { type: 'fritap_console', payload: { level: payload.contentType, message: consoleText(payload) } };
      case 'library_detected':
        this.noteLibrary(payload);
        return { type: 'fritap_event', payload };
      case 'caller_stack':
        return { type: 'fritap_caller_stack', payload: withoutContentType(payload) };
      case 'platform_report':
        return { type: 'fritap_platform_report', payload: withoutContentType(payload) };
      case 'hook_breadcrumb':
        // Init-stage breadcrumbs duplicate the "[init] stage:" console lines; keep the buffer readable.
        return null;
      case undefined:
        return null;
      default:
        return { type: 'fritap_event', payload };
    }
  }

  handleError(description: string, stack?: string): FritapRecord {
    this.stats.errors += 1;
    return { type: 'fritap_error', payload: { description, stack: stack ?? null } };
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    if (this.keylogFd !== null) {
      try { closeSync(this.keylogFd); } catch { /* best-effort */ }
      this.keylogFd = null;
    }
    this.pcap?.close();
  }

  private handleKeylog(payload: Record<string, unknown>): FritapRecord | null {
    const line = typeof payload.keylog === 'string' ? payload.keylog : null;
    if (!line) return null;
    this.stats.keylog_lines += 1;
    if (this.keylogFd !== null) {
      try { writeSync(this.keylogFd, `${line}\n`); } catch (err) { log('warn', `keylog write failed: ${String(err)}`); }
    }
    return { type: 'fritap_keylog', payload: { keylog: line, protocol: payload.protocol ?? 'tls' } };
  }

  private handleDatalog(payload: Record<string, unknown>, data: Buffer | null): FritapRecord | null {
    const bytes = data ?? Buffer.alloc(0);
    const endpoints = endpointsFromDatalog(payload);
    const fn = typeof payload.function === 'string' ? payload.function : '';
    const direction = resolveRecordDirection(fn, payload.direction);
    const resolved = resolveRecordLibrary(payload.library, fn);
    const library = resolved?.source === 'agent' ? resolved.name : null;
    const libraryFamily = resolved?.source === 'function' ? resolved.name : null;
    this.stats.records += 1;
    this.stats.bytes += bytes.length;
    this.countLibraryRecord(resolved?.name ?? UNKNOWN_LIBRARY, direction, bytes.length);
    if (this.pcap && bytes.length > 0) {
      try { this.pcap.writeRecord(endpoints, bytes); } catch (err) { log('warn', `pcap write failed: ${String(err)}`); }
    }
    return {
      type: 'fritap_datalog',
      payload: {
        function: fn,
        direction,
        ...(library ? { library } : {}),
        ...(libraryFamily ? { library_family: libraryFamily } : {}),
        protocol: payload.protocol ?? 'tls',
        src: `${endpoints.srcAddr}:${endpoints.srcPort}`,
        dst: `${endpoints.dstAddr}:${endpoints.dstPort}`,
        transport: endpoints.transport,
        ssl_session_id: payload.ssl_session_id ?? null,
        length: bytes.length,
        hex: bytes.subarray(0, MAX_RECORD_HEX_BYTES).toString('hex'),
        utf8_preview: utf8Preview(bytes),
        truncated: bytes.length > MAX_RECORD_HEX_BYTES,
      },
    };
  }

  private countLibraryRecord(name: string, direction: RecordDirection, byteCount: number): void {
    const known = name in this.stats.per_library;
    const library = known || !this.isPerLibraryFull() ? name : OTHER_LIBRARIES;
    const entry = this.stats.per_library[library] ?? { read: 0, write: 0, bytes: 0 };
    entry[direction] += 1;
    entry.bytes += byteCount;
    this.stats.per_library[library] = entry;
  }

  private isPerLibraryFull(): boolean {
    return Object.keys(this.stats.per_library).length >= MAX_TRACKED_LIBRARIES;
  }

  private noteLibrary(payload: Record<string, unknown>): void {
    const name = typeof payload.library === 'string' ? payload.library : null;
    if (name && !this.stats.libraries_detected.includes(name)) this.stats.libraries_detected.push(name);
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function withoutContentType(payload: Record<string, unknown>): Record<string, unknown> {
  const { contentType: _contentType, ...rest } = payload;
  return rest;
}

function consoleText(payload: Record<string, unknown>): string {
  const key = String(payload.contentType);
  const text = payload[key] ?? payload.console ?? payload.message;
  return typeof text === 'string' ? text : JSON.stringify(text ?? payload);
}

/** Printable utf8 preview; control bytes become '.', like a hex dump. */
export function utf8Preview(bytes: Buffer): string {
  const text = bytes.subarray(0, MAX_RECORD_PREVIEW_CHARS).toString('utf8');
  return text.replace(/[^\x20-\x7e -￿\n\r\t]/g, '.');
}
