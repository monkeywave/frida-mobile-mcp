/**
 * Sinks for one running friTap capture: NSS key log file, optional pcap, and the
 * normalised message records that get buffered on the session (get_messages).
 */
import { closeSync, openSync, writeSync } from 'node:fs';
import { SSL_READ_FUNCTIONS } from './constants.js';
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
  | 'fritap_error';

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
}

export interface FritapCaptureOptions {
  keylogPath?: string;
  pcapPath?: string;
}

export class FritapCapture {
  readonly stats: FritapCaptureStats = { keylog_lines: 0, records: 0, bytes: 0, libraries_detected: [], errors: 0 };
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
    this.stats.records += 1;
    this.stats.bytes += bytes.length;
    if (this.pcap && bytes.length > 0) {
      try { this.pcap.writeRecord(endpoints, bytes); } catch (err) { log('warn', `pcap write failed: ${String(err)}`); }
    }
    return {
      type: 'fritap_datalog',
      payload: {
        function: fn,
        direction: SSL_READ_FUNCTIONS.has(fn) ? 'read' : 'write',
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

  private noteLibrary(payload: Record<string, unknown>): void {
    const name = typeof payload.library === 'string' ? payload.library : null;
    if (name && !this.stats.libraries_detected.includes(name)) this.stats.libraries_detected.push(name);
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
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
