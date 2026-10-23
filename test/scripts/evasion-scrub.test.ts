import { describe, it, expect } from 'vitest';
import vm from 'node:vm';
import { EVASION_SCRUB_SNIPPET } from '../../src/scripts/evasion-scrub.js';

/**
 * The generation sandbox never enters the hook closures (no module is found), so the actual
 * scrub logic is exercised here directly: evaluate the snippet, build an `installEvasion`
 * handle, and drive it with a fake NativePointer-like buffer backed by a byte array.
 */
interface FakeBuf {
  readUtf8String(n?: number): string;
  writeByteArray(bytes: number[]): void;
  bytes(): number[];
}

function fakeBuf(initial: string): FakeBuf {
  let data = Array.from(Buffer.from(initial, 'latin1'));
  return {
    readUtf8String(n?: number) {
      const slice = typeof n === 'number' ? data.slice(0, n) : data;
      // stop at first NUL, like a C string, when no explicit length
      const end = typeof n === 'number' ? slice.length : slice.indexOf(0) >= 0 ? slice.indexOf(0) : slice.length;
      return Buffer.from(slice.slice(0, end)).toString('latin1');
    },
    writeByteArray(b: number[]) { for (let i = 0; i < b.length; i++) data[i] = b[i]; },
    bytes() { return data; },
  };
}

interface Evasion {
  mode: string;
  signatureCount: number;
  matchSignature(s: string | null): string | null;
  handleProcRead(fd: number, buf: FakeBuf, n: number, mode: string): void;
  handleLine(buf: FakeBuf, size: number, mode: string): void;
  markFd(fd: number, path: string): void;
  isSensitive(fd: number): boolean;
}

function makeEvasion(options: Record<string, unknown>): { ev: Evasion; sent: Record<string, unknown>[] } {
  const sent: Record<string, unknown>[] = [];
  const sandbox = { send: (m: Record<string, unknown>) => sent.push(m) };
  const context = vm.createContext(sandbox);
  vm.runInContext(`${EVASION_SCRUB_SNIPPET}\nglobalThis.__make = installEvasion;`, context);
  const ev = (context as unknown as { __make: (o: unknown) => Evasion }).__make(options);
  return { ev, sent };
}

describe('installEvasion', () => {
  it('matches the default Frida signatures case-insensitively', () => {
    const { ev } = makeEvasion({});
    expect(ev.signatureCount).toBeGreaterThan(5);
    // Returns the first matching signature; 'frida' precedes (and is a substring of) 're.frida.server'.
    expect(ev.matchSignature('7f00-7fff r-xp /data/local/tmp/re.frida.server')).toBe('frida');
    expect(ev.matchSignature('FRIDA-AGENT')).toBe('frida');
    expect(ev.matchSignature('/system/lib/libc.so')).toBeNull();
    expect(ev.matchSignature(null)).toBeNull();
  });

  it('honours a custom signature list', () => {
    const { ev } = makeEvasion({ signatures: ['sekret'] });
    expect(ev.signatureCount).toBe(1);
    expect(ev.matchSignature('has sekret inside')).toBe('sekret');
    expect(ev.matchSignature('frida')).toBeNull();
  });

  it('report mode observes a maps read but does NOT modify the buffer', () => {
    const { ev, sent } = makeEvasion({ mode: 'report' });
    ev.markFd(7, '/proc/self/maps');
    const line = 'deadbeef-deadffff r-xp 00000000 /data/local/tmp/frida-agent-64.so\n';
    const buf = fakeBuf(line);
    const original = buf.bytes().slice();
    ev.handleProcRead(7, buf, line.length, 'report');
    expect(sent.some((m) => m.status === 'anti_frida_probe' && m.action === 'observed')).toBe(true);
    expect(buf.bytes()).toEqual(original); // unchanged
  });

  it('spoof mode scrubs the signature in place, preserving length', () => {
    const { ev, sent } = makeEvasion({ mode: 'spoof' });
    ev.markFd(7, '/proc/self/maps');
    const line = 'deadbeef-deadffff r-xp 00000000 /data/local/tmp/frida-agent-64.so\n';
    const buf = fakeBuf(line);
    const before = buf.bytes().length;
    ev.handleProcRead(7, buf, line.length, 'spoof');
    const after = buf.readUtf8String(line.length);
    expect(buf.bytes().length).toBe(before); // same byte count
    expect(after.toLowerCase()).not.toContain('frida');
    expect(after).toHaveLength(line.length);
    expect(sent.some((m) => m.action === 'scrubbed')).toBe(true);
  });

  it('spoof mode zeroes a non-zero TracerPid, preserving length', () => {
    const { ev } = makeEvasion({ mode: 'spoof' });
    ev.markFd(3, '/proc/self/status');
    const status = 'Name:\tcom.app\nTracerPid:\t2345\nUid:\t10100\n';
    const buf = fakeBuf(status);
    ev.handleProcRead(3, buf, status.length, 'spoof');
    const after = buf.readUtf8String(status.length);
    expect(after).toContain('TracerPid:\t0');
    expect(after).not.toContain('2345');
    expect(after).toHaveLength(status.length);
  });

  it('ignores reads on non-sensitive fds', () => {
    const { ev } = makeEvasion({ mode: 'spoof' });
    expect(ev.isSensitive(9)).toBe(false);
  });

  it('handleLine masks only the signature, preserving the rest of the line (not blanking it)', () => {
    const { ev, sent } = makeEvasion({ mode: 'spoof' });
    const line = '7f00-7fff r-xp 00000000 /data/local/tmp/frida-agent-64.so\n';
    const buf = fakeBuf(line);
    ev.handleLine(buf, line.length, 'spoof');
    const after = buf.readUtf8String(line.length);
    expect(after).toHaveLength(line.length);           // length preserved
    expect(after.toLowerCase()).not.toContain('frida'); // signature masked
    expect(after).toContain('r-xp 00000000');           // benign content survives (not blanked)
    expect(after).toContain('.so');
    expect(sent.some((m) => m.action === 'scrubbed')).toBe(true);
  });

  it('handleLine leaves a line with no signature untouched', () => {
    const { ev } = makeEvasion({ mode: 'spoof' });
    const line = '7f00-7fff r-xp 00000000 /system/lib64/libc.so\n';
    const buf = fakeBuf(line);
    const original = buf.bytes().slice();
    ev.handleLine(buf, line.length, 'spoof');
    expect(buf.bytes()).toEqual(original);
  });
});
