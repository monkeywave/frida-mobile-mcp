import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { tmpdir } from 'node:os';
import {
  resolveDumpOutputPath,
  defaultDumpRoots,
  planDumpChunks,
  toBuffer,
  hex,
  DUMP_CHUNK_SIZE,
} from '../../src/tools/advanced/native.js';
import { FridaMcpError } from '../../src/helpers/errors.js';

describe('resolveDumpOutputPath', () => {
  const roots = ['/work/project', '/tmp/scratch'];

  it('accepts absolute paths under an allowed root', () => {
    expect(resolveDumpOutputPath('/work/project/dumps/libfoo.bin', roots)).toBe('/work/project/dumps/libfoo.bin');
    expect(resolveDumpOutputPath('/tmp/scratch/x.bin', roots)).toBe('/tmp/scratch/x.bin');
  });

  it('rejects relative paths', () => {
    expect(() => resolveDumpOutputPath('dumps/libfoo.bin', roots)).toThrow(FridaMcpError);
    expect(() => resolveDumpOutputPath('dumps/libfoo.bin', roots)).toThrow('absolute');
  });

  it('rejects traversal and null bytes', () => {
    expect(() => resolveDumpOutputPath('/work/project/../etc/passwd', roots)).toThrow('traversal');
    expect(() => resolveDumpOutputPath('/work/project/a\0b', roots)).toThrow('null bytes');
    expect(() => resolveDumpOutputPath('', roots)).toThrow('empty');
  });

  it('rejects paths outside every root, including prefix look-alikes', () => {
    expect(() => resolveDumpOutputPath('/etc/passwd', roots)).toThrow('must be inside');
    expect(() => resolveDumpOutputPath('/work/project-evil/x.bin', roots)).toThrow('must be inside');
    expect(() => resolveDumpOutputPath('/work/project', roots)).not.toThrow();
  });

  it('default roots are cwd, the temp dir and the config dumps dir', () => {
    const roots = defaultDumpRoots();
    expect(roots).toContain(path.resolve(process.cwd()));
    expect(roots).toContain(path.resolve(tmpdir()));
    expect(roots.some((r) => r.endsWith(path.join('.config', 'frida-mobile-mcp', 'dumps')))).toBe(true);
    expect(() => resolveDumpOutputPath(path.join(tmpdir(), 'frida-mcp-test.bin'))).not.toThrow();
  });
});

describe('planDumpChunks', () => {
  const base = 0x7f00000000n;

  it('lays chunks out base-relative and splits at the chunk size', () => {
    const plan = planDumpChunks(base, 3 * DUMP_CHUNK_SIZE, [{ base: hex(base), size: 2 * DUMP_CHUNK_SIZE + 10 }], 64 * DUMP_CHUNK_SIZE);
    expect(plan.imageSize).toBe(3 * DUMP_CHUNK_SIZE);
    expect(plan.truncated).toBe(false);
    expect(plan.chunks).toEqual([
      { address: base, length: DUMP_CHUNK_SIZE, fileOffset: 0 },
      { address: base + BigInt(DUMP_CHUNK_SIZE), length: DUMP_CHUNK_SIZE, fileOffset: DUMP_CHUNK_SIZE },
      { address: base + BigInt(2 * DUMP_CHUNK_SIZE), length: 10, fileOffset: 2 * DUMP_CHUNK_SIZE },
    ]);
  });

  it('leaves gaps between ranges (zero-filled in the file) and keeps file offsets relative to base', () => {
    const plan = planDumpChunks(base, 0x5000, [
      { base: hex(base), size: 0x1000 },
      { base: hex(base + 0x3000n), size: 0x1000 },
    ], 1 << 20, 0x800);
    expect(plan.chunks.map((c) => c.fileOffset)).toEqual([0, 0x800, 0x3000, 0x3800]);
    expect(plan.chunks.every((c) => c.length === 0x800)).toBe(true);
  });

  it('clamps ranges to the module and to max_bytes', () => {
    const plan = planDumpChunks(base, 0x4000, [
      { base: hex(base - 0x1000n), size: 0x2000 }, // starts before the module
      { base: hex(base + 0x3000n), size: 0x4000 }, // runs past the module end
    ], 0x3800, 0x1000);
    expect(plan.imageSize).toBe(0x3800);
    expect(plan.truncated).toBe(true);
    expect(plan.chunks).toEqual([
      { address: base, length: 0x1000, fileOffset: 0 },
      { address: base + 0x3000n, length: 0x800, fileOffset: 0x3000 },
    ]);
  });

  it('produces no chunks for an unreadable module', () => {
    expect(planDumpChunks(base, 0x1000, [], 0x1000).chunks).toEqual([]);
  });
});

describe('toBuffer', () => {
  it('normalises Buffer, ArrayBuffer and [result, data] rpc shapes', () => {
    const buf = Buffer.from([1, 2, 3]);
    expect(toBuffer(buf)).toBe(buf);
    expect(toBuffer(new Uint8Array([4, 5]).buffer)).toEqual(Buffer.from([4, 5]));
    expect(toBuffer([{}, buf])).toBe(buf);
    expect(toBuffer(null)).toBeNull();
    expect(toBuffer('nope')).toBeNull();
  });
});

describe('hex', () => {
  it('formats bigints as 0x-prefixed lower-case hex', () => {
    expect(hex(0x7f00000000n)).toBe('0x7f00000000');
    expect(hex(0n)).toBe('0x0');
  });
});
