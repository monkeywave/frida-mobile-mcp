import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SECRET_SCAN_SOURCE } from '../../src/tools/secrets.js';
import { createHash } from 'node:crypto';
import { GOLDEN_CASES, HASHED_CASES, defaultOptions, loadScanner, standardMemory, FakeMemory, CHUNK_STEP, prng, int32Le, permutation, expandAes, chachaState } from './secret-scan-fixture.js';

// The golden file was captured from the ORIGINAL per-offset scanner (before the typed-array /
// sliding-window rewrite). Every case must reproduce it exactly: same candidates in the same order,
// same fields, previews, entropy values, byte/range counters and stop reason.
const GOLDEN_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), '__golden__', 'secret-scan.golden.json');

async function runCase(name: string, over: Record<string, unknown>) {
  const agent = loadScanner(SECRET_SCAN_SOURCE, standardMemory(), defaultOptions(over));
  const result = JSON.parse(JSON.stringify(await agent.rpc.exports.scan()));
  if (!HASHED_CASES.has(name)) return result;
  const json = JSON.stringify(result);
  return { candidate_count: result.candidates.length, stopped: result.stopped, sha256: createHash('sha256').update(json).digest('hex') };
}

describe('find_secrets_in_memory agent scanner (vm)', () => {
  if (process.env.UPDATE_SECRET_GOLDEN === '1') {
    it('writes the golden file', async () => {
      const out: Record<string, unknown> = {};
      for (const [name, over] of Object.entries(GOLDEN_CASES)) out[name] = await runCase(name, over);
      fs.mkdirSync(path.dirname(GOLDEN_PATH), { recursive: true });
      fs.writeFileSync(GOLDEN_PATH, JSON.stringify(out, null, 1) + '\n');
    }, 300_000);
    return;
  }

  const golden = JSON.parse(fs.readFileSync(GOLDEN_PATH, 'utf8')) as Record<string, unknown>;

  for (const [name, over] of Object.entries(GOLDEN_CASES)) {
    it(`reproduces the pre-rewrite output exactly: ${name}`, async () => {
      expect(await runCase(name, over)).toEqual(golden[name]);
    }, 60_000);
  }

  it('the golden set actually exercises every recognizer and stop reason', () => {
    const def = golden.default as { candidates: Array<{ type: string }> };
    const precise = golden.precise_only as { candidates: Array<{ type: string; note: string }> };
    const types = new Set([...def.candidates, ...precise.candidates].map((c) => c.type));
    expect([...types].sort()).toEqual(['aes_key_schedule', 'chacha_key', 'high_entropy_key', 'jwt', 'pem_der', 'rc4_sbox', 'salsa_key']);
    expect(precise.candidates.some((c) => c.note.includes('decryption'))).toBe(true);
    expect((golden.limit_stop as { stopped: string }).stopped).toBe('limit');
    expect((golden.max_bytes_stop as { stopped: string }).stopped).toBe('max_bytes');
    expect((golden.module_missing as { error: string }).error).toMatch(/module_not_found/);
  });

  it('finds structures that straddle a chunk boundary', async () => {
    const rand = prng(99);
    const image = Uint8Array.from({ length: 4 * CHUNK_STEP + 5000 }, () => rand());
    const b = (k: number) => k * CHUNK_STEP;
    image.set(int32Le(permutation(rand)), b(1) - 1000);
    image.set(permutation(rand), b(2) - 100);
    image.set(expandAes(Uint8Array.from({ length: 32 }, () => rand())), b(3) - 40);
    image.set(chachaState('expand 32-byte k', 32, rand), b(4) - 8);
    const mem = new FakeMemory([{ base: 0x1000_0000n, bytes: image }]);
    const agent = loadScanner(SECRET_SCAN_SOURCE, mem, defaultOptions({ recognizers: ['rc4_sbox', 'aes_key_schedule', 'chacha_key'], limit: 1000 }));
    const res = (await agent.rpc.exports.scan()) as { candidates: Array<{ address: string; type: string; size: number }> };
    const at = (off: number) => '0x' + (0x1000_0000 + off).toString(16);
    expect(res.candidates).toEqual([
      expect.objectContaining({ type: 'rc4_sbox', size: 1024, address: at(b(1) - 1000) }),
      expect.objectContaining({ type: 'rc4_sbox', size: 256, address: at(b(2) - 100) }),
      expect.objectContaining({ type: 'aes_key_schedule', size: 240, address: at(b(3) - 40) }),
      expect.objectContaining({ type: 'chacha_key', size: 32, address: at(b(4) + 8) }),
    ]);
  }, 60_000);

  it('reads each chunk exactly once via readByteArray (no per-byte pointer reads)', async () => {
    const mem = standardMemory();
    await loadScanner(SECRET_SCAN_SOURCE, mem, defaultOptions({ recognizers: ['rc4_sbox'] })).rpc.exports.scan();
    expect(mem.reads.every((n) => n <= 1024 * 1024)).toBe(true);
    expect(mem.reads.length).toBeLessThan(12);
  });
});
