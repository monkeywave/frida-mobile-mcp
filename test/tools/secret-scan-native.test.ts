import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { SECRET_SCAN_SOURCE } from '../../src/tools/secrets.js';
import { GOLDEN_CASES, HASHED_CASES, defaultOptions, loadScanner, standardMemory } from './secret-scan-fixture.js';

// Opt-in (needs a local frida-server-less frida-core, i.e. the `frida` node module attaching to its
// own system session): runs the REAL agent in Frida's QuickJS, where the CModule guard pass is
// active, and proves it returns exactly what the JS guard pass returns in the vm (which the golden
// test pins to the pre-rewrite scanner).
const enabled = process.env.FRIDA_MCP_LOCAL_AGENT === '1';

type Session = { createScript(src: string): Promise<any>; detach(): Promise<void> };

describe.skipIf(!enabled)('find_secrets_in_memory agent scanner in local Frida (CModule guards)', () => {
  let session: Session;
  const mem = standardMemory();

  beforeAll(async () => {
    const frida = (await import('frida')).default;
    session = (await (await frida.getLocalDevice()).attach(0)) as unknown as Session;
  });
  afterAll(async () => { await session?.detach(); });

  // Test-only shims: the scanner's ranges become native copies of the fake images, and addresses
  // are mapped back to the fake bases so both runs print identical candidates.
  const shim = (ranges: Array<{ base: string; size: number; module: string | null; readable: boolean }>) => `
var __R = ${JSON.stringify(ranges)}, __bufs = [], __pending = __R.length, __ready;
var __loaded = new Promise(function (r) { __ready = r; });
__R.forEach(function (r, i) {
  if (!r.readable) { __bufs[i] = ptr(16); if (--__pending === 0) __ready(); return; }
  recv('img' + i, function (_m, data) { var p = Memory.alloc(r.size); p.writeByteArray(data); __bufs[i] = p; if (--__pending === 0) __ready(); });
});
function __testRanges() { return __R.map(function (r, i) { return { base: __bufs[i], size: r.size }; }); }
function describeAddress(a) {
  for (var i = 0; i < __R.length; i++) {
    if (!__R[i].readable) continue;
    var d = a.sub(__bufs[i]);
    if (d.compare(ptr(0)) >= 0 && d.compare(ptr(__R[i].size)) < 0) {
      var off = '0x' + d.toString(16);
      return __R[i].module ? { rva: __R[i].module + '+' + off } : { rva: '0x' + (BigInt(__R[i].base) + BigInt(d.toString())).toString(16) };
    }
  }
  return { rva: null };
}
`;

  for (const [name, over] of Object.entries(GOLDEN_CASES)) {
    if (HASHED_CASES.has(name) || (over.scope && over.scope !== 'heap' && over.scope !== 'all')) continue;
    it(`native guard pass matches the JS guard pass: ${name}`, async () => {
      const opts = defaultOptions(over);
      const expected = JSON.parse(JSON.stringify(await loadScanner(SECRET_SCAN_SOURCE, mem, opts).rpc.exports.scan()));
      const ranges = mem.ranges.map((r) => ({ base: '0x' + r.base.toString(16), size: r.bytes?.length ?? 0x1000, module: r.module ?? null, readable: r.bytes !== null }));
      // The shim comes AFTER the source so its describeAddress declaration wins.
      const src = `var __FRIDA_MCP__ = { options: ${JSON.stringify(opts)} };\n` +
        SECRET_SCAN_SOURCE.replace(/Process\.enumerateRanges\(/g, '__testRanges(') + shim(ranges) +
        `\nvar __scan = rpc.exports.scan; rpc.exports.scan = async function () { await __loaded; return __scan(); };\n` +
        `rpc.exports.native = function () { return typeof CModule === 'function'; };`;
      const script = await session.createScript(src);
      await script.load();
      mem.ranges.forEach((r, i) => { if (r.bytes) script.post({ type: 'img' + i }, Buffer.from(r.bytes)); });
      expect(await script.exports.native()).toBe(true);
      const actual = await script.exports.scan();
      await script.unload();
      expect(actual).toEqual(expected);
    }, 60_000);
  }
});
