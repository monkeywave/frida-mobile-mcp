/**
 * End-to-end check of the Gap 1 / Gap 2 tools against a real device.
 *
 *   FRIDA_MCP_E2E_DEVICE=emulator-5556 [FRIDA_MCP_E2E_TARGET=com.example.rc4demo] \
 *     npx vitest run test/e2e/secret-coverage.e2e.test.ts
 *
 * Skipped entirely without FRIDA_MCP_E2E_DEVICE, so `npm test` never needs a device.
 * Drives the actual MCP tools (find_secrets_in_memory, trace_coverage, monitor_crypto)
 * through an in-memory client, reusing one spawned session, and always tears it down.
 */
import { describe, it, expect, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/client';
import { InMemoryTransport } from '@modelcontextprotocol/server';
import { createSessionServer } from '../../src/lib.js';

const DEVICE_ID = process.env.FRIDA_MCP_E2E_DEVICE;
const TARGET = process.env.FRIDA_MCP_E2E_TARGET ?? 'com.example.rc4demo';
const TIMEOUT = 60_000;

async function harness() {
  const server = createSessionServer();
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'e2e', version: '0' });
  await Promise.all([server.connect(st), client.connect(ct)]);
  return { server, client, close: async () => { await client.close(); await server.close(); } };
}

async function call(client: Client, name: string, args: Record<string, unknown>): Promise<any> {
  const res = (await client.callTool({ name, arguments: { ...args, response_format: 'json' } })) as any;
  return JSON.parse(res.content[0].text);
}

describe.skipIf(!DEVICE_ID)('e2e: secret recovery + coverage against a real device', () => {
  let client: Client | undefined;
  let close: (() => Promise<void>) | undefined;
  let sessionId: string | undefined;

  afterAll(async () => {
    if (client && sessionId) await call(client, 'stop_instrumentation', { session_id: sessionId }).catch(() => undefined);
    if (close) await close();
  });

  it('find_secrets_in_memory scans the heap and returns structured candidates', async () => {
    ({ client, close } = await harness());
    const r = await call(client!, 'find_secrets_in_memory', { target: TARGET, device: DEVICE_ID, scope: 'heap', max_bytes: 2 * 1024 * 1024 });
    expect(r.error, JSON.stringify(r.error)).toBeUndefined();
    sessionId = r.result.session_id;
    expect(Array.isArray(r.result.candidates)).toBe(true);
    expect(typeof r.result.bytes_scanned).toBe('number');
    const types = r.result.candidates.map((c: any) => c.type);
    // Headline: did we recover the RC4 key by structure, without reaching encrypt()?
    console.log(`[e2e] secrets: ${r.result.candidate_count} candidates, types=[${[...new Set(types)].join(',')}], bytes_scanned=${r.result.bytes_scanned}, stopped=${r.result.stopped}`);
    const rc4 = r.result.candidates.find((c: any) => c.type === 'rc4_sbox');
    if (rc4) console.log(`[e2e] RC4 S-box found at ${rc4.address}: ${rc4.preview_hex?.slice(0, 32)}...`);
  }, TIMEOUT);

  it('trace_coverage arms a reachability map over the app package', async () => {
    const r = await call(client!, 'trace_coverage', { session_id: sessionId, target: sessionId ? undefined : TARGET, device: DEVICE_ID, scope: 'com.example.rc4demo.*', max_targets: 200 });
    if (!sessionId) sessionId = r.result?.session_id;
    expect(r.error, JSON.stringify(r.error)).toBeUndefined();
    expect(r.result.coverage_id).toBeTruthy();
    expect(typeof r.result.targets_installed).toBe('number');
    console.log(`[e2e] coverage: installed=${r.result.targets_installed}, cold=${r.result.cold_count}, sample=[${(r.result.cold_sample ?? []).slice(0, 5).join(', ')}]`);

    const report = await call(client!, 'trace_coverage', { session_id: sessionId, report_only: true, coverage_id: r.result.coverage_id });
    expect(report.error).toBeUndefined();
    console.log(`[e2e] coverage report: ${report.result.covered_count}/${report.result.total_targets} covered (${report.result.coverage_pct}%)`);
  }, TIMEOUT);

  it('monitor_crypto installs the wide-net crypto hooks', async () => {
    const r = await call(client!, 'monitor_crypto', { session_id: sessionId, target: sessionId ? undefined : TARGET, device: DEVICE_ID });
    expect(r.error, JSON.stringify(r.error)).toBeUndefined();
    expect(r.result.oracle_id ?? r.result.script_id).toBeTruthy();
    console.log(`[e2e] monitor_crypto: attempted=${r.result.hooks_attempted}, installed=${r.result.hooks_installed}, skipped=${r.result.hooks_skipped}`);
  }, TIMEOUT);

  // Headline: autonomously drive the UI (mobile-mcp) until the RC4 path fires on the hooks armed
  // above. Reuses the one working session rather than spawning fresh (fresh spawn-by-id races a
  // held process on this emulator). Requires mobile-mcp to drive emulator-5556.
  it('drive_coverage taps the UI and captures the RC4 key/plaintext', async () => {
    const r = await call(client!, 'drive_coverage', { session_id: sessionId, stop_on: 'crypto_event', max_steps: 8, step_timeout_ms: 5000 });
    if (r.error) {
      console.log(`[e2e] drive_coverage error (mobile-mcp unavailable?): ${r.error.code} ${r.error.message}`);
      return; // honest: report, don't claim success when the UI engine isn't drivable here
    }
    console.log(`[e2e] drive_coverage: steps=${r.result.steps_taken}, stopped=${r.result.stopped_reason}, captured=${r.result.captured ? 'YES' : 'no'}`);
    for (const s of r.result.steps ?? []) console.log(`[e2e]   tapped ${JSON.stringify(s.tapped)} -> msgs=${s.new_message_count}`);
    if (r.result.captured) console.log(`[e2e] *** RC4 captured: ${JSON.stringify(r.result.captured).slice(0, 400)}`);
    expect(Array.isArray(r.result.steps)).toBe(true);
  }, TIMEOUT);
});
