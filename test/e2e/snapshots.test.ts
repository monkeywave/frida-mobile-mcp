/**
 * End-to-end check of per-session script-runtime snapshots against a real device/emulator.
 *
 *   (a) snapshotScript of the static preamble + Java bridge works on V8 (and is reported as
 *       unavailable on QuickJS), and a script created from it sees Java.available === true and
 *       can Java.perform after resume;
 *   (b) create+load latency of a Java-touching rpc script with and without the snapshot
 *       (5 interleaved iterations each; the timings are printed, not asserted);
 *   (c) a second script on the same session reuses the cached snapshot (host-side cache hit)
 *       and still works, including an Interceptor + Java script and a `kind: 'user'` script.
 *
 * Opt in with:
 *   FRIDA_MCP_E2E_DEVICE=emulator-5556 [FRIDA_MCP_E2E_TARGET=com.example.rc4demo] npx vitest run test/e2e/snapshots.test.ts
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import frida from 'frida';
import { createAgentScript, type AgentScriptOptions } from '../../src/agent/script-factory.js';
import { getOrCreateSessionSnapshot, snapshotCacheKey, type SnapshotHost } from '../../src/agent/snapshots.js';

const DEVICE_ID = process.env.FRIDA_MCP_E2E_DEVICE;
const TARGET = process.env.FRIDA_MCP_E2E_TARGET ?? 'com.example.rc4demo';
const TEST_TIMEOUT_MS = 120_000;
const ITERATIONS = 5;

const JAVA_RPC_BODY = `
rpc.exports = {
  probe: function () {
    return javaPerform(function () {
      return { available: Java.available, cls: Java.use('java.lang.String').$className, name: __FRIDA_MCP__.name, opt: __FRIDA_MCP__.options.opt };
    });
  }
};`;

const HOOK_BODY = `
hookNative('libc.so', 'open', { onEnter: function (args) {} });
rpc.exports = {
  stats: function () { return { attempted: _hookStats.attempted, installed: _hookStats.installed }; },
  java: function () { return javaPerform(function () { return Java.use('java.io.File').$className; }); }
};`;

const USER_SOURCE = `rpc.exports = { user: function () { return javaPerform(function () { return Java.use('java.lang.Object').$className; }); } };`;

function withTimeout<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timeout: ${what}`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

async function findDevice(id: string): Promise<frida.Device> {
  const devices = await withTimeout(frida.enumerateDevices(), 10_000, 'enumerateDevices');
  const device = devices.find((d) => d.id === id);
  if (!device) throw new Error(`device ${id} not found among ${devices.map((d) => d.id).join(', ')}`);
  return device;
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

describe.skipIf(!DEVICE_ID)('e2e: session snapshots (V8)', () => {
  let device: frida.Device;
  let pid: number;
  let session: frida.Session;
  let host: SnapshotHost;

  const scriptOptions = (name: string, extra: Partial<AgentScriptOptions> = {}): AgentScriptOptions => ({
    kind: 'generated',
    platform: 'android',
    name,
    source: JAVA_RPC_BODY,
    options: { opt: 42 },
    runtime: 'v8',
    sessionEntry: host,
    ...extra,
  });

  async function loadAndProbe(opts: AgentScriptOptions): Promise<{ createLoadMs: number; result: Record<string, unknown> }> {
    const started = performance.now();
    const script = await createAgentScript(session, opts);
    await script.load();
    const createLoadMs = performance.now() - started;
    const result = (await withTimeout(script.exports.probe(), 30_000, 'probe')) as Record<string, unknown>;
    await script.unload();
    return { createLoadMs, result };
  }

  beforeAll(async () => {
    device = await findDevice(DEVICE_ID!);
    pid = await withTimeout(device.spawn(TARGET), 30_000, 'spawn');
    session = await withTimeout(device.attach(pid), 30_000, 'attach');
    host = { id: 'e2e-snapshots', session };
    await device.resume(pid);
    await new Promise((resolve) => setTimeout(resolve, 1500));
  }, TEST_TIMEOUT_MS);

  afterAll(async () => {
    await session?.detach().catch(() => undefined);
    if (pid) await device?.kill(pid).catch(() => undefined);
  }, TEST_TIMEOUT_MS);

  it('(a) QuickJS cannot snapshot: null is returned and remembered', async () => {
    const snapshot = await getOrCreateSessionSnapshot(host, { platform: 'android', bridges: ['java'], runtime: 'qjs' });
    expect(snapshot).toBeNull();
    expect(host.snapshotFailures?.has(snapshotCacheKey(['java'], 'qjs'))).toBe(true);
  }, TEST_TIMEOUT_MS);

  it('(a) V8 snapshot of the Java bridge is created and Java.perform works from it', async () => {
    const started = performance.now();
    const snapshot = await getOrCreateSessionSnapshot(host, { platform: 'android', bridges: ['java'], runtime: 'v8' });
    const snapshotMs = performance.now() - started;
    expect(snapshot).toBeInstanceOf(Buffer);
    console.log(`[snapshots e2e] V8 snapshot: ${snapshot!.length} bytes in ${snapshotMs.toFixed(1)} ms`);

    const { result } = await loadAndProbe(scriptOptions('e2e:snapshot-java', { useSnapshot: true }));
    expect(result).toEqual({ available: true, cls: 'java.lang.String', name: 'e2e:snapshot-java', opt: 42 });
  }, TEST_TIMEOUT_MS);

  it('(b) create+load latency with and without the snapshot', async () => {
    const plain: number[] = [];
    const snapshotted: number[] = [];
    for (let i = 0; i < ITERATIONS; i++) {
      plain.push((await loadAndProbe(scriptOptions('e2e:plain', { useSnapshot: false }))).createLoadMs);
      snapshotted.push((await loadAndProbe(scriptOptions('e2e:snap', { useSnapshot: true }))).createLoadMs);
    }
    const fmt = (values: number[]) => `${values.map((v) => v.toFixed(1)).join(', ')} (median ${median(values).toFixed(1)} ms)`;
    console.log(`[snapshots e2e] create+load plain:    ${fmt(plain)}`);
    console.log(`[snapshots e2e] create+load snapshot: ${fmt(snapshotted)}`);
    expect(plain).toHaveLength(ITERATIONS);
    expect(snapshotted).toHaveLength(ITERATIONS);
  }, TEST_TIMEOUT_MS);

  it('(c) further scripts reuse the cached snapshot and still work (Interceptor + Java, user script)', async () => {
    const cached = host.snapshots?.get(snapshotCacheKey(['java'], 'v8'));
    expect(cached).toBeInstanceOf(Buffer);
    // frida's Session methods are read-only, so count snapshotScript calls through a proxy host.
    let extraSnapshotCalls = 0;
    const countingSession = new Proxy(session, {
      get(target, property, receiver) {
        if (property === 'snapshotScript') extraSnapshotCalls++;
        const value = Reflect.get(target, property, receiver) as unknown;
        return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(target) : value;
      },
    });
    host = { ...host, session: countingSession };

    const hook = await createAgentScript(session, scriptOptions('e2e:hook', { source: HOOK_BODY, useSnapshot: true }));
    await hook.load();
    expect(await hook.exports.stats()).toEqual({ attempted: 1, installed: 1 });
    expect(await withTimeout(hook.exports.java(), 30_000, 'hook java')).toBe('java.io.File');

    const user = await createAgentScript(session, scriptOptions('user:e2e', { kind: 'user', source: USER_SOURCE, useSnapshot: true }));
    await user.load();
    expect(await withTimeout(user.exports.user(), 30_000, 'user java')).toBe('java.lang.Object');

    expect(extraSnapshotCalls).toBe(0);
    expect(host.snapshots?.get(snapshotCacheKey(['java'], 'v8'))).toBe(cached);

    await user.unload();
    await hook.unload();
  }, TEST_TIMEOUT_MS);
});
