import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type frida from 'frida';
import {
  getOrCreateSessionSnapshot,
  snapshotCacheKey,
  composeSnapshotEmbedSource,
  buildStaticPreamble,
  buildDynamicPreamble,
  buildBridgeInstaller,
  bridgeInstallerCall,
  BRIDGE_INSTALLER_GLOBAL,
  type SnapshotHost,
} from '../../src/agent/snapshots.js';
import {
  createAgentScript,
  composeAgentSource,
  composeSnapshotLiveSource,
  snapshotsEnabled,
  FRIDA_COMPILE_BUNDLE_MARKER,
} from '../../src/agent/script-factory.js';
import { loadConfig } from '../../src/config.js';

const JAVA_BANNER = '/*! frida-java-bridge';
const OBJC_BANNER = '/*! frida-objc-bridge';
const CONTEXT_LINE = /^globalThis\.__FRIDA_MCP__ = /m;

interface FakeSession {
  snapshotScript: ReturnType<typeof vi.fn>;
  createScript: ReturnType<typeof vi.fn>;
}

function fakeSession(overrides: Partial<FakeSession> = {}): FakeSession {
  let counter = 0;
  return {
    snapshotScript: vi.fn(async () => Buffer.from(`snapshot-${++counter}`)),
    createScript: vi.fn(async (source: string, options: frida.ScriptOptions) => ({ source, options })),
    ...overrides,
  };
}

function hostFor(session: FakeSession, id = 'session-1'): SnapshotHost {
  return { id, session: session as unknown as frida.Session };
}

const BODY = 'rpc.exports.ping = function () { return "pong"; };';

describe('preamble split', () => {
  it('static part keeps stubs and helpers but no per-script context', () => {
    const staticPart = buildStaticPreamble('android', ['java']);
    expect(staticPart).not.toMatch(CONTEXT_LINE);
    expect(staticPart).toContain('function findExport(');
    expect(staticPart).toContain('function javaPerform(');
    expect(staticPart).toMatch(/defineProperty\(globalThis, 'ObjC'/);
    expect(staticPart).not.toMatch(/defineProperty\(globalThis, 'Java'/);
  });

  it('dynamic part is exactly the context literal', () => {
    const dynamic = buildDynamicPreamble({ name: 'n', platform: 'android', options: { a: 1 }, injectedBridges: ['java'] });
    expect(dynamic.split('\n')).toHaveLength(1);
    expect(dynamic).toMatch(CONTEXT_LINE);
    expect(JSON.parse(dynamic.replace(CONTEXT_LINE, '').replace(/;$/, ''))).toEqual({ name: 'n', platform: 'android', options: { a: 1 } });
  });

  it('bridge installer defers the IIFEs behind a global function', () => {
    const installer = buildBridgeInstaller(['java', 'objc']);
    expect(installer.startsWith(`globalThis.${BRIDGE_INSTALLER_GLOBAL} = function () {`)).toBe(true);
    expect(installer.trimEnd().endsWith('};')).toBe(true);
    expect(installer).toContain(JAVA_BANNER);
    expect(installer).toContain(OBJC_BANNER);
    expect(bridgeInstallerCall()).toBe(`${BRIDGE_INSTALLER_GLOBAL}();`);
  });

  it('embed source = static preamble + installer', () => {
    const embed = composeSnapshotEmbedSource('android', ['java']);
    expect(embed).not.toMatch(CONTEXT_LINE);
    expect(embed).toContain(JAVA_BANNER);
    expect(embed).not.toContain(OBJC_BANNER);
  });
});

describe('composeSnapshotLiveSource', () => {
  it('carries only context + installer call + body for generated scripts', () => {
    const live = composeSnapshotLiveSource({ kind: 'generated', platform: 'android', name: 't', source: BODY });
    expect(live.bridges).toEqual(['java']);
    expect(live.source).not.toContain(JAVA_BANNER);
    expect(live.source).not.toContain('function findExport(');
    expect(live.source.split('\n')).toEqual([expect.stringMatching(CONTEXT_LINE), bridgeInstallerCall(), BODY]);
  });

  it('omits the installer call when no bridges are requested', () => {
    const live = composeSnapshotLiveSource({ kind: 'generated', platform: 'android', name: 't', source: BODY, bridges: [] });
    expect(live.source).not.toContain(BRIDGE_INSTALLER_GLOBAL);
  });

  it('wraps user scripts in Script.evaluate like the plain layout', () => {
    const live = composeSnapshotLiveSource({ kind: 'user', platform: 'android', name: 'user:x', source: BODY });
    expect(live.source).toContain(`Script.evaluate("user:x", ${JSON.stringify(BODY)});`);
  });

  it('passes frida-compile bundles through untouched', () => {
    const bundle = FRIDA_COMPILE_BUNDLE_MARKER + 'console.log(1);';
    expect(composeSnapshotLiveSource({ kind: 'user', platform: 'android', name: 'b', source: bundle })).toEqual(
      composeAgentSource({ kind: 'user', platform: 'android', name: 'b', source: bundle })
    );
  });
});

describe('getOrCreateSessionSnapshot', () => {
  it('creates once per (bridge set, runtime) and caches on the host', async () => {
    const session = fakeSession();
    const host = hostFor(session);

    const first = await getOrCreateSessionSnapshot(host, { platform: 'android', bridges: ['java'], runtime: 'v8' });
    const again = await getOrCreateSessionSnapshot(host, { platform: 'android', bridges: ['java'], runtime: 'v8' });
    expect(first).toBeInstanceOf(Buffer);
    expect(again).toBe(first);
    expect(session.snapshotScript).toHaveBeenCalledTimes(1);
    expect(host.snapshots?.get(snapshotCacheKey(['java'], 'v8'))).toBe(first);

    const [embed, options] = session.snapshotScript.mock.calls[0] as [string, frida.SnapshotOptions];
    expect(embed).toContain(JAVA_BANNER);
    expect(embed).not.toMatch(CONTEXT_LINE);
    expect(options).toEqual({ runtime: 'v8' });
  });

  it('keeps separate snapshots per bridge set and per runtime', async () => {
    const session = fakeSession();
    const host = hostFor(session);
    const java = await getOrCreateSessionSnapshot(host, { platform: 'android', bridges: ['java'], runtime: 'v8' });
    const both = await getOrCreateSessionSnapshot(host, { platform: 'ios', bridges: ['java', 'objc'], runtime: 'v8' });
    const javaDefault = await getOrCreateSessionSnapshot(host, { platform: 'android', bridges: ['java'], runtime: 'default' });
    expect(new Set([java, both, javaDefault]).size).toBe(3);
    expect(session.snapshotScript).toHaveBeenCalledTimes(3);
    expect(session.snapshotScript.mock.calls[2][1]).toEqual({});
    expect(snapshotCacheKey(['objc', 'java'], 'v8')).toBe(snapshotCacheKey(['java', 'objc'], 'v8'));
  });

  it('shares a single in-flight creation between concurrent callers', async () => {
    const session = fakeSession();
    const host = hostFor(session);
    const opts = { platform: 'android', bridges: ['java'] as const, runtime: 'v8' as const };
    const [a, b] = await Promise.all([getOrCreateSessionSnapshot(host, opts), getOrCreateSessionSnapshot(host, opts)]);
    expect(a).toBe(b);
    expect(session.snapshotScript).toHaveBeenCalledTimes(1);
  });

  it('returns null without calling frida when there are no bridges', async () => {
    const session = fakeSession();
    expect(await getOrCreateSessionSnapshot(hostFor(session), { platform: 'linux', bridges: [], runtime: 'v8' })).toBeNull();
    expect(session.snapshotScript).not.toHaveBeenCalled();
  });

  it('returns null on failure and does not retry on the same session', async () => {
    const session = fakeSession({ snapshotScript: vi.fn(async () => { throw new Error('not supported by the QuickJS runtime'); }) });
    const host = hostFor(session);
    expect(await getOrCreateSessionSnapshot(host, { platform: 'android', bridges: ['java'], runtime: 'qjs' })).toBeNull();
    expect(await getOrCreateSessionSnapshot(host, { platform: 'android', bridges: ['java'], runtime: 'qjs' })).toBeNull();
    expect(session.snapshotScript).toHaveBeenCalledTimes(1);
    expect(host.snapshotFailures?.has(snapshotCacheKey(['java'], 'qjs'))).toBe(true);
    // a different runtime is still attempted
    await getOrCreateSessionSnapshot(host, { platform: 'android', bridges: ['java'], runtime: 'v8' });
    expect(session.snapshotScript).toHaveBeenCalledTimes(2);
  });
});

describe('snapshotsEnabled / createAgentScript switch', () => {
  const savedEnv = { ...process.env };

  beforeEach(() => {
    delete process.env.FRIDA_MCP_SNAPSHOTS;
    delete process.env.FRIDA_MCP_RUNTIME;
    loadConfig();
  });

  afterEach(() => {
    process.env = { ...savedEnv };
    loadConfig();
  });

  it('is off by default, follows config, and the env flag overrides config', () => {
    expect(snapshotsEnabled()).toBe(false);
    loadConfig({ snapshots: true });
    expect(snapshotsEnabled()).toBe(true);
    process.env.FRIDA_MCP_SNAPSHOTS = '0';
    expect(snapshotsEnabled()).toBe(false);
    process.env.FRIDA_MCP_SNAPSHOTS = '1';
    loadConfig({ snapshots: false });
    expect(snapshotsEnabled()).toBe(true);
    expect(snapshotsEnabled(false)).toBe(false);
  });

  it('FRIDA_MCP_SNAPSHOTS is applied by loadConfig', () => {
    process.env.FRIDA_MCP_SNAPSHOTS = 'true';
    expect(loadConfig().snapshots).toBe(true);
    process.env.FRIDA_MCP_SNAPSHOTS = 'false';
    expect(loadConfig({ snapshots: true }).snapshots).toBe(false);
  });

  it('sends the full source when snapshots are off or no sessionEntry is given', async () => {
    const session = fakeSession();
    const base = { kind: 'generated' as const, platform: 'android' as const, name: 't', source: BODY, runtime: 'v8' as const };
    await createAgentScript(session as unknown as frida.Session, base);
    await createAgentScript(session as unknown as frida.Session, { ...base, sessionEntry: hostFor(session), useSnapshot: false });
    expect(session.snapshotScript).not.toHaveBeenCalled();
    for (const [source, options] of session.createScript.mock.calls as Array<[string, frida.ScriptOptions]>) {
      expect(source).toContain(JAVA_BANNER);
      expect(options).toEqual({ name: 't', runtime: 'v8' });
    }
  });

  it('uses the session snapshot and the live layout when enabled', async () => {
    process.env.FRIDA_MCP_SNAPSHOTS = '1';
    const session = fakeSession();
    const host = hostFor(session);
    const base = { kind: 'generated' as const, platform: 'android' as const, name: 't', source: BODY, runtime: 'v8' as const, sessionEntry: host };
    await createAgentScript(session as unknown as frida.Session, base);
    await createAgentScript(session as unknown as frida.Session, { ...base, name: 'second' });
    expect(session.snapshotScript).toHaveBeenCalledTimes(1);
    const snapshot = host.snapshots!.get(snapshotCacheKey(['java'], 'v8'));
    for (const [source, options] of session.createScript.mock.calls as Array<[string, frida.ScriptOptions]>) {
      expect(source).not.toContain(JAVA_BANNER);
      expect(source).toContain(bridgeInstallerCall());
      expect(options.snapshot).toBe(snapshot);
      expect(options.runtime).toBe('v8');
    }
  });

  it('falls back to the full source when the snapshot cannot be created', async () => {
    const session = fakeSession({ snapshotScript: vi.fn(async () => { throw new Error('not supported by the QuickJS runtime'); }) });
    await createAgentScript(session as unknown as frida.Session, {
      kind: 'generated', platform: 'android', name: 't', source: BODY, sessionEntry: hostFor(session), useSnapshot: true,
    });
    const [source, options] = session.createScript.mock.calls[0] as [string, frida.ScriptOptions];
    expect(source).toContain(JAVA_BANNER);
    expect(options).toEqual({ name: 't' });
  });

  it('never snapshots passthrough bundles', async () => {
    const session = fakeSession();
    await createAgentScript(session as unknown as frida.Session, {
      kind: 'user', platform: 'android', name: 'b', source: FRIDA_COMPILE_BUNDLE_MARKER + 'x', sessionEntry: hostFor(session), useSnapshot: true,
    });
    expect(session.snapshotScript).not.toHaveBeenCalled();
    expect(session.createScript.mock.calls[0][1]).toEqual({ name: 'b' });
  });
});
