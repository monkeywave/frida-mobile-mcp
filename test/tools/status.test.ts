import { describe, it, expect } from 'vitest';
import { getScriptRegistry } from '../../src/scripts/registry.js';
import { summarizeSession, summarizeRecentDetaches } from '../../src/tools/status.js';
import type { SessionEntry, DetachRecord } from '../../src/types.js';

// Test the structural aspects we can verify without mocking Frida
describe('get_status tool structure', () => {
  it('script registry is available for status reporting', () => {
    const registry = getScriptRegistry();
    expect(registry.listAll().length).toBe(8);
  });
});

const T0 = Date.UTC(2026, 0, 1, 12, 0, 0);

function fakeSession(overrides: Partial<SessionEntry> & { scriptNames?: Array<string | undefined> } = {}): SessionEntry {
  const { scriptNames = [], ...rest } = overrides;
  const scripts = new Map(
    scriptNames.map((name, i) => [`script-${i}`, { id: `script-${i}`, name, messages: [], persistent: true, createdAt: T0 }])
  );
  return {
    id: 'sess-1',
    pid: 1234,
    deviceId: 'emulator-5554',
    target: 'com.example.app',
    platform: 'android',
    scripts,
    createdAt: T0,
    ...rest,
  } as unknown as SessionEntry;
}

describe('summarizeSession', () => {
  it('falls back to createdAt when lastActivityAt is missing', () => {
    const summary = summarizeSession(fakeSession(), T0 + 30_000);
    expect(summary.last_activity_at).toBe(new Date(T0).toISOString());
    expect(summary.created).toBe(new Date(T0).toISOString());
    expect(summary.idle_seconds).toBe(30);
  });

  it('computes idle_seconds from lastActivityAt and the injected now', () => {
    const summary = summarizeSession(fakeSession({ lastActivityAt: T0 + 10_000 }), T0 + 70_400);
    expect(summary.last_activity_at).toBe(new Date(T0 + 10_000).toISOString());
    expect(summary.idle_seconds).toBe(60);
  });

  it('reports script count and names, using the id when a script has no name', () => {
    const summary = summarizeSession(fakeSession({ scriptNames: ['user:inline', undefined] }), T0);
    expect(summary.scripts).toBe(2);
    expect(summary.script_names).toEqual(['user:inline', 'script-1']);
  });

  it('carries platform, device and crash summary', () => {
    const plain = summarizeSession(fakeSession(), T0);
    expect(plain.platform).toBe('android');
    expect(plain.device).toBe('emulator-5554');
    expect(plain.crash_summary).toBeNull();

    const crashed = summarizeSession(
      fakeSession({ crash: { pid: 1234, processName: 'app', summary: 'SIGSEGV' } }),
      T0
    );
    expect(crashed.crash_summary).toBe('SIGSEGV');
  });
});

function fakeDetach(i: number, overrides: Partial<DetachRecord> = {}): DetachRecord {
  return {
    sessionId: `sess-${i}`,
    target: `app-${i}`,
    pid: 100 + i,
    deviceId: 'dev',
    reason: 'application-requested',
    crash: null,
    timestamp: T0 + i * 1000,
    ...overrides,
  };
}

describe('summarizeRecentDetaches', () => {
  it('returns at most `limit` records, newest first', () => {
    const records = Array.from({ length: 8 }, (_, i) => fakeDetach(i));
    const summary = summarizeRecentDetaches(records);
    expect(summary).toHaveLength(5);
    expect(summary.map((d) => d.target)).toEqual(['app-7', 'app-6', 'app-5', 'app-4', 'app-3']);
    expect(summarizeRecentDetaches(records, 2).map((d) => d.pid)).toEqual([107, 106]);
  });

  it('returns an empty list when nothing was recorded', () => {
    expect(summarizeRecentDetaches([])).toEqual([]);
  });

  it('maps fields, crash summary and ISO timestamps', () => {
    const [crashed, plain] = summarizeRecentDetaches([
      fakeDetach(0),
      fakeDetach(1, {
        sessionId: null,
        reason: 'process-crashed',
        crash: { pid: 101, processName: 'app-1', summary: 'abort()' },
      }),
    ]);
    expect(crashed).toEqual({
      session_id: null,
      target: 'app-1',
      pid: 101,
      device: 'dev',
      reason: 'process-crashed',
      crash_summary: 'abort()',
      timestamp: new Date(T0 + 1000).toISOString(),
    });
    expect(plain.session_id).toBe('sess-0');
    expect(plain.crash_summary).toBeNull();
    expect(plain.timestamp).toBe(new Date(T0).toISOString());
  });
});
