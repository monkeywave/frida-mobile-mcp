import { describe, it, expect, beforeEach, afterAll, vi } from 'vitest';
import { attachScriptLogHandler, attachScriptSinks, buildMessageEntry } from '../../src/helpers/script-sink.js';
import { initState, getState } from '../../src/state.js';
import { loadConfig } from '../../src/config.js';
import { fakeScript, scriptEntry, seedSession, DEFAULT_SESSION_ID } from './mock-fixtures.js';

initState(loadConfig({ mobileMcp: { enabled: false } } as any));

const SCRIPT = 'script-sink-1';

/** A script stub exposing the `logHandler` setter and a drivable `message` channel. */
function sinkScript() {
  let logHandler: ((level: string, text: string) => void) | undefined;
  const listeners: Array<(m: any, d: any) => void> = [];
  return {
    stub: {
      set logHandler(fn: (level: string, text: string) => void) { logHandler = fn; },
      get logHandler() { return logHandler; },
      message: { connect: (fn: (m: any, d: any) => void) => listeners.push(fn) },
    },
    emitLog: (level: string, text: string) => logHandler?.(level, text),
    emitMessage: (m: any, d: any = null) => listeners.forEach((fn) => fn(m, d)),
  };
}

describe('buildMessageEntry', () => {
  it('passes a send payload through as a send entry', () => {
    const entry = buildMessageEntry({ type: 'send', payload: { ok: 1 } } as any, null);
    expect(entry).toMatchObject({ type: 'send', payload: { ok: 1 }, data: null });
  });

  it('preserves error diagnostics (stack/file/line/column) the AI needs to locate a fault', () => {
    const entry = buildMessageEntry(
      {
        type: 'error',
        description: 'TypeError: x is not a function',
        stack: 'at user:inline:3:10',
        fileName: 'user:inline',
        lineNumber: 3,
        columnNumber: 10,
      } as any,
      null,
    );
    expect(entry.type).toBe('error');
    expect(entry.payload).toMatchObject({
      description: 'TypeError: x is not a function',
      stack: 'at user:inline:3:10',
      fileName: 'user:inline',
      lineNumber: 3,
      columnNumber: 10,
    });
  });
});

describe('attachScriptLogHandler', () => {
  beforeEach(() => {
    const state = getState();
    state.sessions.clear();
    seedSession(state, [scriptEntry(SCRIPT, fakeScript())]);
  });
  afterAll(() => getState().stopCleanupTimer());

  it('routes agent console.* into the message buffer as a log entry (never stdout)', () => {
    const { stub, emitLog } = sinkScript();
    attachScriptLogHandler(stub as any, DEFAULT_SESSION_ID, SCRIPT);
    emitLog('info', 'rc4 key hook installed');

    const msgs = getState().getSession(DEFAULT_SESSION_ID)!.scripts.get(SCRIPT)!.messages;
    expect(msgs).toHaveLength(1);
    expect(msgs[0]).toMatchObject({ type: 'log', payload: { level: 'info', text: 'rc4 key hook installed' } });
  });
});

describe('attachScriptSinks', () => {
  beforeEach(() => {
    const state = getState();
    state.sessions.clear();
    seedSession(state, [scriptEntry(SCRIPT, fakeScript())]);
  });

  it('records send/error messages and mirrors each entry to the collector', () => {
    const { stub, emitMessage } = sinkScript();
    const collected: Array<{ type: string }> = [];
    attachScriptSinks(stub as any, DEFAULT_SESSION_ID, SCRIPT, { onEntry: (e) => collected.push({ type: e.type }) });

    emitMessage({ type: 'send', payload: { event: 'key' } });
    emitMessage({ type: 'error', description: 'boom', lineNumber: 7 });

    const msgs = getState().getSession(DEFAULT_SESSION_ID)!.scripts.get(SCRIPT)!.messages;
    expect(msgs.map((m) => m.type)).toEqual(['send', 'error']);
    expect((msgs[1].payload as any).lineNumber).toBe(7);
    expect(collected.map((c) => c.type)).toEqual(['send', 'error']);
  });

  it('routes send messages to onSend (tool-specific handling) while still recording errors', () => {
    const { stub, emitMessage } = sinkScript();
    const sends: unknown[] = [];
    attachScriptSinks(stub as any, DEFAULT_SESSION_ID, SCRIPT, { onSend: (p) => sends.push(p) });

    emitMessage({ type: 'send', payload: { event: 'custom' } });
    emitMessage({ type: 'error', description: 'boom' });

    // onSend owns the send (so it is not double-recorded); the error still lands in the buffer.
    expect(sends).toEqual([{ event: 'custom' }]);
    const msgs = getState().getSession(DEFAULT_SESSION_ID)!.scripts.get(SCRIPT)!.messages;
    expect(msgs.map((m) => m.type)).toEqual(['error']);
  });
});
