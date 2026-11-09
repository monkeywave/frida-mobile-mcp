import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import {
  registerMessagesTool,
  findEvictionLoss,
  messagesEvidenceMeta,
  pageCountAfterTrim,
  cutMessagePayload,
  fitMessagesPage,
  type MessagesPageRenderer,
} from '../../src/tools/messages.js';
import { initState, getState } from '../../src/state.js';
import { loadConfig } from '../../src/config.js';
import {
  callJson,
  fakeScript,
  makeMcpHarness,
  scriptEntry,
  seedSession,
  DEFAULT_SESSION_ID,
  type Json,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

const SCRIPT_A = 'script-a';
const SCRIPT_B = 'script-b';

/** Push a `send`-style message onto a seeded script through the public state path. */
function addMessage(scriptId: string, type: string, payload: unknown): void {
  getState().addMessageToScript(DEFAULT_SESSION_ID, scriptId, {
    timestamp: Date.now(),
    type,
    payload,
    data: null,
  });
}

describe('get_messages MCP tool', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];

  beforeAll(async () => {
    initState(loadConfig({ mobileMcp: { enabled: false } } as any));
    ({ client, close } = await makeMcpHarness((server) => registerMessagesTool(server)));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
  });

  beforeEach(() => {
    const state = getState();
    state.sessions.clear();
    state.hooks.clear();
    state.traces.clear();
  });

  it('is registered as a read-only, idempotent, closed-world tool', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'get_messages');
    expect(tool).toBeDefined();
    expect(tool!.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false });
    expect(tool!.outputSchema).toBeDefined();
  });

  it('returns SESSION_NOT_FOUND for an unknown session', async () => {
    const parsed = await callJson(client, 'get_messages', { session_id: 'nope' });
    expect(parsed.error.code).toBe('SESSION_NOT_FOUND');
    expect(parsed.error.category).toBe('request');
    expect(parsed.error.recovery_actions.map((a: Json) => a.tool)).toContain('get_status');
  });

  it('collects messages from every script, sorted by timestamp, and reports active scripts', async () => {
    const state = getState();
    seedSession(state, [scriptEntry(SCRIPT_A, fakeScript()), scriptEntry(SCRIPT_B, fakeScript())]);
    addMessage(SCRIPT_A, 'hook_invocation', { n: 1 });
    addMessage(SCRIPT_B, 'trace_hit', { n: 2 });
    addMessage(SCRIPT_A, 'hook_invocation', { n: 3 });

    const parsed = await callJson(client, 'get_messages', { session_id: DEFAULT_SESSION_ID });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result.messages_count).toBe(3);
    expect(parsed.result.truncated).toBe(false);
    // Each entry carries its originating script id/name.
    expect(parsed.result.messages.map((m: Json) => m.script_id).sort()).toEqual([SCRIPT_A, SCRIPT_A, SCRIPT_B]);
    expect(parsed.result.active_scripts.map((s: Json) => s.id).sort()).toEqual([SCRIPT_A, SCRIPT_B]);
    const perScript = Object.fromEntries(parsed.result.active_scripts.map((s: Json) => [s.id, s.message_count]));
    expect(perScript[SCRIPT_A]).toBe(2);
    expect(perScript[SCRIPT_B]).toBe(1);
  });

  it('filters to a single script when script_id is given', async () => {
    const state = getState();
    seedSession(state, [scriptEntry(SCRIPT_A, fakeScript()), scriptEntry(SCRIPT_B, fakeScript())]);
    addMessage(SCRIPT_A, 'hook_invocation', { n: 1 });
    addMessage(SCRIPT_B, 'trace_hit', { n: 2 });

    const parsed = await callJson(client, 'get_messages', { session_id: DEFAULT_SESSION_ID, script_id: SCRIPT_A });

    expect(parsed.result.messages_count).toBe(1);
    expect(parsed.result.messages.every((m: Json) => m.script_id === SCRIPT_A)).toBe(true);
  });

  it('limits results and flags truncation, then paginates with since', async () => {
    const state = getState();
    seedSession(state, [scriptEntry(SCRIPT_A, fakeScript())]);
    for (let i = 0; i < 5; i++) addMessage(SCRIPT_A, 'hook_invocation', { i });

    const first = await callJson(client, 'get_messages', { session_id: DEFAULT_SESSION_ID, limit: 2 });
    expect(first.result.messages_count).toBe(2);
    expect(first.result.truncated).toBe(true);
    // A follow-up suggestion seeds the next page with since = last_index (exclusive cursor).
    const more = first.suggested_next.find((s: Json) => s.tool === 'get_messages');
    expect(more.args.since).toBe(first.result.last_index);

    const next = await callJson(client, 'get_messages', { session_id: DEFAULT_SESSION_ID, since: more.args.since });
    expect(next.result.messages.every((m: Json) => m.seq > more.args.since)).toBe(true);
  });

  it('markdown: pages never skip messages hidden by the Markdown list cap', async () => {
    const state = getState();
    seedSession(state, [scriptEntry(SCRIPT_A, fakeScript())]);
    for (let i = 0; i < 250; i++) addMessage(SCRIPT_A, 'hook_invocation', { i });

    const seenSeqs: number[] = [];
    let since = 0;
    for (let guard = 0; guard < 20; guard++) {
      const response = (await client.callTool({
        name: 'get_messages',
        arguments: { session_id: DEFAULT_SESSION_ID, since, limit: 100, response_format: 'markdown' },
      })) as Json;
      const text: string = response.content[0].text;
      const result = response.structuredContent.result as Json;
      const shownSeqs = [...text.matchAll(/\*\*Seq\*\*: (\d+)/g)].map((m) => Number(m[1]));
      expect(result.messages.length).toBeLessThanOrEqual(30);
      expect(text).not.toMatch(/and \d+ more/);
      expect(shownSeqs).toEqual(result.messages.map((m: Json) => m.seq));
      expect(result.last_index).toBe(shownSeqs.at(-1));
      seenSeqs.push(...shownSeqs);
      if (!result.truncated) break;
      since = result.last_index;
    }

    const allSeqs = getState().sessions.get(DEFAULT_SESSION_ID)!.scripts.get(SCRIPT_A)!.messages.map((m) => m.seq);
    expect(seenSeqs).toEqual(allSeqs);
    expect(seenSeqs).toHaveLength(250);
  });

  it('paginates across multiple scripts without skipping or duplicating messages', async () => {
    const state = getState();
    seedSession(state, [scriptEntry(SCRIPT_A, fakeScript()), scriptEntry(SCRIPT_B, fakeScript())]);
    // Interleave messages across two scripts: per-script indices collide (both start at 0),
    // so only the global seq cursor can page a merged stream correctly.
    addMessage(SCRIPT_A, 'hook_invocation', { n: 'a0' });
    addMessage(SCRIPT_B, 'hook_invocation', { n: 'b0' });
    addMessage(SCRIPT_A, 'hook_invocation', { n: 'a1' });
    addMessage(SCRIPT_B, 'hook_invocation', { n: 'b1' });

    const seen: unknown[] = [];
    let since = 0;
    for (let guard = 0; guard < 10; guard++) {
      const page = await callJson(client, 'get_messages', { session_id: DEFAULT_SESSION_ID, since, limit: 2 });
      seen.push(...page.result.messages.map((m: Json) => (m.payload as Json).n));
      if (!page.result.truncated) break;
      since = page.result.last_index;
    }

    // Every message exactly once, in global order.
    expect(seen).toEqual(['a0', 'b0', 'a1', 'b1']);
  });

  it('moves the cursor only past messages actually shown when the response limit trims the page', async () => {
    seedSession(getState(), [scriptEntry(SCRIPT_A, fakeScript())]);
    const big = 'x'.repeat(2000);
    for (let i = 0; i < 40; i++) addMessage(SCRIPT_A, 'send', { i, big });

    const seen: number[] = [];
    let since: number | undefined;
    let pages = 0;
    for (;;) {
      const page = await callJson(client, 'get_messages', { session_id: DEFAULT_SESSION_ID, limit: 100, response_format: 'json', ...(since !== undefined ? { since } : {}) });
      pages++;
      seen.push(...page.result.messages.map((m: Json) => m.payload.i));
      expect(page.result.messages_count).toBe(page.result.messages.length);
      if (!page.result.truncated) break;
      expect(page.result.remaining).toBeGreaterThan(0);
      expect(page.coverage.next_offset).toBe(page.result.last_index);
      since = page.result.last_index;
    }
    expect(pages).toBeGreaterThan(1);
    expect(seen).toEqual(Array.from({ length: 40 }, (_, i) => i));
  });

  for (const format of ['markdown', 'toon'] as const) {
    it(`pages a trimmed ${format} response with the cursor on the last message present in the text`, async () => {
      seedSession(getState(), [scriptEntry(SCRIPT_A, fakeScript())]);
      const big = 'y'.repeat(1500);
      for (let i = 0; i < 60; i++) addMessage(SCRIPT_A, 'send', { tag: `<m${i}>`, big });

      const seen: number[] = [];
      let since: number | undefined;
      let pages = 0;
      for (;;) {
        const response = (await client.callTool({
          name: 'get_messages',
          arguments: { session_id: DEFAULT_SESSION_ID, limit: 100, response_format: format, ...(since !== undefined ? { since } : {}) },
        })) as Json;
        pages++;
        const text: string = response.content[0].text;
        const page = response.structuredContent.result;
        const shown: number[] = page.messages.map((m: Json) => Number(/<m(\d+)>/.exec(m.payload.tag)![1]));
        // Untrimmed render: every returned message (and the cursor's message) is in the text.
        expect(text).not.toMatch(/Result truncated to fit/);
        for (const i of shown) expect(text).toContain(`<m${i}>`);
        expect(page.last_index).toBe(page.messages.at(-1).seq);
        const next = shown.at(-1)! + 1;
        if (next < 60) expect(text).not.toContain(`<m${next}>`);
        seen.push(...shown);
        if (!page.truncated) break;
        since = page.last_index;
      }
      expect(pages).toBeGreaterThan(1);
      expect(seen).toEqual(Array.from({ length: 60 }, (_, i) => i));
    });
  }

  it('never returns more than the requested limit even when the response is trimmed', async () => {
    seedSession(getState(), [scriptEntry(SCRIPT_A, fakeScript())]);
    const big = 'z'.repeat(3000);
    for (let i = 0; i < 40; i++) addMessage(SCRIPT_A, 'send', { i, big: i === 0 ? big.repeat(10) : 'small' });
    const page = await callJson(client, 'get_messages', { session_id: DEFAULT_SESSION_ID, limit: 3 });
    expect(page.result.messages.length).toBeLessThanOrEqual(3);
    expect(page.result.last_index).toBe(page.result.messages.at(-1).seq);
  });

  it('returns a single oversized message with a cut payload and the cursor after it', async () => {
    seedSession(getState(), [scriptEntry(SCRIPT_A, fakeScript())]);
    addMessage(SCRIPT_A, 'send', { huge: 'h'.repeat(200_000) });
    addMessage(SCRIPT_A, 'send', { small: true });

    const page = await callJson(client, 'get_messages', { session_id: DEFAULT_SESSION_ID });

    expect(page.result.messages).toHaveLength(1);
    expect(page.result.messages[0]).toMatchObject({ payload_truncated: true, payload_chars: expect.any(Number) });
    expect(page.result.truncated).toBe(true);
    expect(page.result.remaining).toBe(1);
    expect(page.result.last_index).toBe(page.result.messages[0].seq);
    expect(page.limitations.some((l: string) => /payload was cut/.test(l))).toBe(true);
  });

  it('reports remaining when the limit parameter truncates', async () => {
    seedSession(getState(), [scriptEntry(SCRIPT_A, fakeScript())]);
    for (let i = 0; i < 5; i++) addMessage(SCRIPT_A, 'send', { i });
    const page = await callJson(client, 'get_messages', { session_id: DEFAULT_SESSION_ID, limit: 2 });
    expect(page.result.truncated).toBe(true);
    expect(page.result.remaining).toBe(3);
  });

  it('returns an empty set with last_index echoing the since cursor when nothing is buffered', async () => {
    seedSession(getState(), [scriptEntry(SCRIPT_A, fakeScript())]);

    const parsed = await callJson(client, 'get_messages', { session_id: DEFAULT_SESSION_ID, since: 7 });

    expect(parsed.result.messages_count).toBe(0);
    expect(parsed.result.last_index).toBe(7);
    expect(parsed.result.truncated).toBe(false);
  });
  describe('eviction-aware coverage', () => {
    let originalBuffer: number;

    beforeEach(() => {
      originalBuffer = getState().config.maxMessageBuffer;
      getState().config.maxMessageBuffer = 10;
    });

    afterEach(() => {
      getState().config.maxMessageBuffer = originalBuffer;
    });

    function seedWithEviction() {
      const state = getState();
      seedSession(state, [scriptEntry(SCRIPT_A, fakeScript())]);
      for (let i = 0; i < 12; i++) addMessage(SCRIPT_A, 'hook_invocation', { i });
      return state.sessions.get(DEFAULT_SESSION_ID)!.scripts.get(SCRIPT_A)!;
    }

    it('wires eviction loss into limitations and partial, truncated coverage', async () => {
      const script = seedWithEviction();

      const parsed = await callJson(client, 'get_messages', { session_id: DEFAULT_SESSION_ID, since: 0 });

      expect(parsed.result.messages_count).toBe(10);
      expect(parsed.limitations).toEqual([
        `messages before seq ${script.lastEvictedSeq! + 1} were evicted (maxMessageBuffer=10); raise maxMessageBuffer or poll more often`,
      ]);
      expect(parsed.coverage).toEqual({
        status: 'partial',
        scope: `session:${DEFAULT_SESSION_ID}`,
        next_offset: parsed.result.last_index,
        truncated: true,
      });
    });
  });
});

describe('findEvictionLoss / messagesEvidenceMeta', () => {
  const evicted = { lastEvictedSeq: 5 } as any;

  it('returns null when no script evicted anything', () => {
    expect(findEvictionLoss([{} as any], 0)).toBeNull();
  });

  it('reports the newest lost seq only when the cursor precedes it', () => {
    expect(findEvictionLoss([evicted, { lastEvictedSeq: 3 } as any], 0)).toBe(5);
    expect(findEvictionLoss([evicted], 5)).toBeNull();
  });

  it.each([
    ['nothing lost, limit not hit', false, null, [], { status: 'complete', scope: 'session:s1', next_offset: 9 }],
    ['limit hit', true, null, [], { status: 'partial', scope: 'session:s1', next_offset: 9, truncated: true }],
    [
      'messages evicted',
      false,
      5,
      ['messages before seq 6 were evicted (maxMessageBuffer=10); raise maxMessageBuffer or poll more often'],
      { status: 'partial', scope: 'session:s1', next_offset: 9, truncated: true },
    ],
  ] as const)('builds coverage when %s', (_label, limitHit, lastEvictedSeq, limitations, coverage) => {
    expect(messagesEvidenceMeta('s1', 9, limitHit, lastEvictedSeq, 10)).toEqual({ limitations, coverage });
  });
});

describe('pageCountAfterTrim', () => {
  const rows = Array.from({ length: 10 }, (_, i) => ({ script_id: 's', index: i, seq: i + 1, timestamp: 0, type: 'send', payload: 'x' }));
  const size = JSON.stringify(rows[0]).length;
  const trimmed = (kept: number) => [{ label: 'messages', kept, originalLength: 10 }];

  it('extends the formatter cut by the unused room and never goes below one', () => {
    expect(pageCountAfterTrim(rows, trimmed(3), 900, 1000)).toBe(3 + Math.floor(100 / size) > 10 ? 10 : 3 + Math.floor(100 / size));
    expect(pageCountAfterTrim(rows, trimmed(0), 1000, 1000)).toBe(1);
    expect(pageCountAfterTrim(rows, trimmed(5), 5000, 1000)).toBe(5);
    expect(pageCountAfterTrim(rows, [{ label: 'active_scripts', kept: 0, originalLength: 3 }], 1000, 1000)).toBe(1);
  });

  it('never exceeds min(requested limit, matched.length)', () => {
    expect(pageCountAfterTrim(rows, trimmed(5), 0, 1_000_000, 4)).toBe(4);
    expect(pageCountAfterTrim(rows, trimmed(8), 0, 1_000_000, 2)).toBe(2);
    expect(pageCountAfterTrim(rows, trimmed(3), 0, 1_000_000, 50)).toBe(10);
    expect(pageCountAfterTrim(rows, trimmed(0), 0, 1_000_000, 0)).toBe(0);
  });
});

describe('fitMessagesPage', () => {
  const fake = (fitsUpTo: number, calls: Array<[number, number | undefined]>): MessagesPageRenderer => (count, preview) => {
    calls.push([count, preview]);
    const over = preview === undefined ? count > fitsUpTo : preview > 100;
    return {
      response: { content: [{ type: 'text', text: `${count}:${preview}` }] },
      trimmed: over ? [{ label: 'messages', kept: 0, originalLength: count }] : [],
    };
  };

  it('returns the largest untrimmed count even when the estimate overshoots', () => {
    const calls: Array<[number, number | undefined]> = [];
    const page = fitMessagesPage(fake(7, calls), 20, () => 15, 1000);
    expect(page.response.content[0].text).toBe('7:undefined');
    expect(page.trimmed).toEqual([]);
  });

  it('returns the largest untrimmed count when the estimate undershoots', () => {
    const calls: Array<[number, number | undefined]> = [];
    const page = fitMessagesPage(fake(12, calls), 20, () => 3, 1000);
    expect(page.response.content[0].text).toBe('12:undefined');
  });

  it('falls back to one message with a cut payload when even one is trimmed', () => {
    const calls: Array<[number, number | undefined]> = [];
    const page = fitMessagesPage(fake(0, calls), 5, () => 1, 1000);
    expect(page.trimmed).toEqual([]);
    expect(page.response.content[0].text).toMatch(/^1:\d+$/);
  });

  it('ignores trims of arrays other than messages (active_scripts) for the cursor', () => {
    const render: MessagesPageRenderer = (count) => ({
      response: { content: [{ type: 'text', text: String(count) }] },
      trimmed: [{ label: 'active_scripts', kept: 30, originalLength: 40 }],
    });
    expect(fitMessagesPage(render, 20, () => 5, 1000).response.content[0].text).toBe('20');
  });

  it('cutMessagePayload keeps a JSON prefix and the original size', () => {
    const row = { script_id: 's', index: 0, seq: 1, timestamp: 0, type: 'send', payload: { a: 'x'.repeat(50) } };
    const cut = cutMessagePayload(row, 10);
    expect(cut.payload).toBe(JSON.stringify(row.payload).slice(0, 10));
    expect(cut.payload_chars).toBe(JSON.stringify(row.payload).length);
    expect(cut.payload_truncated).toBe(true);
  });
});
