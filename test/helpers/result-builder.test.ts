import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';

vi.mock('frida', () => ({
  default: {
    getDeviceManager: () => ({}),
    Cancellable: { withTimeout: () => ({ isCancelled: false }) },
  },
}));

vi.mock('../../src/helpers/logger.js', () => ({
  log: vi.fn(),
  initLogger: vi.fn(),
  audit: vi.fn(),
}));

vi.mock('../../src/mobile-mcp/client.js', () => ({
  disconnectMobileMcp: vi.fn().mockResolvedValue(undefined),
}));

import { initState } from '../../src/state.js';
import { DEFAULT_CONFIG, loadConfig } from '../../src/config.js';
import { buildResult, formatToolResponse, pagedCoverage } from '../../src/helpers/result-builder.js';
import { FridaMcpError, RateLimitError } from '../../src/helpers/errors.js';
import { ResponseFormat } from '../../src/constants.js';
import type { EvidenceCoverage } from '../../src/types.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

describe('buildResult evidence envelope', () => {
  beforeAll(() => {
    initState({ ...DEFAULT_CONFIG });
  });

  it('always emits evidence_id, limitations and coverage defaults', () => {
    const res = buildResult({ ok: true });
    expect(res.result).toEqual({ ok: true });
    expect(res.evidence_id).toMatch(UUID_RE);
    expect(res.limitations).toEqual([]);
    expect(res.coverage).toEqual({ status: 'unknown' });
    expect(res.suggested_next).toEqual([]);
    expect(res.session_context).toBeDefined();
    expect('raw_result' in res).toBe(false);
  });

  it('generates a fresh evidence_id per call', () => {
    const a = buildResult({});
    const b = buildResult({});
    expect(a.evidence_id).not.toBe(b.evidence_id);
  });

  it('keeps the two-argument form working', () => {
    const res = buildResult({ x: 1 }, [{ tool: 'get_status', reason: 'check' }]);
    expect(res.suggested_next).toHaveLength(1);
    expect(res.coverage?.status).toBe('unknown');
  });

  it('accepts limitations, coverage and raw_result via the third argument', () => {
    const res = buildResult({ x: 1 }, [], {
      limitations: ['output truncated to 10 records'],
      coverage: { status: 'complete', note: 'all modules enumerated' },
      raw_result: { raw: true },
    });
    expect(res.limitations).toEqual(['output truncated to 10 records']);
    expect(res.coverage).toEqual({ status: 'complete', note: 'all modules enumerated' });
    expect(res.raw_result).toEqual({ raw: true });
  });

  it('copies the limitations array instead of aliasing it', () => {
    const limitations = ['a'];
    const res = buildResult({}, [], { limitations });
    limitations.push('b');
    expect(res.limitations).toEqual(['a']);
  });

  it('exposes the envelope in structuredContent and JSON text', () => {
    const response = formatToolResponse(buildResult({ hello: 'world' }, [], { coverage: { status: 'complete' } }), ResponseFormat.JSON);
    expect(response.isError).toBeUndefined();
    const structured = response.structuredContent as Record<string, unknown>;
    expect(structured.evidence_id).toMatch(UUID_RE);
    expect(structured.coverage).toEqual({ status: 'complete' });
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.evidence_id).toBe(structured.evidence_id);
    expect(parsed.limitations).toEqual([]);
  });

  it('renders limitations and coverage in markdown', () => {
    const response = formatToolResponse(
      buildResult({ hello: 'world' }, [], { limitations: ['partial scan'], coverage: { status: 'unknown', note: 'timed out' } }),
      ResponseFormat.MARKDOWN
    );
    const text = response.content[0].text;
    expect(text).toContain('**Limitations:**');
    expect(text).toContain('- partial scan');
    expect(text).toContain('coverage: unknown (timed out)');
    expect(text).toMatch(/evidence: [0-9a-f-]{36}/);
  });
});

describe('formatToolResponse error envelope', () => {
  it('marks errors with isError and includes category/retryable in JSON', () => {
    const err = new RateLimitError('script', 5);
    const response = formatToolResponse(err.toErrorResponse(), ResponseFormat.JSON);
    expect(response.isError).toBe(true);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.error.code).toBe('RATE_LIMIT_EXCEEDED');
    expect(parsed.error.category).toBe('resource');
    expect(parsed.error.retryable).toBe(true);
    expect(parsed.error.recovery_actions.length).toBeGreaterThan(0);
  });

  it('renders category and remediation in markdown', () => {
    const err = new FridaMcpError('FRIDA_TIMEOUT', 'spawn timed out', [], {}, { remediation: 'Check frida-server' });
    const text = formatToolResponse(err.toErrorResponse(), ResponseFormat.MARKDOWN).content[0].text;
    expect(text).toContain('**Error**: FRIDA_TIMEOUT (timeout, retryable)');
    expect(text).toContain('**Remediation**: Check frida-server');
  });
});

describe('formatToolResponse _meta.evidence_id', () => {
  it('lifts the envelope evidence_id into _meta on success without touching structuredContent', () => {
    const envelope = buildResult({ ok: true });
    const response = formatToolResponse(envelope, ResponseFormat.JSON);
    expect(response._meta?.evidence_id).toBe(envelope.evidence_id);
    expect(response.structuredContent).toEqual({ ...envelope });
  });

  it('carries the error evidence_id and the error body in _meta on error', () => {
    const body = new FridaMcpError('SESSION_NOT_FOUND', 'gone').toErrorResponse();
    const response = formatToolResponse(body, ResponseFormat.JSON);
    expect(response._meta?.evidence_id).toBe(body.error.evidence_id);
    expect(response._meta?.error).toMatchObject({ code: 'SESSION_NOT_FOUND', evidence_id: body.error.evidence_id });
    expect(JSON.parse(response.content[0].text).error.evidence_id).toBe(body.error.evidence_id);
    expect(response.structuredContent).toBeUndefined();
  });
});

describe('formatToolResponse truncation coverage', () => {
  const LIMIT = 2_000;
  const bigPayload = { items: Array.from({ length: 500 }, (_, i) => ({ i, pad: 'x'.repeat(40) })) };

  beforeAll(() => {
    initState(loadConfig({ mobileMcp: { enabled: false }, maxResponseChars: LIMIT } as any));
  });

  afterAll(() => {
    initState(loadConfig({ mobileMcp: { enabled: false } } as any));
  });

  function renderedCoverage(coverage?: EvidenceCoverage) {
    const envelope = buildResult(bigPayload, [], coverage ? { coverage } : {});
    const response = formatToolResponse(envelope, ResponseFormat.JSON);
    expect(response.content[0].text.length).toBeLessThanOrEqual(LIMIT);
    return { parsed: JSON.parse(response.content[0].text), structured: response.structuredContent as Record<string, any> };
  }

  it('flags trimmed text with coverage.truncated=true and a truncation note', () => {
    const { parsed } = renderedCoverage({ status: 'partial' });
    expect(parsed.coverage.truncated).toBe(true);
    expect(parsed.coverage.note).toBe('truncated to fit response limit');
    expect(parsed.coverage.status).toBe('partial');
  });

  it('downgrades complete to partial while preserving scope and next_offset', () => {
    const { parsed, structured } = renderedCoverage({ status: 'complete', scope: 'session:s1', next_offset: 42 });
    expect(parsed.coverage).toMatchObject({ status: 'partial', truncated: true, scope: 'session:s1', next_offset: 42 });
    // structuredContent keeps the untrimmed original.
    expect(structured.coverage).toEqual({ status: 'complete', scope: 'session:s1', next_offset: 42 });
  });

  it('keeps unknown coverage unknown when trimming', () => {
    const { parsed } = renderedCoverage({ status: 'unknown' });
    expect(parsed.coverage.status).toBe('unknown');
    expect(parsed.coverage.truncated).toBe(true);
  });

  it('defaults missing coverage to unknown when trimming', () => {
    const { parsed } = renderedCoverage();
    expect(parsed.coverage).toMatchObject({ status: 'unknown', truncated: true });
  });

  it('leaves coverage untouched when the text fits', () => {
    const response = formatToolResponse(
      buildResult({ small: true }, [], { coverage: { status: 'complete', scope: 'session:s1', next_offset: 3 } }),
      ResponseFormat.JSON,
    );
    expect(JSON.parse(response.content[0].text).coverage).toEqual({ status: 'complete', scope: 'session:s1', next_offset: 3 });
  });
});

describe('pagedCoverage', () => {
  it('is complete without truncation and omits next_offset unless given', () => {
    expect(pagedCoverage('scope', false)).toEqual({ status: 'complete', scope: 'scope' });
    expect(pagedCoverage('scope', false, 7)).toEqual({ status: 'complete', scope: 'scope', next_offset: 7 });
  });

  it('is partial and truncated when items were dropped', () => {
    expect(pagedCoverage('scope', true)).toEqual({ status: 'partial', scope: 'scope', truncated: true });
    expect(pagedCoverage('scope', true, 3)).toEqual({ status: 'partial', scope: 'scope', next_offset: 3, truncated: true });
  });
});
