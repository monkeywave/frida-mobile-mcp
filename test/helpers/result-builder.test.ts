import { describe, it, expect, vi, beforeAll } from 'vitest';

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
import { DEFAULT_CONFIG } from '../../src/config.js';
import { buildResult, formatToolResponse } from '../../src/helpers/result-builder.js';
import { FridaMcpError, RateLimitError } from '../../src/helpers/errors.js';
import { ResponseFormat } from '../../src/constants.js';

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
