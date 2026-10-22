import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { registerCoverageTool, detectCoverageKind, buildCoverageOptions, generateCoverageScript } from '../../src/tools/coverage.js';
import { findRemovedApis } from '../../src/agent/lint.js';
import { initState, getState } from '../../src/state.js';
import { rateLimiter } from '../../src/helpers/rate-limiter.js';
import {
  agentOptions,
  callJson,
  makeMcpHarness,
  makeScriptingSetup,
  TEST_CONFIG,
  TARGET,
  type FakeAgentScript,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

describe('trace_coverage scope detection and options', () => {
  it('detects java / native / objc kinds', () => {
    expect(detectCoverageKind('com.example.Crypto')).toBe('java');
    expect(detectCoverageKind('com.example.*')).toBe('java');
    expect(detectCoverageKind('libfoo.so!*')).toBe('native');
    expect(detectCoverageKind('-[MyClass doThing]')).toBe('objc');
  });

  it('splits options per kind', () => {
    expect(buildCoverageOptions('libfoo.so!SSL_*', 'native', 100, 't')).toMatchObject({ moduleName: 'libfoo.so', funcGlob: 'SSL_*' });
    expect(buildCoverageOptions('com.example.Crypto', 'java', 100, 't')).toMatchObject({ className: 'com.example.Crypto', classGlob: null });
    expect(buildCoverageOptions('com.example.*', 'java', 100, 't')).toMatchObject({ classGlob: 'com.example.*', className: null });
    expect(buildCoverageOptions('-[X y]', 'objc', 100, 't')).toMatchObject({ objcPattern: '-[X y]' });
  });

  it('every coverage body is free of removed Frida APIs', () => {
    for (const kind of ['java', 'native', 'objc'] as const) {
      expect(findRemovedApis(generateCoverageScript(kind))).toEqual([]);
    }
  });
});

describe('trace_coverage MCP tool', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];
  let scripts: FakeAgentScript[];
  let armResult: unknown;

  beforeAll(async () => {
    const setup = makeScriptingSetup(({ name }) => {
      if (name.startsWith('coverage:')) return { exports: { arm: async () => armResult } };
      return {};
    });
    scripts = setup.scripts;
    ({ client, close } = await makeMcpHarness((server) => registerCoverageTool(server, setup.deviceManager)));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
  });

  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    rateLimiter.reset();
    scripts.length = 0;
    armResult = { targets: ['com.example.Crypto.encrypt', 'com.example.Crypto.decrypt'], attempted: 2, installed: 2, skipped: 0 };
  });

  it('arms a coverage run and reports every target cold initially', async () => {
    const parsed = await callJson(client, 'trace_coverage', { target: TARGET, scope: 'com.example.Crypto' });
    expect(parsed.error).toBeUndefined();
    expect(parsed.result).toMatchObject({ scope: 'com.example.Crypto', kind: 'java', targets_installed: 2, covered_count: 0, cold_count: 2 });
    expect(parsed.result.coverage_id).toBeTruthy();
    expect(parsed.result.cold_sample).toEqual(['com.example.Crypto.encrypt', 'com.example.Crypto.decrypt']);
  });

  it('requires a scope when arming', async () => {
    const parsed = await callJson(client, 'trace_coverage', { target: TARGET });
    expect(parsed.error.code).toBe('INVALID_ARGUMENT');
  });

  it('tracks covered vs cold after a hit, with a coverage percentage', async () => {
    const armed = await callJson(client, 'trace_coverage', { target: TARGET, scope: 'com.example.Crypto' });
    const coverageId = armed.result.coverage_id;

    // Simulate the hooked encrypt() firing (what trigger_and_wait would cause the agent to send).
    const covScript = scripts.find((s) => s.name.startsWith('coverage:'))!;
    covScript.emit({ type: 'send', payload: { cov: 'com.example.Crypto.encrypt' } }, null);

    const report = await callJson(client, 'trace_coverage', { report_only: true, coverage_id: coverageId });
    expect(report.result.covered_count).toBe(1);
    expect(report.result.cold_count).toBe(1);
    expect(report.result.coverage_pct).toBe(50);
    expect(report.result.covered[0]).toMatchObject({ target: 'com.example.Crypto.encrypt', hits: 1 });
    expect(report.result.cold).toEqual(['com.example.Crypto.decrypt']);
  });

  it('errors when report_only finds no armed run', async () => {
    const parsed = await callJson(client, 'trace_coverage', { session_id: 'nope', report_only: true });
    expect(parsed.error.code).toBe('COVERAGE_NOT_FOUND');
  });

  it('surfaces an arm failure from the agent', async () => {
    armResult = { error: 'module_not_found: libfoo.so', targets: [], attempted: 0, installed: 0, skipped: 0 };
    const parsed = await callJson(client, 'trace_coverage', { target: TARGET, scope: 'libfoo.so!*' });
    expect(parsed.error.code).toBe('COVERAGE_ARM_FAILED');
    // The failed run is not left dangling in state.
    expect(getState().coverage.size).toBe(0);
  });

  it('passes the native module/glob split to the agent and uses no bridges', async () => {
    armResult = { targets: ['libssl.so!SSL_read'], attempted: 1, installed: 1, skipped: 0 };
    await callJson(client, 'trace_coverage', { target: TARGET, scope: 'libssl.so!SSL_*' });
    const opts = agentOptions(scripts.find((s) => s.name.startsWith('coverage:'))!.source);
    expect(opts).toMatchObject({ kind: 'native', moduleName: 'libssl.so', funcGlob: 'SSL_*' });
  });
});
