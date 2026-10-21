import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { registerSslTool } from '../../src/tools/ssl.js';
import { initState, getState } from '../../src/state.js';
import { rateLimiter } from '../../src/helpers/rate-limiter.js';
import {
  callJson,
  makeMcpHarness,
  makeScriptingSetup,
  TEST_CONFIG,
  TARGET,
  type FakeAgentScript,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

const SCRIPT_NAME = 'prebuilt:ssl_pinning_bypass';

/** A frida `send` message as the connected handler expects to receive it. */
function sent(payload: Record<string, unknown>) {
  return { message: { type: 'send', payload } };
}

describe('bypass_ssl_pinning MCP tool', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];
  let scripts: FakeAgentScript[];
  let emitOnLoad: Array<{ message: any; data?: any }>;

  beforeAll(async () => {
    const setup = makeScriptingSetup(({ name }) => (name === SCRIPT_NAME ? { emitOnLoad } : {}));
    scripts = setup.scripts;
    ({ client, close } = await makeMcpHarness((server) => registerSslTool(server, setup.deviceManager)));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
  });

  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    rateLimiter.reset();
    scripts.length = 0;
    emitOnLoad = [];
  });

  it('is a destructive, idempotent, open-world tool', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'bypass_ssl_pinning')!;
    expect(tool.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true });
    expect(tool.outputSchema).toBeDefined();
  });

  it('partitions the agent messages into bypassed and failed methods', async () => {
    emitOnLoad = [
      sent({ status: 'bypassed', method: 'TrustManagerImpl.verifyChain' }),
      sent({ status: 'bypassed', method: 'OkHttp3.CertificatePinner' }),
      sent({ status: 'failed', method: 'SSLContext.init' }),
    ];

    const parsed = await callJson(client, 'bypass_ssl_pinning', { target: TARGET });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result.platform).toBe('android');
    expect(parsed.result.bypassed_methods).toEqual(['TrustManagerImpl.verifyChain', 'OkHttp3.CertificatePinner']);
    expect(parsed.result.failed_methods).toEqual(['SSLContext.init']);
    expect(parsed.result.all_results).toHaveLength(3);
    expect(parsed.result.message).toMatch(/SSL pinning bypassed via/);

    // The script is tracked on the resolved session so later tools can address it.
    const session = getState().getSession(parsed.result.session_id)!;
    expect(session.scripts.get(parsed.result.script_id)!.name).toBe('ssl_pinning_bypass');
  });

  it('reports a pending bypass when no methods confirmed yet', async () => {
    const parsed = await callJson(client, 'bypass_ssl_pinning', { target: TARGET });
    expect(parsed.result.bypassed_methods).toEqual([]);
    expect(parsed.result.message).toMatch(/will activate on next network request/);
  });

  it('rejects an empty target with no session to fall back on, before touching the device', async () => {
    const parsed = await callJson(client, 'bypass_ssl_pinning', { target: '' });
    expect(parsed.error).toBeDefined();
    expect(parsed.error.message).toMatch(/provide target.*or session_id/i);
  });

  it('enforces the per-minute script rate limit', async () => {
    for (let i = 0; i < TEST_CONFIG.rateLimits.scriptsPerMinute; i++) rateLimiter.record('script');
    const parsed = await callJson(client, 'bypass_ssl_pinning', { target: TARGET });
    expect(parsed.error.code).toBe('RATE_LIMIT_EXCEEDED');
  });
});
