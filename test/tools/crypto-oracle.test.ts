import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { registerCryptoOracleTool, CRYPTO_ORACLE_BODY } from '../../src/tools/crypto-oracle.js';
import { initState, getState } from '../../src/state.js';
import { rateLimiter } from '../../src/helpers/rate-limiter.js';
import { findRemovedApis } from '../../src/agent/lint.js';
import {
  agentOptions,
  agentLiteral,
  callJson,
  makeMcpHarness,
  makeScriptingSetup,
  TEST_CONFIG,
  TARGET,
  type FakeAgentScript,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

const ORACLE_SCRIPT = 'monitor_crypto:android';

// The init_complete the preamble's reportSummary() emits during load, as frida would deliver it.
const INIT_COMPLETE = {
  type: 'send',
  payload: { status: 'init_complete', hooks_attempted: 12, hooks_installed: 10, hooks_skipped: 2 },
};

describe('monitor_crypto MCP tool', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];
  let scripts: FakeAgentScript[];

  beforeAll(async () => {
    const setup = makeScriptingSetup(({ name }) =>
      name === ORACLE_SCRIPT ? { emitOnLoad: [{ message: INIT_COMPLETE }] } : {},
    );
    scripts = setup.scripts;
    ({ client, close } = await makeMcpHarness((server) => registerCryptoOracleTool(server, setup.deviceManager)));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
  });

  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    rateLimiter.reset();
    scripts.length = 0;
  });

  const oracleScript = () => scripts.find((s) => s.name === ORACLE_SCRIPT)!;

  it('is registered as a non-readonly, open-world tool with an output schema', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'monitor_crypto');
    expect(tool).toBeDefined();
    expect(tool!.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true });
    expect(tool!.outputSchema).toBeDefined();
  });

  it('installs a persistent oracle and returns script_id, oracle_id and hook counts', async () => {
    const parsed = await callJson(client, 'monitor_crypto', { target: TARGET });

    expect(parsed.error).toBeUndefined();
    expect(parsed.result.session_id).toEqual(expect.any(String));
    expect(parsed.result.script_id).toEqual(expect.any(String));
    expect(parsed.result.oracle_id).toEqual(expect.any(String));
    // The init_complete captured in onSend surfaces as the hook counts.
    expect(parsed.result).toMatchObject({ hooks_attempted: 12, hooks_installed: 10, hooks_skipped: 2 });

    // Persistent instrumentation: the script is loaded and left loaded (never unloaded).
    expect(oracleScript().loadCalls).toBe(1);
    expect(oracleScript().unloadCalls).toBe(0);

    // The two next-step suggestions that drive-then-read the oracle.
    const next = parsed.suggested_next.map((s: any) => s.tool);
    expect(next).toContain('trigger_and_wait');
    expect(next).toContain('get_messages');
  });

  it('defaults the pattern/max_targets/log_data options and derives appPackage from a dotted target', async () => {
    await callJson(client, 'monitor_crypto', { target: TARGET });
    const opts = agentOptions(oracleScript().source);
    expect(opts.pattern).toContain('rc4');
    expect(opts.maxTargets).toBe(40);
    expect(opts.logData).toBe(true);
    expect(opts.appPackage).toBe(TARGET);
    expect(opts.platform).toBe('android');
  });

  it('passes a custom pattern and log_data=false through as agent options', async () => {
    await callJson(client, 'monitor_crypto', { target: TARGET, pattern: 'myapp\\.crypto', max_targets: 5, log_data: false });
    const opts = agentOptions(oracleScript().source);
    expect(opts.pattern).toBe('myapp\\.crypto');
    expect(opts.maxTargets).toBe(5);
    expect(opts.logData).toBe(false);
  });

  // The pattern must reach the agent only as JSON data, never spliced into code position.
  it('carries a hostile pattern purely as data (no code injection)', async () => {
    const hostile = '"}; globalThis.pwned = 1; ({"x":"';
    await callJson(client, 'monitor_crypto', { target: TARGET, pattern: hostile });
    const parsed = JSON.parse(agentLiteral(oracleScript().source));
    expect(parsed.options.pattern).toBe(hostile);
  });

  it('records the init_complete in the persistent script message buffer', async () => {
    const parsed = await callJson(client, 'monitor_crypto', { target: TARGET });
    const session = getState().sessions.get(parsed.result.session_id)!;
    const entry = session.scripts.get(parsed.result.script_id)!;
    expect(entry.persistent).toBe(true);
    expect(entry.messages.some((m) => m.type === 'crypto_status')).toBe(true);
  });
});

describe('monitor_crypto generated agent body', () => {
  it('uses only Frida 17 APIs (no removed statics)', () => {
    expect(findRemovedApis(CRYPTO_ORACLE_BODY)).toEqual([]);
  });

  it('discovers and hooks in-agent (framework sinks + app-owned classes)', () => {
    // Framework sinks are present...
    expect(CRYPTO_ORACLE_BODY).toContain('javax.crypto.Cipher');
    expect(CRYPTO_ORACLE_BODY).toContain('javax.crypto.spec.SecretKeySpec');
    expect(CRYPTO_ORACLE_BODY).toContain('CCCrypt');
    expect(CRYPTO_ORACLE_BODY).toContain('EVP_EncryptUpdate');
    // ...and the app-owned wide net is self-contained (enumerate + hook in-agent, no host round-trip).
    expect(CRYPTO_ORACLE_BODY).toContain('Java.enumerateLoadedClasses');
    expect(CRYPTO_ORACLE_BODY).toContain('reportSummary');
  });
});
