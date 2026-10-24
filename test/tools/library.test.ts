/**
 * Unit tests for the script-library tools (save/list/run/export). No device required.
 *
 * The config dir resolves from `os.homedir()` (see src/config.ts `getConfigPath`), which reads
 * the HOME / USERPROFILE environment variables live, so each run points those at a throwaway temp
 * dir and the tools read and write real files there.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { mkdtempSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { registerLibraryTools, savedScriptsDir } from '../../src/tools/library.js';
import { initState, getState } from '../../src/state.js';
import { rateLimiter } from '../../src/helpers/rate-limiter.js';
import { sha256Hex } from '../../src/helpers/sanitize.js';
import {
  callJson,
  makeMcpHarness,
  makeScriptingSetup,
  TEST_CONFIG,
  TARGET,
  type FakeAgentScript,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

const CLASSIC = "Java.perform(function () { send({ hello: 'world' }); });";
const PREAMBLE_MARKER = '=== frida-mobile-mcp agent preamble ===';
const BUNDLE_MARKER = '📦';

/** Point HOME / USERPROFILE at a fresh temp dir and return it. */
function freshHome(): string {
  const dir = mkdtempSync(join(tmpdir(), 'frida-mcp-lib-'));
  process.env.HOME = dir;
  process.env.USERPROFILE = dir;
  return dir;
}

describe('script library tools', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];
  let scripts: FakeAgentScript[];
  const envBackup = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };

  beforeAll(async () => {
    const setup = makeScriptingSetup(({ name }) =>
      name?.startsWith('saved:') ? { emitOnLoad: [{ message: { type: 'send', payload: { hello: 'world' } } }] } : {}
    );
    scripts = setup.scripts;
    ({ client, close } = await makeMcpHarness((server) => registerLibraryTools(server, setup.deviceManager)));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
    process.env.HOME = envBackup.HOME;
    process.env.USERPROFILE = envBackup.USERPROFILE;
  });

  beforeEach(() => {
    initState({ ...TEST_CONFIG });
    rateLimiter.reset();
    scripts.length = 0;
    freshHome();
  });

  /** Re-init state with custom scripts allowed (the default fixture locks them down). */
  const allowCustomScripts = () => initState({ ...TEST_CONFIG, allowCustomScripts: true });

  // --- save_script ---------------------------------------------------------

  describe('save_script', () => {
    it('is gated behind allowCustomScripts', async () => {
      const parsed = await callJson(client, 'save_script', { name: 'blocked', source: CLASSIC });
      expect(parsed.error.code).toBe('CUSTOM_SCRIPTS_DISABLED');
    });

    it('writes <name>.js and <name>.json and reports the path and size', async () => {
      allowCustomScripts();
      const parsed = await callJson(client, 'save_script', { name: 'rc4', source: CLASSIC, description: 'RC4 hook' });
      expect(parsed.error).toBeUndefined();
      expect(parsed.result).toMatchObject({ name: 'rc4', saved: true, bytes: Buffer.byteLength(CLASSIC, 'utf-8') });

      const jsPath = join(savedScriptsDir(), 'rc4.js');
      const jsonPath = join(savedScriptsDir(), 'rc4.json');
      expect(parsed.result.path).toBe(jsPath);
      expect(readFileSync(jsPath, 'utf-8')).toBe(CLASSIC);
      const meta = JSON.parse(readFileSync(jsonPath, 'utf-8'));
      expect(meta).toMatchObject({ name: 'rc4', description: 'RC4 hook', size: Buffer.byteLength(CLASSIC, 'utf-8') });
      expect(meta.source_sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(meta.source_sha256).toBe(sha256Hex(CLASSIC));
      expect(typeof meta.created).toBe('string');
    });

    it('refuses to overwrite an existing script unless overwrite is true', async () => {
      allowCustomScripts();
      await callJson(client, 'save_script', { name: 'dup', source: CLASSIC });
      const blocked = await callJson(client, 'save_script', { name: 'dup', source: CLASSIC });
      expect(blocked.error.code).toBe('INVALID_ARGUMENT');
      expect(blocked.error.message).toMatch(/already exists/i);

      const ok = await callJson(client, 'save_script', { name: 'dup', source: "send('v2');", overwrite: true });
      expect(ok.error).toBeUndefined();
      expect(readFileSync(join(savedScriptsDir(), 'dup.js'), 'utf-8')).toBe("send('v2');");
    });

    it('rejects an illegal script name', async () => {
      allowCustomScripts();
      const parsed = await callJson(client, 'save_script', { name: '../evil', source: CLASSIC });
      expect(parsed.error.code).toBe('INVALID_ARGUMENT');
    });

    it('rejects empty source', async () => {
      allowCustomScripts();
      const parsed = await callJson(client, 'save_script', { name: 'empty', source: '   ' });
      expect(parsed.error).toBeDefined();
      expect(existsSync(join(savedScriptsDir(), 'empty.js'))).toBe(false);
    });
  });

  // --- list_saved_scripts --------------------------------------------------

  describe('list_saved_scripts', () => {
    it('returns an empty list and does not create the dir when nothing is saved', async () => {
      const parsed = await callJson(client, 'list_saved_scripts', {});
      expect(parsed.error).toBeUndefined();
      expect(parsed.result).toMatchObject({ count: 0, scripts: [] });
      expect(existsSync(savedScriptsDir())).toBe(false);
    });

    it('lists saved scripts with metadata', async () => {
      allowCustomScripts();
      await callJson(client, 'save_script', { name: 'alpha', source: CLASSIC, description: 'first' });
      await callJson(client, 'save_script', { name: 'beta', source: "send(1);" });

      const parsed = await callJson(client, 'list_saved_scripts', {});
      expect(parsed.result.count).toBe(2);
      const names = parsed.result.scripts.map((s: any) => s.name);
      expect(names).toEqual(['alpha', 'beta']);
      const alpha = parsed.result.scripts.find((s: any) => s.name === 'alpha');
      expect(alpha).toMatchObject({ description: 'first', bytes: Buffer.byteLength(CLASSIC, 'utf-8') });
      expect(alpha.path).toBe(join(savedScriptsDir(), 'alpha.js'));
      expect(typeof alpha.created).toBe('string');
    });
  });

  // --- run_saved_script ----------------------------------------------------

  describe('run_saved_script', () => {
    it('is gated behind allowCustomScripts', async () => {
      const parsed = await callJson(client, 'run_saved_script', { name: 'x', target: TARGET });
      expect(parsed.error.code).toBe('CUSTOM_SCRIPTS_DISABLED');
    });

    it('reports SCRIPT_NOT_FOUND for an unknown name', async () => {
      allowCustomScripts();
      const parsed = await callJson(client, 'run_saved_script', { name: 'nope', target: TARGET });
      expect(parsed.error.code).toBe('SCRIPT_NOT_FOUND');
    });

    it('requires a target or a session_id', async () => {
      allowCustomScripts();
      const parsed = await callJson(client, 'run_saved_script', { name: 'whatever' });
      expect(parsed.error.code).toBe('INVALID_ARGUMENT');
      expect(parsed.error.message).toMatch(/target.*or.*session_id/i);
    });

    it('loads a saved classic script into the target and captures its messages', async () => {
      allowCustomScripts();
      await callJson(client, 'save_script', { name: 'runme', source: CLASSIC });

      const parsed = await callJson(client, 'run_saved_script', { name: 'runme', target: TARGET });
      expect(parsed.error).toBeUndefined();
      expect(parsed.result).toMatchObject({ name: 'runme', persistent: true, messages_received: 1 });
      expect(parsed.result.messages[0]).toMatchObject({ type: 'send', payload: { hello: 'world' } });
      expect(typeof parsed.result.script_id).toBe('string');
      expect(typeof parsed.result.session_id).toBe('string');

      // The classic source was composed with the preamble and wrapped as a user script.
      const composed = scripts.find((s) => s.name === 'saved:runme')!;
      expect(composed.source).toContain(PREAMBLE_MARKER);
      expect(composed.source).toContain('Script.evaluate');
      expect(composed.loadCalls).toBe(1);

      // Provenance: full digest of the saved source, also recorded on the script entry.
      expect(parsed.result.source_sha256).toBe(sha256Hex(CLASSIC));
      const entry = getState().getSession(parsed.result.session_id)!.scripts.get(parsed.result.script_id)!;
      expect(entry.sourceSha256).toBe(sha256Hex(CLASSIC));
    });
  });

  // --- export_script -------------------------------------------------------

  describe('export_script', () => {
    it('emits a standalone classic script: CLI header + preamble + body, no bundle marker or TS', async () => {
      const parsed = await callJson(client, 'export_script', { source: CLASSIC, package: 'com.example.rc4demo' });
      expect(parsed.error).toBeUndefined();
      const text: string = parsed.result.inline_text;
      expect(text).toContain('frida -U -f com.example.rc4demo -l');
      expect(text).toContain(PREAMBLE_MARKER);
      expect(text).toContain(CLASSIC);
      expect(text).not.toContain(BUNDLE_MARKER);
      expect(parsed.result.bytes).toBe(Buffer.byteLength(text, 'utf-8'));
    });

    it('uses a <package> placeholder when no package is given', async () => {
      const parsed = await callJson(client, 'export_script', { source: CLASSIC });
      expect(parsed.result.inline_text).toContain('frida -U -f <package> -l');
    });

    it('requires exactly one of source or name', async () => {
      const both = await callJson(client, 'export_script', { source: CLASSIC, name: 'rc4' });
      expect(both.error.code).toBe('INVALID_ARGUMENT');
      const neither = await callJson(client, 'export_script', {});
      expect(neither.error.code).toBe('INVALID_ARGUMENT');
    });

    it('exports a saved script by name', async () => {
      allowCustomScripts();
      await callJson(client, 'save_script', { name: 'saved-one', source: CLASSIC });
      initState({ ...TEST_CONFIG }); // export does not need custom scripts enabled
      const parsed = await callJson(client, 'export_script', { name: 'saved-one' });
      expect(parsed.error).toBeUndefined();
      expect(parsed.result.inline_text).toContain(CLASSIC);
      expect(parsed.result.inline_text).toContain(PREAMBLE_MARKER);
    });

    it('reports SCRIPT_NOT_FOUND exporting an unknown saved name', async () => {
      const parsed = await callJson(client, 'export_script', { name: 'ghost' });
      expect(parsed.error.code).toBe('SCRIPT_NOT_FOUND');
    });

    it('mentions the ObjC bridge in the header for iOS', async () => {
      const parsed = await callJson(client, 'export_script', { source: CLASSIC, platform: 'ios' });
      expect(parsed.result.inline_text).toContain('ObjC');
    });

    it('writes the exported script to out_path when given', async () => {
      const outPath = join(freshHome(), 'exported.js');
      const parsed = await callJson(client, 'export_script', { source: CLASSIC, out_path: outPath });
      expect(parsed.error).toBeUndefined();
      expect(parsed.result).toMatchObject({ exported: true, path: outPath });
      expect(parsed.result.inline_text).toBeUndefined();
      const written = readFileSync(outPath, 'utf-8');
      expect(written).toContain(PREAMBLE_MARKER);
      expect(written).toContain(CLASSIC);
    });
  });
});
