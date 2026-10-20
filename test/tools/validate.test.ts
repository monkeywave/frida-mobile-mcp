import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/client';
import { McpServer, InMemoryTransport } from '@modelcontextprotocol/server';
import { validateScriptSource, detectScriptKind, registerValidateTool } from '../../src/tools/validate.js';
import { clearCompilerCache } from '../../src/agent/compiler.js';
import { initState } from '../../src/state.js';
import { loadConfig } from '../../src/config.js';

const REMOVED_API_SCRIPT = "var p = Module.findExportByName('libc.so', 'open'); send(p);";
const SYNTAX_ERROR_SCRIPT = 'function f( { send(1); }';
const VALID_CLASSIC_SCRIPT = "Java.perform(function () { send({ ok: Java.available }); });";
const BUNDLE_SCRIPT = '📦\n5 /agent.js\n✄\nsend(1)';
const ESM_TYPE_ERROR = "import Java from 'frida-java-bridge';\nconst n: number = 'x';\nJava.perform(() => send(n));";
const ESM_PLAIN_JS = "import Java from 'frida-java-bridge';\nfunction f(a) { return a; }\nJava.perform(() => send(f(1)));";

describe('detectScriptKind', () => {
  it('classifies classic, esm and bundle sources', () => {
    expect(detectScriptKind(VALID_CLASSIC_SCRIPT)).toBe('classic');
    expect(detectScriptKind(ESM_PLAIN_JS)).toBe('esm');
    expect(detectScriptKind(BUNDLE_SCRIPT)).toBe('bundle');
  });
});

describe('validateScriptSource (no compiler needed)', () => {
  it('flags a removed Frida 17 API in a classic script', async () => {
    const result = await validateScriptSource({ source: REMOVED_API_SCRIPT });
    expect(result.kind).toBe('classic');
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toEqual([]);
    expect(result.removed_apis).toHaveLength(1);
    expect(result.removed_apis[0].line).toBe(1);
  });

  it('reports a syntax error in a classic script with a location', async () => {
    const result = await validateScriptSource({ source: SYNTAX_ERROR_SCRIPT });
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toHaveLength(1);
    const [diag] = result.diagnostics;
    expect(diag.severity).toBe('error');
    expect(diag.file).toBe('inline');
    expect(diag.line).toBe(1);
    expect(diag.column).toBeGreaterThan(0);
    expect(diag.message.length).toBeGreaterThan(0);
  });

  it('accepts a valid classic Java.perform script', async () => {
    const result = await validateScriptSource({ source: VALID_CLASSIC_SCRIPT });
    expect(result).toEqual({ ok: true, kind: 'classic', diagnostics: [], removed_apis: [] });
  });

  it('passes frida-compile bundles through', async () => {
    const result = await validateScriptSource({ source: BUNDLE_SCRIPT });
    expect(result.kind).toBe('bundle');
    expect(result.ok).toBe(true);
  });

  it('requires source or file_path', async () => {
    await expect(validateScriptSource({})).rejects.toThrow(/source or file_path/);
  });

  describe('file_path', () => {
    let dir: string;
    beforeAll(() => {
      dir = mkdtempSync(path.join(tmpdir(), 'frida-mcp-validate-'));
    });
    afterAll(() => {
      rmSync(dir, { recursive: true, force: true });
    });

    it('reads and validates a classic script file, naming diagnostics after the file', async () => {
      const file = path.join(dir, 'broken.js');
      writeFileSync(file, SYNTAX_ERROR_SCRIPT);
      const result = await validateScriptSource({ file_path: file });
      expect(result.ok).toBe(false);
      expect(result.diagnostics[0].file).toBe('broken.js');

      const good = path.join(dir, 'good.js');
      writeFileSync(good, VALID_CLASSIC_SCRIPT);
      expect((await validateScriptSource({ file_path: good })).ok).toBe(true);
    });

    it('rejects directory traversal', async () => {
      await expect(validateScriptSource({ file_path: '../etc/passwd.js' })).rejects.toThrow(/traversal/);
    });

    it('rejects unreadable files', async () => {
      await expect(validateScriptSource({ file_path: path.join(dir, 'missing.js') })).rejects.toThrow(/Cannot read file/);
    });
  });
});

describe.skipIf(process.env.FRIDA_MCP_SKIP_COMPILER === '1')('validateScriptSource (ESM via frida Compiler)', () => {
  let projectDir: string;
  let previousOverride: string | undefined;

  beforeAll(() => {
    previousOverride = process.env.FRIDA_MCP_COMPILER_PROJECT_DIR;
    projectDir = mkdtempSync(path.join(tmpdir(), 'frida-mcp-validate-compiler-'));
    process.env.FRIDA_MCP_COMPILER_PROJECT_DIR = projectDir;
    clearCompilerCache();
  });

  afterAll(() => {
    if (previousOverride === undefined) delete process.env.FRIDA_MCP_COMPILER_PROJECT_DIR;
    else process.env.FRIDA_MCP_COMPILER_PROJECT_DIR = previousOverride;
    rmSync(projectDir, { recursive: true, force: true });
  });

  it('reports a type error in strict mode', async () => {
    const result = await validateScriptSource({ source: ESM_TYPE_ERROR, platform: 'android' });
    expect(result.kind).toBe('esm');
    expect(result.ok).toBe(false);
    const typeError = result.diagnostics.find((d) => d.code === 2322);
    expect(typeError).toBeDefined();
    expect(typeError!.line).toBe(2);
    expect(typeError!.file).toBe('inline');
  });

  it('skips the type check when strict is false', async () => {
    const result = await validateScriptSource({ source: ESM_TYPE_ERROR, platform: 'android', strict: false });
    expect(result.ok).toBe(true);
    expect(result.diagnostics).toEqual([]);
  });

  it('accepts valid plain-JavaScript ESM in strict mode', async () => {
    const result = await validateScriptSource({ source: ESM_PLAIN_JS, platform: 'android' });
    expect(result.ok).toBe(true);
    expect(result.kind).toBe('esm');
  });
});

describe('validate_script MCP tool', () => {
  let client: Client;
  let server: McpServer;

  beforeAll(async () => {
    initState(loadConfig({ mobileMcp: { enabled: false } } as any));
    server = new McpServer({ name: 't', version: '0' });
    registerValidateTool(server);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    client = new Client({ name: 'test-client', version: '0' });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  });

  afterAll(async () => {
    await client.close();
    await server.close();
  });

  it('is registered as a read-only tool', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'validate_script');
    expect(tool).toBeDefined();
    expect(tool!.annotations?.readOnlyHint).toBe(true);
    expect(tool!.annotations?.destructiveHint).toBe(false);
  });

  it('returns structured validation results', async () => {
    const response = await client.callTool({
      name: 'validate_script',
      arguments: { source: REMOVED_API_SCRIPT, response_format: 'json' },
    });
    expect(response.isError).toBeFalsy();
    const structured = response.structuredContent as { result: { ok: boolean; kind: string; removed_apis: unknown[] }; suggested_next: Array<{ tool: string }> };
    expect(structured.result.ok).toBe(false);
    expect(structured.result.kind).toBe('classic');
    expect(structured.result.removed_apis).toHaveLength(1);
    expect(structured.suggested_next[0].tool).toBe('frida_help');
  });

  it('suggests execute_script for a valid script', async () => {
    const response = await client.callTool({
      name: 'validate_script',
      arguments: { source: VALID_CLASSIC_SCRIPT, response_format: 'json' },
    });
    const structured = response.structuredContent as { result: { ok: boolean }; suggested_next: Array<{ tool: string }> };
    expect(structured.result.ok).toBe(true);
    expect(structured.suggested_next[0].tool).toBe('execute_script');
  });

  it('returns an error response when no source is given', async () => {
    const response = await client.callTool({ name: 'validate_script', arguments: { response_format: 'json' } });
    expect(response.isError).toBe(true);
  });
});
