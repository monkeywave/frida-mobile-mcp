/**
 * Runs frida-node's Compiler locally (no device needed). Set FRIDA_MCP_SKIP_COMPILER=1 to skip,
 * e.g. on CI runners without the frida native binding or without the bridge devDependencies.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  compileEsmAgent,
  getCompilerDiagnostics,
  clearCompilerCache,
  looksLikeTypeScript,
  formatDiagnostics,
  getCompilerProjectDir,
} from '../../src/agent/compiler.js';
import { isFridaCompileBundle } from '../../src/agent/script-factory.js';
import { ScriptError } from '../../src/helpers/errors.js';

const JAVA_AGENT = [
  "import Java from 'frida-java-bridge';",
  'Java.perform(() => { send({ available: Java.available }); });',
  'export {};',
].join('\n');

const TYPE_ERROR_AGENT = [
  "import Java from 'frida-java-bridge';",
  "const count: number = 'oops';",
  'Java.perform(() => { send(count); });',
].join('\n');

describe('looksLikeTypeScript', () => {
  it('detects common TypeScript syntax', () => {
    expect(looksLikeTypeScript('interface Foo { a: number }')).toBe(true);
    expect(looksLikeTypeScript("const n: number = 1;")).toBe(true);
    expect(looksLikeTypeScript('function f(): void {}')).toBe(true);
    expect(looksLikeTypeScript("import type { X } from 'y';")).toBe(true);
    expect(looksLikeTypeScript('const p = ptr(1) as NativePointer;')).toBe(true);
  });

  it('treats plain JavaScript as JS', () => {
    expect(looksLikeTypeScript("import Java from 'frida-java-bridge';\nfunction f(a) { return a; }")).toBe(false);
    expect(looksLikeTypeScript('const o = { a: 1 }; send(o.a ? "x" : "y");')).toBe(false);
  });
});

describe('formatDiagnostics', () => {
  it('renders file:line:column prefixes when present', () => {
    const text = formatDiagnostics([
      { severity: 'error', message: 'boom', file: 'agent.ts', line: 2, column: 7, code: 2322 },
      { severity: 'warning', message: 'meh', file: null, line: null, column: null, code: null },
    ]);
    expect(text).toBe('agent.ts:2:7: error: boom\nwarning: meh');
  });
});

describe.skipIf(process.env.FRIDA_MCP_SKIP_COMPILER === '1')('frida Compiler integration', () => {
  let projectDir: string;
  let previousOverride: string | undefined;

  beforeAll(() => {
    previousOverride = process.env.FRIDA_MCP_COMPILER_PROJECT_DIR;
    projectDir = mkdtempSync(path.join(tmpdir(), 'frida-mcp-compiler-'));
    process.env.FRIDA_MCP_COMPILER_PROJECT_DIR = projectDir;
    clearCompilerCache();
  });

  afterAll(() => {
    if (previousOverride === undefined) delete process.env.FRIDA_MCP_COMPILER_PROJECT_DIR;
    else process.env.FRIDA_MCP_COMPILER_PROJECT_DIR = previousOverride;
    rmSync(projectDir, { recursive: true, force: true });
  });

  it('honours the project dir override', () => {
    expect(getCompilerProjectDir()).toBe(projectDir);
  });

  it('compiles a 3-line ESM agent into a frida-compile bundle', async () => {
    const started = Date.now();
    const bundle = await compileEsmAgent(JAVA_AGENT, { platform: 'android', name: 'agent.ts' });
    const elapsed = Date.now() - started;

    expect(isFridaCompileBundle(bundle)).toBe(true);
    expect(bundle.startsWith('📦\n')).toBe(true);
    // The bridge got bundled in and the user code survived.
    expect(bundle).toContain('frida-java-bridge');
    expect(bundle).toMatch(/send\(\{ available: \w+\.available \}\)/);
    // Source maps are omitted so the bundle stays small for the wire.
    expect(bundle).not.toContain('.js.map');
    expect(elapsed).toBeLessThan(8000);

    // Project layout was created and the bridges are linked in.
    expect(existsSync(path.join(projectDir, 'package.json'))).toBe(true);
    expect(existsSync(path.join(projectDir, 'node_modules', 'frida-java-bridge', 'package.json'))).toBe(true);
    expect(existsSync(path.join(projectDir, 'node_modules', 'frida-objc-bridge', 'package.json'))).toBe(true);
    // The temp entrypoint is removed after the build.
    expect(readdirSync(path.join(projectDir, 'agents'))).toEqual([]);
  });

  it('returns the cached bundle for identical source + platform', async () => {
    const first = await compileEsmAgent(JAVA_AGENT, { platform: 'android' });
    const second = await compileEsmAgent(JAVA_AGENT, { platform: 'android' });
    expect(second).toBe(first);
    const other = await compileEsmAgent(JAVA_AGENT, { platform: 'ios' });
    expect(other).not.toBe(first);
  });

  it('reports a type error through getCompilerDiagnostics with 1-based positions', async () => {
    const result = await getCompilerDiagnostics(TYPE_ERROR_AGENT, { platform: 'android', name: 'agent.ts' });
    expect(result.ok).toBe(false);
    expect(result.diagnostics.length).toBeGreaterThan(0);
    const typeError = result.diagnostics.find((d) => d.code === 2322);
    expect(typeError).toBeDefined();
    expect(typeError!.severity).toBe('error');
    expect(typeError!.message).toContain("Type 'string' is not assignable to type 'number'");
    expect(typeError!.file).toBe('agent.ts');
    expect(typeError!.line).toBe(2);
    expect(typeError!.column).toBe(7);
  });

  it('type-checks Frida globals without @types/frida-gum', async () => {
    const result = await getCompilerDiagnostics(
      'const p: NativePointer = ptr(1);\nsend({ pid: Process.id, p });\nexport {};',
      { platform: 'ios', name: 'globals.ts' }
    );
    expect(result).toEqual({ ok: true, diagnostics: [] });
  });

  it('does not apply strict TypeScript rules to plain JavaScript in strict mode', async () => {
    const result = await getCompilerDiagnostics(
      "import Java from 'frida-java-bridge';\nfunction f(a) { return a; }\nJava.perform(() => send(f(1)));",
      { platform: 'android', name: 'agent.js' }
    );
    expect(result.ok).toBe(true);
  });

  it('rejects a syntax error with a ScriptError carrying the diagnostic', async () => {
    await expect(
      compileEsmAgent("import Java from 'frida-java-bridge';\nconst = ;\n", { platform: 'android', name: 'broken.ts' })
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(ScriptError);
      expect((err as ScriptError).message).toContain('broken.ts:2:7');
      return true;
    });
  });

  it('serialises concurrent builds without mixing results', async () => {
    const sources = [1, 2, 3].map((n) => `send(${n});\nexport {};`);
    const bundles = await Promise.all(sources.map((s) => compileEsmAgent(s, { platform: 'android' })));
    bundles.forEach((bundle, i) => {
      expect(bundle).toContain(`send(${i + 1});`);
    });
  });
});
