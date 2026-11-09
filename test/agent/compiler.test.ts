/**
 * Runs frida-node's Compiler locally (no device needed). Set FRIDA_MCP_SKIP_COMPILER=1 to skip,
 * e.g. on CI runners without the frida native binding or without the bridge devDependencies.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, existsSync, readdirSync, lstatSync, mkdirSync, writeFileSync, readFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  compileEsmAgent,
  getCompilerDiagnostics,
  clearCompilerCache,
  looksLikeTypeScript,
  formatDiagnostics,
  getCompilerProjectDir,
  linkPackage,
  needsRefresh,
  installLocalPackage,
  patchProjectJavaBridge,
} from '../../src/agent/compiler.js';
import { isJavaBridgeThreadDetachSkipped } from '../../src/agent/java-bridge-patch.js';
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

describe('linkPackage / needsRefresh', () => {
  const packageName = 'frida-java-bridge';
  const src = path.resolve('node_modules', packageName);
  let root: string;

  const installedDir = (): string => path.join(root, 'node_modules', packageName);

  beforeEach(() => {
    root = mkdtempSync(path.join(tmpdir(), 'frida-mcp-link-'));
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it('copies the package instead of linking it on win32', () => {
    linkPackage(root, packageName, src, 'win32');
    expect(lstatSync(installedDir()).isSymbolicLink()).toBe(false);
    expect(existsSync(path.join(installedDir(), 'package.json'))).toBe(true);
  });

  it.skipIf(process.platform === 'win32')('links the package on posix', () => {
    linkPackage(root, packageName, src, 'linux');
    expect(lstatSync(installedDir()).isSymbolicLink()).toBe(true);
    expect(existsSync(path.join(installedDir(), 'package.json'))).toBe(true);
  });

  it('needsRefresh is true when the installed version differs and false after linking', () => {
    mkdirSync(installedDir(), { recursive: true });
    writeFileSync(path.join(installedDir(), 'package.json'), '{"name":"frida-java-bridge","version":"0.0.1"}\n');
    expect(needsRefresh(root, packageName, src)).toBe(true);
    linkPackage(root, packageName, src, 'win32');
    expect(needsRefresh(root, packageName, src)).toBe(false);
  });

  it('needsRefresh is true when nothing is installed', () => {
    expect(needsRefresh(root, packageName, src)).toBe(true);
  });
});

describe('Java bridge unload workaround in the compiler project', () => {
  const packageName = 'frida-java-bridge';
  const src = path.resolve('node_modules', packageName);
  let root: string;

  const installedIndex = (): string => path.join(root, 'node_modules', packageName, 'index.js');
  const originalIndex = (): string => readFileSync(path.join(src, 'index.js'), 'utf8');

  beforeEach(() => {
    root = mkdtempSync(path.join(tmpdir(), 'frida-mcp-javapatch-'));
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it.each(['linux', 'darwin', 'win32'] as const)('copies (never links) and patches the bridge on %s', (platform) => {
    installLocalPackage(root, packageName, src, platform);
    expect(lstatSync(path.join(root, 'node_modules', packageName)).isSymbolicLink()).toBe(false);
    expect(patchProjectJavaBridge(root)).toBe('patched');
    expect(isJavaBridgeThreadDetachSkipped(readFileSync(installedIndex(), 'utf8'))).toBe(true);
    // The shared original in this repo's node_modules stays untouched.
    expect(isJavaBridgeThreadDetachSkipped(originalIndex())).toBe(false);
  });

  it('is idempotent across project preparations', () => {
    installLocalPackage(root, packageName, src, 'linux');
    patchProjectJavaBridge(root);
    const patchedOnce = readFileSync(installedIndex(), 'utf8');
    expect(patchProjectJavaBridge(root)).toBe('already-patched');
    expect(readFileSync(installedIndex(), 'utf8')).toBe(patchedOnce);
  });

  it('refuses to patch through a symlink to the shared original', () => {
    mkdirSync(path.join(root, 'node_modules'), { recursive: true });
    symlinkSync(src, path.join(root, 'node_modules', packageName), 'junction');
    expect(patchProjectJavaBridge(root)).toBe('skipped');
    expect(isJavaBridgeThreadDetachSkipped(originalIndex())).toBe(false);
  });

  it('flags an upstream index.js without the VM.dispose call', () => {
    mkdirSync(path.dirname(installedIndex()), { recursive: true });
    writeFileSync(installedIndex(), 'export default {};\n');
    expect(patchProjectJavaBridge(root)).toBe('pattern-not-found');
    expect(readFileSync(installedIndex(), 'utf8')).toBe('export default {};\n');
  });

  it('still links other bridges', () => {
    installLocalPackage(root, 'frida-objc-bridge', path.resolve('node_modules', 'frida-objc-bridge'), 'linux');
    expect(lstatSync(path.join(root, 'node_modules', 'frida-objc-bridge')).isSymbolicLink()).toBe(true);
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
    const javaIndex = readFileSync(path.join(projectDir, 'node_modules', 'frida-java-bridge', 'index.js'), 'utf8');
    expect(isJavaBridgeThreadDetachSkipped(javaIndex)).toBe(true);
    // The bundled bridge keeps its runtime dispose (hooks get reverted) but no longer detaches the JS thread.
    expect(bundle).toMatch(/Script\.bindWeak\(runtime\d*,/);
    // (esbuild drops the comments, leaving an empty nextTick callback.)
    expect(bundle).toMatch(/Env\w*\.dispose\(env\d*\);\s*\}\);\s*Script\.nextTick\(\(\)\s*=>\s*\{\s*\}\)/);
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

describe('compiledBundleUsesJavaBridge', () => {
  it('reads the bundle header module paths', async () => {
    const { compiledBundleUsesJavaBridge } = await import('../../src/agent/compiler.js');
    expect(compiledBundleUsesJavaBridge('📦\n3 /node_modules/frida-java-bridge/index.js\n2 /agent.js\n✄\nabc\n✄\nde')).toBe(true);
    expect(compiledBundleUsesJavaBridge('📦\n2 /agent.js\n✄\nfrida-java-bridge')).toBe(false);
  });
});
