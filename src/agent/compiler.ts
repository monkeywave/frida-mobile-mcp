/**
 * Host-side compilation of ES module agents with frida-node's `Compiler` (Frida 17).
 *
 * The Compiler needs a project directory with a `package.json` and a `node_modules` folder
 * that contains the packages the agent imports (`frida-java-bridge`, `frida-objc-bridge`).
 * We keep one such project under `os.tmpdir()/frida-mobile-mcp/compiler-project` and
 * populate its `node_modules` in the cheapest way available:
 *
 *   1. symlink (or copy, when symlinks are not permitted) the packages from this package's own
 *      `node_modules` when they are present (they are devDependencies, so a dev checkout has them);
 *   2. otherwise fall back to `frida.PackageManager().install(...)`, which downloads them from
 *      the npm registry — this path needs network access the first time it runs.
 *
 * `@types/frida-gum` is optional: the Compiler bundles its own Gum typings, so Frida globals
 * (`send`, `Process`, `NativePointer`, ...) type-check without it; it is linked when available.
 *
 * Build results are cached in memory by sha256(source + platform + typeCheck + language) and
 * builds are serialised through a simple promise queue so concurrent tool calls never run two
 * Compiler instances against the same project directory at once.
 */
import frida from 'frida';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { log } from '../helpers/logger.js';
import { ScriptError } from '../helpers/errors.js';

export type CompilerTypeCheck = 'full' | 'none';
export type CompilerLanguage = 'auto' | 'ts' | 'js';

export interface CompileOptions {
  /** Target platform; part of the cache key and reported in logs. */
  platform: string;
  /** Display name used in diagnostics instead of the hashed temp file (e.g. 'inline', 'agent.ts'). */
  name?: string;
  /** Defaults to 'none' for compileEsmAgent and 'full' for getCompilerDiagnostics. */
  typeCheck?: CompilerTypeCheck;
  /**
   * Which TypeScript loader to use. 'ts' type-checks strictly (implicit any is an error), 'js'
   * only syntax-checks. 'auto' sniffs the source for TypeScript syntax. Irrelevant when
   * typeCheck is 'none' (esbuild strips types either way), where 'ts' is always used.
   */
  language?: CompilerLanguage;
}

export interface CompilerDiagnostic {
  severity: 'error' | 'warning' | 'message' | 'suggestion';
  message: string;
  file: string | null;
  /** 1-based, null when the diagnostic has no location. */
  line: number | null;
  /** 1-based, null when the diagnostic has no location. */
  column: number | null;
  /** TypeScript diagnostic code; -1 for esbuild (syntax) errors. */
  code: number | null;
}

export interface CompilerDiagnosticsResult {
  ok: boolean;
  diagnostics: CompilerDiagnostic[];
}

interface BuildOutcome {
  bundle: string | null;
  diagnostics: CompilerDiagnostic[];
  error: string | null;
  durationMs: number;
}

interface DependencySpec {
  name: string;
  /** npm spec used by the PackageManager fallback. */
  spec: string;
  required: boolean;
}

const PROJECT_PACKAGE_JSON = {
  name: 'frida-mobile-mcp-compiler-project',
  version: '0.0.0',
  private: true,
  type: 'module',
};

const DEPENDENCIES: readonly DependencySpec[] = [
  { name: 'frida-java-bridge', spec: 'frida-java-bridge@7', required: true },
  { name: 'frida-objc-bridge', spec: 'frida-objc-bridge@8', required: true },
  { name: '@types/frida-gum', spec: '@types/frida-gum', required: false },
];

const MAX_CACHED_BUNDLES = 32;
/** The Compiler reports esbuild (parse) errors with this code; TypeScript codes are positive. */
const ESBUILD_DIAGNOSTIC_CODE = -1;

const TS_SYNTAX_PATTERNS: readonly RegExp[] = [
  /^\s*(export\s+)?(declare\s+)?(interface|type|enum|namespace|abstract\s+class)\s+[A-Za-z_$][\w$]*/m,
  /\bimport\s+type\b/,
  /\bexport\s+type\b/,
  /\b(let|const|var)\s+[A-Za-z_$][\w$]*\s*:\s*[A-Za-z_$][\w$.<>[\]|&]*\s*=/,
  /\)\s*:\s*[A-Za-z_$][\w$.<>[\]|&]*\s*(=>|\{)/,
  /\bas\s+(const|[A-Z][\w$.<>[\]]*)\b/,
  /\b(private|protected|public|readonly)\s+[A-Za-z_$][\w$]*\s*[:;=(]/,
];

// ---------------------------------------------------------------------------
// Project directory
// ---------------------------------------------------------------------------

/** `FRIDA_MCP_COMPILER_PROJECT_DIR` overrides the location (tests, read-only temp dirs). */
export function getCompilerProjectDir(): string {
  const override = process.env.FRIDA_MCP_COMPILER_PROJECT_DIR;
  if (override) return override;
  return path.join(os.tmpdir(), 'frida-mobile-mcp', 'compiler-project');
}

function agentsDir(): string {
  return path.join(getCompilerProjectDir(), 'agents');
}

function ownPackageRoot(): string {
  // Both src/agent (vitest) and dist/agent (compiled) are two levels below the package root.
  return fileURLToPath(new URL('../../', import.meta.url));
}

/** Locate a dependency on this machine without touching the network. */
function findLocalPackage(name: string): string | null {
  const candidate = path.join(ownPackageRoot(), 'node_modules', name);
  if (existsSync(path.join(candidate, 'package.json'))) return candidate;
  try {
    const require = createRequire(import.meta.url);
    return path.dirname(require.resolve(`${name}/package.json`));
  } catch {
    return null;
  }
}

function isInstalled(projectRoot: string, name: string): boolean {
  return existsSync(path.join(projectRoot, 'node_modules', name, 'package.json'));
}

function copyPackage(target: string, sourceDir: string): void {
  cpSync(sourceDir, target, { recursive: true, dereference: true });
}

function symlinkPackage(target: string, sourceDir: string): void {
  symlinkSync(sourceDir, target, 'junction');
}

/**
 * Put the package into the project's `node_modules`: a copy on Windows, a symlink elsewhere
 * (falling back to a copy when symlinks are not permitted). Exported as a test hook.
 */
export function linkPackage(
  projectRoot: string,
  name: string,
  sourceDir: string,
  platform: NodeJS.Platform = process.platform
): void {
  const target = path.join(projectRoot, 'node_modules', name);
  mkdirSync(path.dirname(target), { recursive: true });
  removeIfPresent(target);
  if (platform === 'win32') {
    // frida-core's TypeScript host cannot read through junctions, see frida/frida-compile#104.
    copyPackage(target, sourceDir);
    return;
  }
  try {
    symlinkPackage(target, sourceDir);
  } catch (err) {
    log('debug', `Symlink for ${name} failed (${String(err)}); copying instead`);
    copyPackage(target, sourceDir);
  }
}

function installedVersion(dir: string): string | null {
  try {
    const parsed = JSON.parse(readFileSync(path.join(dir, 'package.json'), 'utf8')) as { version?: unknown };
    return typeof parsed.version === 'string' ? parsed.version : null;
  } catch {
    return null;
  }
}

/** True when the package is missing or its version differs from the local source. Exported as a test hook. */
export function needsRefresh(projectRoot: string, name: string, sourceDir: string): boolean {
  const installedDir = path.join(projectRoot, 'node_modules', name);
  if (!isInstalled(projectRoot, name)) return true;
  return installedVersion(installedDir) !== installedVersion(sourceDir);
}

function removeIfPresent(target: string): void {
  try {
    const stat = lstatSync(target);
    if (stat.isSymbolicLink()) unlinkSync(target);
    else rmSync(target, { recursive: true, force: true });
  } catch {
    /* nothing to remove */
  }
}

async function installFromRegistry(projectRoot: string, deps: DependencySpec[]): Promise<void> {
  const specs = deps.map((d) => d.spec);
  log('info', `Installing compiler dependencies from the npm registry (network required): ${specs.join(', ')}`);
  const manager = new frida.PackageManager();
  const options: frida.PackageInstallOptions = { projectRoot, specs, role: frida.PackageRole.Runtime };
  await manager.install(options);
}

async function populateDependencies(projectRoot: string): Promise<void> {
  const missing: DependencySpec[] = [];
  for (const dep of DEPENDENCIES) {
    const local = findLocalPackage(dep.name);
    if (local) {
      if (needsRefresh(projectRoot, dep.name, local)) linkPackage(projectRoot, dep.name, local);
    } else if (!isInstalled(projectRoot, dep.name)) {
      missing.push(dep);
    }
  }
  if (missing.some((dep) => dep.required)) {
    await installFromRegistry(projectRoot, missing);
    const stillMissing = missing.filter((dep) => dep.required && !isInstalled(projectRoot, dep.name));
    if (stillMissing.length > 0) {
      throw new Error(`Could not install ${stillMissing.map((d) => d.name).join(', ')} into ${projectRoot}`);
    }
  } else if (missing.length > 0) {
    log('debug', `Optional compiler dependencies not found locally, skipped: ${missing.map((d) => d.name).join(', ')}`);
  }
}

let projectReady: Promise<string> | null = null;
let projectReadyFor: string | null = null;

/** Create (once per process) the cached project directory and return its path. */
export function ensureCompilerProject(): Promise<string> {
  const projectRoot = getCompilerProjectDir();
  if (projectReady && projectReadyFor === projectRoot) return projectReady;

  projectReadyFor = projectRoot;
  projectReady = (async () => {
    mkdirSync(path.join(projectRoot, 'node_modules'), { recursive: true });
    mkdirSync(path.join(projectRoot, 'agents'), { recursive: true });
    const packageJson = path.join(projectRoot, 'package.json');
    if (!existsSync(packageJson)) {
      writeFileSync(packageJson, JSON.stringify(PROJECT_PACKAGE_JSON, null, 2) + '\n');
    }
    await populateDependencies(projectRoot);
    return projectRoot;
  })();
  projectReady.catch(() => {
    // Let the next caller retry instead of caching a failed setup.
    projectReady = null;
    projectReadyFor = null;
  });
  return projectReady;
}

// ---------------------------------------------------------------------------
// Language sniffing and hashing
// ---------------------------------------------------------------------------

export function looksLikeTypeScript(source: string): boolean {
  return TS_SYNTAX_PATTERNS.some((pattern) => pattern.test(source));
}

function resolveLanguage(source: string, options: CompileOptions, typeCheck: CompilerTypeCheck): 'ts' | 'js' {
  if (typeCheck === 'none') return 'ts';
  const language = options.language ?? 'auto';
  if (language !== 'auto') return language;
  return looksLikeTypeScript(source) ? 'ts' : 'js';
}

function hashSource(source: string, platform: string, typeCheck: CompilerTypeCheck, language: 'ts' | 'js'): string {
  return createHash('sha256').update(`${platform}\0${typeCheck}\0${language}\0${source}`).digest('hex');
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

function toNumber(value: unknown): number | null {
  if (typeof value === 'bigint') return Number(value);
  if (typeof value === 'number') return value;
  return null;
}

function toSeverity(category: unknown): CompilerDiagnostic['severity'] {
  switch (category) {
    case 'warning':
    case 'message':
    case 'suggestion':
      return category;
    default:
      return 'error';
  }
}

/** Convert one raw Compiler diagnostic (0-based bigint positions) into the public shape. */
function normalizeDiagnostic(raw: unknown, displayName: string | undefined, tempFile: string): CompilerDiagnostic {
  if (typeof raw !== 'object' || raw === null) {
    return { severity: 'error', message: String(raw), file: null, line: null, column: null, code: null };
  }
  const diagnostic = raw as Record<string, unknown>;
  const code = toNumber(diagnostic.code);
  const location = (diagnostic.file ?? null) as Record<string, unknown> | null;
  const line = location ? toNumber(location.line) : null;
  const column = location ? toNumber(location.character) : null;
  let file = location && typeof location.path === 'string' ? location.path : null;
  // path.basename handles both separators on win32; POSIX frida only emits '/'.
  if (file && displayName && path.basename(file) === tempFile) file = displayName;
  // TypeScript diagnostics carry 0-based lines; esbuild (syntax) diagnostics, marked by code -1,
  // already carry 1-based lines. Columns are 0-based in both.
  const lineOffset = code === ESBUILD_DIAGNOSTIC_CODE ? 0 : 1;
  return {
    severity: toSeverity(diagnostic.category),
    message: String(diagnostic.text ?? diagnostic.message ?? ''),
    file,
    line: line === null ? null : line + lineOffset,
    column: column === null ? null : column + 1,
    code,
  };
}

function collectDiagnostics(payload: unknown, displayName: string | undefined, tempFile: string): CompilerDiagnostic[] {
  const items = Array.isArray(payload) ? payload : [payload];
  return items.map((item) => normalizeDiagnostic(item, displayName, tempFile));
}

export function formatDiagnostics(diagnostics: CompilerDiagnostic[]): string {
  return diagnostics
    .map((d) => {
      const where = d.file ? `${d.file}${d.line !== null ? `:${d.line}` : ''}${d.column !== null ? `:${d.column}` : ''}: ` : '';
      return `${where}${d.severity}: ${d.message}`;
    })
    .join('\n');
}

// ---------------------------------------------------------------------------
// Build queue and cache
// ---------------------------------------------------------------------------

let buildQueue: Promise<unknown> = Promise.resolve();

/** Serialise builds: the Compiler shares one project directory, so never run two at once. */
function withBuildLock<T>(task: () => Promise<T>): Promise<T> {
  const run = buildQueue.then(task, task);
  buildQueue = run.catch(() => undefined);
  return run;
}

const bundleCache = new Map<string, string>();

function rememberBundle(key: string, bundle: string): void {
  if (bundleCache.size >= MAX_CACHED_BUNDLES) {
    const oldest = bundleCache.keys().next().value;
    if (oldest !== undefined) bundleCache.delete(oldest);
  }
  bundleCache.set(key, bundle);
}

/** Test hook. */
export function clearCompilerCache(): void {
  bundleCache.clear();
}

async function runBuild(
  source: string,
  options: CompileOptions,
  typeCheck: CompilerTypeCheck,
  language: 'ts' | 'js',
  key: string
): Promise<BuildOutcome> {
  const projectRoot = await ensureCompilerProject();
  const tempFile = `${key.slice(0, 16)}.${language}`;
  const entrypoint = path.join(agentsDir(), tempFile);
  writeFileSync(entrypoint, source);

  const diagnostics: CompilerDiagnostic[] = [];
  const compiler = new frida.Compiler();
  const onDiagnostics = (payload: unknown) => {
    diagnostics.push(...collectDiagnostics(payload, options.name, tempFile));
  };
  compiler.diagnostics.connect(onDiagnostics);

  const startedAt = Date.now();
  try {
    // BuildOptions is typed `{}` in frida-node's d.ts but the runtime accepts CompilerOptions.
    const buildOptions: frida.CompilerOptions = {
      projectRoot,
      bundleFormat: frida.BundleFormat.Esm,
      outputFormat: frida.OutputFormat.Unescaped,
      typeCheck: typeCheck === 'full' ? frida.TypeCheckMode.Full : frida.TypeCheckMode.None,
      sourceMaps: frida.SourceMaps.Omitted,
      compression: frida.JsCompression.None,
      platform: frida.JsPlatform.Gum,
    };
    const bundle = await compiler.build(entrypoint, buildOptions as frida.BuildOptions);
    return { bundle, diagnostics, error: null, durationMs: Date.now() - startedAt };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { bundle: null, diagnostics, error: message, durationMs: Date.now() - startedAt };
  } finally {
    compiler.diagnostics.disconnect(onDiagnostics);
    removeIfPresent(entrypoint);
  }
}

function hasErrors(diagnostics: CompilerDiagnostic[]): boolean {
  return diagnostics.some((d) => d.severity === 'error');
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Compile an ES module agent into a frida-compile bundle (starts with the 📦 marker) that can
 * be handed straight to `createAgentScript` / `session.createScript`. Throws `ScriptError`
 * with the compiler diagnostics when the build fails.
 */
export async function compileEsmAgent(source: string, options: CompileOptions): Promise<string> {
  const typeCheck = options.typeCheck ?? 'none';
  const language = resolveLanguage(source, options, typeCheck);
  const key = hashSource(source, options.platform, typeCheck, language);
  const cached = bundleCache.get(key);
  if (cached !== undefined) return cached;

  const outcome = await withBuildLock(() => runBuild(source, options, typeCheck, language, key));
  if (outcome.bundle === null || hasErrors(outcome.diagnostics)) {
    const details = outcome.diagnostics.length > 0 ? formatDiagnostics(outcome.diagnostics) : outcome.error ?? 'unknown error';
    throw new ScriptError(`ES module compilation failed:\n${details}`, source);
  }
  log('debug', `Compiled ESM agent ${options.name ?? key.slice(0, 16)} for ${options.platform} in ${outcome.durationMs}ms`);
  rememberBundle(key, outcome.bundle);
  return outcome.bundle;
}

/**
 * Type-check (by default) an ES module agent and return the compiler diagnostics without
 * throwing on compile errors. Infrastructure failures (project setup, network) still throw.
 */
export async function getCompilerDiagnostics(
  source: string,
  options: CompileOptions
): Promise<CompilerDiagnosticsResult> {
  const typeCheck = options.typeCheck ?? 'full';
  const language = resolveLanguage(source, options, typeCheck);
  const key = hashSource(source, options.platform, typeCheck, language);
  if (bundleCache.has(key)) return { ok: true, diagnostics: [] };

  const outcome = await withBuildLock(() => runBuild(source, options, typeCheck, language, key));
  const diagnostics = [...outcome.diagnostics];
  if (outcome.bundle === null && !hasErrors(diagnostics)) {
    diagnostics.push({
      severity: 'error',
      message: outcome.error ?? 'Compilation failed',
      file: options.name ?? null,
      line: null,
      column: null,
      code: null,
    });
  }
  const ok = outcome.bundle !== null && !hasErrors(diagnostics);
  if (ok) rememberBundle(key, outcome.bundle as string);
  return { ok, diagnostics };
}
