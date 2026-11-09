/**
 * Workaround for frida-java-bridge 7.0.13 with several scripts in one process.
 *
 * Each script has its own bridge instance. On unload, `Script.bindWeak(runtime, ...)` runs
 * `runtime._dispose()`, which (1) reverts the script's method hooks and global ART patches
 * (`ClassFactory._disposeAll`), (2) deletes its global refs (`Env.dispose`) and then, on the next
 * tick, (3) `VM.dispose(vm)` detaches the JS thread from the VM when this instance attached it.
 * Step 3 breaks every sibling script: their bridge instances still cache a JNIEnv for that thread,
 * and their next DeleteGlobalRef aborts the app with "JNI DETECTED ERROR IN APPLICATION: a thread
 * is making JNI calls without being attached".
 *
 * The patch comments out only the `VM.dispose(...)` call inside `_dispose`, so the JS thread stays
 * attached while hooks are still reverted (skipping all of `_dispose` leaves ART methods pointing
 * at freed trampolines and crashes the app on the next call). The JS thread is a Frida-owned
 * thread; ART detaches it on thread exit, so leaving it attached is harmless.
 *
 * Consumers: build/bundle-bridges.mjs (classic bundle, rollup transform on index.js; plain Node,
 * runs before tsc, so it transpiles this file on the fly), the ESM compile path (compiler.ts,
 * patches the project copy of index.js) and the friTap agent (agent-loader.ts, a frida-compile
 * bundle patched in memory via {@link patchJavaBridgeInCompiledBundle}).
 * Keep this module self-contained: no imports, so the build script can load it standalone.
 */

export const JAVA_BRIDGE_PATCH_MARKER = '/* frida-mobile-mcp: JS thread stays attached (multi-script unload) */';
/** `Script.nextTick(() => { VM.dispose(vm); })` in Runtime._dispose; esbuild may rename both identifiers. */
const VM_DISPOSE_CALL_PATTERN = /(Script\.nextTick\(\s*\(\)\s*=>\s*\{\s*)(VM\w*\.dispose\(\s*[\w$]+\s*\);)/;

export type JavaBridgePatchStatus = 'patched' | 'already-patched' | 'pattern-not-found';

export interface JavaBridgePatchResult {
  source: string;
  /** True when the returned source carries the workaround (newly applied or already present). */
  patched: boolean;
  status: JavaBridgePatchStatus;
}

export function isJavaBridgeThreadDetachSkipped(source: string): boolean {
  return source.includes(JAVA_BRIDGE_PATCH_MARKER);
}

/**
 * Comment out the JS-thread detach (`VM.dispose(vm)`) in frida-java-bridge's Runtime._dispose.
 * Works on index.js and on bundles that inline it. Idempotent. Returns the source unchanged
 * with 'pattern-not-found' when upstream changed.
 */
export function skipJavaBridgeThreadDetach(source: string): JavaBridgePatchResult {
  if (isJavaBridgeThreadDetachSkipped(source)) return patchResult(source, 'already-patched');
  if (!VM_DISPOSE_CALL_PATTERN.test(source)) return patchResult(source, 'pattern-not-found');
  const patched = source.replace(VM_DISPOSE_CALL_PATTERN, (_m, head: string, call: string) =>
    `${head}${JAVA_BRIDGE_PATCH_MARKER} /* ${call} */`);
  return patchResult(patched, 'patched');
}

function patchResult(source: string, status: JavaBridgePatchStatus): JavaBridgePatchResult {
  return { source, patched: status !== 'pattern-not-found', status };
}

const BUNDLE_MAGIC = '📦\n';
const BUNDLE_SEPARATOR = '\n✄\n';

/**
 * Apply {@link skipJavaBridgeThreadDetach} to every module of a frida-compile bundle
 * (`📦\n<bytes> <path>\n...✄\n<module>\n✄\n<module>`) and rewrite the byte sizes in the header.
 * Status is 'pattern-not-found' when the bundle cannot be parsed or no module contains the bridge.
 */
export function patchJavaBridgeInCompiledBundle(bundle: string): JavaBridgePatchResult {
  const parsed = parseCompiledBundle(bundle);
  if (!parsed) return patchResult(bundle, 'pattern-not-found');
  const results = parsed.modules.map((m) => skipJavaBridgeThreadDetach(m.contents));
  const status = bundleStatus(results);
  if (status !== 'patched') return patchResult(bundle, status);
  const modules = parsed.modules.map((m, i) => ({ path: m.path, contents: results[i].source }));
  return patchResult(serializeCompiledBundle(modules), status);
}

function bundleStatus(results: JavaBridgePatchResult[]): JavaBridgePatchStatus {
  if (results.some((r) => r.status === 'patched')) return 'patched';
  return results.some((r) => r.status === 'already-patched') ? 'already-patched' : 'pattern-not-found';
}

interface BundleModule { path: string; contents: string }

function parseCompiledBundle(bundle: string): { modules: BundleModule[] } | null {
  if (!bundle.startsWith(BUNDLE_MAGIC)) return null;
  const headerEnd = bundle.indexOf('\n✄\n');
  if (headerEnd < 0) return null;
  const entries = bundle.slice(BUNDLE_MAGIC.length, headerEnd).split('\n').map((line) => /^(\d+) (.+)$/.exec(line));
  if (entries.some((e) => e === null)) return null;
  let body = Buffer.from(bundle.slice(headerEnd + BUNDLE_SEPARATOR.length), 'utf8');
  const modules: BundleModule[] = [];
  for (const [i, entry] of entries.entries()) {
    const size = Number(entry![1]);
    if (body.length < size) return null;
    modules.push({ path: entry![2], contents: body.subarray(0, size).toString('utf8') });
    body = body.subarray(size);
    const separator = i < entries.length - 1 ? BUNDLE_SEPARATOR : '';
    if (body.subarray(0, Buffer.byteLength(separator)).toString('utf8') !== separator) return null;
    body = body.subarray(Buffer.byteLength(separator));
  }
  return body.length === 0 ? { modules } : null;
}

function serializeCompiledBundle(modules: BundleModule[]): string {
  const header = modules.map((m) => `${Buffer.byteLength(m.contents, 'utf8')} ${m.path}\n`).join('');
  return `${BUNDLE_MAGIC}${header}✄\n${modules.map((m) => m.contents).join(BUNDLE_SEPARATOR)}`;
}
