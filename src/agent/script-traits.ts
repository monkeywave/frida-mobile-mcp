/**
 * Per-script traits recorded when a script is created, keyed by the frida.Script object so every
 * creation path (createAgentScript) tags its scripts without each tool threading a flag through.
 *
 * `usesJavaBridge` matters for teardown order: every script that bundles its own
 * frida-java-bridge and hooks a Java method patches the prologue of the same ART entry routines.
 * Those patches can only be reverted newest-first; unloading an older bridge script before a
 * newer one leaves the newer instance "restoring" bytes that jump into freed code (SIGBUS).
 *
 * Merely carrying the bridge is not enough to create that hazard: a classic script on Android gets
 * the `java` bridge injected by default even when it only uses Interceptor. So the trait is set
 * only when the script also hooks Java methods (or the caller says it does).
 */
import type frida from 'frida';
import type { ComposedAgentSource } from './script-factory.js';

const JAVA_BRIDGE_PACKAGE_MARKER = 'frida-java-bridge';

/**
 * Source-level signs that a script patches ART: replacing a method implementation, registering a
 * Java class, or forcing deoptimization. `(?!=)` keeps `.implementation == x` comparisons out.
 */
const JAVA_METHOD_HOOK_PATTERN = /\.implementation\s*=(?!=)|\bJava\s*\.\s*(?:registerClass|deoptimize\w*)\b/;

const BUNDLE_MAGIC = '📦\n';
const BUNDLE_SEPARATOR = '\n✄\n';

const javaBridgeUsage = new WeakMap<object, boolean>();

/** What the trait needs from the creation options beyond the composed source. */
export interface JavaHookHints {
  /** Original (uncomposed) script source; the composed source also contains the bridge itself. */
  source: string;
  /** 'generated' passthrough bundles are internal agents (friTap) trusted to hook Java. */
  kind?: 'generated' | 'user';
  /** Explicit marker from callers that know whether the script hooks Java methods. */
  hooksJavaMethods?: boolean;
}

/** Whether a script source replaces Java method implementations or otherwise patches ART. */
export function sourceHooksJavaMethods(source: string): boolean {
  return JAVA_METHOD_HOOK_PATTERN.test(source);
}

/**
 * Whether the application modules of a frida-compile bundle (everything outside node_modules,
 * so the embedded bridge's own `.implementation =` code does not count) hook Java methods.
 * Null when the bundle cannot be parsed.
 */
export function bundleAppModulesHookJavaMethods(bundle: string): boolean | null {
  const modules = parseBundleModules(bundle);
  if (!modules) return null;
  return modules.some((m) => !m.path.includes('node_modules/') && sourceHooksJavaMethods(m.contents));
}

function parseBundleModules(bundle: string): Array<{ path: string; contents: string }> | null {
  if (!bundle.startsWith(BUNDLE_MAGIC)) return null;
  const headerEnd = bundle.indexOf(BUNDLE_SEPARATOR);
  if (headerEnd < 0) return null;
  const entries = bundle.slice(BUNDLE_MAGIC.length, headerEnd).split('\n').map((line) => /^(\d+) (.+)$/.exec(line));
  if (entries.some((e) => e === null)) return null;
  let body = Buffer.from(bundle.slice(headerEnd + BUNDLE_SEPARATOR.length), 'utf8');
  const separatorBytes = Buffer.byteLength(BUNDLE_SEPARATOR);
  const modules: Array<{ path: string; contents: string }> = [];
  for (const entry of entries) {
    const size = Number(entry![1]);
    if (body.length < size) return null;
    modules.push({ path: entry![2], contents: body.subarray(0, size).toString('utf8') });
    body = body.subarray(Math.min(body.length, size + separatorBytes));
  }
  return modules;
}

/**
 * Whether a script carries a Java bridge AND hooks Java methods (the newest-first unload hazard).
 *
 * - Classic scripts: the injected `java` bridge plus a Java hook in the original source (or the
 *   caller's explicit `hooksJavaMethods`). Without hints, carrying the bridge is treated as hooking.
 * - Passthrough bundles: must embed frida-java-bridge (explicit `usesJavaBridge`, else the package
 *   name in the source). Generated bundles (friTap's agent) then count as hooking; user bundles
 *   are checked for Java hooks in their non-node_modules modules, staying conservative (true)
 *   when the bundle cannot be parsed.
 */
export function composedSourceUsesJavaBridge(composed: ComposedAgentSource, hints?: JavaHookHints): boolean {
  if (composed.passthrough) return passthroughUsesJavaBridge(composed, hints);
  if (!composed.bridges.includes('java')) return false;
  if (!hints) return true;
  return hints.hooksJavaMethods ?? sourceHooksJavaMethods(hints.source);
}

function passthroughUsesJavaBridge(composed: ComposedAgentSource, hints?: JavaHookHints): boolean {
  const embedsBridge = composed.usesJavaBridge ?? composed.source.includes(JAVA_BRIDGE_PACKAGE_MARKER);
  if (!embedsBridge || !hints) return embedsBridge;
  if (hints.hooksJavaMethods !== undefined) return hints.hooksJavaMethods;
  if (hints.kind === 'generated') return true;
  return bundleAppModulesHookJavaMethods(composed.source) ?? true;
}

export function recordJavaBridgeUsage(script: frida.Script | object, usesJavaBridge: boolean): void {
  javaBridgeUsage.set(script, usesJavaBridge);
}

/** Recorded trait; false for scripts not created through createAgentScript. */
export function scriptUsesJavaBridge(script: frida.Script | object): boolean {
  return javaBridgeUsage.get(script) ?? false;
}
