/**
 * Agent preamble: the runtime helpers every generated Frida script can rely on.
 *
 * The preamble is plain, classic JavaScript (no imports) that runs inside the target
 * process before the template body. It provides:
 *   - `__FRIDA_MCP__`  : { name, platform, options } — template options as a JSON literal,
 *                        so no user-controlled value is ever spliced into code position.
 *   - `Java` / `ObjC`  : `{ available: false }` stubs for bridges that were not injected, so
 *                        `Java.available` checks never throw a ReferenceError.
 *   - findExport()     : Frida 17 export lookup (replaces the removed static Module.findExportByName).
 *   - hookNative()     : attach with bookkeeping; errors are recorded, not swallowed. An optional
 *                        4th argument carries Frida 17.10 Interceptor instrumentation options
 *                        ({ scenario, relocation, scratchRegister, redirectSpaceHint }), applied
 *                        as Interceptor.attach({ target: addr, ...options }, callbacks).
 *   - objcClassNames() : flattens ObjC.enumerateLoadedClassesSync() ({ modulePath: [names] }).
 *   - javaPerform()    : Promise-returning Java.perform for rpc exports (frida awaits promises).
 *   - reportSummary()  : sends the `init_complete` message with hook statistics.
 */
import type { BridgeName } from './bridges.js';

export interface PreambleContext {
  name: string;
  platform: string;
  options: Record<string, unknown>;
  injectedBridges: readonly BridgeName[];
}

const HELPERS = `
var _hookStats = { attempted: 0, installed: 0, skipped: 0, errors: [] };

function findExport(lib, name) {
  try {
    if (lib === null || lib === undefined || lib === '') {
      return Module.findGlobalExportByName(name);
    }
    var mod = Process.findModuleByName(lib);
    if (mod === null) return null;
    return mod.findExportByName(name);
  } catch (e) {
    return null;
  }
}

function hookNative(lib, name, callbacks, options) {
  _hookStats.attempted++;
  try {
    var addr = findExport(lib, name);
    if (addr) {
      Interceptor.attach(options ? Object.assign({}, options, { target: addr }) : addr, callbacks);
      _hookStats.installed++;
      return true;
    }
    _hookStats.skipped++;
    return false;
  } catch (e) {
    _hookStats.skipped++;
    _hookStats.errors.push({ target: (lib || '*') + '!' + name, error: String(e && e.message ? e.message : e) });
    return false;
  }
}

function recordHookError(target, e) {
  _hookStats.errors.push({ target: String(target), error: String(e && e.message ? e.message : e) });
}

function objcClassNames() {
  if (typeof ObjC === 'undefined' || !ObjC.available) return [];
  var byModule = ObjC.enumerateLoadedClassesSync();
  var names = [];
  for (var modulePath in byModule) {
    var list = byModule[modulePath];
    for (var i = 0; i < list.length; i++) names.push(list[i]);
  }
  return names;
}

function javaPerform(fn) {
  return new Promise(function (resolve, reject) {
    if (typeof Java === 'undefined' || !Java.available) {
      reject(new Error('Java runtime not available in this process'));
      return;
    }
    try {
      Java.perform(function () {
        try { resolve(fn()); } catch (e) { reject(e); }
      });
    } catch (e) {
      reject(e);
    }
  });
}

function reportSummary(scriptName) {
  send({
    status: 'init_complete',
    script: scriptName || __FRIDA_MCP__.name,
    hooks_attempted: _hookStats.attempted,
    hooks_installed: _hookStats.installed,
    hooks_skipped: _hookStats.skipped,
    hook_errors: _hookStats.errors.slice(0, 50)
  });
}
`;

function stubFor(global: 'Java' | 'ObjC'): string {
  return `if (typeof ${global} === 'undefined') { Object.defineProperty(globalThis, '${global}', { value: { available: false }, writable: true, configurable: true }); }`;
}

/**
 * Build the preamble. The JSON literal is emitted with JSON.stringify, which is a strict
 * subset of a JS object literal (U+2028/2029 are legal in string literals since ES2019).
 */
export function buildPreamble(ctx: PreambleContext): string {
  const context = JSON.stringify({ name: ctx.name, platform: ctx.platform, options: ctx.options ?? {} });
  const stubs: string[] = [];
  if (!ctx.injectedBridges.includes('java')) stubs.push(stubFor('Java'));
  if (!ctx.injectedBridges.includes('objc')) stubs.push(stubFor('ObjC'));
  return [
    '// === frida-mobile-mcp agent preamble ===',
    `globalThis.__FRIDA_MCP__ = ${context};`,
    ...stubs,
    HELPERS,
    '// === end preamble ===',
  ].join('\n');
}

/** Stub-only preamble section, exported for tests. */
export function buildBridgeStubs(injected: readonly BridgeName[]): string {
  const stubs: string[] = [];
  if (!injected.includes('java')) stubs.push(stubFor('Java'));
  if (!injected.includes('objc')) stubs.push(stubFor('ObjC'));
  return stubs.join('\n');
}
