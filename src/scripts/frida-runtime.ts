/**
 * Shared Frida runtime helpers injected as a preamble into generated scripts.
 * Provides consistent hook installation, error reporting, and summary stats.
 *
 * Cached as a module-level constant to avoid recreating on every script generation.
 */

const FRIDA_RUNTIME = `
// === Frida Runtime Helpers ===
var _hookStats = { attempted: 0, installed: 0, skipped: 0 };

function hookNative(lib, name, callbacks) {
  _hookStats.attempted++;
  try {
    var addr = Module.findExportByName(lib, name);
    if (addr) {
      Interceptor.attach(addr, callbacks);
      _hookStats.installed++;
    } else {
      _hookStats.skipped++;
    }
  } catch(e) {
    _hookStats.skipped++;
  }
}

function reportSummary(scriptName) {
  send({ status: 'init_complete', script: scriptName, hooks_attempted: _hookStats.attempted, hooks_installed: _hookStats.installed, hooks_skipped: _hookStats.skipped });
}
// === End Frida Runtime ===
`;

export function getFridaRuntime(): string {
  return FRIDA_RUNTIME;
}
