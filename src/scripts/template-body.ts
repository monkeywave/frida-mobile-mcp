/**
 * Shared composition for prebuilt template bodies.
 *
 * Every template body is a constant classic-JS string that runs after the agent preamble
 * (src/agent/preamble.ts). The preamble provides `__FRIDA_MCP__`, `findExport`, `hookNative`,
 * `recordHookError`, `objcClassNames`, `reportSummary` and `_hookStats`. Templates read their
 * options at runtime from `__FRIDA_MCP__.options`, so no option value is ever spliced into code.
 *
 * `installHook` is the Java/ObjC counterpart of `hookNative`: it wraps a hook installation in
 * try/catch and feeds `_hookStats` so that `reportSummary()` reflects every hook, not only the
 * native ones.
 */

const HOOK_BOOKKEEPING = `
function installHook(target, install, onError) {
  _hookStats.attempted++;
  try {
    install();
    _hookStats.installed++;
    return true;
  } catch (e) {
    _hookStats.skipped++;
    recordHookError(target, e);
    if (onError) { try { onError(e); } catch (ignored) {} }
    return false;
  }
}

function reportSkipped(method) {
  return function (e) {
    send({ status: 'skipped', method: method, reason: String(e && e.message ? e.message : e) });
  };
}

function templateOptions() {
  var ctx = (typeof __FRIDA_MCP__ === 'object' && __FRIDA_MCP__) ? __FRIDA_MCP__ : {};
  return ctx.options || {};
}

// Shared bytes -> lowercase hex formatter for log_data output; bounded to maxBytes (default 256).
function toHex(buffer, maxBytes) {
  var bytes = new Uint8Array(buffer);
  var limit = typeof maxBytes === 'number' ? Math.min(bytes.length, maxBytes) : bytes.length;
  var out = '';
  for (var i = 0; i < limit; i++) out += ('0' + bytes[i].toString(16)).slice(-2);
  return out;
}
`;

/**
 * Wrap a template body in an IIFE with the hook bookkeeping helpers and a trailing
 * `reportSummary(name)` call. The result is a constant string per template.
 */
export function buildTemplateBody(name: string, body: string): string {
  if (!/^[a-z0-9_]+$/.test(name)) {
    throw new Error(`Template name must be a plain identifier, got: ${name}`);
  }
  return [
    '(function() {',
    HOOK_BOOKKEEPING,
    body,
    `reportSummary('${name}');`,
    '})();',
  ].join('\n');
}
