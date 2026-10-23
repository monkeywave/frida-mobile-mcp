import type { ScriptTemplate } from '../types.js';
import { buildTemplateBody } from './template-body.js';
import { EVASION_SCRUB_SNIPPET } from './evasion-scrub.js';

/**
 * anti_frida_evasion — observe, and optionally neutralize, the native primitives RASP uses to
 * detect Frida: reads of /proc/self/{maps,status,task}, `strstr` for "frida"-family needles,
 * thread-name probes, dlopen of the agent, and (iOS) dyld image-name scans.
 *
 * Default mode is `report`: it only *reports* each probe and never modifies the target. `spoof`
 * additionally scrubs the matched signatures from the data the target reads back (equal-length
 * in-place rewrites so buffer sizes never change) and makes `strstr` miss. `spoof` is a memory
 * write path, so the tool gates it on `memoryWriteEnabled`.
 */
const BODY = buildTemplateBody('anti_frida_evasion', `
  ${EVASION_SCRUB_SNIPPET}

  var o = templateOptions();
  var ev = installEvasion(o);
  var mode = ev.mode;
  // 'read' and 'strstr' are extremely hot on ART; hooking them globally can destabilize a busy
  // process, so they are opt-in. The default set scrubs at the far-less-hot fgets/fread layer,
  // which covers the common fopen()+fgets() way RASP parses /proc/self/maps.
  var aggressive = o.aggressive === true;

  // --- open / openat: report sensitive /proc opens and remember their fds ---
  hookNative(null, 'open', {
    onEnter: function(args) { try { this.path = args[0].readUtf8String(); } catch (e) { this.path = null; } },
    onLeave: function(retval) {
      try { if (ev.isProcSensitive(this.path)) ev.report('open', this.path); ev.markFd(retval.toInt32(), this.path); } catch (e) {}
    }
  });
  hookNative(null, 'openat', {
    onEnter: function(args) { try { this.path = args[1].readUtf8String(); } catch (e) { this.path = null; } },
    onLeave: function(retval) {
      try { if (ev.isProcSensitive(this.path)) ev.report('openat', this.path); ev.markFd(retval.toInt32(), this.path); } catch (e) {}
    }
  });
  hookNative(null, 'close', {
    onEnter: function(args) { try { ev.unmarkFd(args[0].toInt32()); } catch (e) {} }
  });

  // --- fopen: report sensitive /proc opens (FILE* reads are scrubbed at fgets/fread) ---
  hookNative(null, 'fopen', {
    onEnter: function(args) { try { this.path = args[0].readUtf8String(); } catch (e) { this.path = null; } },
    onLeave: function() { try { if (ev.isProcSensitive(this.path)) ev.report('fopen', this.path); } catch (e) {} }
  });

  // --- fgets / fread: line- and block-oriented reads; scan (and in spoof mode scrub) the
  // returned data. Shared wiring so it stays identical to watch_tamper's scrub path. ---
  ev.installBufferScrubHooks(mode);

  if (aggressive) {
    // --- read: scan/scrub bytes returned from a sensitive fd (raw open()+read() maps reads) ---
    hookNative(null, 'read', {
      onEnter: function(args) { this.fd = args[0].toInt32(); this.buf = args[1]; },
      onLeave: function(retval) {
        try { var n = retval.toInt32(); if (n > 0 && ev.isSensitive(this.fd)) ev.handleProcRead(this.fd, this.buf, n, mode); } catch (e) {}
      }
    });

    // --- strstr / strcasestr: RASP greps its own maps/strings for "frida" etc. ---
    ['strstr', 'strcasestr'].forEach(function(name) {
      hookNative(null, name, {
        onEnter: function(args) { try { this.needle = args[1].readUtf8String(); } catch (e) { this.needle = null; } },
        onLeave: function(retval) {
          try { var hit = ev.matchSignature(this.needle); if (hit) { ev.report(name, 'needle=' + hit); if (mode === 'spoof') retval.replace(ptr(0)); } } catch (e) {}
        }
      });
    });
  }

  // --- pthread_getname_np: thread-name probe (gum-js-loop, gmain, pool-frida, ...) ---
  hookNative(null, 'pthread_getname_np', {
    onEnter: function(args) { this.buf = args[1]; this.len = args[2] ? args[2].toInt32() : 0; },
    onLeave: function(retval) {
      try {
        var name = this.buf.readUtf8String();
        var hit = ev.matchSignature(name);
        if (!hit) return;
        ev.report('pthread_getname_np', 'thread=' + hit);
        if (mode === 'spoof') ev.overwriteCString(this.buf, this.len, 'Thread-1');
      } catch (e) {}
    }
  });

  // Note: we deliberately do NOT hook dlopen here — intercepting it interferes with the Android
  // loader and can terminate the target. Agent/gadget library loads are reported by watch_loads.

  // --- iOS: dyld image-name scan for FridaGadget ---
  if (ObjC.available) {
    hookNative(null, '_dyld_get_image_name', {
      onEnter: function(args) { this.index = args[0].toInt32(); },
      onLeave: function(retval) {
        try {
          if (retval.isNull()) return;
          var name = retval.readUtf8String();
          var hit = ev.matchSignature(name);
          if (!hit) return;
          ev.report('_dyld_get_image_name', 'image=' + hit);
          if (mode === 'spoof') retval.replace(Memory.allocUtf8String('/usr/lib/libSystem.B.dylib'));
        } catch (e) {}
      }
    });
  }

  send({ status: 'evasion_armed', mode: mode, aggressive: aggressive, signatures: ev.signatureCount });
`);

export const antiFridaEvasionTemplate: ScriptTemplate = {
  name: 'anti_frida_evasion',
  description: 'Observe (report) or neutralize (spoof) the native primitives RASP uses to detect Frida: /proc/self/{maps,status,task} reads, strstr "frida" greps, thread-name and dlopen probes, and iOS dyld image scans. Default mode=report is observe-only; mode=spoof scrubs signatures and requires memoryWriteEnabled.',
  platforms: ['android', 'ios'],
  category: 'detection',
  riskTier: 3,
  options: {
    mode: { type: 'string', description: "'report' (default, observe-only, no memory writes) or 'spoof' (scrub matched signatures; requires memoryWriteEnabled).", default: 'report' },
    aggressive: { type: 'boolean', description: 'Also hook the very hot read() and strstr()/strcasestr() (covers raw open()+read() maps reads and strstr greps). Can destabilize busy processes; off by default. The stable default set scrubs at fopen/fgets/fread.', default: false },
    signatures: { type: 'array', description: 'Override the default Frida signature strings matched (case-insensitive) in maps/thread names/needles.' },
  },
  requiresMemoryWrite: (options) =>
    options.mode === 'spoof'
      ? 'anti_frida_evasion with mode="spoof" writes to target memory (it scrubs matched Frida signatures from /proc reads, thread names and iOS dyld image names, and zeroes TracerPid). Enable it with memoryWriteEnabled: true in config or FRIDA_MCP_MEMORY_WRITE=1, or run with mode="report" (observe-only).'
      : null,
  generate: () => BODY,
};
