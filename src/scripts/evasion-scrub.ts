/**
 * Shared classic-JS snippet for anti-anti-Frida scrubbing, embedded verbatim into both the
 * `anti_frida_evasion` prebuilt template and the `watch_tamper` tool's agent so there is a single
 * implementation of signature matching and length-preserving in-place scrubbing.
 *
 * It defines one function, `installEvasion(options)`, returning a handle used by the hook
 * closures. It must stay valid classic JavaScript and Frida-17-clean (no removed APIs): buffer
 * writes go through `NativePointer#writeByteArray`, never `Memory.writeX`. It uses only the agent
 * global `send()` from the preamble. Signature matching is manual (no RegExp built from a needle),
 * both to be injection-proof and to avoid a literal `${` inside this template literal.
 */
export const EVASION_SCRUB_SNIPPET = `
function installEvasion(o) {
  var DEFAULT_SIGS = ['frida', 'gum-js-loop', 'gmain', 'gdbus', 'pool-frida', 'linjector', 'frida-agent', 'frida-gadget', 'libgadget', 're.frida.server', ':27042'];
  var raw = (o && Array.isArray(o.signatures) && o.signatures.length) ? o.signatures : DEFAULT_SIGS;
  var sigs = [];
  for (var s = 0; s < raw.length; s++) { var v = String(raw[s]); if (v) sigs.push(v); }
  var sigsLc = sigs.map(function (x) { return x.toLowerCase(); });
  var mode = (o && o.mode === 'spoof') ? 'spoof' : 'report';
  var sensitive = {};
  // Hoisted once: a fresh regex literal per call would allocate on the open/read Interceptor hot path.
  var PROC_RE = /\\/proc\\/(self|\\d+)\\/(maps|status|task)/;
  var TRACERPID_RE = /TracerPid:\\s*[1-9]/;

  function isWs(c) { return c === ' ' || c === '\\t'; }

  function matchSignature(str) {
    if (!str) return null;
    var lc = String(str).toLowerCase();
    for (var i = 0; i < sigsLc.length; i++) { if (sigsLc[i] && lc.indexOf(sigsLc[i]) >= 0) return sigs[i]; }
    return null;
  }

  function report(api, detail) {
    send({ status: 'anti_frida_probe', api: api, detail: detail, action: mode === 'spoof' ? 'scrubbed' : 'observed' });
  }

  function isProcSensitive(path) {
    return !!path && PROC_RE.test(path);
  }
  function markFd(fd, path) { if (fd >= 0 && isProcSensitive(path)) sensitive[fd] = path; }
  function unmarkFd(fd) { if (sensitive[fd]) delete sensitive[fd]; }
  function isSensitive(fd) { return Object.prototype.hasOwnProperty.call(sensitive, fd); }

  // Replace each signature occurrence (case-insensitive) with equal-length 'x', preserving length.
  function scrubSignatures(text) {
    var arr = text.split('');
    var lc = text.toLowerCase();
    for (var s = 0; s < sigsLc.length; s++) {
      var needle = sigsLc[s];
      if (!needle) continue;
      var from = 0;
      while (true) {
        var idx = lc.indexOf(needle, from);
        if (idx < 0) break;
        for (var k = 0; k < needle.length; k++) arr[idx + k] = 'x';
        from = idx + needle.length;
      }
    }
    return arr.join('');
  }

  // Zero out the TracerPid value in /proc/.../status, preserving total length.
  function scrubTracerPid(text) {
    var marker = 'TracerPid:';
    var at = text.indexOf(marker);
    if (at < 0) return text;
    var arr = text.split('');
    var j = at + marker.length;
    while (j < arr.length && isWs(arr[j])) j++;
    var first = true;
    while (j < arr.length && arr[j] >= '0' && arr[j] <= '9') { arr[j] = first ? '0' : ' '; first = false; j++; }
    return arr.join('');
  }

  // ASCII-only byte array for an equal-length in-place rewrite (non-ASCII char -> 'x').
  function asciiBytes(str) {
    var a = [];
    for (var i = 0; i < str.length; i++) { var code = str.charCodeAt(i); a.push(code > 255 ? 120 : code); }
    return a;
  }

  // Core: read a chunk, and if it contains a Frida signature or a live TracerPid, report it
  // and (in spoof mode) rewrite it in place with an equal-length scrub. Only rewrites when a
  // hit is present, so benign buffers are never touched.
  function scrubChunk(buf, n, activeMode, label) {
    var text;
    try { text = buf.readUtf8String(n); } catch (e) { return; }
    var hit = matchSignature(text) || (TRACERPID_RE.test(text) ? 'TracerPid' : null);
    if (!hit) return;
    report(label, hit);
    if (activeMode !== 'spoof') return;
    var scrubbed = scrubTracerPid(scrubSignatures(text));
    if (scrubbed.length !== text.length) return; // never change the byte count
    var bytes = asciiBytes(scrubbed);
    if (bytes.length !== n) return; // only ASCII /proc content is rewritten in place
    try { buf.writeByteArray(bytes); } catch (e) {}
  }

  function handleProcRead(fd, buf, n, activeMode) { scrubChunk(buf, n, activeMode, 'read:' + sensitive[fd]); }

  // Generic buffered-read scrub (fread) with a size cap so a large binary read is skipped cheaply.
  function handleBuffer(buf, n, activeMode, label) { if (n > 0 && n <= 1048576) scrubChunk(buf, n, activeMode, label || 'fread'); }

  function isAscii(str) {
    for (var i = 0; i < str.length; i++) { if (str.charCodeAt(i) > 127) return false; }
    return true;
  }

  function handleLine(buf, size, activeMode) {
    var line;
    try { line = buf.readUtf8String(); } catch (e) { return; }
    var hit = matchSignature(line);
    if (!hit) return;
    report('fgets', hit);
    if (activeMode !== 'spoof') return;
    // Mask only the matched signature in place (equal-length 'x'), preserving the rest of the
    // line, rather than blanking the whole line — less collateral damage to benign /proc content.
    // Only ASCII lines are rewritten, so the JS string length equals the byte length we overwrite.
    if (!isAscii(line)) return;
    var scrubbed = scrubSignatures(line);
    if (scrubbed.length !== line.length) return;
    try { buf.writeByteArray(asciiBytes(scrubbed)); } catch (e) {}
  }

  function overwriteCString(buf, len, replacement) {
    try {
      var bytes = asciiBytes(replacement);
      bytes.push(0);
      if (len && bytes.length > len) return;
      buf.writeByteArray(bytes);
    } catch (e) {}
  }

  // Install the fgets/fread scan-and-scrub hooks (the common fopen()+fgets()/fread() way RASP
  // parses /proc/self/maps). Shared by the anti_frida_evasion template and watch_tamper so the
  // hot-path hook wiring lives in one place. Needs the agent-global hookNative() from the preamble.
  function installBufferScrubHooks(activeMode) {
    hookNative(null, 'fgets', {
      onEnter: function (args) { this.buf = args[0]; this.size = args[1].toInt32(); },
      onLeave: function (retval) { try { if (!retval.isNull()) handleLine(this.buf, this.size, activeMode); } catch (e) {} }
    });
    hookNative(null, 'fread', {
      onEnter: function (args) { this.buf = args[0]; this.size = args[1].toInt32(); },
      onLeave: function (retval) { try { var items = retval.toInt32(); if (items > 0 && this.size > 0) handleBuffer(this.buf, items * this.size, activeMode, 'fread'); } catch (e) {} }
    });
  }

  return {
    mode: mode,
    signatureCount: sigs.length,
    matchSignature: matchSignature,
    report: report,
    isProcSensitive: isProcSensitive,
    markFd: markFd,
    unmarkFd: unmarkFd,
    isSensitive: isSensitive,
    handleProcRead: handleProcRead,
    handleBuffer: handleBuffer,
    handleLine: handleLine,
    overwriteCString: overwriteCString,
    installBufferScrubHooks: installBufferScrubHooks
  };
}
`;
