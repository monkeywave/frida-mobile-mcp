import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError, FridaMcpError } from '../helpers/errors.js';
import { resolveInstrumentationTarget } from './hook.js';
import { responseFormatSchema } from '../constants.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
import { createAgentScript } from '../agent/script-factory.js';
import type { BridgeName } from '../agent/bridges.js';
import { RESOLVE_TARGET_SNIPPET } from '../agent/address.js';
import { callRpcWithTimeout } from '../helpers/rpc-timeout.js';

const NO_BRIDGES: BridgeName[] = [];

/** True when a target string looks like an app package id (dotted, non-numeric), not a PID. */
function looksLikePackage(target: string): boolean {
  return /^[A-Za-z][\w]*(\.[A-Za-z][\w]*)+$/.test(target);
}

/**
 * Default regex for anything that smells like crypto, across Java class names, ObjC class
 * names and native export symbols. Deliberately broad: the point is to find the real
 * implementation without assuming it lives in `javax.crypto` (rc4demo's RC4, for example,
 * is a plain Java `Rc4Client` class, and other apps roll their own or call BoringSSL).
 */
const DEFAULT_CRYPTO_PATTERN = 'crypt|cipher|rc4|aes|des|blowfish|chacha|salsa|rsa|hmac|sha|md5|digest|encode|decode|secret|\\bkey\\b|sign|hash|base64';

/** Known native crypto / TLS symbols worth flagging even when they don't match the regex loosely. */
const KNOWN_NATIVE_SYMBOLS = [
  'EVP_', 'SSL_read', 'SSL_write', 'SSL_get_session', 'CCCrypt', 'CCCryptorCreate',
  'RC4', 'AES_', 'aes_', 'rc4_', 'crypto_', 'mbedtls_', 'wc_',
];

interface JavaClassHit {
  class: string;
  methods?: string[];
  app_owned: boolean;
}
interface NativeSymbolHit {
  module: string;
  symbol: string;
  address: string;
}
interface DiscoverResult {
  java: JavaClassHit[];
  native: NativeSymbolHit[];
  error?: { message: string };
}

export function registerDiscoverTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'discover_crypto',
    {
      title: 'Discover Crypto / Candidate Hook Targets',
      description:
        'Find where an app actually performs cryptography (or any API family), without assuming javax.crypto. In one pass it enumerates: Java/ObjC classes whose name matches a pattern (across all class loaders), and native export symbols matching the pattern or a known crypto/TLS symbol (EVP_*, SSL_read/write, CCCrypt, RC4, AES_, mbedtls_, ...). Returns ranked candidates — app-owned classes first, then framework classes, then native symbols. Native candidates hook as-is ("module!symbol"); Java/ObjC candidates are CLASSES — pass "Class.method" to hook_method (method names are in the `java` list), or trace "Class.*". Use this before guessing a hook when the goal is "capture the key", "trace the cipher", etc.',
      inputSchema: z.object({
        target: z.string().optional().describe('App bundle ID, process name, or PID. Optional when session_id is given.'),
        session_id: z.string().optional().describe('Reuse an existing session (from explore_app/get_status) instead of re-attaching by target.'),
        device: z.string().optional().describe('Device ID'),
        pattern: z.string().optional().describe(`Regex matched (case-insensitive) against class names and native symbols. Defaults to a broad crypto pattern: ${DEFAULT_CRYPTO_PATTERN}`),
        include_methods: z.boolean().optional().default(true).describe('Include method names for matched Java/ObjC classes (default: true).'),
        limit: z.number().optional().default(40).describe('Max hits per category (Java classes, native symbols). Default: 40.'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ target, session_id, device, pattern, include_methods, limit, response_format }) => {
      try {
        const resolved = resolveInstrumentationTarget(target, session_id);
        const { sessionEntry } = await getOrCreateSession(deviceManager, { target: resolved.target, device, sessionId: resolved.sessionId });
        const platform = sessionEntry.platform;
        const effectivePattern = pattern ?? DEFAULT_CRYPTO_PATTERN;
        const maxResults = limit ?? 40;

        const script = await createAgentScript(sessionEntry.session, {
          sessionEntry,
          source: DISCOVER_SOURCE,
          platform,
          name: 'discover_crypto:' + platform,
          kind: 'generated',
          options: {
            pattern: effectivePattern,
            includeMethods: include_methods ?? true,
            maxResults,
            knownNativeSymbols: KNOWN_NATIVE_SYMBOLS,
            // The app package lets the agent classify app-owned classes precisely (name starts
            // with the package) rather than guessing from a framework-prefix blocklist.
            appPackage: looksLikePackage(resolved.target) ? resolved.target : null,
          },
          // Generic (non-android/ios) targets have no bridge; Android/iOS get their default.
          ...(platform === 'android' || platform === 'ios' ? {} : { bridges: NO_BRIDGES }),
        });
        await script.load();
        let discovered: DiscoverResult;
        try {
          discovered = await callRpcWithTimeout(script.exports.discover() as Promise<DiscoverResult>, 'Crypto discovery');
        } finally {
          await script.unload();
        }

        if (discovered.error) {
          throw new FridaMcpError('INVALID_PATTERN', `Invalid pattern regex: ${discovered.error.message}`, [
            { tool: 'discover_crypto', args: { session_id: sessionEntry.id }, reason: 'Retry with a valid regex pattern' },
          ]);
        }

        // Defensive: the agent always returns arrays, but never let a malformed RPC payload crash ranking.
        discovered.java = Array.isArray(discovered.java) ? discovered.java : [];
        discovered.native = Array.isArray(discovered.native) ? discovered.native : [];
        const candidates = rankCandidates(discovered);
        // Build a hook suggestion that actually resolves: a Java class is NOT hookable on its
        // own (hook_method needs Class.method), so for the top Java candidate we point at a
        // concrete method from its discovered method list; native module!symbol is hookable as-is.
        const hookSuggestion = topHookSuggestion(candidates, discovered, sessionEntry.id);
        return formatToolResponse(
          buildResult(
            {
              session_id: sessionEntry.id,
              platform,
              pattern: effectivePattern,
              java_count: discovered.java.length,
              native_count: discovered.native.length,
              java: discovered.java,
              native: discovered.native,
              // Ranked list — app code first. Native entries hook as-is (module!symbol); Java
              // entries are classes — hook a specific method (see the `java` list) or trace Class.*.
              candidates,
            },
            [
              ...(hookSuggestion ? [hookSuggestion] : []),
              { tool: 'get_status', args: { session_id: sessionEntry.id }, reason: 'After hooking + driving the app, check hook liveness (did it fire?)' },
              { tool: 'mobile_action', args: { action: 'mobile_list_elements_on_screen', session_id: sessionEntry.id }, reason: 'Drive the app to exercise the hooked code' },
            ],
            discovered.java.length === 0 && discovered.native.length === 0
              ? { limitations: ['No matching classes or symbols. Native code may load later — retry after driving the app, or widen the pattern.'] }
              : {},
          ),
          response_format,
        );
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    },
  );
}

interface Candidate {
  kind: 'java' | 'native';
  hook_target: string;
  app_owned?: boolean;
}

/**
 * A valid hook_method suggestion for the top candidate, or null when none is hookable.
 * Native candidates (`module!symbol`) are passed through; a Java candidate is a class, so we
 * pair it with a concrete method from the discovered `java` list (hook_method needs Class.method).
 * When a Java class has no listed methods, we suggest tracing all of them instead of emitting a
 * guaranteed-miss `hook_method` call on the bare class name.
 */
function topHookSuggestion(candidates: Candidate[], d: DiscoverResult, sessionId: string): { tool: string; args: Record<string, unknown>; reason: string } | null {
  const top = candidates[0];
  if (!top) return null;
  if (top.kind === 'native') {
    return { tool: 'hook_method', args: { session_id: sessionId, method: top.hook_target }, reason: `Hook the top candidate (${top.hook_target})` };
  }
  const javaHit = d.java.find((j) => j.class === top.hook_target);
  const method = javaHit?.methods?.[0];
  if (method) {
    const target = `${top.hook_target}.${method}`;
    return { tool: 'hook_method', args: { session_id: sessionId, method: target }, reason: `Hook a method of the top class (${target}); see the \`java\` list for its other methods` };
  }
  return { tool: 'trace_method', args: { session_id: sessionId, pattern: `${top.hook_target}.*` }, reason: `Trace all methods of the top class (${top.hook_target}) to see which run` };
}

/**
 * Rank hits so the AI tries the most likely place first: app-owned classes, then framework
 * classes, then native symbols. Candidates are intentionally lightweight (no method lists —
 * those live in the `java` array) so this flat, ranked list stays compact.
 */
function rankCandidates(d: DiscoverResult): Candidate[] {
  const javaApp = d.java.filter((c) => c.app_owned);
  const javaFramework = d.java.filter((c) => !c.app_owned);
  const toJava = (c: JavaClassHit): Candidate => ({ kind: 'java', hook_target: c.class, app_owned: c.app_owned });
  const toNative = (n: NativeSymbolHit): Candidate => ({ kind: 'native', hook_target: `${n.module}!${n.symbol}` });
  return [...javaApp.map(toJava), ...javaFramework.map(toJava), ...d.native.map(toNative)];
}

/**
 * Combined discovery agent. Runs the Java/ObjC bridge path when available and always scans
 * native module exports. The user pattern is compiled inside the agent (never spliced into
 * code), and class-name framework detection decides `app_owned`.
 */
const DISCOVER_SOURCE = RESOLVE_TARGET_SNIPPET + `
  function compilePattern() {
    try {
      return { re: new RegExp(__FRIDA_MCP__.options.pattern, 'i') };
    } catch (e) {
      return { error: { message: String(e && e.message ? e.message : e) } };
    }
  }

  // When the app package is known, a class is app-owned iff its name starts with that package —
  // precise, and immune to the framework-prefix blocklist missing a package (jdk., libcore., ...).
  // Without it, fall back to "not a known platform/framework package".
  var FRAMEWORK_PREFIXES = ['java.', 'javax.', 'android.', 'androidx.', 'kotlin.', 'kotlinx.',
    'dalvik.', 'libcore.', 'com.android.', 'com.google.android.', 'sun.', 'jdk.', 'org.json.',
    'org.apache.', 'org.w3c.', 'org.xml.', 'org.intellij.', 'org.jetbrains.'];
  function isAppOwned(name) {
    var pkg = __FRIDA_MCP__.options.appPackage;
    if (pkg) return name.indexOf(pkg) === 0;
    for (var i = 0; i < FRAMEWORK_PREFIXES.length; i++) {
      if (name.indexOf(FRAMEWORK_PREFIXES[i]) === 0) return false;
    }
    return true;
  }

  function discoverJava(re, o) {
    return javaPerform(function () {
      // App-owned matches are always kept (never crowded out by the cap); framework matches are
      // bounded. Array descriptors ("[Lfoo;") are skipped. App classes rank first, then cut to max.
      var appMatched = [];
      var fwMatched = [];
      Java.enumerateLoadedClasses({
        onMatch: function (name) {
          if (name.charAt(0) === '[') return;
          if (!re.test(name)) return;
          // Classify once, here; app-owned is kept unbounded, framework is capped.
          if (isAppOwned(name)) appMatched.push({ class: name, app_owned: true });
          else if (fwMatched.length < 500) fwMatched.push({ class: name, app_owned: false });
        },
        onComplete: function () {}
      });
      var hits = appMatched.concat(fwMatched).slice(0, o.maxResults);
      if (o.includeMethods) {
        for (var i = 0; i < hits.length; i++) {
          try {
            var cls = Java.use(hits[i].class);
            var methods = cls.class.getDeclaredMethods().map(function (m) { return m.getName(); });
            hits[i].methods = methods.filter(function (v, idx, a) { return a.indexOf(v) === idx; }).slice(0, 25);
          } catch (e) { hits[i].methods = []; }
        }
      }
      return hits;
    });
  }

  function discoverObjc(re, o) {
    var hits = [];
    var names = objcClassNames();
    for (var i = 0; i < names.length && hits.length < o.maxResults; i++) {
      if (!re.test(names[i])) continue;
      var entry = { class: names[i], app_owned: true };
      if (o.includeMethods) {
        try { entry.methods = ObjC.classes[names[i]].$ownMethods || []; } catch (e) { entry.methods = []; }
      }
      hits.push(entry);
    }
    return hits;
  }

  function discoverNative(re, known, max) {
    var hits = [];
    function matches(sym) {
      if (re.test(sym)) return true;
      for (var k = 0; k < known.length; k++) { if (sym.indexOf(known[k]) !== -1) return true; }
      return false;
    }
    var modules = Process.enumerateModules();
    for (var m = 0; m < modules.length && hits.length < max; m++) {
      var mod = modules[m];
      var exps;
      try { exps = mod.enumerateExports(); } catch (e) { continue; }
      for (var e = 0; e < exps.length && hits.length < max; e++) {
        if (exps[e].type !== 'function') continue;
        if (matches(exps[e].name)) {
          // Reuse the shared module+0xoff notation (RESOLVE_TARGET_SNIPPET) instead of hand-rolling it.
          var d = describeAddress(exps[e].address);
          hits.push({ module: mod.name, symbol: exps[e].name, address: d.rva !== null ? d.rva : d.address });
        }
      }
    }
    return hits;
  }

  rpc.exports.discover = function () {
    var o = __FRIDA_MCP__.options;
    var compiled = compilePattern();
    if (compiled.error) return { java: [], native: [], error: compiled.error };
    var re = compiled.re;

    // Native scan is synchronous; the Java scan runs under javaPerform (a Promise), so when
    // Java is present we await it before returning (frida resolves a Promise returned here).
    var nativeHits = discoverNative(re, o.knownNativeSymbols || [], o.maxResults);
    if (typeof Java !== 'undefined' && Java.available) {
      return discoverJava(re, o).then(function (javaHits) {
        return { java: javaHits, native: nativeHits };
      });
    }
    if (typeof ObjC !== 'undefined' && ObjC.available) {
      return { java: discoverObjc(re, o), native: nativeHits };
    }
    return { java: [], native: nativeHits };
  };
`;
