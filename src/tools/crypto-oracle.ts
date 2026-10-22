import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../helpers/errors.js';
import { resolveInstrumentationTarget } from './hook.js';
import { responseFormatSchema } from '../constants.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
import { createAgentScript } from '../agent/script-factory.js';
import { attachScriptSinks } from '../helpers/script-sink.js';
import type { BridgeName } from '../agent/bridges.js';
import { getState } from '../state.js';
import { buildTemplateBody } from '../scripts/template-body.js';

const NO_BRIDGES: BridgeName[] = [];
/** How long to wait after load() for the agent's init_complete summary if it didn't arrive during load. */
const INIT_SUMMARY_WAIT_MS = 2000;

/**
 * Default regex for "anything that smells like crypto" — the same broad net discover_crypto
 * uses, so monitor_crypto catches app code that rolls its own cipher (rc4demo's `Rc4Client`)
 * as well as the usual `javax.crypto` callers. Compiled INSIDE the agent (never spliced).
 */
const DEFAULT_CRYPTO_PATTERN =
  'crypt|cipher|rc4|aes|des|blowfish|chacha|salsa|rsa|hmac|sha|md5|digest|encode|decode|secret|\\bkey\\b|sign|hash|base64';

/** True when a target string looks like an app package id (dotted, non-numeric), not a PID. */
function looksLikePackage(target: string): boolean {
  return /^[A-Za-z][\w]*(\.[A-Za-z][\w]*)+$/.test(target);
}

/** The `init_complete` summary the preamble's reportSummary() emits during load. */
interface InitSummary {
  status: 'init_complete';
  hooks_attempted?: number;
  hooks_installed?: number;
  hooks_skipped?: number;
}

export function registerCryptoOracleTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'monitor_crypto',
    {
      title: 'Monitor Crypto (Wide-Net Oracle)',
      description:
        'Cast a wide net over cryptography instead of hooking one method at a time. In a single persistent script it discovers and hooks ALL likely crypto sinks at once — app-owned Java classes whose name matches a crypto pattern (every overload of every declared method), plus the framework sinks that almost every app funnels through: javax.crypto Cipher (doFinal/init/getInstance), Mac, MessageDigest and SecretKeySpec on Android; CommonCrypto (CCCrypt, CCCryptorCreate, CC_SHA256, CC_MD5) on iOS; and native OpenSSL/BoringSSL (EVP_*Update, RC4, AES_set_encrypt_key). Every call dumps its byte[]/String key, input and output as hex, so you capture the key and plaintext WITHOUT knowing the exact method. This is persistent instrumentation (like hook_method): it returns immediately, then you drive the app and read the captured events with get_messages. Use when the goal is "grab the key / see the plaintext" and discover_crypto gave too many candidates to hook by hand.',
      inputSchema: z.object({
        target: z.string().optional().describe('App bundle ID, process name, or PID. Optional when session_id is given.'),
        session_id: z.string().optional().describe('Reuse an existing session (from explore_app/get_status) instead of re-attaching by target.'),
        device: z.string().optional().describe('Device ID'),
        pattern: z
          .string()
          .optional()
          .describe(`Regex matched (case-insensitive, compiled in-agent) against app-owned class names to decide which to hook. Defaults to a broad crypto pattern: ${DEFAULT_CRYPTO_PATTERN}`),
        max_targets: z.number().optional().default(40).describe('Max app-owned crypto classes to hook (framework sinks are always hooked on top). Default: 40.'),
        log_data: z
          .boolean()
          .optional()
          .default(true)
          .describe('Dump plaintext/ciphertext buffers as hex (default: true). When false, only key material and metadata (sizes, algorithm, direction) are logged — keys are always captured.'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async ({ target, session_id, device, pattern, max_targets, log_data, response_format }) => {
      try {
        const state = getState();
        const resolved = resolveInstrumentationTarget(target, session_id);
        const { sessionEntry } = await getOrCreateSession(deviceManager, {
          target: resolved.target,
          device,
          sessionId: resolved.sessionId,
        });
        const platform = sessionEntry.platform;
        const effectivePattern = pattern ?? DEFAULT_CRYPTO_PATTERN;
        const maxTargets = max_targets ?? 40;
        const logData = log_data ?? true;

        const script = await createAgentScript(sessionEntry.session, {
          sessionEntry,
          source: CRYPTO_ORACLE_BODY,
          platform,
          name: 'monitor_crypto:' + platform,
          kind: 'generated',
          options: {
            pattern: effectivePattern,
            maxTargets,
            logData,
            // Lets the agent classify app-owned classes precisely (name starts with the package)
            // rather than guessing from a framework-prefix blocklist; null when the target is a PID.
            appPackage: looksLikePackage(resolved.target) ? resolved.target : null,
            platform,
          },
          // Generic (non-android/ios) targets have no bridge; Android/iOS get their default.
          ...(platform === 'android' || platform === 'ios' ? {} : { bridges: NO_BRIDGES }),
        });

        const scriptId = state.generateId();
        const oracleId = state.generateId();

        // Persistent: the script stays loaded so the user can drive the app and read events later.
        sessionEntry.scripts.set(scriptId, {
          id: scriptId,
          script,
          messages: [],
          name: 'monitor_crypto',
          persistent: true,
          createdAt: Date.now(),
        });

        // The agent's reportSummary() init_complete arrives from reportSummary() — usually during
        // load, but frida-node may deliver the message in a later turn, so we await it (bounded)
        // rather than reading `summary` synchronously after load() and risking null hook counts.
        let summary: InitSummary | null = null;
        let onInit: () => void = () => {};
        const initSeen = new Promise<void>((resolve) => {
          onInit = resolve;
        });
        attachScriptSinks(script, sessionEntry.id, scriptId, {
          onSend: (payload, data) => {
            const p = payload as { status?: string } | null;
            if (p && p.status === 'init_complete') {
              summary = payload as InitSummary;
              state.addMessageToScript(sessionEntry.id, scriptId, { timestamp: Date.now(), type: 'crypto_status', payload, data: data ?? null });
              onInit();
              return;
            }
            state.addMessageToScript(sessionEntry.id, scriptId, { timestamp: Date.now(), type: 'crypto_event', payload, data: data ?? null });
          },
        });

        try {
          await script.load();
        } catch (loadErr) {
          sessionEntry.scripts.delete(scriptId);
          throw loadErr;
        }

        // Give the init_complete message a brief window to arrive if it did not land during load().
        if (summary === null) {
          await Promise.race([initSeen, new Promise<void>((resolve) => setTimeout(resolve, INIT_SUMMARY_WAIT_MS))]);
        }
        const installed = summary as InitSummary | null;
        return formatToolResponse(
          buildResult(
            {
              session_id: sessionEntry.id,
              script_id: scriptId,
              oracle_id: oracleId,
              hooks_attempted: installed?.hooks_attempted ?? null,
              hooks_installed: installed?.hooks_installed ?? null,
              hooks_skipped: installed?.hooks_skipped ?? null,
            },
            [
              { tool: 'trigger_and_wait', args: { session_id: sessionEntry.id }, reason: 'Drive the app so a crypto sink fires' },
              { tool: 'get_messages', args: { session_id: sessionEntry.id }, reason: 'Read captured crypto events' },
            ],
          ),
          response_format,
        );
      } catch (err) {
        if (err instanceof FridaMcpError) return formatToolResponse(err.toErrorResponse(), response_format);
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    },
  );
}

/**
 * Self-contained persistent oracle agent. On load it discovers and hooks, in-agent, both the
 * app-owned crypto classes (regex compiled from options, never spliced) and the always-present
 * framework sinks. Each hook emits `send({ api, class?, method?, direction, key_hex?, data_hex?,
 * ret_hex?, text? })`; the trailing reportSummary('crypto_oracle') reports the hook counts.
 *
 * Frida 17 only: Java/ObjC bridges via the preamble stubs, native reads via NativePointer#readByteArray,
 * exports via findExport()/hookNative(). No removed statics (Module.findExportByName, Memory.readX, *Sync).
 */
export const CRYPTO_ORACLE_BODY = buildTemplateBody('crypto_oracle', `
  var o = templateOptions();
  var logData = o.logData !== false;                                 // default true
  var maxTargets = typeof o.maxTargets === 'number' ? o.maxTargets : 40;

  // Compile the user pattern IN-agent so no value is ever spliced into code (discover_crypto pattern).
  var re = null;
  try { re = new RegExp(o.pattern, 'i'); } catch (e) { re = null; }

  // App-owned iff the name starts with the known package; without one, "not a framework package".
  var FRAMEWORK_PREFIXES = ['java.', 'javax.', 'android.', 'androidx.', 'kotlin.', 'kotlinx.',
    'dalvik.', 'libcore.', 'com.android.', 'com.google.android.', 'sun.', 'jdk.', 'org.json.',
    'org.apache.', 'org.w3c.', 'org.xml.', 'org.intellij.', 'org.jetbrains.'];
  function isAppOwned(name) {
    var pkg = o.appPackage;
    if (pkg) return name.indexOf(pkg) === 0;
    for (var i = 0; i < FRAMEWORK_PREFIXES.length; i++) {
      if (name.indexOf(FRAMEWORK_PREFIXES[i]) === 0) return false;
    }
    return true;
  }

  // --- byte[]/String helpers --------------------------------------------------
  function looksLikeByteArray(v) {
    return v !== null && typeof v === 'object' && typeof v.length === 'number' && (v.length === 0 || typeof v[0] === 'number');
  }
  // Java byte[] holds signed bytes; normalise to 0..255 before hex. Bounded so a huge buffer
  // never floods the message channel.
  function hexBytes(arr, max) {
    try {
      var n = Math.min(arr.length, max || 256);
      var out = '';
      for (var i = 0; i < n; i++) { var b = (arr[i] + 256) % 256; out += ('0' + b.toString(16)).slice(-2); }
      return out;
    } catch (e) { return null; }
  }
  // Native reads use the preamble toHex(buffer, maxBytes) over a bounded readByteArray slice.
  function readHex(ptr, len, max) {
    try {
      if (!ptr || ptr.isNull() || len <= 0) return null;
      return toHex(ptr.readByteArray(Math.min(len, max || 256)), max || 256);
    } catch (e) { return null; }
  }

  // For a generic (unknown-shape) Java method: the first byte[] arg is treated as data, each
  // String arg as text. A known key sink instead routes its byte[] arg to key_hex (kept even
  // when log_data is off, since the key is the prize).
  function describeJavaArgs(info, args, keySink) {
    for (var i = 0; i < args.length; i++) {
      var a = args[i];
      if (a === null || a === undefined) continue;
      if (looksLikeByteArray(a)) {
        if (keySink) {
          if (!info.key_hex) { info.key_hex = hexBytes(a, 64); info.key_size = a.length; }
        } else if (info.data_size === undefined) {
          info.data_size = a.length;
          if (logData) info.data_hex = hexBytes(a, 256);
        }
      } else if (typeof a === 'string') {
        if (!info.text) info.text = a.slice(0, 200);
      }
    }
  }
  function describeJavaRet(info, ret) {
    if (ret === null || ret === undefined) return;
    if (looksLikeByteArray(ret)) {
      info.ret_size = ret.length;
      if (logData) info.ret_hex = hexBytes(ret, 256);
    } else if (typeof ret === 'string' && !info.text) {
      info.text = ret.slice(0, 200);
    }
  }

  // --- Java: app-owned crypto classes (the wide net) --------------------------
  function hookAppClassMethods(className) {
    installHook(className, function () {
      var cls = Java.use(className);
      var declared = cls.class.getDeclaredMethods();
      var seen = {};
      for (var i = 0; i < declared.length; i++) seen[declared[i].getName()] = true;
      Object.keys(seen).forEach(function (mName) {
        var m = cls[mName];
        if (!m || !m.overloads) return;
        m.overloads.forEach(function (ov) {
          // Each overload is its own hook so reportSummary reflects true coverage.
          installHook(className + '.' + mName, function () {
            ov.implementation = function () {
              var info = { api: 'java', class: className, method: mName, direction: 'call' };
              describeJavaArgs(info, arguments, false);
              var ret = ov.apply(this, arguments);
              describeJavaRet(info, ret);
              send(info);
              return ret;
            };
          });
        });
      });
    });
  }

  // --- Java: framework sinks (always) -----------------------------------------
  function hookJavaFramework() {
    // Cipher.init carries the key as a Key object (getEncoded()), so it gets a dedicated hook;
    // doFinal/update carry raw byte[] and go through the generic describe path.
    installHook('javax.crypto.Cipher', function () {
      var Cipher = Java.use('javax.crypto.Cipher');

      installHook('Cipher.init', function () {
        Cipher.init.overloads.forEach(function (ov) {
          ov.implementation = function () {
            // opmode: ENCRYPT_MODE=1, DECRYPT_MODE=2, WRAP=3, UNWRAP=4.
            var mode = arguments[0];
            var info = { api: 'javax.crypto.Cipher', class: 'javax.crypto.Cipher', method: 'init', direction: (mode === 1 || mode === 3) ? 'encrypt' : 'decrypt' };
            try {
              var key = arguments[1];
              if (key && key.getEncoded) {
                var enc = key.getEncoded();
                if (enc) { info.key_hex = hexBytes(enc, 64); info.key_size = enc.length; }
              }
            } catch (e) {}
            try { info.algorithm = this.getAlgorithm(); } catch (e) {}
            send(info);
            return ov.apply(this, arguments);
          };
        });
      });

      ['doFinal', 'update'].forEach(function (mName) {
        installHook('Cipher.' + mName, function () {
          Cipher[mName].overloads.forEach(function (ov) {
            ov.implementation = function () {
              var info = { api: 'javax.crypto.Cipher', class: 'javax.crypto.Cipher', method: mName, direction: 'crypt' };
              try { info.algorithm = this.getAlgorithm(); } catch (e) {}
              describeJavaArgs(info, arguments, false);
              var ret = ov.apply(this, arguments);
              describeJavaRet(info, ret);
              send(info);
              return ret;
            };
          });
        });
      });

      installHook('Cipher.getInstance', function () {
        Cipher.getInstance.overloads.forEach(function (ov) {
          ov.implementation = function () {
            send({ api: 'javax.crypto.Cipher', class: 'javax.crypto.Cipher', method: 'getInstance', direction: 'config', text: String(arguments[0]) });
            return ov.apply(this, arguments);
          };
        });
      });
    });

    // SecretKeySpec($init) — the raw symmetric key material; always captured.
    installHook('javax.crypto.spec.SecretKeySpec', function () {
      var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
      SecretKeySpec.$init.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var info = { api: 'javax.crypto.spec.SecretKeySpec', class: 'javax.crypto.spec.SecretKeySpec', method: '$init', direction: 'key' };
          describeJavaArgs(info, arguments, true);
          info.text = String(arguments[arguments.length - 1]);
          send(info);
          return ov.apply(this, arguments);
        };
      });
    });

    // Mac (HMAC) doFinal.
    installHook('javax.crypto.Mac', function () {
      var Mac = Java.use('javax.crypto.Mac');
      Mac.doFinal.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var info = { api: 'javax.crypto.Mac', class: 'javax.crypto.Mac', method: 'doFinal', direction: 'mac' };
          try { info.algorithm = this.getAlgorithm(); } catch (e) {}
          describeJavaArgs(info, arguments, false);
          var ret = ov.apply(this, arguments);
          describeJavaRet(info, ret);
          send(info);
          return ret;
        };
      });
    });

    // MessageDigest.digest.
    installHook('java.security.MessageDigest', function () {
      var MessageDigest = Java.use('java.security.MessageDigest');
      MessageDigest.digest.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var info = { api: 'java.security.MessageDigest', class: 'java.security.MessageDigest', method: 'digest', direction: 'hash' };
          try { info.algorithm = this.getAlgorithm(); } catch (e) {}
          describeJavaArgs(info, arguments, false);
          var ret = ov.apply(this, arguments);
          describeJavaRet(info, ret);
          send(info);
          return ret;
        };
      });
    });
  }

  if (Java.available) {
    Java.perform(function () {
      hookJavaFramework();
      if (re) {
        var count = 0;
        Java.enumerateLoadedClasses({
          onMatch: function (name) {
            if (count >= maxTargets) return;
            if (name.charAt(0) === '[') return;          // skip array descriptors ("[Lfoo;")
            if (!re.test(name)) return;
            if (!isAppOwned(name)) return;                 // framework classes are covered above
            count++;
            hookAppClassMethods(name);
          },
          onComplete: function () {}
        });
      }
    });
  }

  // --- iOS CommonCrypto --------------------------------------------------------
  if (ObjC.available) {
    var ccOps = ['encrypt', 'decrypt'];
    var ccAlgos = ['AES128', 'DES', '3DES', 'CAST', 'RC4', 'RC2', 'Blowfish'];

    // CCCrypt(op, alg, options, key, keyLength, iv, dataIn, dataInLength, dataOut, ...).
    hookNative('libcommonCrypto.dylib', 'CCCrypt', {
      onEnter: function (args) {
        var info = { api: 'CCCrypt', direction: ccOps[args[0].toInt32()] || 'unknown', algorithm: ccAlgos[args[1].toInt32()] || 'unknown' };
        var keyLen = args[4].toInt32();
        info.key_size = keyLen;
        info.key_hex = readHex(args[3], keyLen, 64);       // key always
        if (logData) info.data_hex = readHex(args[6], args[7].toInt32(), 256);
        this.info = info;
      },
      onLeave: function (retval) { this.info.result = retval.toInt32() === 0 ? 'success' : 'error'; send(this.info); }
    });

    // CCCryptorCreate(op, alg, options, key, keyLength, iv, cryptorRef).
    hookNative('libcommonCrypto.dylib', 'CCCryptorCreate', {
      onEnter: function (args) {
        try {
          var keyLen = args[4].toInt32();
          this.info = { api: 'CCCryptorCreate', direction: ccOps[args[0].toInt32()] || 'unknown', algorithm: ccAlgos[args[1].toInt32()] || 'unknown', key_size: keyLen, key_hex: readHex(args[3], keyLen, 64) };
        } catch (e) { this.info = null; }
      },
      onLeave: function (retval) { if (this.info) { this.info.result = retval.toInt32() === 0 ? 'success' : 'error'; send(this.info); } }
    });

    // CC_SHA256(data, len, md) / CC_MD5(data, len, md).
    ['CC_SHA256', 'CC_MD5'].forEach(function (name) {
      hookNative('libcommonCrypto.dylib', name, {
        onEnter: function (args) {
          var len = 0; try { len = args[1].toInt32(); } catch (e) {}
          var info = { api: name, direction: 'hash', data_size: len };
          if (logData) info.data_hex = readHex(args[0], len, 256);
          send(info);
        }
      });
    });
  }

  // --- Native OpenSSL / BoringSSL (searched across all modules) ----------------
  // EVP_EncryptUpdate(ctx, out, outl, in, inl) / EVP_DecryptUpdate(...): in=args[3], inl=args[4].
  ['EVP_EncryptUpdate', 'EVP_DecryptUpdate'].forEach(function (name) {
    hookNative(null, name, {
      onEnter: function (args) {
        var len = 0; try { len = args[4].toInt32(); } catch (e) {}
        var info = { api: name, direction: name.indexOf('Encrypt') !== -1 ? 'encrypt' : 'decrypt', data_size: len };
        if (logData) info.data_hex = readHex(args[3], len, 256);
        send(info);
      }
    });
  });

  // RC4(key, len, indata, outdata): the data is args[2], length args[1] (key is the scheduled struct).
  hookNative(null, 'RC4', {
    onEnter: function (args) {
      var len = 0; try { len = args[1].toInt32(); } catch (e) {}
      var info = { api: 'RC4', direction: 'crypt', data_size: len };
      if (logData) info.data_hex = readHex(args[2], len, 256);
      send(info);
    }
  });

  // AES_set_encrypt_key(userKey, bits, key): the raw key is args[0], length bits/8. Key always captured.
  hookNative(null, 'AES_set_encrypt_key', {
    onEnter: function (args) {
      var bits = 0; try { bits = args[1].toInt32(); } catch (e) {}
      send({ api: 'AES_set_encrypt_key', direction: 'key', key_size: bits / 8, key_hex: readHex(args[0], bits / 8, 64) });
    }
  });
`);
