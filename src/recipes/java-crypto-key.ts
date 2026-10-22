import type { Recipe } from './types.js';
import { JAVA_CLASS_LOOKUP_SNIPPET } from '../agent/java-class-lookup.js';

/**
 * Recipe: capture key material from an *app-defined* crypto class.
 *
 * The motivating case (com.example.rc4demo) implements RC4 in a custom class
 * (Rc4Client/Rc4Managed/Rc4Native) rather than through javax.crypto, so the usual
 * Cipher/SecretKeySpec hooks never fire. This recipe hooks a class + method named in
 * options and dumps every byte[]/String argument (and the return value) as hex + UTF-8,
 * which is where a hand-rolled cipher's key/IV/plaintext show up.
 */
const CUSTOM_JAVA_CRYPTO_SOURCE = `${JAVA_CLASS_LOOKUP_SNIPPET}
(function () {
  var o = __FRIDA_MCP__.options || {};
  var className = o.class_name;
  var methodName = o.method_name; // optional: omit to hook every declared method
  var maxBytes = typeof o.max_bytes === 'number' ? o.max_bytes : 256;

  if (typeof Java === 'undefined' || !Java.available) {
    send({ type: 'error', error: 'Java runtime not available' });
    return;
  }
  if (!className) {
    send({ type: 'error', error: 'class_name option is required' });
    return;
  }

  function describeArg(value) {
    if (value === null || value === undefined) return { kind: 'null' };
    try {
      // byte[] comes through as a JS array of signed bytes.
      if (Array.isArray(value) || (value.length !== undefined && typeof value !== 'string' && value.$className === undefined)) {
        var bytes = value;
        var hex = '';
        var ascii = '';
        var n = Math.min(bytes.length, maxBytes);
        for (var i = 0; i < n; i++) {
          var b = (bytes[i] + 256) % 256;
          hex += ('0' + b.toString(16)).slice(-2);
          ascii += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.';
        }
        return { kind: 'bytes', length: bytes.length, hex: hex, ascii: ascii };
      }
    } catch (e) { /* fall through to string */ }
    try { return { kind: 'value', value: String(value) }; } catch (e) { return { kind: 'opaque' }; }
  }

  Java.perform(function () {
    var cls = useInAnyLoader(className);
    if (cls === null) {
      send({ type: 'error', error: 'class not loaded in any loader: ' + className + ' (try watch_loads, then re-run)' });
      return;
    }

    var methods = [];
    if (methodName) {
      methods.push(methodName);
    } else {
      // Enumerate declared method names via reflection.
      try {
        var declared = cls.class.getDeclaredMethods();
        var seen = {};
        for (var i = 0; i < declared.length; i++) {
          var nm = declared[i].getName();
          if (!seen[nm]) { seen[nm] = true; methods.push(nm); }
        }
      } catch (e) {
        send({ type: 'error', error: 'could not enumerate methods: ' + e.message });
        return;
      }
    }

    var installed = 0;
    methods.forEach(function (nm) {
      var handle = cls[nm];
      if (!handle || !handle.overloads) return;
      handle.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var args = [];
          for (var i = 0; i < arguments.length; i++) args.push(describeArg(arguments[i]));
          var retval = overload.apply(this, arguments);
          send({
            type: 'crypto_call',
            class: className,
            method: nm,
            args: args,
            retval: describeArg(retval)
          });
          return retval;
        };
        installed++;
      });
    });
    send({ type: 'installed', class: className, methods: methods, overloads: installed });
  });
})();
`;

export const customJavaCryptoRecipe: Recipe = {
  name: 'custom-java-crypto-key',
  title: 'Capture key material from a custom Java crypto class',
  purpose:
    'Dump byte[]/String arguments and return values of an app-defined crypto class (e.g. a hand-rolled RC4/AES helper) that never touches javax.crypto, to recover keys, IVs and plaintext.',
  platforms: ['android'],
  tags: ['crypto', 'key', 'rc4', 'aes', 'custom', 'java', 'decrypt', 'rc4demo'],
  options: [
    { name: 'class_name', description: 'Fully-qualified class to hook.', required: true, example: 'com.example.rc4demo.Rc4Client' },
    { name: 'method_name', description: 'Single method to hook; omit to hook every declared method.', required: false, example: 'encrypt' },
    { name: 'max_bytes', description: 'Max bytes dumped per byte[] argument (default 256).', required: false, example: 256 },
  ],
  source: CUSTOM_JAVA_CRYPTO_SOURCE,
  usage:
    'Run with execute_script (classic). First confirm the class name with describe_class or search_classes_and_methods; if the class is lazily loaded, use watch_loads first. Each call is reported as a crypto_call message with hex+ascii of every byte[] arg and the return value.',
};

/**
 * Recipe: capture key material going through the standard javax.crypto API.
 *
 * Hooks SecretKeySpec/IvParameterSpec constructors and Cipher.init so the raw key and IV
 * bytes are captured at the moment they enter the JCE, regardless of the algorithm.
 */
const JAVAX_CRYPTO_SOURCE = `
(function () {
  var o = __FRIDA_MCP__.options || {};
  var maxBytes = typeof o.max_bytes === 'number' ? o.max_bytes : 256;

  if (typeof Java === 'undefined' || !Java.available) {
    send({ type: 'error', error: 'Java runtime not available' });
    return;
  }

  function hex(bytes) {
    var out = '';
    var n = Math.min(bytes.length, maxBytes);
    for (var i = 0; i < n; i++) out += ('0' + ((bytes[i] + 256) % 256).toString(16)).slice(-2);
    return out;
  }

  Java.perform(function () {
    try {
      var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
      SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (keyBytes, algo) {
        send({ type: 'key', api: 'SecretKeySpec', algorithm: String(algo), key_hex: hex(keyBytes), key_len: keyBytes.length });
        return this.$init(keyBytes, algo);
      };
    } catch (e) { send({ type: 'skipped', api: 'SecretKeySpec', reason: e.message }); }

    try {
      var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
      IvParameterSpec.$init.overload('[B').implementation = function (iv) {
        send({ type: 'iv', api: 'IvParameterSpec', iv_hex: hex(iv), iv_len: iv.length });
        return this.$init(iv);
      };
    } catch (e) { send({ type: 'skipped', api: 'IvParameterSpec', reason: e.message }); }

    try {
      var Cipher = Java.use('javax.crypto.Cipher');
      Cipher.init.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var info = { type: 'cipher_init', mode: arguments.length ? arguments[0] : null };
          try { info.transformation = this.getAlgorithm(); } catch (e) {}
          send(info);
          return overload.apply(this, arguments);
        };
      });
    } catch (e) { send({ type: 'skipped', api: 'Cipher.init', reason: e.message }); }

    send({ type: 'installed', api: 'javax.crypto' });
  });
})();
`;

export const javaxCryptoRecipe: Recipe = {
  name: 'javax-crypto-key',
  title: 'Capture key/IV from the standard javax.crypto API',
  purpose: 'Record raw key and IV bytes as they enter SecretKeySpec/IvParameterSpec and when Cipher.init runs.',
  platforms: ['android'],
  tags: ['crypto', 'key', 'iv', 'aes', 'cipher', 'javax', 'jce', 'java'],
  options: [
    { name: 'max_bytes', description: 'Max key/IV bytes dumped (default 256).', required: false, example: 256 },
  ],
  source: JAVAX_CRYPTO_SOURCE,
  usage:
    'Run with execute_script (classic). Fires when the app uses the standard JCE. If keys never appear, the app likely rolls its own crypto — use the custom-java-crypto-key recipe with the app class instead.',
};
