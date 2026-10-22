import type { Recipe } from './types.js';
import { JAVA_CLASS_LOOKUP_SNIPPET } from '../agent/java-class-lookup.js';

/**
 * Recipe: harness a single string-decryptor method.
 *
 * Obfuscated Android apps routinely funnel every protected string through one decryptor
 * method (e.g. a.b("...") that returns the cleartext). Hook that method once and you get a
 * running log of every plaintext the app reveals. This generalises custom-java-crypto-key:
 * point it at the decryptor's class + method, call through, and dump each return value
 * (byte[] returns are rendered as hex).
 */
const STRING_DECRYPTOR_HARNESS_SOURCE = `${JAVA_CLASS_LOOKUP_SNIPPET}
(function () {
  var o = __FRIDA_MCP__.options || {};
  var className = o.class_name;
  var methodName = o.method_name;
  var logArgs = o.log_args === undefined ? true : !!o.log_args;
  var maxBytes = typeof o.max_bytes === 'number' ? o.max_bytes : 256;

  if (typeof Java === 'undefined' || !Java.available) {
    send({ type: 'error', error: 'Java runtime not available' });
    return;
  }
  if (!className) { send({ type: 'error', error: 'class_name option is required' }); return; }
  if (!methodName) { send({ type: 'error', error: 'method_name option is required' }); return; }

  function describe(value) {
    if (value === null || value === undefined) return null;
    try {
      // byte[] arrives as a JS array of signed bytes (no $className, has numeric length).
      if (Array.isArray(value) || (typeof value !== 'string' && value.length !== undefined && value.$className === undefined)) {
        var hex = '';
        var n = Math.min(value.length, maxBytes);
        for (var i = 0; i < n; i++) hex += ('0' + ((value[i] + 256) % 256).toString(16)).slice(-2);
        return '[bytes len=' + value.length + ' hex=' + hex + ']';
      }
    } catch (e) { /* fall through */ }
    try { return String(value); } catch (e) { return '[opaque]'; }
  }

  Java.perform(function () {
    var cls = useInAnyLoader(className);
    if (cls === null) {
      send({ type: 'error', error: 'class not loaded in any loader: ' + className + ' (try watch_loads, then re-run)' });
      return;
    }

    var handle = cls[methodName];
    if (!handle || !handle.overloads) {
      send({ type: 'error', error: 'method not found: ' + className + '.' + methodName });
      return;
    }

    var fqmn = className + '.' + methodName;
    var installed = 0;
    handle.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var ret = overload.apply(this, arguments);
        var msg = { type: 'plaintext', method: fqmn, plaintext: describe(ret) };
        if (logArgs) {
          var args = [];
          for (var i = 0; i < arguments.length; i++) args.push(describe(arguments[i]));
          msg.args = args;
        }
        send(msg);
        return ret;
      };
      installed++;
    });
    send({ type: 'installed', method: fqmn, overloads: installed });
  });
})();
`;

export const stringDecryptorHarnessRecipe: Recipe = {
  name: 'string-decryptor-harness',
  title: 'Dump every plaintext from a string-decryptor method',
  purpose:
    'Hook a single obfuscation decryptor method and log every plaintext it returns (and optionally its arguments), to recover an app\'s deobfuscated strings in one pass.',
  platforms: ['android'],
  tags: ['string', 'decrypt', 'deobfuscate', 'harness', 'java'],
  options: [
    { name: 'class_name', description: 'Fully-qualified class that owns the decryptor method.', required: true, example: 'com.example.app.a' },
    { name: 'method_name', description: 'The decryptor method to hook (all overloads are instrumented).', required: true, example: 'b' },
    { name: 'log_args', description: 'Also report each call\'s arguments (default true).', required: false, example: true },
    { name: 'max_bytes', description: 'Max bytes rendered when an argument/return is a byte[] (default 256).', required: false, example: 256 },
  ],
  source: STRING_DECRYPTOR_HARNESS_SOURCE,
  usage:
    'Run with execute_script (classic) on Android. Find the decryptor first (search_classes_and_methods / describe_class, or a method that takes a token and returns a String); if it is lazily loaded, use watch_loads then re-run. Each invocation is reported as a plaintext message with the return value (byte[] returns shown as hex) and, when log_args is true, the arguments. Set log_args:false to cut noise when only the outputs matter.',
};
