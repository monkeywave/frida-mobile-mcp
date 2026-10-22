import type { Recipe } from './types.js';

/**
 * Recipe: observe Android Keystore KEY USAGE.
 *
 * Hardware-backed Keystore keys never leave the TEE/StrongBox, so you *cannot* extract the
 * raw key material with Frida. What you CAN do is watch how the app uses the keystore: which
 * aliases it loads, what algorithms/purposes it sets up, and when it encrypts, signs or
 * verifies. This recipe hooks the common entry points and reports each as a usage event, so
 * you learn the key's lifecycle and role without ever seeing its bytes.
 */
const ANDROID_KEYSTORE_USAGE_SOURCE = `
(function () {
  var o = __FRIDA_MCP__.options || {};
  var filter = typeof o.filter === 'string' && o.filter.length ? o.filter : null;

  if (typeof Java === 'undefined' || !Java.available) {
    send({ type: 'error', error: 'Java runtime not available' });
    return;
  }

  // Only alias-bearing events honour the filter; algorithm-only events always report.
  function aliasMatches(alias) {
    if (!filter) return true;
    try { return String(alias).indexOf(filter) !== -1; } catch (e) { return true; }
  }

  function report(info) {
    if (info.alias !== undefined && info.alias !== null && !aliasMatches(info.alias)) return;
    info.type = 'keystore_usage';
    send(info);
  }

  Java.perform(function () {
    var installed = [];

    // java.security.KeyStore.getKey(alias, password) -> loads a key handle by alias.
    try {
      var KeyStore = Java.use('java.security.KeyStore');
      KeyStore.getKey.overload('java.lang.String', '[C').implementation = function (alias, pw) {
        report({ api: 'KeyStore.getKey', alias: String(alias), note: 'app loaded a key handle by alias (material stays in the keystore)' });
        return this.getKey(alias, pw);
      };
      installed.push('KeyStore.getKey');
    } catch (e) { send({ type: 'skipped', api: 'KeyStore.getKey', reason: e.message }); }

    // javax.crypto.Cipher.init(...) -> encryption/decryption; log algorithm + whether a Key arg is present.
    try {
      var Cipher = Java.use('javax.crypto.Cipher');
      Cipher.init.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var algorithm = null;
          try { algorithm = String(this.getAlgorithm()); } catch (e) {}
          var keyPresent = arguments.length >= 2 && arguments[1] !== null && arguments[1] !== undefined;
          report({ api: 'Cipher.init', algorithm: algorithm, key_present: keyPresent, note: 'cipher initialised' + (keyPresent ? ' with a Key argument' : '') });
          return overload.apply(this, arguments);
        };
      });
      installed.push('Cipher.init');
    } catch (e) { send({ type: 'skipped', api: 'Cipher.init', reason: e.message }); }

    // java.security.KeyPairGenerator.initialize(...) -> asymmetric key generation setup.
    try {
      var KeyPairGenerator = Java.use('java.security.KeyPairGenerator');
      KeyPairGenerator.initialize.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var algorithm = null;
          try { algorithm = String(this.getAlgorithm()); } catch (e) {}
          report({ api: 'KeyPairGenerator.initialize', algorithm: algorithm, note: 'asymmetric key pair generation configured' });
          return overload.apply(this, arguments);
        };
      });
      installed.push('KeyPairGenerator.initialize');
    } catch (e) { send({ type: 'skipped', api: 'KeyPairGenerator.initialize', reason: e.message }); }

    // javax.crypto.KeyGenerator.init(...) -> symmetric key generation setup.
    try {
      var KeyGenerator = Java.use('javax.crypto.KeyGenerator');
      KeyGenerator.init.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var algorithm = null;
          try { algorithm = String(this.getAlgorithm()); } catch (e) {}
          report({ api: 'KeyGenerator.init', algorithm: algorithm, note: 'symmetric key generation configured' });
          return overload.apply(this, arguments);
        };
      });
      installed.push('KeyGenerator.init');
    } catch (e) { send({ type: 'skipped', api: 'KeyGenerator.init', reason: e.message }); }

    // android.security.keystore.KeyGenParameterSpec$Builder(alias, purposes) -> the spec that
    // asks the Keystore to mint a hardware-backed key; log the alias and the purpose bitmask.
    try {
      var Builder = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
      Builder.$init.overload('java.lang.String', 'int').implementation = function (alias, purposes) {
        report({ api: 'KeyGenParameterSpec.Builder', alias: String(alias), purposes: purposes, note: 'keystore key spec created (purposes is a KeyProperties.PURPOSE_* bitmask)' });
        return this.$init(alias, purposes);
      };
      installed.push('KeyGenParameterSpec$Builder');
    } catch (e) { send({ type: 'skipped', api: 'KeyGenParameterSpec$Builder', reason: e.message }); }

    // java.security.Signature.initSign / initVerify -> the key is being used to sign or verify.
    try {
      var Signature = Java.use('java.security.Signature');
      Signature.initSign.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var algorithm = null;
          try { algorithm = String(this.getAlgorithm()); } catch (e) {}
          report({ api: 'Signature.initSign', algorithm: algorithm, note: 'private key used for signing' });
          return overload.apply(this, arguments);
        };
      });
      Signature.initVerify.overloads.forEach(function (overload) {
        overload.implementation = function () {
          var algorithm = null;
          try { algorithm = String(this.getAlgorithm()); } catch (e) {}
          report({ api: 'Signature.initVerify', algorithm: algorithm, note: 'public key used for verification' });
          return overload.apply(this, arguments);
        };
      });
      installed.push('Signature.initSign/initVerify');
    } catch (e) { send({ type: 'skipped', api: 'Signature', reason: e.message }); }

    send({ type: 'installed', api: 'android-keystore-usage', hooks: installed });
  });
})();
`;

export const androidKeystoreUsageRecipe: Recipe = {
  name: 'android-keystore-usage',
  title: 'Observe Android Keystore key usage',
  purpose:
    'Trace how an app uses the Android Keystore (loads aliases, configures key generation, encrypts, signs and verifies) to learn each key\'s lifecycle and role.',
  platforms: ['android'],
  tags: ['keystore', 'android', 'key', 'usage', 'hsm', 'credentials'],
  options: [
    {
      name: 'filter',
      description: 'Optional substring; alias-bearing events are only reported when the alias contains it. Algorithm-only events always report.',
      required: false,
      example: 'user_',
    },
  ],
  source: ANDROID_KEYSTORE_USAGE_SOURCE,
  usage:
    'Run with execute_script (classic) on Android. IMPORTANT: hardware-backed Keystore keys live in the TEE/StrongBox and CANNOT be extracted with Frida — this recipe only observes their USE, never their bytes. Each hook fires as a keystore_usage message (api, alias?, algorithm?, note); exercise the app flow that touches the key, then read the events to reconstruct the key\'s lifecycle. Set the filter option to narrow to one alias.',
};
