import type { ScriptTemplate } from '../types.js';
import { getFridaRuntime } from './frida-runtime.js';

export const cryptoMonitorTemplate: ScriptTemplate = {
  name: 'crypto_monitor',
  description: 'Monitor cryptographic API calls. Android: javax.crypto.Cipher, MessageDigest. iOS: CCCrypt, SecKey. Native: EVP_* (OpenSSL).',
  platforms: ['android', 'ios'],
  category: 'crypto',
  riskTier: 1,
  options: {
    log_keys: { type: 'boolean', description: 'Log encryption keys', default: true },
    log_data: { type: 'boolean', description: 'Log plaintext data', default: false },
  },
  generate: (options) => {
    const logKeys = options.log_keys !== false;
    const logData = options.log_data === true;
    return `
    (function() {
      ${getFridaRuntime()}
      if (Java && Java.available) {
        Java.perform(function() {
          // Cipher — single Java.use call shared by doFinal, init, and getInstance hooks
          try {
            var Cipher = Java.use('javax.crypto.Cipher');

            // Cipher.doFinal
            try {
              Cipher.doFinal.overload('[B').implementation = function(input) {
                var result = this.doFinal(input);
                var info = { api: 'Cipher.doFinal', algorithm: this.getAlgorithm(), mode: this.getBlockMode ? this.getBlockMode() : 'unknown' };
                ${logData ? "try { info.input = Array.from(input).map(function(b){return ('0'+((b+256)%256).toString(16)).slice(-2);}).join('').slice(0,200); } catch(e) {}" : ''}
                ${logKeys ? "try { var key = this.getParameters(); if (key) info.params = key.toString(); } catch(e) {}" : ''}
                send(info);
                return result;
              };
            } catch(e) {}

            // Cipher.init — captures key material
            try {
              Cipher.init.overloads.forEach(function(overload) {
                overload.implementation = function() {
                  var info = { api: 'Cipher.init', mode: arguments[0] };
                  try { if (arguments[1]) info.algorithm = arguments[1].getAlgorithm(); } catch(e) {}
                  send(info);
                  return overload.apply(this, arguments);
                };
              });
            } catch(e) {}

            // Cipher.getInstance
            try {
              Cipher.getInstance.overloads.forEach(function(overload) {
                overload.implementation = function() {
                  send({ api: 'Cipher.getInstance', transformation: String(arguments[0]) });
                  return overload.apply(this, arguments);
                };
              });
            } catch(e) {}

            send({ status: 'hooked', api: 'javax.crypto.Cipher' });
          } catch(e) {}

          // MessageDigest
          try {
            var MessageDigest = Java.use('java.security.MessageDigest');
            MessageDigest.digest.overload('[B').implementation = function(input) {
              var result = this.digest(input);
              send({ api: 'MessageDigest.digest', algorithm: this.getAlgorithm(), input_size: input.length });
              return result;
            };
            send({ status: 'hooked', api: 'java.security.MessageDigest' });
          } catch(e) {}

          // SecretKeySpec — raw key material
          try {
            var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
            SecretKeySpec.$init.overloads.forEach(function(overload) {
              overload.implementation = function() {
                var info = { api: 'SecretKeySpec.$init', algorithm: String(arguments[arguments.length - 1]) };
                send(info);
                return overload.apply(this, arguments);
              };
            });
          } catch(e) {}

          // Mac (HMAC)
          try {
            var Mac = Java.use('javax.crypto.Mac');
            Mac.doFinal.overloads.forEach(function(overload) {
              overload.implementation = function() {
                send({ api: 'Mac.doFinal', algorithm: this.getAlgorithm() });
                return overload.apply(this, arguments);
              };
            });
          } catch(e) {}
        });
      }

      if (ObjC && ObjC.available) {
        // Shared CommonCrypto lookup tables
        var ccOps = ['encrypt', 'decrypt'];
        var ccAlgos = ['AES128', 'DES', '3DES', 'CAST', 'RC4', 'RC2', 'Blowfish'];

        // CCCrypt
        hookNative('libcommonCrypto.dylib', 'CCCrypt', {
          onEnter: function(args) {
            this.info = {
              api: 'CCCrypt',
              operation: ccOps[args[0].toInt32()] || 'unknown',
              algorithm: ccAlgos[args[1].toInt32()] || 'unknown',
              data_size: args[5].toInt32(),
            };
            ${logKeys ? "try { this.info.key_size = args[3].toInt32(); } catch(e) {}" : ''}
          },
          onLeave: function(retval) {
            this.info.result = retval.toInt32() === 0 ? 'success' : 'error';
            send(this.info);
          }
        });

        // CCCryptorCreate — full lifecycle
        hookNative('libcommonCrypto.dylib', 'CCCryptorCreate', {
          onEnter: function(args) {
            try {
              this.info = { api: 'CCCryptorCreate', operation: ccOps[args[0].toInt32()] || 'unknown', algorithm: ccAlgos[args[1].toInt32()] || 'unknown', key_size: args[3].toInt32() };
            } catch(e) { this.info = null; }
          },
          onLeave: function(retval) {
            if (this.info) { this.info.result = retval.toInt32() === 0 ? 'success' : 'error'; send(this.info); }
          }
        });

        // CC_SHA256
        hookNative('libcommonCrypto.dylib', 'CC_SHA256', {
          onEnter: function(args) { try { this.len = args[1].toInt32(); } catch(e) { this.len = 0; } },
          onLeave: function(retval) { send({ api: 'CC_SHA256', data_size: this.len }); }
        });

        // CC_MD5
        hookNative('libcommonCrypto.dylib', 'CC_MD5', {
          onEnter: function(args) { try { this.len = args[1].toInt32(); } catch(e) { this.len = 0; } },
          onLeave: function(retval) { send({ api: 'CC_MD5', data_size: this.len }); }
        });
      }

      // Native OpenSSL EVP
      ['EVP_EncryptUpdate', 'EVP_DecryptUpdate'].forEach(function(name) {
        hookNative(null, name, {
          onEnter: function(args) { try { this.name = name; this.len = args[3].toInt32(); } catch(e) { this.name = name; this.len = 0; } },
          onLeave: function(retval) { send({ api: name, data_size: this.len }); }
        });
      });

      reportSummary('crypto_monitor');
    })();
    `;
  },
};
