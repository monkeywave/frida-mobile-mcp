import type { ScriptTemplate } from '../types.js';

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
      if (Java && Java.available) {
        Java.perform(function() {
          // Cipher
          try {
            var Cipher = Java.use('javax.crypto.Cipher');
            Cipher.doFinal.overload('[B').implementation = function(input) {
              var result = this.doFinal(input);
              var info = { api: 'Cipher.doFinal', algorithm: this.getAlgorithm(), mode: this.getBlockMode ? this.getBlockMode() : 'unknown' };
              ${logData ? "try { info.input = Array.from(input).map(function(b){return ('0'+((b+256)%256).toString(16)).slice(-2);}).join('').slice(0,200); } catch(e) {}" : ''}
              ${logKeys ? "try { var key = this.getParameters(); if (key) info.params = key.toString(); } catch(e) {}" : ''}
              send(info);
              return result;
            };
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
        });
      }

      if (ObjC && ObjC.available) {
        // CCCrypt
        try {
          var CCCrypt = Module.findExportByName('libcommonCrypto.dylib', 'CCCrypt');
          if (CCCrypt) {
            Interceptor.attach(CCCrypt, {
              onEnter: function(args) {
                var ops = ['encrypt', 'decrypt'];
                var algos = ['AES128', 'DES', '3DES', 'CAST', 'RC4', 'RC2', 'Blowfish'];
                this.info = {
                  api: 'CCCrypt',
                  operation: ops[args[0].toInt32()] || 'unknown',
                  algorithm: algos[args[1].toInt32()] || 'unknown',
                  data_size: args[5].toInt32(),
                };
                ${logKeys ? "try { this.info.key_size = args[3].toInt32(); } catch(e) {}" : ''}
              },
              onLeave: function(retval) {
                this.info.result = retval.toInt32() === 0 ? 'success' : 'error';
                send(this.info);
              }
            });
            send({ status: 'hooked', api: 'CCCrypt' });
          }
        } catch(e) {}
      }

      // Native OpenSSL EVP
      try {
        ['EVP_EncryptUpdate', 'EVP_DecryptUpdate'].forEach(function(name) {
          var addr = Module.findExportByName(null, name);
          if (addr) {
            Interceptor.attach(addr, {
              onEnter: function(args) { this.name = name; this.len = args[3].toInt32(); },
              onLeave: function(retval) { send({ api: name, data_size: this.len }); }
            });
            send({ status: 'hooked', api: name });
          }
        });
      } catch(e) {}
    })();
    `;
  },
};
