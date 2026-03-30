import type { ScriptTemplate } from '../types.js';

export const sslPinningBypassTemplate: ScriptTemplate = {
  name: 'ssl_pinning_bypass',
  description: 'Bypass SSL certificate pinning. Android: TrustManager, OkHttp, Conscrypt. iOS: SecTrust, ATS, BoringSSL.',
  platforms: ['android', 'ios'],
  category: 'bypass',
  riskTier: 2,
  options: {
    platform: { type: 'string', description: 'Force platform: android or ios. Auto-detected if omitted.' },
  },
  generate: (options) => {
    return `
    // SSL Pinning Bypass - Universal
    (function() {
      // Try Android first
      if (Java && Java.available) {
        Java.perform(function() {
          // TrustManager bypass
          try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.verifyChain.implementation = function() {
              send({ status: 'bypassed', method: 'TrustManagerImpl.verifyChain', platform: 'android' });
              return arguments[0];
            };
          } catch(e) { send({ status: 'skipped', method: 'TrustManagerImpl', reason: e.message }); }

          // X509TrustManager
          try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var TrustManager = Java.registerClass({
              name: 'com.frida.TrustManager',
              implements: [X509TrustManager],
              methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
              }
            });
          } catch(e) {}

          // SSLContext
          try {
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
              this.init(km, tm, sr);
              send({ status: 'bypassed', method: 'SSLContext.init', platform: 'android' });
            };
          } catch(e) { send({ status: 'skipped', method: 'SSLContext.init', reason: e.message }); }

          // OkHttp3 CertificatePinner
          try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
              send({ status: 'bypassed', method: 'OkHttp3.CertificatePinner', platform: 'android' });
            };
          } catch(e) { send({ status: 'skipped', method: 'OkHttp3', reason: e.message }); }

          // Conscrypt
          try {
            var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
            OpenSSLSocketImpl.verifyCertificateChain.implementation = function() {
              send({ status: 'bypassed', method: 'Conscrypt', platform: 'android' });
            };
          } catch(e) { send({ status: 'skipped', method: 'Conscrypt', reason: e.message }); }

          send({ status: 'complete', platform: 'android' });
        });
      }

      // Try iOS
      if (ObjC && ObjC.available) {
        // SecTrustEvaluate
        try {
          var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
          if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
              Memory.writeU32(result, 4); // kSecTrustResultProceed
              send({ status: 'bypassed', method: 'SecTrustEvaluate', platform: 'ios' });
              return 0; // errSecSuccess
            }, 'int', ['pointer', 'pointer']));
          }
        } catch(e) { send({ status: 'skipped', method: 'SecTrustEvaluate', reason: e.message }); }

        // SecTrustEvaluateWithError
        try {
          var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
          if (SecTrustEvaluateWithError) {
            Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
              send({ status: 'bypassed', method: 'SecTrustEvaluateWithError', platform: 'ios' });
              return 1; // true = trusted
            }, 'bool', ['pointer', 'pointer']));
          }
        } catch(e) { send({ status: 'skipped', method: 'SecTrustEvaluateWithError', reason: e.message }); }

        // BoringSSL
        try {
          var SSL_CTX_set_custom_verify = Module.findExportByName('libboringssl.dylib', 'SSL_CTX_set_custom_verify');
          if (SSL_CTX_set_custom_verify) {
            Interceptor.replace(SSL_CTX_set_custom_verify, new NativeCallback(function(ctx, mode, cb) {
              send({ status: 'bypassed', method: 'BoringSSL.SSL_CTX_set_custom_verify', platform: 'ios' });
            }, 'void', ['pointer', 'int', 'pointer']));
          }
        } catch(e) { send({ status: 'skipped', method: 'BoringSSL', reason: e.message }); }

        send({ status: 'complete', platform: 'ios' });
      }
    })();
    `;
  },
};
