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
              this.init(km, [TrustManager.$new()], sr);
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

          // OkHttp4 CertificatePinner (Kotlin rewrite)
          try {
            var CertPinner = Java.use('okhttp3.CertificatePinner');
            if (CertPinner['check$okhttp']) {
              CertPinner['check$okhttp'].implementation = function() {
                send({ status: 'bypassed', method: 'OkHttp4.check$okhttp', platform: 'android' });
              };
            }
          } catch(e) { send({ status: 'skipped', method: 'OkHttp4', reason: e.message }); }

          // WebViewClient SSL error bypass
          try {
            var WebViewClient = Java.use('android.webkit.WebViewClient');
            WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
              handler.proceed();
              send({ status: 'bypassed', method: 'WebViewClient.onReceivedSslError', platform: 'android' });
            };
          } catch(e) { send({ status: 'skipped', method: 'WebViewClient', reason: e.message }); }

          // NetworkSecurityTrustManager (Android 7+)
          try {
            var NSTM = Java.use('android.security.net.config.NetworkSecurityTrustManager');
            NSTM.checkServerTrusted.overloads.forEach(function(overload) {
              overload.implementation = function() {
                send({ status: 'bypassed', method: 'NetworkSecurityTrustManager', platform: 'android' });
              };
            });
          } catch(e) { send({ status: 'skipped', method: 'NetworkSecurityTrustManager', reason: e.message }); }

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
              try {
                if (!result.isNull()) {
                  Memory.writeU32(result, 4); // kSecTrustResultProceed
                }
                send({ status: 'bypassed', method: 'SecTrustEvaluate', platform: 'ios' });
                return 0; // errSecSuccess
              } catch(e) {
                send({ status: 'error', method: 'SecTrustEvaluate', reason: e.message });
                return 0;
              }
            }, 'int', ['pointer', 'pointer']));
          }
        } catch(e) { send({ status: 'skipped', method: 'SecTrustEvaluate', reason: e.message }); }

        // SecTrustEvaluateWithError
        try {
          var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
          if (SecTrustEvaluateWithError) {
            Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
              try {
                send({ status: 'bypassed', method: 'SecTrustEvaluateWithError', platform: 'ios' });
                return 1; // true = trusted
              } catch(e) {
                send({ status: 'error', method: 'SecTrustEvaluateWithError', reason: e.message });
                return 1;
              }
            }, 'bool', ['pointer', 'pointer']));
          }
        } catch(e) { send({ status: 'skipped', method: 'SecTrustEvaluateWithError', reason: e.message }); }

        // BoringSSL
        try {
          var SSL_CTX_set_custom_verify = Module.findExportByName('libboringssl.dylib', 'SSL_CTX_set_custom_verify');
          if (SSL_CTX_set_custom_verify) {
            var original_set_custom_verify = new NativeFunction(SSL_CTX_set_custom_verify, 'void', ['pointer', 'int', 'pointer']);
            var permissive_verify_cb = new NativeCallback(function(ssl, out_alert) {
              return 0; // ssl_verify_ok
            }, 'int', ['pointer', 'pointer']);
            Interceptor.replace(SSL_CTX_set_custom_verify, new NativeCallback(function(ctx, mode, cb) {
              try {
                original_set_custom_verify(ctx, mode, permissive_verify_cb);
                send({ status: 'bypassed', method: 'BoringSSL.SSL_CTX_set_custom_verify', platform: 'ios' });
              } catch(e) {
                send({ status: 'error', method: 'BoringSSL.SSL_CTX_set_custom_verify', reason: e.message });
              }
            }, 'void', ['pointer', 'int', 'pointer']));
          }
        } catch(e) { send({ status: 'skipped', method: 'BoringSSL', reason: e.message }); }

        // BoringSSL SSL_set_custom_verify (per-connection)
        try {
          var SSL_set_custom_verify = Module.findExportByName('libboringssl.dylib', 'SSL_set_custom_verify');
          if (SSL_set_custom_verify) {
            var origSetVerify = new NativeFunction(SSL_set_custom_verify, 'void', ['pointer', 'int', 'pointer']);
            var verifyOk = new NativeCallback(function(ssl, out_alert) { return 0; }, 'int', ['pointer', 'pointer']);
            Interceptor.replace(SSL_set_custom_verify, new NativeCallback(function(ssl, mode, cb) {
              try { origSetVerify(ssl, mode, verifyOk); } catch(e) {}
              send({ status: 'bypassed', method: 'BoringSSL.SSL_set_custom_verify', platform: 'ios' });
            }, 'void', ['pointer', 'int', 'pointer']));
          }
        } catch(e) { send({ status: 'skipped', method: 'BoringSSL.SSL_set_custom_verify', reason: e.message }); }

        // AFNetworking AFSecurityPolicy
        try {
          if (ObjC.classes.AFSecurityPolicy) {
            var AFPolicy = ObjC.classes.AFSecurityPolicy;
            Interceptor.attach(AFPolicy['- evaluateServerTrust:forDomain:'].implementation, {
              onLeave: function(retval) {
                retval.replace(ptr(1));
                send({ status: 'bypassed', method: 'AFSecurityPolicy.evaluateServerTrust', platform: 'ios' });
              }
            });
          }
        } catch(e) { send({ status: 'skipped', method: 'AFNetworking', reason: e.message }); }

        send({ status: 'complete', platform: 'ios' });
      }
    })();
    `;
  },
};
