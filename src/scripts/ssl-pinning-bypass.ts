import type { ScriptTemplate } from '../types.js';
import { buildTemplateBody } from './template-body.js';

// SSL Pinning Bypass - Universal (the `platform` option is informational; the body probes
// Java.available / ObjC.available at runtime and installs whichever hooks apply).
const BODY = buildTemplateBody('ssl_pinning_bypass', `
  // Try Android first
  if (Java.available) {
    Java.perform(function() {
      // TrustManager bypass
      installHook('TrustManagerImpl.verifyChain', function() {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function() {
          send({ status: 'bypassed', method: 'TrustManagerImpl.verifyChain', platform: 'android' });
          return arguments[0];
        };
      }, reportSkipped('TrustManagerImpl'));

      // X509TrustManager
      var TrustManager = null;
      installHook('X509TrustManager', function() {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        TrustManager = Java.registerClass({
          name: 'com.frida.TrustManager',
          implements: [X509TrustManager],
          methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
          }
        });
      });

      // SSLContext
      installHook('SSLContext.init', function() {
        if (!TrustManager) throw new Error('custom TrustManager was not registered');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
          this.init(km, [TrustManager.$new()], sr);
          send({ status: 'bypassed', method: 'SSLContext.init', platform: 'android' });
        };
      }, reportSkipped('SSLContext.init'));

      // OkHttp3 CertificatePinner
      installHook('OkHttp3.CertificatePinner', function() {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
          send({ status: 'bypassed', method: 'OkHttp3.CertificatePinner', platform: 'android' });
        };
      }, reportSkipped('OkHttp3'));

      // Conscrypt: TrustManagerImpl is the platform trust manager on every modern Android
      // (verifyChain returns the chain it was given; checkTrustedRecursive returns a list).
      installHook('Conscrypt.TrustManagerImpl.verifyChain', function() {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
          send({ status: 'bypassed', method: 'Conscrypt.TrustManagerImpl.verifyChain', platform: 'android', host: String(host) });
          return untrustedChain;
        };
      }, reportSkipped('Conscrypt.TrustManagerImpl.verifyChain'));

      installHook('Conscrypt.TrustManagerImpl.checkTrustedRecursive', function() {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        var ArrayList = Java.use('java.util.ArrayList');
        TrustManagerImpl.checkTrustedRecursive.implementation = function(certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used) {
          send({ status: 'bypassed', method: 'Conscrypt.TrustManagerImpl.checkTrustedRecursive', platform: 'android', host: String(host) });
          return ArrayList.$new();
        };
      }, reportSkipped('Conscrypt.TrustManagerImpl.checkTrustedRecursive'));

      // Conscrypt socket-level verification (class name varies by Android version)
      installHook('Conscrypt.Socket.verifyCertificateChain', function() {
        var socketClasses = ['com.android.org.conscrypt.ConscryptFileDescriptorSocket', 'com.android.org.conscrypt.ConscryptEngineSocket', 'com.android.org.conscrypt.OpenSSLSocketImpl'];
        var hooked = 0;
        for (var i = 0; i < socketClasses.length; i++) {
          try {
            var SocketCls = Java.use(socketClasses[i]);
            if (!SocketCls.verifyCertificateChain) continue;
            SocketCls.verifyCertificateChain.implementation = function() {
              send({ status: 'bypassed', method: 'Conscrypt.verifyCertificateChain', platform: 'android' });
            };
            hooked++;
          } catch (e) {}
        }
        if (hooked === 0) throw new Error('no Conscrypt socket class with verifyCertificateChain found');
      }, reportSkipped('Conscrypt.Socket.verifyCertificateChain'));

      // OkHttp4 CertificatePinner (Kotlin rewrite)
      installHook('OkHttp4.check$okhttp', function() {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        if (!CertPinner['check$okhttp']) throw new Error('check$okhttp not present (OkHttp < 4)');
        CertPinner['check$okhttp'].implementation = function() {
          send({ status: 'bypassed', method: 'OkHttp4.check$okhttp', platform: 'android' });
        };
      }, reportSkipped('OkHttp4'));

      // WebViewClient SSL error bypass
      installHook('WebViewClient.onReceivedSslError', function() {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
          handler.proceed();
          send({ status: 'bypassed', method: 'WebViewClient.onReceivedSslError', platform: 'android' });
        };
      }, reportSkipped('WebViewClient'));

      // NetworkSecurityTrustManager (Android 7+)
      installHook('NetworkSecurityTrustManager', function() {
        var NSTM = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NSTM.checkServerTrusted.overloads.forEach(function(overload) {
          overload.implementation = function() {
            send({ status: 'bypassed', method: 'NetworkSecurityTrustManager', platform: 'android' });
          };
        });
      }, reportSkipped('NetworkSecurityTrustManager'));

      send({ status: 'complete', platform: 'android' });
    });
  }

  // Try iOS
  if (ObjC.available) {
    // SecTrustEvaluate
    installHook('SecTrustEvaluate', function() {
      var SecTrustEvaluate = findExport('Security', 'SecTrustEvaluate');
      if (!SecTrustEvaluate) throw new Error('SecTrustEvaluate export not found');
      Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
        try {
          if (!result.isNull()) {
            result.writeU32(4); // kSecTrustResultProceed
          }
          send({ status: 'bypassed', method: 'SecTrustEvaluate', platform: 'ios' });
          return 0; // errSecSuccess
        } catch (e) {
          send({ status: 'error', method: 'SecTrustEvaluate', reason: e.message });
          return 0;
        }
      }, 'int', ['pointer', 'pointer']));
    }, reportSkipped('SecTrustEvaluate'));

    // SecTrustEvaluateWithError
    installHook('SecTrustEvaluateWithError', function() {
      var SecTrustEvaluateWithError = findExport('Security', 'SecTrustEvaluateWithError');
      if (!SecTrustEvaluateWithError) throw new Error('SecTrustEvaluateWithError export not found');
      Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
        try {
          send({ status: 'bypassed', method: 'SecTrustEvaluateWithError', platform: 'ios' });
          return 1; // true = trusted
        } catch (e) {
          send({ status: 'error', method: 'SecTrustEvaluateWithError', reason: e.message });
          return 1;
        }
      }, 'bool', ['pointer', 'pointer']));
    }, reportSkipped('SecTrustEvaluateWithError'));

    // BoringSSL
    installHook('BoringSSL.SSL_CTX_set_custom_verify', function() {
      var SSL_CTX_set_custom_verify = findExport('libboringssl.dylib', 'SSL_CTX_set_custom_verify');
      if (!SSL_CTX_set_custom_verify) throw new Error('SSL_CTX_set_custom_verify export not found');
      var original_set_custom_verify = new NativeFunction(SSL_CTX_set_custom_verify, 'void', ['pointer', 'int', 'pointer']);
      var permissive_verify_cb = new NativeCallback(function(ssl, out_alert) {
        return 0; // ssl_verify_ok
      }, 'int', ['pointer', 'pointer']);
      Interceptor.replace(SSL_CTX_set_custom_verify, new NativeCallback(function(ctx, mode, cb) {
        try {
          original_set_custom_verify(ctx, mode, permissive_verify_cb);
          send({ status: 'bypassed', method: 'BoringSSL.SSL_CTX_set_custom_verify', platform: 'ios' });
        } catch (e) {
          send({ status: 'error', method: 'BoringSSL.SSL_CTX_set_custom_verify', reason: e.message });
        }
      }, 'void', ['pointer', 'int', 'pointer']));
    }, reportSkipped('BoringSSL'));

    // BoringSSL SSL_set_custom_verify (per-connection)
    installHook('BoringSSL.SSL_set_custom_verify', function() {
      var SSL_set_custom_verify = findExport('libboringssl.dylib', 'SSL_set_custom_verify');
      if (!SSL_set_custom_verify) throw new Error('SSL_set_custom_verify export not found');
      var origSetVerify = new NativeFunction(SSL_set_custom_verify, 'void', ['pointer', 'int', 'pointer']);
      var verifyOk = new NativeCallback(function(ssl, out_alert) { return 0; }, 'int', ['pointer', 'pointer']);
      Interceptor.replace(SSL_set_custom_verify, new NativeCallback(function(ssl, mode, cb) {
        try { origSetVerify(ssl, mode, verifyOk); } catch (e) {}
        send({ status: 'bypassed', method: 'BoringSSL.SSL_set_custom_verify', platform: 'ios' });
      }, 'void', ['pointer', 'int', 'pointer']));
    }, reportSkipped('BoringSSL.SSL_set_custom_verify'));

    // AFNetworking AFSecurityPolicy
    installHook('AFSecurityPolicy.evaluateServerTrust', function() {
      if (!ObjC.classes.AFSecurityPolicy) throw new Error('AFSecurityPolicy class not loaded');
      var AFPolicy = ObjC.classes.AFSecurityPolicy;
      Interceptor.attach(AFPolicy['- evaluateServerTrust:forDomain:'].implementation, {
        onLeave: function(retval) {
          retval.replace(ptr(1));
          send({ status: 'bypassed', method: 'AFSecurityPolicy.evaluateServerTrust', platform: 'ios' });
        }
      });
    }, reportSkipped('AFNetworking'));

    send({ status: 'complete', platform: 'ios' });
  }
`);

export const sslPinningBypassTemplate: ScriptTemplate = {
  name: 'ssl_pinning_bypass',
  description: 'Bypass SSL certificate pinning. Android: TrustManager, OkHttp (3/4), Conscrypt, WebView. iOS: SecTrust (also covers ATS), BoringSSL, AFNetworking.',
  platforms: ['android', 'ios'],
  category: 'bypass',
  riskTier: 2,
  options: {
    platform: { type: 'string', description: 'Force platform: android or ios. Auto-detected if omitted.' },
  },
  generate: () => BODY,
};
