// frida-mobile-mcp: SSL Pinning Bypass for Android
// Usage: frida -U -f com.example.app -l ssl-pinning-bypass-android.js
(function() {
  Java.perform(function() {
    // TrustManagerImpl
    try {
      var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
      TrustManagerImpl.verifyChain.implementation = function() {
        console.log('[+] SSL Bypass: TrustManagerImpl.verifyChain');
        return arguments[0];
      };
    } catch(e) {}
    // SSLContext.init
    try {
      var SSLContext = Java.use('javax.net.ssl.SSLContext');
      SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
        console.log('[+] SSL Bypass: SSLContext.init');
        this.init(km, tm, sr);
      };
    } catch(e) {}
    // OkHttp3
    try {
      var CertificatePinner = Java.use('okhttp3.CertificatePinner');
      CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
        console.log('[+] SSL Bypass: OkHttp3.CertificatePinner');
      };
    } catch(e) {}
    // Conscrypt
    try {
      var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
      OpenSSLSocketImpl.verifyCertificateChain.implementation = function() {
        console.log('[+] SSL Bypass: Conscrypt');
      };
    } catch(e) {}
    console.log('[*] Android SSL pinning bypass loaded');
  });
})();
