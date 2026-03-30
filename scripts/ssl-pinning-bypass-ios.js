// frida-mobile-mcp: SSL Pinning Bypass for iOS
// Usage: frida -U -f com.example.app -l ssl-pinning-bypass-ios.js
(function() {
  // SecTrustEvaluate
  try {
    var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
    if (SecTrustEvaluate) {
      Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
        Memory.writeU32(result, 4);
        console.log('[+] SSL Bypass: SecTrustEvaluate');
        return 0;
      }, 'int', ['pointer', 'pointer']));
    }
  } catch(e) {}
  // SecTrustEvaluateWithError
  try {
    var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
    if (SecTrustEvaluateWithError) {
      Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
        console.log('[+] SSL Bypass: SecTrustEvaluateWithError');
        return 1;
      }, 'bool', ['pointer', 'pointer']));
    }
  } catch(e) {}
  // BoringSSL
  try {
    var SSL_CTX_set_custom_verify = Module.findExportByName('libboringssl.dylib', 'SSL_CTX_set_custom_verify');
    if (SSL_CTX_set_custom_verify) {
      Interceptor.replace(SSL_CTX_set_custom_verify, new NativeCallback(function(ctx, mode, cb) {
        console.log('[+] SSL Bypass: BoringSSL');
      }, 'void', ['pointer', 'int', 'pointer']));
    }
  } catch(e) {}
  console.log('[*] iOS SSL pinning bypass loaded');
})();
