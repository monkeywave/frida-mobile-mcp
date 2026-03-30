// frida-mobile-mcp: Jailbreak Detection Bypass for iOS
// Usage: frida -U -f com.example.app -l jailbreak-detection-bypass.js
(function() {
  var jailbreakPaths = ['/Applications/Cydia.app', '/Library/MobileSubstrate/MobileSubstrate.dylib', '/bin/bash', '/usr/sbin/sshd', '/etc/apt', '/private/var/lib/apt/', '/usr/bin/ssh'];
  try {
    var NSFileManager = ObjC.classes.NSFileManager;
    Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
      onEnter: function(args) { this.path = ObjC.Object(args[2]).toString(); },
      onLeave: function(retval) {
        if (jailbreakPaths.some(function(p) { return this.path.indexOf(p) !== -1; }.bind(this))) {
          retval.replace(0);
          console.log('[+] JB Bypass: blocked fileExistsAtPath("' + this.path + '")');
        }
      }
    });
  } catch(e) {}
  try {
    var fork = Module.findExportByName('libSystem.B.dylib', 'fork');
    if (fork) {
      Interceptor.replace(fork, new NativeCallback(function() {
        console.log('[+] JB Bypass: blocked fork()');
        return -1;
      }, 'int', []));
    }
  } catch(e) {}
  console.log('[*] iOS jailbreak detection bypass loaded');
})();
