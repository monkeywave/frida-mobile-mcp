// frida-mobile-mcp: Root Detection Bypass for Android
// Usage: frida -U -f com.example.app -l root-detection-bypass.js
(function() {
  Java.perform(function() {
    var rootPaths = ['/system/app/Superuser.apk', '/sbin/su', '/system/bin/su', '/system/xbin/su', '/data/local/xbin/su', '/data/local/bin/su', '/system/sd/xbin/su', '/system/bin/failsafe/su', '/data/local/su', '/su/bin/su'];
    try {
      var Runtime = Java.use('java.lang.Runtime');
      Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {
          console.log('[+] Root Bypass: blocked Runtime.exec("' + cmd + '")');
          throw Java.use('java.io.IOException').$new('Permission denied');
        }
        return this.exec(cmd);
      };
    } catch(e) {}
    try {
      var File = Java.use('java.io.File');
      File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (rootPaths.indexOf(path) !== -1) {
          console.log('[+] Root Bypass: blocked File.exists("' + path + '")');
          return false;
        }
        return this.exists();
      };
    } catch(e) {}
    try {
      var Build = Java.use('android.os.Build');
      Build.TAGS.value = 'release-keys';
      console.log('[+] Root Bypass: Build.TAGS set to release-keys');
    } catch(e) {}
    console.log('[*] Android root detection bypass loaded');
  });
})();
