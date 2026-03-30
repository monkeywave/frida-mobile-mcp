import type { ScriptTemplate } from '../types.js';

export const rootJailbreakBypassTemplate: ScriptTemplate = {
  name: 'root_jailbreak_bypass',
  description: 'Bypass root detection (Android) and jailbreak detection (iOS). Hooks common detection methods.',
  platforms: ['android', 'ios'],
  category: 'bypass',
  riskTier: 2,
  generate: () => {
    return `
    (function() {
      if (Java && Java.available) {
        Java.perform(function() {
          // Hook Runtime.exec to filter su checks
          try {
            var Runtime = Java.use('java.lang.Runtime');
            Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
              if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {
                send({ status: 'bypassed', method: 'Runtime.exec', blocked: cmd, platform: 'android' });
                throw Java.use('java.io.IOException').$new('Permission denied');
              }
              return this.exec(cmd);
            };
          } catch(e) {}

          // Hook File.exists for root paths
          try {
            var File = Java.use('java.io.File');
            var rootPaths = ['/system/app/Superuser.apk', '/sbin/su', '/system/bin/su', '/system/xbin/su', '/data/local/xbin/su', '/data/local/bin/su', '/system/sd/xbin/su', '/system/bin/failsafe/su', '/data/local/su', '/su/bin/su'];
            File.exists.implementation = function() {
              var path = this.getAbsolutePath();
              if (rootPaths.indexOf(path) !== -1) {
                send({ status: 'bypassed', method: 'File.exists', blocked: path, platform: 'android' });
                return false;
              }
              return this.exists();
            };
          } catch(e) {}

          // Hook Build.TAGS
          try {
            var Build = Java.use('android.os.Build');
            Build.TAGS.value = 'release-keys';
            send({ status: 'bypassed', method: 'Build.TAGS', platform: 'android' });
          } catch(e) {}

          send({ status: 'complete', platform: 'android' });
        });
      }

      if (ObjC && ObjC.available) {
        // Hook NSFileManager fileExistsAtPath for jailbreak paths
        try {
          var jailbreakPaths = ['/Applications/Cydia.app', '/Library/MobileSubstrate/MobileSubstrate.dylib', '/bin/bash', '/usr/sbin/sshd', '/etc/apt', '/private/var/lib/apt/', '/usr/bin/ssh'];
          var NSFileManager = ObjC.classes.NSFileManager;
          Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
            onEnter: function(args) {
              this.path = ObjC.Object(args[2]).toString();
            },
            onLeave: function(retval) {
              if (jailbreakPaths.some(function(p) { return this.path.indexOf(p) !== -1; }.bind(this))) {
                retval.replace(0);
                send({ status: 'bypassed', method: 'NSFileManager.fileExistsAtPath', blocked: this.path, platform: 'ios' });
              }
            }
          });
        } catch(e) {}

        // Hook fork
        try {
          var fork = Module.findExportByName('libSystem.B.dylib', 'fork');
          if (fork) {
            Interceptor.replace(fork, new NativeCallback(function() {
              send({ status: 'bypassed', method: 'fork', platform: 'ios' });
              return -1;
            }, 'int', []));
          }
        } catch(e) {}

        send({ status: 'complete', platform: 'ios' });
      }
    })();
    `;
  },
};
