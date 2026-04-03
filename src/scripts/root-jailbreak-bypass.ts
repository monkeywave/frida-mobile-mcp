import type { ScriptTemplate } from '../types.js';
import { getFridaRuntime } from './frida-runtime.js';

export const rootJailbreakBypassTemplate: ScriptTemplate = {
  name: 'root_jailbreak_bypass',
  description: 'Bypass root detection (Android) and jailbreak detection (iOS). Hooks common detection methods.',
  platforms: ['android', 'ios'],
  category: 'bypass',
  riskTier: 2,
  generate: () => {
    return `
    (function() {
      ${getFridaRuntime()}
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
            var rootPaths = ['/system/app/Superuser.apk', '/sbin/su', '/system/bin/su', '/system/xbin/su', '/data/local/xbin/su', '/data/local/bin/su', '/system/sd/xbin/su', '/system/bin/failsafe/su', '/data/local/su', '/su/bin/su', '/sbin/magisk', '/sbin/.magisk', '/data/adb/magisk', '/data/adb/modules', '/system/xbin/daemonsu'];
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

          // Hook ProcessBuilder.start to filter su/magisk commands
          try {
            var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
            ProcessBuilder.start.implementation = function() {
              var cmd = this.command().toString();
              if (cmd.indexOf('su') >= 0 || cmd.indexOf('magisk') >= 0 || cmd.indexOf('which') >= 0) {
                send({ status: 'blocked', method: 'ProcessBuilder.start', command: cmd, platform: 'android' });
                throw Java.use('java.io.IOException').$new('Permission denied');
              }
              return this.start();
            };
          } catch(e) { send({ status: 'skipped', method: 'ProcessBuilder', reason: e.message }); }

          // Hook SystemProperties.get to spoof detection-related properties
          try {
            var SystemProperties = Java.use('android.os.SystemProperties');
            var spoofedProps = {
              'ro.debuggable': '0', 'ro.secure': '1', 'ro.build.selinux': '1',
              'ro.build.tags': 'release-keys', 'ro.build.type': 'user',
              'service.adb.root': '0', 'ro.boot.verifiedbootstate': 'green',
              'ro.boot.flash.locked': '1', 'ro.boot.vbmeta.device_state': 'locked',
            };
            SystemProperties.get.overloads.forEach(function(overload) {
              overload.implementation = function() {
                var key = arguments[0];
                if (spoofedProps[key] !== undefined) {
                  send({ status: 'spoofed', method: 'SystemProperties.get', key: key, platform: 'android' });
                  return spoofedProps[key];
                }
                return overload.apply(this, arguments);
              };
            });
          } catch(e) { send({ status: 'skipped', method: 'SystemProperties', reason: e.message }); }

          // Hook PackageManager.getInstalledPackages to filter root apps
          try {
            var PM = Java.use('android.app.ApplicationPackageManager');
            var rootPkgs = new Set(['com.topjohnwu.magisk', 'eu.chainfire.supersu', 'com.noshufou.android.su', 'com.thirdparty.superuser', 'com.koushikdutta.superuser', 'com.scottyab.rootbeer', 'com.devadvance.rootcloak', 'de.robv.android.xposed.installer', 'com.saurik.substrate', 'com.amphoras.hidemyroot']);
            PM.getInstalledPackages.overloads.forEach(function(overload) {
              overload.implementation = function() {
                var list = overload.apply(this, arguments);
                var Iterator = Java.use('java.util.Iterator');
                var it = list.iterator();
                while (it.hasNext()) {
                  var pkg = it.next();
                  if (rootPkgs.has(pkg.packageName.value)) {
                    it.remove();
                    send({ status: 'filtered', method: 'getInstalledPackages', package: pkg.packageName.value, platform: 'android' });
                  }
                }
                return list;
              };
            });
          } catch(e) { send({ status: 'skipped', method: 'PackageManager', reason: e.message }); }

          // Native fopen hook — block opening root-related paths
          var rootPathRegex = new RegExp(rootPaths.map(function(p) { return p.replace(/\\./g, '\\\\.'); }).join('|'));
          hookNative('libc.so', 'fopen', {
            onEnter: function(args) {
              try {
                var path = args[0].readUtf8String();
                if (path && path.match(rootPathRegex)) {
                  this.block = true;
                  send({ status: 'blocked', method: 'fopen', path: path, platform: 'android' });
                }
              } catch(e) {}
            },
            onLeave: function(retval) {
              if (this.block) retval.replace(ptr(0));
            }
          });

          // Native access hook — return -1 for root paths
          hookNative('libc.so', 'access', {
            onEnter: function(args) {
              try {
                var path = args[0].readUtf8String();
                if (path && path.match(/\/su|\/magisk|\/supersu/)) {
                  this.block = true;
                }
              } catch(e) {}
            },
            onLeave: function(retval) {
              if (this.block) retval.replace(ptr(-1));
            }
          });

          send({ status: 'complete', platform: 'android' });
        });
      }

      if (ObjC && ObjC.available) {
        // Hook NSFileManager fileExistsAtPath for jailbreak paths
        try {
          var jailbreakPaths = ['/Applications/Cydia.app', '/Library/MobileSubstrate/MobileSubstrate.dylib', '/Library/MobileSubstrate', '/bin/bash', '/usr/sbin/sshd', '/etc/apt', '/private/var/lib/apt/', '/usr/bin/ssh', '/var/jb', '/var/checkra1n.dmg', '/.installed_unc0ver', '/private/preboot/procursus', '/Applications/Sileo.app', '/usr/libexec/cydia', '/var/lib/cydia', '/private/var/stash'];
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

        // Hook UIApplication.canOpenURL to block jailbreak URL schemes
        try {
          var blockedSchemes = ['cydia://', 'sileo://', 'zbra://', 'filza://', 'activator://'];
          if (ObjC.classes.UIApplication) {
            Interceptor.attach(ObjC.classes.UIApplication['- canOpenURL:'].implementation, {
              onEnter: function(args) {
                try {
                  var url = new ObjC.Object(args[2]).toString();
                  this.blocked = blockedSchemes.some(function(s) { return url.indexOf(s) === 0; });
                } catch(e) { this.blocked = false; }
              },
              onLeave: function(retval) {
                if (this.blocked) {
                  retval.replace(ptr(0));
                  send({ status: 'blocked', method: 'canOpenURL', platform: 'ios' });
                }
              }
            });
          }
        } catch(e) { send({ status: 'skipped', method: 'canOpenURL', reason: e.message }); }

        // Native stat hook — hide jailbreak paths
        hookNative('libSystem.B.dylib', 'stat', {
          onEnter: function(args) {
            try {
              var path = args[0].readUtf8String();
              this.block = path && jailbreakPaths.some(function(p) { return path.indexOf(p) >= 0; });
            } catch(e) { this.block = false; }
          },
          onLeave: function(retval) {
            if (this.block) retval.replace(ptr(-1));
          }
        });

        // Hook sysctl to detect P_TRACED anti-debug checks
        hookNative('libSystem.B.dylib', 'sysctl', {
          onEnter: function(args) {
            try {
              var mib = args[0];
              var mib0 = mib.readS32();
              var mib1 = mib.add(4).readS32();
              this.isKernProc = (mib0 === 1 && mib1 === 14); // CTL_KERN, KERN_PROC
            } catch(e) { this.isKernProc = false; }
          },
          onLeave: function(retval) {
            if (this.isKernProc) {
              try {
                // Remove P_TRACED flag from p_flag
                // Not modifying here to avoid instability — just report
                send({ status: 'detected', method: 'sysctl.KERN_PROC', platform: 'ios' });
              } catch(e) {}
            }
          }
        });

        send({ status: 'complete', platform: 'ios' });
      }

      reportSummary('root_jailbreak_bypass');
    })();
    `;
  },
};
