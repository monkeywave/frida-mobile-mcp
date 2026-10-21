import type { ScriptTemplate } from '../types.js';
import { buildTemplateBody } from './template-body.js';

// NOTE: this is a TS template literal. A regex that must contain a backslash in the emitted
// script needs a doubled backslash here (e.g. `\\/` emits `\/`, `\\\\.` emits `\\.`).
const BODY = buildTemplateBody('root_jailbreak_bypass', `
  var o = templateOptions();
  var bypassDebugger = o.bypass_debugger === true;

  if (Java.available) {
    Java.perform(function() {
      var rootPaths = ['/system/app/Superuser.apk', '/sbin/su', '/system/bin/su', '/system/xbin/su', '/data/local/xbin/su', '/data/local/bin/su', '/system/sd/xbin/su', '/system/bin/failsafe/su', '/data/local/su', '/su/bin/su', '/sbin/magisk', '/sbin/.magisk', '/data/adb/magisk', '/data/adb/modules', '/system/xbin/daemonsu'];

      // Hook Runtime.exec to filter su checks
      installHook('Runtime.exec', function() {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
          if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {
            send({ status: 'bypassed', method: 'Runtime.exec', blocked: cmd, platform: 'android' });
            throw Java.use('java.io.IOException').$new('Permission denied');
          }
          return this.exec(cmd);
        };
      });

      // Hook File.exists for root paths
      installHook('File.exists', function() {
        var File = Java.use('java.io.File');
        File.exists.implementation = function() {
          var path = this.getAbsolutePath();
          if (rootPaths.indexOf(path) !== -1) {
            send({ status: 'bypassed', method: 'File.exists', blocked: path, platform: 'android' });
            return false;
          }
          return this.exists();
        };
      });

      // Hook Build.TAGS
      installHook('Build.TAGS', function() {
        var Build = Java.use('android.os.Build');
        Build.TAGS.value = 'release-keys';
        send({ status: 'bypassed', method: 'Build.TAGS', platform: 'android' });
      });

      // Hook ProcessBuilder.start to filter su/magisk commands
      installHook('ProcessBuilder.start', function() {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.implementation = function() {
          var cmd = this.command().toString();
          if (cmd.indexOf('su') >= 0 || cmd.indexOf('magisk') >= 0 || cmd.indexOf('which') >= 0) {
            send({ status: 'blocked', method: 'ProcessBuilder.start', command: cmd, platform: 'android' });
            throw Java.use('java.io.IOException').$new('Permission denied');
          }
          return this.start();
        };
      }, reportSkipped('ProcessBuilder'));

      // Hook SystemProperties.get to spoof detection-related properties
      installHook('SystemProperties.get', function() {
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
      }, reportSkipped('SystemProperties'));

      // Hook PackageManager.getInstalledPackages to filter root apps
      installHook('PackageManager.getInstalledPackages', function() {
        var PM = Java.use('android.app.ApplicationPackageManager');
        var rootPkgs = new Set(['com.topjohnwu.magisk', 'eu.chainfire.supersu', 'com.noshufou.android.su', 'com.thirdparty.superuser', 'com.koushikdutta.superuser', 'com.scottyab.rootbeer', 'com.devadvance.rootcloak', 'de.robv.android.xposed.installer', 'com.saurik.substrate', 'com.amphoras.hidemyroot']);
        PM.getInstalledPackages.overloads.forEach(function(overload) {
          overload.implementation = function() {
            var list = overload.apply(this, arguments);
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
      }, reportSkipped('PackageManager'));

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
          } catch (e) {}
        },
        onLeave: function(retval) {
          if (this.block) retval.replace(ptr(0));
        }
      });

      // Native access hook — return -1 for root paths
      var suPathRegex = /\\/su|\\/magisk|\\/supersu/;
      hookNative('libc.so', 'access', {
        onEnter: function(args) {
          try {
            var path = args[0].readUtf8String();
            if (path && path.match(suPathRegex)) {
              this.block = true;
            }
          } catch (e) {}
        },
        onLeave: function(retval) {
          if (this.block) retval.replace(ptr(-1));
        }
      });

      send({ status: 'complete', platform: 'android' });
    });
  }

  if (ObjC.available) {
    var jailbreakPaths = ['/Applications/Cydia.app', '/Library/MobileSubstrate/MobileSubstrate.dylib', '/Library/MobileSubstrate', '/bin/bash', '/usr/sbin/sshd', '/etc/apt', '/private/var/lib/apt/', '/usr/bin/ssh', '/var/jb', '/var/checkra1n.dmg', '/.installed_unc0ver', '/private/preboot/procursus', '/Applications/Sileo.app', '/usr/libexec/cydia', '/var/lib/cydia', '/private/var/stash'];

    // Hook NSFileManager fileExistsAtPath for jailbreak paths
    installHook('NSFileManager.fileExistsAtPath', function() {
      var NSFileManager = ObjC.classes.NSFileManager;
      Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
        onEnter: function(args) {
          this.path = new ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
          if (jailbreakPaths.some(function(p) { return this.path.indexOf(p) !== -1; }.bind(this))) {
            retval.replace(0);
            send({ status: 'bypassed', method: 'NSFileManager.fileExistsAtPath', blocked: this.path, platform: 'ios' });
          }
        }
      });
    });

    // Hook fork
    installHook('fork', function() {
      var fork = findExport('libSystem.B.dylib', 'fork');
      if (!fork) throw new Error('fork export not found');
      Interceptor.replace(fork, new NativeCallback(function() {
        send({ status: 'bypassed', method: 'fork', platform: 'ios' });
        return -1;
      }, 'int', []));
    });

    // Hook UIApplication.canOpenURL to block jailbreak URL schemes
    installHook('UIApplication.canOpenURL', function() {
      var blockedSchemes = ['cydia://', 'sileo://', 'zbra://', 'filza://', 'activator://'];
      if (!ObjC.classes.UIApplication) throw new Error('UIApplication class not loaded');
      Interceptor.attach(ObjC.classes.UIApplication['- canOpenURL:'].implementation, {
        onEnter: function(args) {
          try {
            var url = new ObjC.Object(args[2]).toString();
            this.blocked = blockedSchemes.some(function(s) { return url.indexOf(s) === 0; });
          } catch (e) { this.blocked = false; }
        },
        onLeave: function(retval) {
          if (this.blocked) {
            retval.replace(ptr(0));
            send({ status: 'blocked', method: 'canOpenURL', platform: 'ios' });
          }
        }
      });
    }, reportSkipped('canOpenURL'));

    // Native stat hook — hide jailbreak paths
    hookNative('libSystem.B.dylib', 'stat', {
      onEnter: function(args) {
        try {
          var path = args[0].readUtf8String();
          this.block = path && jailbreakPaths.some(function(p) { return path.indexOf(p) >= 0; });
        } catch (e) { this.block = false; }
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
          var namelen = args[1].toInt32();
          var mib0 = mib.readS32();
          var mib1 = mib.add(4).readS32();
          var mib2 = namelen > 2 ? mib.add(8).readS32() : -1;
          // The anti-debug check is sysctl({CTL_KERN, KERN_PROC, KERN_PROC_PID, pid}); only that
          // form returns a single kinfo_proc whose p_flag we can patch at a fixed offset.
          // KERN_PROC_ALL and friends return an array and must not be touched this way.
          this.isProcPidQuery = (mib0 === 1 && mib1 === 14 && mib2 === 1); // CTL_KERN, KERN_PROC, KERN_PROC_PID
          this.oldp = args[2]; // oldp: pointer to the kinfo_proc the caller receives
        } catch (e) { this.isProcPidQuery = false; }
      },
      onLeave: function(retval) {
        if (!this.isProcPidQuery) return;
        try {
          // Only a successful call has a fully populated kinfo_proc to read/patch.
          if (retval.toInt32() !== 0 || !this.oldp || this.oldp.isNull()) {
            send({ status: 'detected', method: 'sysctl.KERN_PROC_PID', platform: 'ios' });
            return;
          }
          if (bypassDebugger) {
            // kinfo_proc.kp_proc.p_flag sits at offset 0x20 on 64-bit Darwin; P_TRACED = 0x800.
            var P_TRACED = 0x800;
            var pFlagPtr = this.oldp.add(0x20);
            var flags = pFlagPtr.readU32();
            if (flags & P_TRACED) {
              pFlagPtr.writeU32(flags & ~P_TRACED);
              send({ status: 'bypassed', method: 'sysctl.KERN_PROC_PID', detail: 'cleared P_TRACED', platform: 'ios' });
            } else {
              send({ status: 'detected', method: 'sysctl.KERN_PROC_PID', detail: 'P_TRACED not set', platform: 'ios' });
            }
          } else {
            // Report-only by default; enable bypass_debugger to strip P_TRACED (may be unstable).
            send({ status: 'detected', method: 'sysctl.KERN_PROC_PID', platform: 'ios' });
          }
        } catch (e) {}
      }
    });

    send({ status: 'complete', platform: 'ios' });
  }
`);

export const rootJailbreakBypassTemplate: ScriptTemplate = {
  name: 'root_jailbreak_bypass',
  description: 'Bypass root detection (Android) and jailbreak detection (iOS). Hooks common detection methods.',
  platforms: ['android', 'ios'],
  category: 'bypass',
  riskTier: 2,
  options: {
    bypass_debugger: {
      type: 'boolean',
      description: 'iOS only: actively strip the P_TRACED flag in sysctl(KERN_PROC) results to defeat anti-debug checks. Off by default (report-only), because patching the returned struct can be unstable.',
      default: false,
    },
  },
  generate: () => BODY,
};
