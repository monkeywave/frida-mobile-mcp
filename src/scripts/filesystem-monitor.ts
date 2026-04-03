import type { ScriptTemplate } from '../types.js';
import { escapeForScript } from '../helpers/sanitize.js';
import { getFridaRuntime } from './frida-runtime.js';

export const filesystemMonitorTemplate: ScriptTemplate = {
  name: 'filesystem_monitor',
  description: 'Monitor file system I/O operations: open, read, write, unlink. Logs file paths and data sizes.',
  platforms: ['android', 'ios'],
  category: 'filesystem',
  riskTier: 1,
  options: {
    filter_path: { type: 'string', description: 'Regex filter for file paths' },
    log_data: { type: 'boolean', description: 'Log file data content', default: false },
  },
  generate: (options) => {
    const filterPath = options.filter_path ? escapeForScript(String(options.filter_path)) : '';
    return `
    (function() {
      ${getFridaRuntime()}
      ${filterPath ? `var pathFilter = new RegExp('${filterPath}');` : 'var pathFilter = null;'}

      // Hook open
      hookNative(null, 'open', {
        onEnter: function(args) {
          try {
            this.path = args[0].readUtf8String();
            this.flags = args[1].toInt32();
          } catch(e) { this.path = null; }
        },
        onLeave: function(retval) {
          if (this.path && (!pathFilter || pathFilter.test(this.path))) {
            send({ api: 'open', path: this.path, flags: this.flags, fd: retval.toInt32() });
          }
        }
      });

      // Hook read
      hookNative(null, 'read', {
        onEnter: function(args) { this.fd = args[0].toInt32(); this.size = args[2].toInt32(); },
        onLeave: function(retval) {
          var bytesRead = retval.toInt32();
          if (bytesRead > 0) {
            send({ api: 'read', fd: this.fd, requested: this.size, read: bytesRead });
          }
        }
      });

      // Hook write
      hookNative(null, 'write', {
        onEnter: function(args) { this.fd = args[0].toInt32(); this.size = args[2].toInt32(); },
        onLeave: function(retval) {
          send({ api: 'write', fd: this.fd, size: this.size, written: retval.toInt32() });
        }
      });

      // Hook unlink
      hookNative(null, 'unlink', {
        onEnter: function(args) {
          try {
            var path = args[0].readUtf8String();
            if (!pathFilter || pathFilter.test(path)) {
              send({ api: 'unlink', path: path });
            }
          } catch(e) {}
        }
      });

      // openat — modern POSIX replacement for open
      hookNative(null, 'openat', {
        onEnter: function(args) {
          try { this.path = args[1].readUtf8String(); this.flags = args[2].toInt32(); } catch(e) { this.path = null; }
        },
        onLeave: function(retval) {
          if (this.path && (!pathFilter || pathFilter.test(this.path))) {
            send({ api: 'openat', path: this.path, flags: this.flags, fd: retval.toInt32() });
          }
        }
      });

      // stat — file existence checks
      hookNative(null, 'stat', {
        onEnter: function(args) {
          try { this.path = args[0].readUtf8String(); } catch(e) { this.path = null; }
        },
        onLeave: function(retval) {
          if (this.path && (!pathFilter || pathFilter.test(this.path))) {
            send({ api: 'stat', path: this.path, result: retval.toInt32() === 0 ? 'exists' : 'not_found' });
          }
        }
      });

      // lstat
      hookNative(null, 'lstat', {
        onEnter: function(args) {
          try { this.path = args[0].readUtf8String(); } catch(e) { this.path = null; }
        },
        onLeave: function(retval) {
          if (this.path && (!pathFilter || pathFilter.test(this.path))) {
            send({ api: 'lstat', path: this.path, result: retval.toInt32() === 0 ? 'exists' : 'not_found' });
          }
        }
      });

      // SQLite3 monitoring
      hookNative(null, 'sqlite3_open', {
        onEnter: function(args) {
          try { this.path = args[0].readUtf8String(); } catch(e) { this.path = null; }
        },
        onLeave: function(retval) {
          if (this.path) send({ api: 'sqlite3_open', path: this.path, result: retval.toInt32() === 0 ? 'success' : 'error' });
        }
      });

      hookNative(null, 'sqlite3_exec', {
        onEnter: function(args) {
          try { this.sql = args[1].readUtf8String(); } catch(e) { this.sql = null; }
        },
        onLeave: function(retval) {
          if (this.sql) send({ api: 'sqlite3_exec', sql: this.sql.substring(0, 200), result: retval.toInt32() === 0 ? 'success' : 'error' });
        }
      });

      // Android ContentResolver hooks
      if (Java && Java.available) {
        Java.perform(function() {
          var ContentResolver = Java.use('android.content.ContentResolver');
          try {
            ContentResolver.openInputStream.overload('android.net.Uri').implementation = function(uri) {
              send({ api: 'ContentResolver.openInputStream', uri: uri.toString() });
              return this.openInputStream(uri);
            };
          } catch(e) {}
          try {
            ContentResolver.openOutputStream.overload('android.net.Uri').implementation = function(uri) {
              send({ api: 'ContentResolver.openOutputStream', uri: uri.toString() });
              return this.openOutputStream(uri);
            };
          } catch(e) {}
        });
      }

      // iOS NSFileManager hooks
      if (ObjC && ObjC.available) {
        try {
          var NSFileManager = ObjC.classes.NSFileManager;
          Interceptor.attach(NSFileManager['- contentsOfDirectoryAtPath:error:'].implementation, {
            onEnter: function(args) { this.path = ObjC.Object(args[2]).toString(); },
            onLeave: function(retval) {
              send({ api: 'NSFileManager.contentsOfDirectoryAtPath', path: this.path });
            }
          });
        } catch(e) {}
        try {
          Interceptor.attach(NSFileManager['- createFileAtPath:contents:attributes:'].implementation, {
            onEnter: function(args) {
              send({ api: 'NSFileManager.createFileAtPath', path: ObjC.Object(args[2]).toString() });
            }
          });
        } catch(e) {}
      }

      reportSummary('filesystem_monitor');
    })();
    `;
  },
};
