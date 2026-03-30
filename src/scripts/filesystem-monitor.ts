import type { ScriptTemplate } from '../types.js';

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
    const filterPath = options.filter_path || '';
    return `
    (function() {
      ${filterPath ? `var pathFilter = new RegExp('${filterPath}');` : 'var pathFilter = null;'}

      // Hook open
      try {
        var openFunc = Module.findExportByName(null, 'open');
        if (openFunc) {
          Interceptor.attach(openFunc, {
            onEnter: function(args) {
              this.path = args[0].readUtf8String();
              this.flags = args[1].toInt32();
            },
            onLeave: function(retval) {
              if (this.path && (!pathFilter || pathFilter.test(this.path))) {
                send({ api: 'open', path: this.path, flags: this.flags, fd: retval.toInt32() });
              }
            }
          });
          send({ status: 'hooked', api: 'open' });
        }
      } catch(e) {}

      // Hook read
      try {
        var readFunc = Module.findExportByName(null, 'read');
        if (readFunc) {
          Interceptor.attach(readFunc, {
            onEnter: function(args) { this.fd = args[0].toInt32(); this.size = args[2].toInt32(); },
            onLeave: function(retval) {
              var bytesRead = retval.toInt32();
              if (bytesRead > 0) {
                send({ api: 'read', fd: this.fd, requested: this.size, read: bytesRead });
              }
            }
          });
        }
      } catch(e) {}

      // Hook write
      try {
        var writeFunc = Module.findExportByName(null, 'write');
        if (writeFunc) {
          Interceptor.attach(writeFunc, {
            onEnter: function(args) { this.fd = args[0].toInt32(); this.size = args[2].toInt32(); },
            onLeave: function(retval) {
              send({ api: 'write', fd: this.fd, size: this.size, written: retval.toInt32() });
            }
          });
        }
      } catch(e) {}

      // Hook unlink
      try {
        var unlinkFunc = Module.findExportByName(null, 'unlink');
        if (unlinkFunc) {
          Interceptor.attach(unlinkFunc, {
            onEnter: function(args) {
              var path = args[0].readUtf8String();
              if (!pathFilter || pathFilter.test(path)) {
                send({ api: 'unlink', path: path });
              }
            }
          });
        }
      } catch(e) {}

      // Android ContentResolver hooks
      if (Java && Java.available) {
        Java.perform(function() {
          try {
            var ContentResolver = Java.use('android.content.ContentResolver');
            ContentResolver.openInputStream.overload('android.net.Uri').implementation = function(uri) {
              send({ api: 'ContentResolver.openInputStream', uri: uri.toString() });
              return this.openInputStream(uri);
            };
          } catch(e) {}
          try {
            var ContentResolver = Java.use('android.content.ContentResolver');
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
    })();
    `;
  },
};
