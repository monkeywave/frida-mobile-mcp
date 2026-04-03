import type { ScriptTemplate } from '../types.js';
import { getFridaRuntime } from './frida-runtime.js';

export const keychainPrefsTemplate: ScriptTemplate = {
  name: 'keychain_prefs',
  description: 'Monitor iOS Keychain access (SecItemCopyMatching, SecItemAdd) and Android SharedPreferences operations.',
  platforms: ['android', 'ios'],
  category: 'security',
  riskTier: 1,
  options: {
    filter_key: { type: 'string', description: 'Filter by key name pattern' },
  },
  generate: (options) => {
    return `
    (function() {
      ${getFridaRuntime()}
      if (Java && Java.available) {
        Java.perform(function() {
          try {
            var SharedPreferences = Java.use('android.app.SharedPreferencesImpl');
            ['getString', 'getInt', 'getBoolean', 'getLong', 'getFloat'].forEach(function(method) {
              try {
                SharedPreferences[method].overloads.forEach(function(overload) {
                  overload.implementation = function() {
                    var key = arguments[0];
                    var retval = overload.apply(this, arguments);
                    send({ api: 'SharedPreferences.' + method, key: String(key), value: String(retval), operation: 'read' });
                    return retval;
                  };
                });
              } catch(e) {}
            });
            send({ status: 'hooked', api: 'SharedPreferences (read)' });
          } catch(e) {}

          try {
            var Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
            ['putString', 'putInt', 'putBoolean', 'putLong', 'putFloat'].forEach(function(method) {
              try {
                Editor[method].overloads.forEach(function(overload) {
                  overload.implementation = function() {
                    send({ api: 'SharedPreferences.' + method, key: String(arguments[0]), value: String(arguments[1]), operation: 'write' });
                    return overload.apply(this, arguments);
                  };
                });
              } catch(e) {}
            });
            send({ status: 'hooked', api: 'SharedPreferences (write)' });
          } catch(e) {}
        });
      }

      if (ObjC && ObjC.available) {
        // SecItemCopyMatching
        hookNative('Security', 'SecItemCopyMatching', {
          onEnter: function(args) {
            try {
              var query = new ObjC.Object(args[0]);
              this.query = query.toString();
            } catch(e) { this.query = 'unknown'; }
          },
          onLeave: function(retval) {
            send({ api: 'SecItemCopyMatching', query: this.query, result: retval.toInt32() === 0 ? 'found' : 'not_found', operation: 'read' });
          }
        });

        // SecItemAdd
        hookNative('Security', 'SecItemAdd', {
          onEnter: function(args) {
            try { this.attrs = new ObjC.Object(args[0]).toString(); } catch(e) { this.attrs = 'unknown'; }
          },
          onLeave: function(retval) {
            send({ api: 'SecItemAdd', attributes: this.attrs, result: retval.toInt32() === 0 ? 'success' : 'error', operation: 'write' });
          }
        });

        // NSUserDefaults
        try {
          var NSUserDefaults = ObjC.classes.NSUserDefaults;
          Interceptor.attach(NSUserDefaults['- objectForKey:'].implementation, {
            onEnter: function(args) { this.key = ObjC.Object(args[2]).toString(); },
            onLeave: function(retval) {
              var val = retval.isNull() ? null : new ObjC.Object(retval).toString();
              send({ api: 'NSUserDefaults.objectForKey', key: this.key, value: val, operation: 'read' });
            }
          });
          send({ status: 'hooked', api: 'NSUserDefaults' });
        } catch(e) {}

        // SecItemUpdate
        hookNative('Security', 'SecItemUpdate', {
          onEnter: function(args) {
            try { this.query = new ObjC.Object(args[0]).toString(); this.attrs = new ObjC.Object(args[1]).toString(); } catch(e) { this.query = 'unknown'; this.attrs = 'unknown'; }
          },
          onLeave: function(retval) {
            send({ api: 'SecItemUpdate', query: this.query, attributes: this.attrs, result: retval.toInt32() === 0 ? 'success' : 'error', operation: 'update' });
          }
        });

        // SecItemDelete
        hookNative('Security', 'SecItemDelete', {
          onEnter: function(args) {
            try { this.query = new ObjC.Object(args[0]).toString(); } catch(e) { this.query = 'unknown'; }
          },
          onLeave: function(retval) {
            send({ api: 'SecItemDelete', query: this.query, result: retval.toInt32() === 0 ? 'success' : 'error', operation: 'delete' });
          }
        });
      }
      reportSummary('keychain_prefs');
    })();
    `;
  },
};
