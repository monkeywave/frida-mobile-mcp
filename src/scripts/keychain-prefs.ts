import type { ScriptTemplate } from '../types.js';
import { buildTemplateBody } from './template-body.js';

const BODY = buildTemplateBody('keychain_prefs', `
  var o = templateOptions();
  var keyFilter = null;
  if (o.filter_key) {
    try { keyFilter = new RegExp(String(o.filter_key)); } catch (e) { send({ status: 'error', error: 'Invalid filter_key regex: ' + e.message }); }
  }

  function keyMatches(key) {
    return !keyFilter || keyFilter.test(String(key));
  }

  if (Java.available) {
    Java.perform(function() {
      installHook('SharedPreferences (read)', function() {
        var SharedPreferences = Java.use('android.app.SharedPreferencesImpl');
        ['getString', 'getInt', 'getBoolean', 'getLong', 'getFloat'].forEach(function(method) {
          try {
            SharedPreferences[method].overloads.forEach(function(overload) {
              overload.implementation = function() {
                var key = arguments[0];
                var retval = overload.apply(this, arguments);
                if (keyMatches(key)) {
                  send({ api: 'SharedPreferences.' + method, key: String(key), value: String(retval), operation: 'read' });
                }
                return retval;
              };
            });
          } catch (e) {}
        });
        send({ status: 'hooked', api: 'SharedPreferences (read)' });
      });

      installHook('SharedPreferences (write)', function() {
        var Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        ['putString', 'putInt', 'putBoolean', 'putLong', 'putFloat'].forEach(function(method) {
          try {
            Editor[method].overloads.forEach(function(overload) {
              overload.implementation = function() {
                if (keyMatches(arguments[0])) {
                  send({ api: 'SharedPreferences.' + method, key: String(arguments[0]), value: String(arguments[1]), operation: 'write' });
                }
                return overload.apply(this, arguments);
              };
            });
          } catch (e) {}
        });
        send({ status: 'hooked', api: 'SharedPreferences (write)' });
      });
    });
  }

  if (ObjC.available) {
    // SecItemCopyMatching
    hookNative('Security', 'SecItemCopyMatching', {
      onEnter: function(args) {
        try {
          var query = new ObjC.Object(args[0]);
          this.query = query.toString();
        } catch (e) { this.query = 'unknown'; }
      },
      onLeave: function(retval) {
        if (keyMatches(this.query)) {
          send({ api: 'SecItemCopyMatching', query: this.query, result: retval.toInt32() === 0 ? 'found' : 'not_found', operation: 'read' });
        }
      }
    });

    // SecItemAdd
    hookNative('Security', 'SecItemAdd', {
      onEnter: function(args) {
        try { this.attrs = new ObjC.Object(args[0]).toString(); } catch (e) { this.attrs = 'unknown'; }
      },
      onLeave: function(retval) {
        if (keyMatches(this.attrs)) {
          send({ api: 'SecItemAdd', attributes: this.attrs, result: retval.toInt32() === 0 ? 'success' : 'error', operation: 'write' });
        }
      }
    });

    // NSUserDefaults
    installHook('NSUserDefaults.objectForKey', function() {
      var NSUserDefaults = ObjC.classes.NSUserDefaults;
      Interceptor.attach(NSUserDefaults['- objectForKey:'].implementation, {
        onEnter: function(args) { this.key = new ObjC.Object(args[2]).toString(); },
        onLeave: function(retval) {
          if (!keyMatches(this.key)) return;
          var val = retval.isNull() ? null : new ObjC.Object(retval).toString();
          send({ api: 'NSUserDefaults.objectForKey', key: this.key, value: val, operation: 'read' });
        }
      });
      send({ status: 'hooked', api: 'NSUserDefaults' });
    });

    // SecItemUpdate
    hookNative('Security', 'SecItemUpdate', {
      onEnter: function(args) {
        try { this.query = new ObjC.Object(args[0]).toString(); this.attrs = new ObjC.Object(args[1]).toString(); } catch (e) { this.query = 'unknown'; this.attrs = 'unknown'; }
      },
      onLeave: function(retval) {
        if (keyMatches(this.query)) {
          send({ api: 'SecItemUpdate', query: this.query, attributes: this.attrs, result: retval.toInt32() === 0 ? 'success' : 'error', operation: 'update' });
        }
      }
    });

    // SecItemDelete
    hookNative('Security', 'SecItemDelete', {
      onEnter: function(args) {
        try { this.query = new ObjC.Object(args[0]).toString(); } catch (e) { this.query = 'unknown'; }
      },
      onLeave: function(retval) {
        if (keyMatches(this.query)) {
          send({ api: 'SecItemDelete', query: this.query, result: retval.toInt32() === 0 ? 'success' : 'error', operation: 'delete' });
        }
      }
    });
  }
`);

export const keychainPrefsTemplate: ScriptTemplate = {
  name: 'keychain_prefs',
  description: 'Monitor iOS Keychain access (SecItemCopyMatching, SecItemAdd) and Android SharedPreferences operations.',
  platforms: ['android', 'ios'],
  category: 'security',
  riskTier: 1,
  options: {
    filter_key: { type: 'string', description: 'Filter by key name pattern' },
  },
  generate: () => BODY,
};
