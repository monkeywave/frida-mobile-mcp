import type { Recipe } from './types.js';

/**
 * Recipe: trace iOS Keychain reads and writes.
 *
 * Hooks the Security.framework C functions SecItemAdd/SecItemCopyMatching/SecItemUpdate so
 * you can see which keychain items (accounts, tokens, keys) the app stores and retrieves.
 * The arguments are CFDictionary queries; this logs the call and the result status, which is
 * enough to spot which items matter — adapt to parse the CFDictionary when you need values.
 */
const KEYCHAIN_SOURCE = `
(function () {
  if (typeof ObjC === 'undefined' || !ObjC.available) { send({ type: 'error', error: 'Objective-C runtime not available' }); return; }

  var fns = ['SecItemAdd', 'SecItemCopyMatching', 'SecItemUpdate', 'SecItemDelete'];
  var installed = [];
  fns.forEach(function (name) {
    var addr = findExport('Security', name) || findExport(null, name);
    if (addr === null) { send({ type: 'skipped', api: name, reason: 'export not found' }); return; }
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.info = { type: 'keychain', api: name };
        try {
          var dict = new ObjC.Object(args[0]);
          this.info.query = dict.toString();
        } catch (e) {}
      },
      onLeave: function (retval) {
        this.info.status = retval.toInt32(); // OSStatus; 0 == errSecSuccess
        send(this.info);
      }
    });
    installed.push(name);
  });
  send({ type: 'installed', api: 'keychain', functions: installed });
})();
`;

export const keychainRecipe: Recipe = {
  name: 'ios-keychain-trace',
  title: 'Trace iOS Keychain access',
  purpose: 'Log SecItemAdd/CopyMatching/Update/Delete calls with their query dictionaries and OSStatus, to see which keychain items the app stores and reads.',
  platforms: ['ios'],
  tags: ['keychain', 'ios', 'security', 'secitem', 'credentials', 'objc'],
  options: [],
  source: KEYCHAIN_SOURCE,
  usage:
    'Run with execute_script (classic) on iOS. Each keychain message carries the CFDictionary query and OSStatus; extend the onEnter to read specific keys (kSecAttrAccount, kSecValueData) when you need the stored values.',
};
