import type { Recipe } from './types.js';

/**
 * Recipe: enumerate custom class loaders and the classes each can see.
 *
 * Packed/plugin/split-dex apps load code through loaders other than the default one, so a
 * target class is invisible to Java.use until you reach its loader. This lists every loaded
 * loader and (optionally) the classes matching a pattern per loader.
 */
const CLASSLOADER_SOURCE = `
(function () {
  var o = __FRIDA_MCP__.options || {};
  var listClasses = o.list_classes === true;

  if (typeof Java === 'undefined' || !Java.available) { send({ type: 'error', error: 'Java runtime not available' }); return; }

  var pattern = null;
  if (o.pattern) {
    try { pattern = new RegExp(o.pattern); }
    catch (e) { send({ type: 'error', error: 'invalid pattern regex: ' + e.message }); return; }
  }

  Java.perform(function () {
    var loaders = [];
    Java.enumerateClassLoaders({
      onMatch: function (loader) {
        var info = { loader: String(loader) };
        if (listClasses) {
          var classes = [];
          try {
            var factory = Java.ClassFactory.get(loader);
            factory.enumerateLoadedClasses({
              onMatch: function (name) { if (!pattern || pattern.test(name)) classes.push(name); },
              onComplete: function () {}
            });
          } catch (e) { info.error = e.message; }
          info.classes = classes.slice(0, 500);
          info.class_count = classes.length;
        }
        loaders.push(info);
      },
      onComplete: function () { send({ type: 'classloaders', count: loaders.length, loaders: loaders }); }
    });
  });
})();
`;

export const classloaderRecipe: Recipe = {
  name: 'custom-classloader-enum',
  title: 'Enumerate custom class loaders and their classes',
  purpose: 'List every loaded class loader (and optionally the classes each exposes) to find code hidden behind plugin/split-dex/packed loaders.',
  platforms: ['android'],
  tags: ['classloader', 'dex', 'packed', 'plugin', 'enumeration', 'java'],
  options: [
    { name: 'list_classes', description: 'Also list classes per loader (default false).', required: false, example: true },
    { name: 'pattern', description: 'Regex to filter class names when list_classes is set.', required: false, example: 'com\\.example\\..*' },
  ],
  source: CLASSLOADER_SOURCE,
  usage:
    'Run with execute_script (classic). Once you see which loader holds a class, hook_method / describe_class already resolve it automatically via the cross-loader lookup.',
};

/**
 * Recipe: trace incoming Intents and deep links.
 *
 * Hooks Activity.getIntent and Intent.getData so you can see how the app is launched and
 * what URI a deep link carries (a frequent entry point for logic and auth bugs).
 */
const INTENT_SOURCE = `
(function () {
  if (typeof Java === 'undefined' || !Java.available) { send({ type: 'error', error: 'Java runtime not available' }); return; }

  Java.perform(function () {
    try {
      var Activity = Java.use('android.app.Activity');
      Activity.getIntent.implementation = function () {
        var intent = this.getIntent();
        var info = { type: 'intent', source: 'Activity.getIntent', activity: this.getClass().getName() };
        try { info.action = intent.getAction(); } catch (e) {}
        try { var data = intent.getData(); if (data) info.data = data.toString(); } catch (e) {}
        try { info.component = String(this.getComponentName()); } catch (e) {}
        send(info);
        return intent;
      };
    } catch (e) { send({ type: 'skipped', api: 'Activity.getIntent', reason: e.message }); }

    try {
      var Intent = Java.use('android.content.Intent');
      Intent.getData.implementation = function () {
        var uri = this.getData();
        if (uri) send({ type: 'deeplink', source: 'Intent.getData', uri: uri.toString() });
        return uri;
      };
    } catch (e) { send({ type: 'skipped', api: 'Intent.getData', reason: e.message }); }

    send({ type: 'installed', api: 'intent-trace' });
  });
})();
`;

export const intentTraceRecipe: Recipe = {
  name: 'intent-deeplink-trace',
  title: 'Trace incoming Intents and deep links',
  purpose: 'Log the Intent action/data/component each Activity receives and every deep-link URI, to map launch and navigation entry points.',
  platforms: ['android'],
  tags: ['intent', 'deeplink', 'uri', 'activity', 'navigation', 'java'],
  options: [],
  source: INTENT_SOURCE,
  usage: 'Run with execute_script (classic), then drive the app or fire a deep link (mobile_action / adb am start). Each navigation is reported as an intent/deeplink message.',
};

/**
 * Recipe: expose a WebView's JavaScript bridge.
 *
 * Hooks WebView.addJavascriptInterface so you can see which native objects are exposed to
 * page JS under which name — a common bridge-to-native attack surface.
 */
const WEBVIEW_SOURCE = `
(function () {
  if (typeof Java === 'undefined' || !Java.available) { send({ type: 'error', error: 'Java runtime not available' }); return; }

  Java.perform(function () {
    try {
      var WebView = Java.use('android.webkit.WebView');
      WebView.addJavascriptInterface.implementation = function (obj, name) {
        var info = { type: 'js_interface', name: String(name) };
        try { info.object_class = obj.getClass().getName(); } catch (e) {}
        try {
          var methods = obj.getClass().getDeclaredMethods();
          var names = [];
          for (var i = 0; i < methods.length; i++) names.push(methods[i].getName());
          info.methods = names;
        } catch (e) {}
        send(info);
        return this.addJavascriptInterface(obj, name);
      };
      send({ type: 'installed', api: 'WebView.addJavascriptInterface' });
    } catch (e) { send({ type: 'error', error: e.message }); }
  });
})();
`;

export const webviewBridgeRecipe: Recipe = {
  name: 'webview-bridge',
  title: 'Expose a WebView JavaScript bridge',
  purpose: 'Report every native object exposed to page JavaScript via WebView.addJavascriptInterface, with the bridge name and callable methods.',
  platforms: ['android'],
  tags: ['webview', 'javascriptinterface', 'bridge', 'hybrid', 'java'],
  options: [],
  source: WEBVIEW_SOURCE,
  usage: 'Run with execute_script (classic) on spawn, before the WebView is created. Each js_interface message names the bridge and its methods callable from the page.',
};
