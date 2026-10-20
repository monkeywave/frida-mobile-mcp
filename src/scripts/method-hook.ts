import type { ScriptTemplate } from '../types.js';
import { buildTemplateBody } from './template-body.js';

const BODY = buildTemplateBody('method_hook', `
  var o = templateOptions();
  var className = String(o.class_name || '');
  var methodName = String(o.method_name || '');
  var logBacktrace = o.log_backtrace === true;
  var label = className + '.' + methodName;
  var hasTarget = Boolean(className && methodName);

  if (!className || !methodName) {
    send({ status: 'error', error: 'class_name and method_name are required' });
  }

  function nativeBacktrace(context) {
    try {
      return Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).map(function(s) { return s.toString(); });
    } catch (e) {
      return [];
    }
  }

  function javaBacktrace() {
    try {
      var Log = Java.use('android.util.Log');
      var Exception = Java.use('java.lang.Exception');
      return Log.getStackTraceString(Exception.$new());
    } catch (e) {
      return '';
    }
  }

  if (Java.available && hasTarget) {
    Java.perform(function() {
      installHook(label, function() {
        var cls = Java.use(className);
        cls[methodName].overloads.forEach(function(overload) {
          overload.implementation = function() {
            var args = [];
            for (var i = 0; i < arguments.length; i++) {
              try { args.push(String(arguments[i])); } catch (e) { args.push('<err>'); }
            }
            var retval = overload.apply(this, arguments);
            var info = { method: label, args: args };
            try { info.retval = String(retval); } catch (e) { info.retval = '<err>'; }
            if (logBacktrace) info.backtrace = javaBacktrace();
            send(info);
            return retval;
          };
        });
        send({ status: 'hooked', method: label });
      }, function(e) { send({ status: 'error', error: e.message }); });
    });
  }

  // ObjC method hooking
  if (ObjC.available && hasTarget) {
    installHook(label, function() {
      var cls = ObjC.classes[className];
      if (!(cls && cls[methodName])) {
        throw new Error('ObjC method not found: ' + label);
      }
      Interceptor.attach(cls[methodName].implementation, {
        onEnter: function(args) {
          try {
            var info = { method: label, args: [] };
            // ObjC args start at index 2 (self, _cmd, ...)
            for (var i = 2; i < Math.min(args.length || 6, 8); i++) {
              try { info.args.push(new ObjC.Object(args[i]).toString()); } catch (e) { info.args.push(String(args[i])); }
            }
            if (logBacktrace) info.backtrace = nativeBacktrace(this.context);
            send(info);
          } catch (e) {}
        }
      });
      send({ status: 'hooked', method: label, type: 'objc' });
    }, function(e) { send({ status: 'error', error: e.message, type: 'objc' }); });
  }
`);

export const methodHookTemplate: ScriptTemplate = {
  name: 'method_hook',
  description: 'Generic method hook with argument and return value logging. Works for Java, ObjC, and native methods.',
  platforms: ['android', 'ios'],
  category: 'security',
  riskTier: 1,
  options: {
    class_name: { type: 'string', description: 'Class name', required: true },
    method_name: { type: 'string', description: 'Method name', required: true },
    log_backtrace: { type: 'boolean', description: 'Log call backtrace', default: false },
  },
  generate: () => BODY,
};
