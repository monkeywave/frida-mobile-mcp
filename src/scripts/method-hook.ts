import type { ScriptTemplate } from '../types.js';
import { buildTemplateBody } from './template-body.js';
import { RESOLVE_TARGET_SNIPPET } from '../agent/address.js';

const BODY = buildTemplateBody('method_hook', `
  ${RESOLVE_TARGET_SNIPPET}

  var o = templateOptions();
  var className = String(o.class_name || '');
  var methodName = String(o.method_name || '');
  var target = String(o.target || '');
  var argCount = typeof o.arg_count === 'number' && o.arg_count >= 0 ? o.arg_count : 4;
  var logBacktrace = o.log_backtrace === true;
  var label = className + '.' + methodName;
  var hasManagedTarget = Boolean(className && methodName);
  var hasNativeTarget = Boolean(target);

  if (!hasManagedTarget && !hasNativeTarget) {
    send({ status: 'error', error: 'Provide class_name + method_name (Java/ObjC), or target (a native address like "libfoo.so!func", "libfoo.so+0x1234" or "0x...")' });
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

  if (Java.available && hasManagedTarget) {
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
            var info = { method: label, type: 'java', args: args };
            try { info.retval = String(retval); } catch (e) { info.retval = '<err>'; }
            if (logBacktrace) info.backtrace = javaBacktrace();
            send(info);
            return retval;
          };
        });
        send({ status: 'hooked', method: label, type: 'java' });
      }, function(e) { send({ status: 'error', error: e.message, type: 'java' }); });
    });
  }

  // ObjC method hooking
  if (ObjC.available && hasManagedTarget) {
    installHook(label, function() {
      var cls = ObjC.classes[className];
      if (!(cls && cls[methodName])) {
        throw new Error('ObjC method not found: ' + label);
      }
      Interceptor.attach(cls[methodName].implementation, {
        onEnter: function(args) {
          try {
            this.info = { method: label, type: 'objc', args: [] };
            // ObjC args start at index 2 (self, _cmd, ...)
            for (var i = 2; i < Math.min(args.length || 6, 8); i++) {
              try { this.info.args.push(new ObjC.Object(args[i]).toString()); } catch (e) { this.info.args.push(String(args[i])); }
            }
            if (logBacktrace) this.info.backtrace = symbolizeBacktrace(this.context, 16);
          } catch (e) {}
        },
        onLeave: function(retval) {
          try {
            var info = this.info || { method: label, type: 'objc', args: [] };
            try { info.retval = new ObjC.Object(retval).toString(); } catch (e) { info.retval = retval.toString(); }
            send(info);
          } catch (e) {}
        }
      });
      send({ status: 'hooked', method: label, type: 'objc' });
    }, function(e) { send({ status: 'error', error: e.message, type: 'objc' }); });
  }

  // Native method hooking: hook an exported function, module offset or absolute address.
  if (hasNativeTarget) {
    installHook(target, function() {
      var addr = resolveTarget(target);
      if (!addr) throw new Error('Native target not found: ' + target);
      Interceptor.attach(addr, {
        onEnter: function(args) {
          this.args = [];
          for (var i = 0; i < argCount; i++) {
            try { this.args.push(args[i].toString()); } catch (e) { this.args.push('<err>'); }
          }
          if (logBacktrace) this.bt = symbolizeBacktrace(this.context, 16);
        },
        onLeave: function(retval) {
          var info = { method: target, type: 'native', args: this.args };
          try { info.retval = retval.toString(); } catch (e) { info.retval = '<err>'; }
          if (logBacktrace && this.bt) info.backtrace = this.bt;
          send(info);
        }
      });
      send({ status: 'hooked', method: target, type: 'native' });
    }, function(e) { send({ status: 'error', error: e.message, type: 'native' }); });
  }
`);

export const methodHookTemplate: ScriptTemplate = {
  name: 'method_hook',
  description: 'Generic method hook with argument and return value logging. Hooks a Java/ObjC method (class_name + method_name) or a native function (target address like "libfoo.so!func").',
  platforms: ['android', 'ios'],
  category: 'security',
  riskTier: 1,
  options: {
    class_name: { type: 'string', description: 'Class name (Java/ObjC method hooking)' },
    method_name: { type: 'string', description: 'Method name (Java/ObjC method hooking)' },
    target: { type: 'string', description: 'Native target address (module!symbol, module+0xoffset, 0xaddress, or a bare global export). Alternative to class_name/method_name. Resolved once when the script loads, so the target module must already be loaded in the process (attach after the library loads, or spawn+resume past library load).' },
    arg_count: { type: 'number', description: 'Number of native arguments to log (native target only)', default: 4 },
    log_backtrace: { type: 'boolean', description: 'Log call backtrace', default: false },
  },
  generate: () => BODY,
};
