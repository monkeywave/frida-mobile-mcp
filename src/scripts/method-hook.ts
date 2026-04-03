import type { ScriptTemplate } from '../types.js';
import { escapeForScript } from '../helpers/sanitize.js';

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
  generate: (options) => {
    const className = escapeForScript(String(options.class_name || ''));
    const methodName = escapeForScript(String(options.method_name || ''));
    const logBt = options.log_backtrace || false;
    return `
    (function() {
      if (Java && Java.available) {
        Java.perform(function() {
          try {
            var cls = Java.use('${className}');
            cls['${methodName}'].overloads.forEach(function(overload) {
              overload.implementation = function() {
                var args = [];
                for (var i = 0; i < arguments.length; i++) {
                  try { args.push(String(arguments[i])); } catch(e) { args.push('<err>'); }
                }
                var retval = overload.apply(this, arguments);
                var info = { method: '${className}.${methodName}', args: args };
                try { info.retval = String(retval); } catch(e) { info.retval = '<err>'; }
                ${logBt ? "info.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).map(function(s){return s.toString();});" : ''}
                send(info);
                return retval;
              };
            });
            send({ status: 'hooked', method: '${className}.${methodName}' });
          } catch(e) { send({ status: 'error', error: e.message }); }
        });
      }
      // ObjC method hooking
      if (ObjC && ObjC.available) {
        try {
          var cls = ObjC.classes['${className}'];
          if (cls && cls['${methodName}']) {
            Interceptor.attach(cls['${methodName}'].implementation, {
              onEnter: function(args) {
                try {
                  var info = { method: '${className}.${methodName}', args: [] };
                  // ObjC args start at index 2 (self, _cmd, ...)
                  for (var i = 2; i < Math.min(args.length || 6, 8); i++) {
                    try { info.args.push(new ObjC.Object(args[i]).toString()); } catch(e) { info.args.push(String(args[i])); }
                  }
                  ${logBt ? "try { info.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).map(function(s){return s.toString();}); } catch(e) {}" : ''}
                  send(info);
                } catch(e) {}
              }
            });
            send({ status: 'hooked', method: '${className}.${methodName}', type: 'objc' });
          }
        } catch(e) { send({ status: 'error', error: e.message, type: 'objc' }); }
      }
    })();
    `;
  },
};
