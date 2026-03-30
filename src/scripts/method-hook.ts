import type { ScriptTemplate } from '../types.js';

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
    const className = options.class_name || '';
    const methodName = options.method_name || '';
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
    })();
    `;
  },
};
