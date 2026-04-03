import type { ScriptTemplate } from '../types.js';
import { escapeForScript } from '../helpers/sanitize.js';

export const classEnumerationTemplate: ScriptTemplate = {
  name: 'class_enumeration',
  description: 'Enumerate all loaded Java classes (Android) or ObjC classes (iOS) with optional regex filter.',
  platforms: ['android', 'ios'],
  category: 'enumeration',
  riskTier: 1,
  options: {
    filter: { type: 'string', description: 'Regex pattern to filter class names', default: '.*' },
    limit: { type: 'number', description: 'Max classes to return', default: 500 },
    include_methods: { type: 'boolean', description: 'Include method names and inheritance info for each class', default: false },
  },
  generate: (options) => {
    const filter = escapeForScript(String(options.filter || '.*'));
    const limit = options.limit || 500;
    const includeMethods = options.include_methods === true;
    return `
    (function() {
      var re = new RegExp('${filter}');
      var results = [];
      if (Java && Java.available) {
        Java.perform(function() {
          Java.enumerateLoadedClasses({
            onMatch: function(name) {
              if (results.length < ${limit} && re.test(name)) {
                var entry = { name: name };
                ${includeMethods ? `
                try {
                  var cls = Java.use(name);
                  var methods = cls.class.getDeclaredMethods();
                  entry.methods = [];
                  for (var i = 0; i < Math.min(methods.length, 50); i++) {
                    entry.methods.push(methods[i].getName());
                  }
                  // Inheritance
                  try {
                    var superCls = cls.class.getSuperclass();
                    if (superCls) entry.superclass = superCls.getName();
                    var ifaces = cls.class.getInterfaces();
                    entry.interfaces = [];
                    for (var j = 0; j < ifaces.length; j++) entry.interfaces.push(ifaces[j].getName());
                  } catch(e) {}
                } catch(e) {}
                ` : ''}
                results.push(entry);
              }
            },
            onComplete: function() {
              send({ platform: 'android', total: results.length, classes: results });
            }
          });
        });
      } else if (ObjC && ObjC.available) {
        var classes = ObjC.enumerateLoadedClassesSync();
        for (var name in classes) {
          if (results.length >= ${limit}) break;
          if (re.test(name)) {
            var entry = { name: name };
            ${includeMethods ? `
            try {
              var cls = ObjC.classes[name];
              if (cls.$ownMethods) {
                entry.methods = cls.$ownMethods.slice(0, 50);
              }
              if (cls.$superClass) entry.superclass = cls.$superClass.$className;
              if (cls.$protocols) {
                entry.protocols = Object.keys(cls.$protocols).slice(0, 20);
              }
            } catch(e) {}
            ` : ''}
            results.push(entry);
          }
        }
        send({ platform: 'ios', total: results.length, classes: results });
      }
    })();
    `;
  },
};
