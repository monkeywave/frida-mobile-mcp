import type { ScriptTemplate } from '../types.js';
import { buildTemplateBody } from './template-body.js';

const BODY = buildTemplateBody('class_enumeration', `
  var o = templateOptions();
  var limit = Number(o.limit) > 0 ? Number(o.limit) : 500;
  var includeMethods = o.include_methods === true;
  var re;
  try {
    re = new RegExp(String(o.filter || '.*'));
  } catch (e) {
    send({ status: 'error', error: 'Invalid filter regex: ' + e.message });
    re = new RegExp('.*');
  }
  var results = [];

  function describeJavaClass(name, entry) {
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
      } catch (e) {}
    } catch (e) {}
  }

  function describeObjCClass(name, entry) {
    try {
      var cls = ObjC.classes[name];
      if (cls.$ownMethods) {
        entry.methods = cls.$ownMethods.slice(0, 50);
      }
      if (cls.$superClass) entry.superclass = cls.$superClass.$className;
      if (cls.$protocols) {
        entry.protocols = Object.keys(cls.$protocols).slice(0, 20);
      }
    } catch (e) {}
  }

  if (Java.available) {
    Java.perform(function() {
      // Collect names first: Java.use() inside the enumerateLoadedClasses callback can
      // deadlock the process, so describe classes only after enumeration completed.
      Java.enumerateLoadedClasses({
        onMatch: function(name) {
          if (results.length < limit && re.test(name)) {
            results.push({ name: name });
          }
        },
        onComplete: function() {}
      });
      if (includeMethods) {
        for (var d = 0; d < results.length; d++) describeJavaClass(results[d].name, results[d]);
      }
      send({ platform: 'android', total: results.length, classes: results });
    });
  } else if (ObjC.available) {
    var names = objcClassNames();
    for (var k = 0; k < names.length; k++) {
      if (results.length >= limit) break;
      var className = names[k];
      if (re.test(className)) {
        var objcEntry = { name: className };
        if (includeMethods) describeObjCClass(className, objcEntry);
        results.push(objcEntry);
      }
    }
    send({ platform: 'ios', total: results.length, classes: results });
  } else {
    send({ status: 'error', error: 'Neither Java nor ObjC runtime is available in this process' });
  }
`);

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
  generate: () => BODY,
};
