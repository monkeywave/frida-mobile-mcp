import type { ScriptTemplate } from '../types.js';

export const classEnumerationTemplate: ScriptTemplate = {
  name: 'class_enumeration',
  description: 'Enumerate all loaded Java classes (Android) or ObjC classes (iOS) with optional regex filter.',
  platforms: ['android', 'ios'],
  category: 'enumeration',
  riskTier: 1,
  options: {
    filter: { type: 'string', description: 'Regex pattern to filter class names', default: '.*' },
    limit: { type: 'number', description: 'Max classes to return', default: 500 },
  },
  generate: (options) => {
    const filter = options.filter || '.*';
    const limit = options.limit || 500;
    return `
    (function() {
      var re = new RegExp('${filter}');
      var results = [];
      if (Java && Java.available) {
        Java.perform(function() {
          Java.enumerateLoadedClasses({
            onMatch: function(name) {
              if (results.length < ${limit} && re.test(name)) results.push(name);
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
          if (re.test(name)) results.push(name);
        }
        send({ platform: 'ios', total: results.length, classes: results });
      }
    })();
    `;
  },
};
