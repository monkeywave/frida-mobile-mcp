/**
 * In-agent Java class lookup shared by every script that resolves an app class by name
 * (hook_method, describe_class, recipes).
 *
 * `Java.use(name)` only searches the default class loader, so a class loaded by a plugin,
 * split-dex or custom loader looks "missing". `useInAnyLoader(name)` falls back to walking
 * every loaded class loader and returns the first wrapper found, or `null`.
 *
 * Classic JS; must run inside `Java.perform` (or `javaPerform`).
 */
export const JAVA_CLASS_LOOKUP_SNIPPET = `
function useInAnyLoader(name) {
  try { return Java.use(name); } catch (first) { /* fall through to loader walk */ }
  var found = null;
  try {
    Java.enumerateClassLoaders({
      onMatch: function (loader) {
        if (found) return;
        try { found = Java.ClassFactory.get(loader).use(name); } catch (e) { /* not in this loader */ }
      },
      onComplete: function () {}
    });
  } catch (e) { /* enumerateClassLoaders unavailable */ }
  return found;
}
`;
