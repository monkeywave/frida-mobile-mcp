import type { Recipe } from './types.js';

/**
 * Recipe: hook a native export and dump its arguments.
 *
 * Uses the preamble's findExport() (Frida 17 instance API) to resolve the symbol, then
 * Interceptor.attach. A bounded number of pointer-sized args is logged; adapt the arg
 * handling (readUtf8String / readByteArray) once you know the signature.
 */
const NATIVE_EXPORT_SOURCE = `
(function () {
  var o = __FRIDA_MCP__.options || {};
  var lib = o.module || null;       // e.g. 'libnative-lib.so'; null = search all modules
  var symbol = o.symbol;            // e.g. 'Java_com_example_rc4demo_Rc4Native_encrypt'
  var argCount = typeof o.arg_count === 'number' ? o.arg_count : 4;
  var readString = o.read_string_arg; // optional index to read as a C string

  if (!symbol) { send({ type: 'error', error: 'symbol option is required' }); return; }

  var addr = findExport(lib, symbol);
  if (addr === null) {
    send({ type: 'error', error: 'export not found: ' + (lib || '*') + '!' + symbol });
    return;
  }

  Interceptor.attach(addr, {
    onEnter: function (args) {
      var dump = [];
      for (var i = 0; i < argCount; i++) {
        var entry = { index: i, ptr: args[i].toString() };
        if (readString === i) { try { entry.string = args[i].readUtf8String(); } catch (e) {} }
        dump.push(entry);
      }
      this.dump = dump;
    },
    onLeave: function (retval) {
      send({ type: 'native_call', module: lib, symbol: symbol, args: this.dump, retval: retval.toString() });
    }
  });
  send({ type: 'installed', symbol: symbol, address: addr.toString() });
})();
`;

export const nativeExportHookRecipe: Recipe = {
  name: 'native-export-hook',
  title: 'Hook a native export and dump its arguments',
  purpose: 'Attach to an exported native function by name and log its pointer arguments and return value.',
  platforms: ['android', 'ios'],
  tags: ['native', 'export', 'interceptor', 'so', 'dylib', 'jni'],
  options: [
    { name: 'symbol', description: 'Export name to hook.', required: true, example: 'SSL_read' },
    { name: 'module', description: 'Module to search; omit to search all modules.', required: false, example: 'libssl.so' },
    { name: 'arg_count', description: 'How many pointer args to log (default 4).', required: false, example: 4 },
    { name: 'read_string_arg', description: 'Arg index to also read as a UTF-8 C string.', required: false, example: 1 },
  ],
  source: NATIVE_EXPORT_SOURCE,
  usage:
    'Run with execute_script (classic). Use enumerate_exports to find the symbol first. For a known module-relative offset from Ghidra/IDA, prefer hook_method with evidence { module, offset } instead.',
};

/**
 * Recipe: discover native methods bound through JNI RegisterNatives.
 *
 * Many apps hide their native entry points by binding them dynamically with
 * RegisterNatives instead of exporting Java_* symbols. Hooking RegisterNatives reveals
 * the Java class/method each native pointer backs, so you can then hook the pointer.
 */
const REGISTER_NATIVES_SOURCE = `
(function () {
  var o = __FRIDA_MCP__.options || {};
  var addr = findExport('libart.so', 'RegisterNatives') || findExport(null, 'RegisterNatives');
  // Fall back to the dalvik export name on old runtimes.
  if (addr === null) addr = findExport('libdvm.so', 'dvmRegisterNative');
  if (addr === null) {
    // Scan libart.so exports for the demangled JNI RegisterNatives.
    try {
      var art = Process.findModuleByName('libart.so');
      if (art) {
        var exps = art.enumerateExports();
        for (var i = 0; i < exps.length; i++) {
          if (exps[i].name.indexOf('RegisterNatives') !== -1 && exps[i].name.indexOf('CheckJNI') === -1) { addr = exps[i].address; break; }
        }
      }
    } catch (e) {}
  }
  if (addr === null) { send({ type: 'error', error: 'RegisterNatives not found' }); return; }

  Interceptor.attach(addr, {
    onEnter: function (args) {
      // jint RegisterNatives(JNIEnv*, jclass, const JNINativeMethod*, jint)
      var methods = args[2];
      var count = args[3].toInt32();
      var list = [];
      for (var i = 0; i < count; i++) {
        var entry = methods.add(i * Process.pointerSize * 3);
        try {
          var name = entry.readPointer().readUtf8String();
          var sig = entry.add(Process.pointerSize).readPointer().readUtf8String();
          var fnPtr = entry.add(Process.pointerSize * 2).readPointer();
          list.push({ name: name, signature: sig, fnPtr: fnPtr.toString() });
        } catch (e) {}
      }
      send({ type: 'register_natives', count: count, methods: list });
    }
  });
  send({ type: 'installed', api: 'RegisterNatives', address: addr.toString() });
})();
`;

export const registerNativesRecipe: Recipe = {
  name: 'jni-register-natives',
  title: 'Reveal dynamically-bound JNI natives (RegisterNatives)',
  purpose: 'Hook JNI RegisterNatives to map each native function pointer to the Java class/method it backs, exposing hidden native entry points.',
  platforms: ['android'],
  tags: ['jni', 'native', 'registernatives', 'libart', 'obfuscation', 'java'],
  options: [],
  source: REGISTER_NATIVES_SOURCE,
  usage:
    'Run with execute_script (classic) early, ideally on a fresh spawn before the .so finishes registering (watch_loads helps). Each register_natives message lists name/signature/fnPtr; hook a reported fnPtr as an absolute address with hook_method.',
};
