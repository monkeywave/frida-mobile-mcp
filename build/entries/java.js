// Entry for the Java bridge bundle. Bundled by build/bundle-bridges.mjs into a
// classic (non-module) IIFE that installs the bridge as a global, exactly like
// frida-tools 14 does for its REPL and frida-trace agents.
import Java from 'frida-java-bridge';

Object.defineProperty(globalThis, 'Java', { value: Java, writable: true, configurable: true, enumerable: true });
