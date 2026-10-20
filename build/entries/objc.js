// Entry for the Objective-C bridge bundle (see java.js for the rationale).
import ObjC from 'frida-objc-bridge';

Object.defineProperty(globalThis, 'ObjC', { value: ObjC, writable: true, configurable: true, enumerable: true });
