import { describe, it, expect } from 'vitest';
import {
  normalizeJavaType,
  javaTypeToSource,
  parseJavaSignature,
  formatJavaSignature,
} from '../../src/agent/java-signature.js';

describe('normalizeJavaType', () => {
  it.each([
    // primitives
    ['int', 'int'],
    ['boolean', 'boolean'],
    ['I', 'int'],
    ['Z', 'boolean'],
    // classes
    ['java.lang.String', 'java.lang.String'],
    ['Ljava/lang/String;', 'java.lang.String'],
    ['Ljava.lang.String;', 'java.lang.String'],
    ['com.example.Outer$Inner', 'com.example.Outer$Inner'],
    ['String', 'String'],
    // arrays, source form
    ['byte[]', '[B'],
    ['int[][]', '[[I'],
    ['java.lang.String[]', '[Ljava.lang.String;'],
    ['String[]', '[LString;'],
    ['byte [ ]', '[B'],
    // arrays, binary / descriptor form
    ['[B', '[B'],
    ['[[B', '[[B'],
    ['[Ljava.lang.String;', '[Ljava.lang.String;'],
    ['[Ljava/lang/String;', '[Ljava.lang.String;'],
    // varargs and generics
    ['String...', '[LString;'],
    ['java.lang.String...', '[Ljava.lang.String;'],
    ['java.util.List<java.lang.String>', 'java.util.List'],
    ['Map<String, List<Integer>>[]', '[LMap;'],
  ])('%s -> %s', (input, expected) => {
    expect(normalizeJavaType(input)).toBe(expected);
  });

  it.each(['', '   ', '[', '[V', '[X', '1abc', 'foo-bar', 'void[]', 'Lfoo;bar', 'List<String'])('rejects %j', (input) => {
    expect(() => normalizeJavaType(input)).toThrow();
  });
});

describe('javaTypeToSource', () => {
  it.each([
    ['int', 'int'],
    ['java.lang.String', 'java.lang.String'],
    ['[B', 'byte[]'],
    ['[[I', 'int[][]'],
    ['[Ljava.lang.String;', 'java.lang.String[]'],
    ['[LString;', 'String[]'],
  ])('%s -> %s', (input, expected) => {
    expect(javaTypeToSource(input)).toBe(expected);
  });

  it('rejects a malformed canonical array', () => {
    expect(() => javaTypeToSource('[X')).toThrow();
  });
});

describe('parseJavaSignature', () => {
  it('parses the source form', () => {
    expect(parseJavaSignature('encrypt(byte[], java.lang.String)')).toEqual({
      name: 'encrypt',
      argTypes: ['[B', 'java.lang.String'],
    });
  });

  it('parses the Frida / binary form', () => {
    expect(parseJavaSignature('encrypt([B,java.lang.String)')).toEqual({
      name: 'encrypt',
      argTypes: ['[B', 'java.lang.String'],
    });
  });

  it('parses a signature without a name', () => {
    expect(parseJavaSignature('(byte[])')).toEqual({ argTypes: ['[B'] });
  });

  it('parses a zero-argument signature', () => {
    expect(parseJavaSignature('start()')).toEqual({ name: 'start', argTypes: [] });
    expect(parseJavaSignature('()')).toEqual({ argTypes: [] });
  });

  it('parses a Java declaration with return type, parameter names and modifiers', () => {
    expect(parseJavaSignature('public static final byte[] encrypt(final byte[] data, String key) throws Exception;')).toEqual({
      name: 'encrypt',
      argTypes: ['[B', 'String'],
      returnType: '[B',
    });
  });

  it('parses annotations and generics in a declaration', () => {
    expect(parseJavaSignature('@Override public <T> java.util.List<T> wrap(@NonNull java.util.Map<String, T> m, int... xs)')).toEqual({
      name: 'wrap',
      argTypes: ['java.util.Map', '[I'],
      returnType: 'java.util.List',
    });
  });

  it('parses a JVM descriptor with and without a name', () => {
    expect(parseJavaSignature('encrypt([BLjava/lang/String;)[B')).toEqual({
      name: 'encrypt',
      argTypes: ['[B', 'java.lang.String'],
      returnType: '[B',
    });
    expect(parseJavaSignature('([BLjava/lang/String;)[B')).toEqual({
      argTypes: ['[B', 'java.lang.String'],
      returnType: '[B',
    });
    expect(parseJavaSignature('run(IJ[[Ljava/lang/Object;)V')).toEqual({
      name: 'run',
      argTypes: ['int', 'long', '[[Ljava.lang.Object;'],
      returnType: 'void',
    });
  });

  it('maps <init> to Frida\'s $init', () => {
    expect(parseJavaSignature('<init>(Ljava/lang/String;)V')).toEqual({
      name: '$init',
      argTypes: ['java.lang.String'],
      returnType: 'void',
    });
  });

  it('treats a single binary array argument as one type', () => {
    expect(parseJavaSignature('f([Ljava.lang.String;)')).toEqual({ name: 'f', argTypes: ['[Ljava.lang.String;'] });
  });

  it('parses unqualified and varargs parameters', () => {
    expect(parseJavaSignature('format(String, Object...)')).toEqual({
      name: 'format',
      argTypes: ['String', '[LObject;'],
    });
  });

  it.each([
    'encrypt',
    'encrypt(byte[]',
    'encrypt)byte[](',
    'a b c(int)',
    'com.example.C.encrypt(int)',
    'encrypt(int,)',
    'encrypt(byte[] data extra)',
    'encrypt(int) garbage',
    'byte[] encrypt(int)[B',
    'f(int)(int)',
    '',
  ])('rejects malformed %j', (input) => {
    expect(() => parseJavaSignature(input)).toThrow();
  });
});

describe('formatJavaSignature', () => {
  it('formats in Java source form', () => {
    expect(formatJavaSignature('encrypt', ['[B', 'java.lang.String'])).toBe('encrypt(byte[], java.lang.String)');
    expect(formatJavaSignature('start', [])).toBe('start()');
  });

  it.each([
    ['encrypt', ['[B', 'java.lang.String']],
    ['run', ['int', 'long', '[[Ljava.lang.Object;', '[LString;']],
    ['$init', []],
  ])('round-trips %s through parseJavaSignature', (name, argTypes) => {
    expect(parseJavaSignature(formatJavaSignature(name, argTypes))).toEqual({ name, argTypes });
  });
});
