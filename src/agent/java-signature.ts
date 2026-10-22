/**
 * Java method-signature vocabulary shared by hook_method (overload selection) and
 * describe_class (signature output), so a signature copied from jadx / JEB / Ghidra /
 * a JVM descriptor / describe_class can be handed straight to a hook.
 *
 * Canonical type form = what Frida reports as `overload.argumentTypes[i].className`
 * (== `java.lang.Class#getName()`):
 *   primitives   int, byte, boolean, ...
 *   classes      java.lang.String, com.example.Outer$Inner
 *   arrays       [B, [I, [[B, [Ljava.lang.String;
 * An unqualified class name (`String`) is kept unqualified (`String`, `[LString;`); the
 * agent matches it against the runtime type by simple name.
 *
 * Accepted input forms:
 *   source       byte[], java.lang.String[], int[][], String, String... (varargs)
 *   binary       [B, [Ljava.lang.String;
 *   descriptor   I, Ljava/lang/String;, [Ljava/lang/String;
 */

export interface ParsedJavaSignature {
  /** Method name, if the signature carried one (`<init>` is reported as Frida's `$init`). */
  name?: string;
  /** Canonical parameter types (see module doc). */
  argTypes: string[];
  /** Canonical return type, if the signature carried one. */
  returnType?: string;
}

const DESCRIPTOR_TO_PRIMITIVE: Readonly<Record<string, string>> = {
  Z: 'boolean', B: 'byte', C: 'char', S: 'short', I: 'int', J: 'long', F: 'float', D: 'double', V: 'void',
};

const PRIMITIVE_TO_DESCRIPTOR: Readonly<Record<string, string>> = Object.fromEntries(
  Object.entries(DESCRIPTOR_TO_PRIMITIVE).map(([descriptor, primitive]) => [primitive, descriptor])
);

/** Dotted (or slashed) Java class name; `$` covers inner classes and Kotlin/obfuscator names. */
const CLASS_NAME_PATTERN = /^[A-Za-z_$][\w$]*([./][A-Za-z_$][\w$]*)*$/;
const METHOD_NAME_PATTERN = /^[A-Za-z_$][\w$]*$/;

/** Declaration keywords dropped from `public static byte[] encrypt(final byte[] data)`. */
const MODIFIERS = new Set([
  'public', 'protected', 'private', 'static', 'final', 'abstract', 'synchronized', 'native',
  'strictfp', 'default', 'transient', 'volatile', 'synthetic', 'bridge', 'varargs',
]);

/** Remove `<...>` generic sections (nested), e.g. `Map<String, List<Integer>>` -> `Map`. */
function stripGenerics(text: string): string {
  let out = '';
  let depth = 0;
  for (const ch of text) {
    if (ch === '<') depth++;
    else if (ch === '>') {
      if (depth === 0) throw new Error(`Unbalanced '>' in Java signature: ${text}`);
      depth--;
    } else if (depth === 0) out += ch;
  }
  if (depth !== 0) throw new Error(`Unbalanced '<' in Java signature: ${text}`);
  return out;
}

/** Drop annotations (`@NonNull`, `@Foo(x = 1)`). */
function stripAnnotations(text: string): string {
  return text.replace(/@[\w$.]+(\([^)]*\))?/g, ' ');
}

/** Glue `[]` / `...` onto the preceding token: `String [] x` -> `String[] x`. */
function glueArraySuffixes(text: string): string {
  return text.replace(/\s+(?=\[\]|\.\.\.)/g, '').replace(/(\[\])\s+(?=\[\])/g, '$1');
}

function tokens(text: string): string[] {
  return glueArraySuffixes(text).split(/\s+/).filter((t) => t.length > 0 && !MODIFIERS.has(t));
}

/** `[[Ljava/lang/String;` / `[B` -> canonical binary form. */
function normalizeBinaryArray(text: string): string {
  const dims = text.length - text.replace(/^\[+/, '').length;
  const element = text.slice(dims);
  if (element.length === 1 && element in DESCRIPTOR_TO_PRIMITIVE && element !== 'V') {
    return '['.repeat(dims) + element;
  }
  if (element.startsWith('L') && element.endsWith(';')) {
    const className = element.slice(1, -1);
    if (CLASS_NAME_PATTERN.test(className)) return `${'['.repeat(dims)}L${className.replace(/\//g, '.')};`;
  }
  throw new Error(`Invalid Java array type: ${text}`);
}

/** `byte[][]` / `String...` / `java.lang.String` -> canonical form. */
function normalizeSourceType(text: string): string {
  const varargs = text.endsWith('...');
  let base = varargs ? text.slice(0, -3) : text;
  let dims = varargs ? 1 : 0;
  while (base.endsWith('[]')) {
    base = base.slice(0, -2);
    dims++;
  }
  const isPrimitive = base in PRIMITIVE_TO_DESCRIPTOR;
  if (!isPrimitive && !CLASS_NAME_PATTERN.test(base)) throw new Error(`Invalid Java type: ${text}`);
  const dotted = base.replace(/\//g, '.');
  if (dims === 0) return dotted;
  if (base === 'void') throw new Error(`Invalid Java type: ${text}`);
  return '['.repeat(dims) + (isPrimitive ? PRIMITIVE_TO_DESCRIPTOR[base] : `L${dotted};`);
}

/**
 * Normalise one Java type (source, binary or JVM-descriptor element form) to the
 * canonical `Class#getName()` form. Throws on malformed input.
 */
export function normalizeJavaType(type: string): string {
  const text = stripGenerics(type).replace(/\s+/g, '');
  if (text.length === 0) throw new Error('Java type cannot be empty');
  if (text.startsWith('[')) return normalizeBinaryArray(text);
  if (text.length === 1 && text in DESCRIPTOR_TO_PRIMITIVE) return DESCRIPTOR_TO_PRIMITIVE[text];
  if (/^L.+;$/.test(text)) {
    const className = text.slice(1, -1);
    if (!CLASS_NAME_PATTERN.test(className)) throw new Error(`Invalid Java type: ${type}`);
    return className.replace(/\//g, '.');
  }
  return normalizeSourceType(text);
}

/** Canonical type -> Java source form: `[B` -> `byte[]`, `[Ljava.lang.String;` -> `java.lang.String[]`. */
export function javaTypeToSource(canonical: string): string {
  const element = canonical.replace(/^\[+/, '');
  const dims = canonical.length - element.length;
  if (dims === 0) return canonical;
  const base = element.startsWith('L') && element.endsWith(';')
    ? element.slice(1, -1)
    : DESCRIPTOR_TO_PRIMITIVE[element];
  if (!base) throw new Error(`Invalid canonical Java type: ${canonical}`);
  return base + '[]'.repeat(dims);
}

/**
 * Parse a run of JVM descriptor types (`[BLjava/lang/String;I`) into canonical types.
 * Returns null when the text is not a valid descriptor run, so callers can fall back.
 */
function parseDescriptorRun(text: string, allowVoid = false): string[] | null {
  const types: string[] = [];
  let i = 0;
  while (i < text.length) {
    let dims = 0;
    while (text[i] === '[') { dims++; i++; }
    const ch = text[i];
    if (ch === 'L') {
      const end = text.indexOf(';', i);
      if (end < 0) return null;
      const className = text.slice(i + 1, end);
      if (!CLASS_NAME_PATTERN.test(className)) return null;
      types.push(dims > 0 ? `${'['.repeat(dims)}L${className.replace(/\//g, '.')};` : className.replace(/\//g, '.'));
      i = end + 1;
    } else if (ch !== undefined && ch in DESCRIPTOR_TO_PRIMITIVE && (ch !== 'V' || (allowVoid && dims === 0))) {
      types.push(dims > 0 ? '['.repeat(dims) + ch : DESCRIPTOR_TO_PRIMITIVE[ch]);
      i++;
    } else {
      return null;
    }
  }
  return types;
}

/** One comma-separated parameter: `final byte[] data`, `String key`, `@NonNull int[] x`. */
function parseParameter(param: string, signature: string): string {
  const parts = tokens(param);
  if (parts.length === 0 || parts.length > 2) {
    throw new Error(`Cannot parse parameter "${param.trim()}" in Java signature: ${signature}`);
  }
  return normalizeJavaType(parts[0]);
}

function parseParameterList(inside: string, signature: string): string[] {
  const compact = inside.replace(/\s+/g, '');
  if (compact.length === 0) return [];
  // A descriptor run (`[BLjava/lang/String;`) has no commas or blanks; try it first.
  if (!inside.includes(',') && !/\S\s+\S/.test(inside.trim())) {
    const descriptor = parseDescriptorRun(compact);
    if (descriptor) return descriptor;
  }
  return inside.split(',').map((param) => parseParameter(param, signature));
}

/** `byte[] encrypt` / `encrypt` / `` -> name + optional return type. */
function parseHead(head: string, signature: string): Pick<ParsedJavaSignature, 'name' | 'returnType'> {
  const parts = tokens(head);
  if (parts.length === 0) return {};
  if (parts.length > 2) throw new Error(`Cannot parse method name in Java signature: ${signature}`);
  const name = parts[parts.length - 1];
  if (!METHOD_NAME_PATTERN.test(name)) throw new Error(`Invalid Java method name "${name}" in signature: ${signature}`);
  return parts.length === 2 ? { name, returnType: normalizeJavaType(parts[0]) } : { name };
}

/** Text after `)`: a descriptor return type, a `throws ...` clause, or nothing. */
function parseTail(tail: string, signature: string): string | undefined {
  const text = tail.replace(/;$/, '').trim();
  if (text.length === 0 || /^throws\b/.test(text)) return undefined;
  const run = parseDescriptorRun(text.replace(/\s+/g, ''), true);
  if (!run || run.length !== 1) throw new Error(`Unexpected text after ')' in Java signature: ${signature}`);
  return run[0];
}

/**
 * Parse a Java method signature in any of the common notations:
 *   `encrypt(byte[], java.lang.String)`          source form (jadx, describe_class)
 *   `encrypt([B,java.lang.String)`               Frida / Class#getName form
 *   `(byte[])`                                   no name
 *   `public static byte[] encrypt(byte[] data, String key) throws Exception`
 *   `encrypt([BLjava/lang/String;)[B`, `([B)V`   JVM descriptor (smali, Ghidra)
 *   `name()`                                     zero arguments
 * Generics are stripped; `<init>` is reported as Frida's `$init`. Throws on malformed input.
 */
export function parseJavaSignature(signature: string): ParsedJavaSignature {
  const source = (signature ?? '').trim().replace(/<(cl)?init>/g, (m) => (m === '<init>' ? '$init' : '$clinit'));
  const text = stripGenerics(stripAnnotations(source));
  const open = text.indexOf('(');
  const close = text.indexOf(')', open + 1);
  if (open < 0 || close < 0) {
    throw new Error(`Java signature must contain a parameter list in parentheses, e.g. "encrypt(byte[], java.lang.String)": ${signature}`);
  }
  if (text.indexOf('(', open + 1) >= 0 || text.indexOf(')', close + 1) >= 0) {
    throw new Error(`Java signature has more than one parameter list: ${signature}`);
  }
  const { name, returnType: declaredReturn } = parseHead(text.slice(0, open), signature);
  const argTypes = parseParameterList(text.slice(open + 1, close), signature);
  const descriptorReturn = parseTail(text.slice(close + 1), signature);
  if (declaredReturn && descriptorReturn) {
    throw new Error(`Java signature gives the return type twice: ${signature}`);
  }
  const returnType = declaredReturn ?? descriptorReturn;
  return {
    ...(name !== undefined ? { name } : {}),
    argTypes,
    ...(returnType !== undefined ? { returnType } : {}),
  };
}

/** `name(type, type)` in Java source form; round-trips through parseJavaSignature. */
export function formatJavaSignature(name: string, argTypes: readonly string[]): string {
  return `${name}(${argTypes.map(javaTypeToSource).join(', ')})`;
}
