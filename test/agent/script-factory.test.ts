import { describe, it, expect } from 'vitest';
import {
  composeAgentSource,
  defaultBridgesFor,
  looksLikeEsModule,
  isFridaCompileBundle,
  FRIDA_COMPILE_BUNDLE_MARKER,
  type AgentPlatform,
} from '../../src/agent/script-factory.js';
import { ScriptError } from '../../src/helpers/errors.js';

const JAVA_BANNER = '/*! frida-java-bridge';
const OBJC_BANNER = '/*! frida-objc-bridge';
const JAVA_STUB = /defineProperty\(globalThis, 'Java', \{ value: \{ available: false \}/;
const OBJC_STUB = /defineProperty\(globalThis, 'ObjC', \{ value: \{ available: false \}/;

const PREAMBLE_START = '// === frida-mobile-mcp agent preamble ===';
const PREAMBLE_END = '// === end preamble ===';

function preambleOf(source: string): string {
  const start = source.indexOf(PREAMBLE_START);
  const end = source.indexOf(PREAMBLE_END);
  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  return source.slice(start, end + PREAMBLE_END.length);
}

function contextLiteralOf(source: string): Record<string, unknown> {
  // `[^\n]*` rather than `.*`: U+2028/2029 are line terminators for `.` but emitted raw by JSON.stringify.
  const m = source.match(/^globalThis\.__FRIDA_MCP__ = ([^\n]*);$/m);
  expect(m).not.toBeNull();
  return JSON.parse(m![1]) as Record<string, unknown>;
}

/** Extract the second argument of `Script.evaluate(name, source)` as the raw JSON text. */
function evaluateCallOf(source: string): { name: string; body: string } {
  const m = source.match(/^Script\.evaluate\(("(?:[^"\\]|\\.)*"), ("(?:[^"\\]|\\.)*")\);$/m);
  expect(m, 'Script.evaluate(...) call not found').not.toBeNull();
  return { name: JSON.parse(m![1]) as string, body: JSON.parse(m![2]) as string };
}

const GENERATED = 'rpc.exports.ping = function () { return "pong"; };';

function compose(platform: AgentPlatform, extra: Partial<Parameters<typeof composeAgentSource>[0]> = {}) {
  return composeAgentSource({ kind: 'generated', platform, name: `test:${platform}`, source: GENERATED, ...extra });
}

describe('defaultBridgesFor', () => {
  it.each([
    ['android', ['java']],
    ['ios', ['objc']],
    ['macos', ['objc']],
    ['linux', []],
    ['windows', []],
    ['unknown', []],
  ] as Array<[AgentPlatform, string[]]>)('%s -> %j', (platform, expected) => {
    expect(defaultBridgesFor(platform)).toEqual(expected);
  });
});

describe('composeAgentSource: bridge selection', () => {
  it('android injects the java bundle and an ObjC stub, but no Java stub', () => {
    const { source, bridges, passthrough } = compose('android');
    expect(passthrough).toBe(false);
    expect(bridges).toEqual(['java']);
    expect(source).toContain(JAVA_BANNER);
    expect(source).not.toContain(OBJC_BANNER);
    expect(source).toMatch(OBJC_STUB);
    expect(source).not.toMatch(JAVA_STUB);
  });

  it('ios injects the objc bundle and a Java stub, but no ObjC stub', () => {
    const { source, bridges } = compose('ios');
    expect(bridges).toEqual(['objc']);
    expect(source).toContain(OBJC_BANNER);
    expect(source).not.toContain(JAVA_BANNER);
    expect(source).toMatch(JAVA_STUB);
    expect(source).not.toMatch(OBJC_STUB);
  });

  it.each(['linux', 'unknown'] as AgentPlatform[])('%s injects stubs only', (platform) => {
    const { source, bridges } = compose(platform);
    expect(bridges).toEqual([]);
    expect(source).not.toContain(JAVA_BANNER);
    expect(source).not.toContain(OBJC_BANNER);
    expect(source).toMatch(JAVA_STUB);
    expect(source).toMatch(OBJC_STUB);
  });

  it('explicit bridges: [] overrides the platform default', () => {
    const { source, bridges } = compose('android', { bridges: [] });
    expect(bridges).toEqual([]);
    expect(source).not.toContain(JAVA_BANNER);
    expect(source).toMatch(JAVA_STUB);
    expect(source).toMatch(OBJC_STUB);
  });

  it('explicit bridges can inject both bundles', () => {
    const { source } = compose('linux', { bridges: ['java', 'objc'] });
    expect(source).toContain(JAVA_BANNER);
    expect(source).toContain(OBJC_BANNER);
    expect(source).not.toMatch(JAVA_STUB);
    expect(source).not.toMatch(OBJC_STUB);
  });

  it('preamble precedes the bridge bundle, which precedes the body', () => {
    const { source } = compose('android');
    const preambleEnd = source.indexOf(PREAMBLE_END);
    const bridgeAt = source.indexOf(JAVA_BANNER);
    const bodyAt = source.indexOf(GENERATED);
    expect(preambleEnd).toBeLessThan(bridgeAt);
    expect(bridgeAt).toBeLessThan(bodyAt);
  });
});

describe('composeAgentSource: generated scripts', () => {
  it('appends the generated source verbatim (no Script.evaluate wrapper)', () => {
    const { source } = compose('android');
    expect(source.endsWith(GENERATED)).toBe(true);
    expect(source).not.toContain('Script.evaluate(');
  });

  it('exposes name, platform and options in the __FRIDA_MCP__ literal', () => {
    const options = { lib: 'libssl.so', verbose: true, depth: 3, nested: { a: [1, 2] } };
    const { source } = compose('android', { name: 'prebuilt:demo', options });
    expect(contextLiteralOf(source)).toEqual({ name: 'prebuilt:demo', platform: 'android', options });
  });

  it('defaults options to {}', () => {
    const { source } = compose('ios');
    expect(contextLiteralOf(source)).toEqual({ name: 'test:ios', platform: 'ios', options: {} });
  });

  it('a hostile option value stays inside the JSON string literal', () => {
    const hostile = `'); send("pwned"); //`;
    const { source } = compose('android', { options: { target: hostile } });
    // JSON.stringify escapes the double quotes, so the raw call text never appears in code position.
    expect(source).not.toContain('send("pwned")');
    expect(contextLiteralOf(source).options).toEqual({ target: hostile });
  });

  it('escapes U+2028/U+2029 safely enough to parse back', () => {
    const weird = 'line sep para';
    const { source } = compose('android', { options: { weird } });
    expect(contextLiteralOf(source).options).toEqual({ weird });
  });
});

describe('composeAgentSource: user scripts', () => {
  const legacy = `Java.perform(function () {\n  send({ cls: Java.use('java.lang.String').class.getName() });\n});\n`;

  it('wraps a classic script in Script.evaluate(name, source) and the JSON round-trips', () => {
    const { source } = composeAgentSource({ kind: 'user', platform: 'android', name: 'user:execute_script', source: legacy });
    const call = evaluateCallOf(source);
    expect(call.name).toBe('user:execute_script');
    expect(call.body).toBe(legacy);
  });

  it('does not reject classic scripts that use Java.perform', () => {
    expect(() =>
      composeAgentSource({ kind: 'user', platform: 'android', name: 'user:legacy', source: legacy })
    ).not.toThrow();
  });

  it('still injects the platform bridge before the user script', () => {
    const { source, bridges } = composeAgentSource({ kind: 'user', platform: 'android', name: 'user:x', source: legacy });
    expect(bridges).toEqual(['java']);
    expect(source.indexOf(JAVA_BANNER)).toBeLessThan(source.indexOf('Script.evaluate('));
  });

  it('a user source containing quotes, backslashes and newlines survives the round-trip', () => {
    const tricky = `var s = "a\\"b\\\\c";\nvar t = 'x\\ny';\n// \${not} a template\nsend("</script>");\n`;
    const { source } = composeAgentSource({ kind: 'user', platform: 'linux', name: 'user:tricky', source: tricky });
    expect(evaluateCallOf(source).body).toBe(tricky);
  });

  it.each([
    [`import Java from 'frida-java-bridge';\nJava.perform(function () {});`],
    [`import { log } from "./log.js";`],
    [`import 'side-effect';`],
    [`export default function main() {}`],
    [`export const x = 1;`],
    [`  export function f() {}`],
  ])('rejects ES module user source: %s', (src) => {
    expect(looksLikeEsModule(src)).toBe(true);
    expect(() => composeAgentSource({ kind: 'user', platform: 'android', name: 'user:esm', source: src })).toThrow(ScriptError);
    expect(() => composeAgentSource({ kind: 'user', platform: 'android', name: 'user:esm', source: src })).toThrow(
      /ES module syntax/
    );
  });

  it('does not misclassify classic code mentioning import/export in strings or comments', () => {
    const src = `// this script does not import anything\nsend("export done");\nvar importantValue = 1;\n`;
    expect(looksLikeEsModule(src)).toBe(false);
    expect(() => composeAgentSource({ kind: 'user', platform: 'android', name: 'user:ok', source: src })).not.toThrow();
  });
});

describe('composeAgentSource: frida-compile bundle passthrough', () => {
  const bundle = `${FRIDA_COMPILE_BUNDLE_MARKER}12 /agent.js\n✄\nconsole.log("hi");\n`;

  it('detects the 📦 marker', () => {
    expect(isFridaCompileBundle(bundle)).toBe(true);
    expect(isFridaCompileBundle('// 📦 not at start')).toBe(false);
  });

  it.each(['generated', 'user'] as const)('passes a %s-kind bundle through byte-identical', (kind) => {
    const result = composeAgentSource({ kind, platform: 'android', name: 'bundle:x', source: bundle, options: { a: 1 } });
    expect(result.passthrough).toBe(true);
    expect(result.bridges).toEqual([]);
    expect(result.name).toBe('bundle:x');
    expect(result.source).toBe(bundle);
    expect(Buffer.from(result.source, 'utf8').equals(Buffer.from(bundle, 'utf8'))).toBe(true);
  });
});

describe('preamble snapshots (preamble portion only)', () => {
  it.each(['android', 'ios', 'linux'] as AgentPlatform[])('%s', (platform) => {
    const { source } = composeAgentSource({
      kind: 'generated',
      platform,
      name: `snapshot:${platform}`,
      source: GENERATED,
      options: { example: true },
    });
    expect(preambleOf(source)).toMatchSnapshot();
  });
});
