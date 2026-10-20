import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { REMOVED_API_PATTERNS, findRemovedApis } from '../../src/agent/lint.js';
import { getScriptRegistry } from '../../src/scripts/registry.js';
import type { PlatformContext, ScriptTemplate } from '../../src/types.js';

const SRC_DIR = fileURLToPath(new URL('../../src/', import.meta.url));

/** Files that legitimately mention removed APIs (the lint itself, docs/help text). */
const SCAN_EXCLUDES = ['agent/lint.ts', 'tools/help.ts', 'prompts.ts', 'resources.ts'].map((p) =>
  path.join(SRC_DIR, p)
);

function listSourceFiles(dir: string): string[] {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts'))
    .map((entry) => path.join(entry.parentPath ?? entry.path, entry.name))
    .sort();
}

function formatFindings(label: string, findings: ReturnType<typeof findRemovedApis>): string[] {
  return findings.map((f) => `${label}:${f.line}  ${f.match.trim()}  -> use ${f.replacement}`);
}

describe('REMOVED_API_PATTERNS', () => {
  const positives: Array<[string, string]> = [
    ['Module.findExportByName (static)', `var p = Module.findExportByName('libc.so', 'open');`],
    ['Module.findExportByName null lib', `Module.findExportByName(null, "open")`],
    ['Module.getExportByName', `Module.getExportByName("libssl.so", "SSL_read")`],
    ['Module.findSymbolByName', `Module.findSymbolByName('libart.so', 'x')`],
    ['Module.getSymbolByName', `Module.getSymbolByName ('libart.so', 'x')`],
    ['Module.findBaseAddress', `const base = Module.findBaseAddress('libfoo.so');`],
    ['Module.getBaseAddress', `Module.getBaseAddress('libfoo.so')`],
    ['Module.ensureInitialized', `Module.ensureInitialized('Foundation');`],
    ['Module.enumerateExports', `Module.enumerateExports('libc.so')`],
    ['Module.enumerateExportsSync', `Module.enumerateExportsSync('libc.so')`],
    ['Module.enumerateImports', `Module.enumerateImports("x")`],
    ['Module.enumerateSymbols', `Module.enumerateSymbols("x")`],
    ['Module.enumerateRanges', `Module.enumerateRanges("x", "r--")`],
    ['Module.enumerateSections', `Module.enumerateSections("x")`],
    ['Module.enumerateDependencies', `Module.enumerateDependencies("x")`],
    ['Memory.readUtf8String', `Memory.readUtf8String(ptr)`],
    ['Memory.readPointer', `var x = Memory.readPointer(args[0]);`],
    ['Memory.writeU32', `Memory.writeU32(addr, 1)`],
    ['Memory.readByteArray', `Memory.readByteArray(buf, len)`],
    ['Process.enumerateModulesSync', `Process.enumerateModulesSync()`],
    ['Process.enumerateThreadsSync', `Process.enumerateThreadsSync()`],
    ['Process.enumerateRangesSync', `Process.enumerateRangesSync('r--')`],
    ['Java && Java.available', `if (Java && Java.available) {}`],
    ['ObjC && ObjC.available', `if (ObjC && ObjC.available) {}`],
    ['Swift && Swift.available', `if (Swift&&Swift.available) {}`],
    ['ObjC.Object without new', `var o = ObjC.Object(ptr);`],
  ];

  const negatives: Array<[string, string]> = [
    ['new ObjC.Object(', `var o = new ObjC.Object(args[2]);`],
    ['Module.load(', `Module.load('/system/lib64/libfoo.so');`],
    ['Module.findGlobalExportByName(', `Module.findGlobalExportByName('open')`],
    ['Module.getGlobalExportByName(', `Module.getGlobalExportByName('open')`],
    ['Process.enumerateModules()', `Process.enumerateModules().forEach(function (m) {});`],
    ['Process.enumerateThreads()', `Process.enumerateThreads()`],
    ['Process.getModuleByName(...).findExportByName', `Process.getModuleByName('libc.so').findExportByName('open')`],
    ['module instance enumerateExports', `mod.enumerateExports()`],
    ['Process.findModuleByName', `var m = Process.findModuleByName('libc.so');`],
    ['NativePointer readUtf8String', `args[0].readUtf8String()`],
    ['NativePointer writeU32', `addr.writeU32(1)`],
    ['Memory.alloc', `Memory.alloc(16)`],
    ['Memory.scan', `Memory.scan(base, size, pattern, cbs)`],
    ['Memory.protect', `Memory.protect(addr, 4096, 'rwx')`],
    ['Java.available', `if (Java.available) {}`],
    ['ObjC.available', `if (ObjC.available) {}`],
    ['typeof ObjC guard', `if (typeof ObjC !== 'undefined' && ObjC.available) {}`],
    ['ObjC.classes', `ObjC.classes.NSString`],
    ['preamble helper', `findExport('libc.so', 'open')`],
    ['prefixed identifier', `MyModule.findExportByName('x')`],
    ['removed API name in a string without a call', `const name = 'Module.findExportByName';`],
  ];

  it.each(positives)('flags: %s', (_label, sample) => {
    expect(findRemovedApis(sample)).not.toHaveLength(0);
  });

  it.each(negatives)('does not flag: %s', (_label, sample) => {
    expect(findRemovedApis(sample)).toEqual([]);
  });

  it('every pattern has a non-empty replacement hint', () => {
    for (const { pattern, replacement } of REMOVED_API_PATTERNS) {
      expect(pattern).toBeInstanceOf(RegExp);
      expect(replacement.length).toBeGreaterThan(0);
    }
  });

  it('reports 1-based line numbers and the matched text', () => {
    const src = `var a = 1;\nvar b = Module.findExportByName(null, 'open');\nvar c = Memory.readU8(b);`;
    const findings = findRemovedApis(src);
    expect(findings.map((f) => f.line)).toEqual([2, 3]);
    expect(findings[0].match).toBe('Module.findExportByName(');
    expect(findings[1].match).toBe('Memory.readU8(');
  });

  it('reports multiple findings on separate lines', () => {
    const src = `Module.findExportByName('a', 'b');\n\nModule.findExportByName('c', 'd');`;
    expect(findRemovedApis(src)).toHaveLength(2);
  });
});

describe('src/**/*.ts contains no removed Frida APIs', () => {
  const files = listSourceFiles(SRC_DIR).filter((file) => !SCAN_EXCLUDES.includes(file));

  it('scans a non-trivial set of files', () => {
    expect(files.length).toBeGreaterThan(5);
    expect(files.some((f) => f.endsWith(path.join('agent', 'lint.ts')))).toBe(false);
  });

  it('no file uses a removed API', () => {
    const offenders: string[] = [];
    for (const file of files) {
      const findings = findRemovedApis(readFileSync(file, 'utf8'));
      offenders.push(...formatFindings(path.relative(SRC_DIR, file), findings));
    }
    expect(offenders, `Removed Frida APIs found:\n  ${offenders.join('\n  ')}`).toEqual([]);
  });
});

describe('registered templates render without removed Frida APIs', () => {
  const templates = getScriptRegistry().listAll();

  function defaultOptions(template: ScriptTemplate): Record<string, unknown> {
    const options: Record<string, unknown> = {};
    for (const [key, opt] of Object.entries(template.options ?? {})) {
      if (opt.default !== undefined) options[key] = opt.default;
    }
    return options;
  }

  function contextsFor(template: ScriptTemplate): Array<PlatformContext | undefined> {
    return [undefined, ...template.platforms.map((platform) => ({ platform }))];
  }

  it('registry has templates', () => {
    expect(templates.length).toBeGreaterThan(0);
  });

  it('all templates (default options, every supported platform context) are clean', () => {
    const offenders: string[] = [];
    for (const template of templates) {
      for (const context of contextsFor(template)) {
        const label = `${template.name}[${context?.platform ?? 'no-context'}]`;
        const rendered = template.generate(defaultOptions(template), context);
        offenders.push(...formatFindings(label, findRemovedApis(rendered)));
      }
    }
    expect(offenders, `Removed Frida APIs in rendered templates:\n  ${offenders.join('\n  ')}`).toEqual([]);
  });
});
