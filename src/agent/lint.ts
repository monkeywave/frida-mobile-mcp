/**
 * Patterns for Frida APIs removed in Frida 17 (or otherwise wrong on 17.x). Shared by the
 * test-suite lint (test/agent/removed-apis.test.ts) and available for runtime assertions.
 */
export interface RemovedApiPattern {
  pattern: RegExp;
  replacement: string;
}

export const REMOVED_API_PATTERNS: readonly RemovedApiPattern[] = [
  { pattern: /\bModule\.(find|get)ExportByName\s*\(/, replacement: 'findExport(lib, name) / Process.getModuleByName(lib).findExportByName(name) / Module.findGlobalExportByName(name)' },
  { pattern: /\bModule\.(find|get)SymbolByName\s*\(/, replacement: 'Process.getModuleByName(lib).findSymbolByName(name)' },
  { pattern: /\bModule\.(find|get)BaseAddress\s*\(/, replacement: 'Process.getModuleByName(lib).base' },
  { pattern: /\bModule\.ensureInitialized\s*\(/, replacement: 'Process.getModuleByName(lib).ensureInitialized()' },
  { pattern: /\bModule\.enumerate(Exports|Imports|Symbols|Ranges|Sections|Dependencies)(Sync)?\s*\(/, replacement: 'module.enumerateExports() on a Module instance' },
  { pattern: /\bMemory\.(read|write)[A-Z]\w*\s*\(/, replacement: 'NativePointer#readX()/writeX()' },
  { pattern: /\bProcess\.enumerate\w+Sync\s*\(/, replacement: 'Process.enumerateX() (returns an array)' },
  { pattern: /\b(Java|ObjC|Swift)\s*&&\s*\1\.available/, replacement: 'X.available (the preamble guarantees a stub object)' },
  { pattern: /(?<!new\s+)\bObjC\.Object\s*\(/, replacement: 'new ObjC.Object(...)' },
];

export function findRemovedApis(source: string): Array<{ match: string; replacement: string; line: number }> {
  const findings: Array<{ match: string; replacement: string; line: number }> = [];
  const lines = source.split('\n');
  lines.forEach((line, i) => {
    for (const { pattern, replacement } of REMOVED_API_PATTERNS) {
      const m = line.match(pattern);
      if (m) findings.push({ match: m[0], replacement, line: i + 1 });
    }
  });
  return findings;
}
