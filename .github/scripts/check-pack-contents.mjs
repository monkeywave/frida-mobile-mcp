// Verifies that the npm tarball produced by `npm pack` contains the files the
// published package cannot work without. Reads the JSON that
// `npm pack --dry-run --json` writes to stdout, so it is shell-agnostic:
//   npm pack --dry-run --json | node .github/scripts/check-pack-contents.mjs
import { readFileSync } from 'node:fs';

const REQUIRED_FILES = [
  'dist/index.js',
  'dist/bridges/java.js',
  'dist/bridges/objc.js',
  'dist/bridges/manifest.json',
  'dist/lib.js',
  'dist/lib.d.ts',
  'skills/mobile-dynamic-analysis/SKILL.md',
  'README.md',
];

const packResult = JSON.parse(readFileSync(0, 'utf8'));
const packedPaths = new Set(packResult[0].files.map((file) => file.path));

console.log(`Tarball ${packResult[0].filename}: ${packedPaths.size} files`);
for (const path of [...packedPaths].sort()) console.log(`  ${path}`);

const missing = REQUIRED_FILES.filter((path) => !packedPaths.has(path));
if (missing.length > 0) {
  console.error(`\nMissing from tarball: ${missing.join(', ')}`);
  process.exit(1);
}
console.log('\nAll required files are present in the tarball.');
