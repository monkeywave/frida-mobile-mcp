#!/usr/bin/env node
/**
 * Bundles the Frida Java / ObjC bridges into classic IIFE scripts under dist/bridges/.
 *
 * Frida 17 removed the bridges from the GumJS runtime; scripts created through the
 * frida-node API no longer see `Java` / `ObjC`. frida-tools solves this by prebuilding
 * each bridge with rollup and evaluating the result before user code runs. We do the same.
 *
 * Output: dist/bridges/{java,objc}.js and dist/bridges/manifest.json
 */
import { rollup } from 'rollup';
import nodeResolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import terser from '@rollup/plugin-terser';
import polyfills from '@frida/rollup-plugin-node-polyfills';
import { createRequire } from 'node:module';
import { mkdir, readFile, writeFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import ts from 'typescript';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.resolve(here, '..', 'dist', 'bridges');

const BRIDGES = [
  { name: 'java', pkg: 'frida-java-bridge', entry: path.join(here, 'entries', 'java.js') },
  { name: 'objc', pkg: 'frida-objc-bridge', entry: path.join(here, 'entries', 'objc.js') },
];

const JAVA_BRIDGE_PATCH_MODULE = path.resolve(here, '..', 'src', 'agent', 'java-bridge-patch.ts');

/**
 * Load the shared (import-free) TypeScript helper without a prior tsc run: this script runs
 * before tsc, and Node's own type stripping is not available on every supported Node version.
 */
async function loadJavaBridgePatch() {
  const source = await readFile(JAVA_BRIDGE_PATCH_MODULE, 'utf8');
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  });
  return import(`data:text/javascript;base64,${Buffer.from(outputText).toString('base64')}`);
}

const javaBridgePatch = await loadJavaBridgePatch();

const JAVA_BRIDGE_INDEX = /node_modules[\\/]frida-java-bridge[\\/]index\.js$/;

/** Warn (do not fail) when upstream no longer has the VM.dispose call the workaround comments out. */
function warnJavaBridgePatchMissing(file) {
  console.error(`[bridges] WARNING: VM.dispose(vm) call not found in ${file}; ` +
    'the multi-script unload workaround may be obsolete or ineffective (see src/agent/java-bridge-patch.ts)');
}

/** Rollup transform: multi-script unload workaround for frida-java-bridge, see src/agent/java-bridge-patch.ts. */
function javaBridgeThreadDetachPatch() {
  let sawIndex = false;
  return {
    name: 'frida-java-bridge-skip-thread-detach',
    transform(code, id) {
      if (!JAVA_BRIDGE_INDEX.test(id)) return null;
      sawIndex = true;
      const result = javaBridgePatch.skipJavaBridgeThreadDetach(code);
      if (!result.patched) warnJavaBridgePatchMissing(id);
      return result.status === 'patched' ? { code: result.source, map: null } : null;
    },
    buildEnd() {
      if (!sawIndex && this.getModuleIds().some((id) => /frida-java-bridge/.test(id))) {
        warnJavaBridgePatchMissing('frida-java-bridge/index.js (module not seen)');
      }
    },
  };
}

function packageVersion(pkg) {
  return require(`${pkg}/package.json`).version;
}

async function bundle(bridge) {
  const version = packageVersion(bridge.pkg);
  const build = await rollup({
    input: bridge.entry,
    plugins: [
      // The ObjC bridge relies on side effects during module evaluation; never tree-shake it.
      {
        name: 'frida-bridges-no-treeshake',
        transform(code, id) {
          if (/node_modules[\\/]frida-objc-bridge/.test(id)) {
            return { code, map: null, moduleSideEffects: 'no-treeshake' };
          }
          return null;
        },
      },
      javaBridgeThreadDetachPatch(),
      polyfills(),
      nodeResolve(),
      commonjs(),
      terser({ ecma: 2022 }),
    ],
    onwarn(warning, warn) {
      if (warning.code === 'CIRCULAR_DEPENDENCY') return;
      warn(warning);
    },
  });

  const banner = `/*! ${bridge.pkg} ${version} - bundled by frida-mobile-mcp (classic script, evaluates via Script.evaluate) */`;
  const { output } = await build.generate({
    format: 'iife',
    strict: false,
    banner,
    generatedCode: { preset: 'es2015' },
  });
  await build.close();

  const file = path.join(outDir, `${bridge.name}.js`);
  await writeFile(file, output[0].code, 'utf8');
  const { size } = await stat(file);
  return { name: bridge.name, package: bridge.pkg, version, file: `${bridge.name}.js`, bytes: size };
}

async function main() {
  await mkdir(outDir, { recursive: true });
  const entries = [];
  for (const bridge of BRIDGES) {
    const info = await bundle(bridge);
    entries.push(info);
    console.error(`[bridges] ${info.file}: ${info.package}@${info.version}, ${(info.bytes / 1024).toFixed(0)} KiB`);
  }
  const manifest = { generatedAt: new Date().toISOString(), bridges: entries };
  await writeFile(path.join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', 'utf8');
}

main().catch((err) => {
  console.error('[bridges] bundling failed:', err);
  process.exit(1);
});
