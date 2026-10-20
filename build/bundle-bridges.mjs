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
import { mkdir, writeFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.resolve(here, '..', 'dist', 'bridges');

const BRIDGES = [
  { name: 'java', pkg: 'frida-java-bridge', entry: path.join(here, 'entries', 'java.js') },
  { name: 'objc', pkg: 'frida-objc-bridge', entry: path.join(here, 'entries', 'objc.js') },
];

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
  // Workaround for frida-java-bridge 7.0.13 with several scripts in one process: each script
  // has its own bridge instance; the one that attached the JS thread to the VM detaches it again
  // in its runtime-level dispose (Script.bindWeak(runtime, ...) at module evaluation) while
  // sibling scripts still hold a cached JNIEnv for that thread. Their next DeleteGlobalRef then
  // aborts the app with "JNI DETECTED ERROR IN APPLICATION: a thread is making JNI calls without
  // being attached". Skipping only that top-level weak binding keeps the thread attached; the
  // per-object handle destructors (bound later, at runtime) are unaffected.
  const intro = bridge.name === 'java'
    ? 'var __fridaMcpBindWeak = Script.bindWeak; Script.bindWeak = function () { return 0; };'
    : '';
  const outro = bridge.name === 'java' ? 'Script.bindWeak = __fridaMcpBindWeak;' : '';
  const { output } = await build.generate({
    format: 'iife',
    strict: false,
    banner,
    intro,
    outro,
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
