/**
 * Loader for the prebuilt Frida bridge bundles (dist/bridges/*.js).
 *
 * Frida 17 no longer ships the Java / ObjC bridges inside the GumJS runtime, so a script
 * created through frida-node does not see `Java` or `ObjC` unless we inject them ourselves.
 * `build/bundle-bridges.mjs` turns the npm bridge packages into classic IIFE scripts that
 * install the bridge as a global; this module reads those files at runtime.
 */
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export type BridgeName = 'java' | 'objc';

export const BRIDGE_NAMES: readonly BridgeName[] = ['java', 'objc'] as const;

export interface BridgeManifestEntry {
  name: BridgeName;
  package: string;
  version: string;
  file: string;
  bytes: number;
}

export interface BridgeManifest {
  generatedAt: string;
  bridges: BridgeManifestEntry[];
}

const sourceCache = new Map<BridgeName, string>();

/**
 * Resolve the directory containing the bundles. Works from both `src/agent` (vitest, ts
 * sources) and `dist/agent` (compiled) because both are two levels below the package root.
 * `FRIDA_MCP_BRIDGES_DIR` overrides the location (useful for packaging and tests).
 */
export function getBridgesDir(): string {
  const override = process.env.FRIDA_MCP_BRIDGES_DIR;
  if (override) return override;
  const packageRoot = fileURLToPath(new URL('../../', import.meta.url));
  return path.join(packageRoot, 'dist', 'bridges');
}

export function bridgeBundlePath(name: BridgeName): string {
  return path.join(getBridgesDir(), `${name}.js`);
}

export function areBridgesBuilt(): boolean {
  return BRIDGE_NAMES.every((name) => existsSync(bridgeBundlePath(name)));
}

export function loadBridgeManifest(): BridgeManifest | null {
  const manifestPath = path.join(getBridgesDir(), 'manifest.json');
  if (!existsSync(manifestPath)) return null;
  return JSON.parse(readFileSync(manifestPath, 'utf8')) as BridgeManifest;
}

/**
 * Return the bundled bridge source. Cached after first read; the bundles are ~50-300 KiB.
 * Throws a descriptive error when the bundles have not been built.
 */
export function loadBridgeSource(name: BridgeName): string {
  const cached = sourceCache.get(name);
  if (cached !== undefined) return cached;

  const file = bridgeBundlePath(name);
  if (!existsSync(file)) {
    throw new Error(
      `Frida ${name} bridge bundle not found at ${file}. ` +
        `Run "npm run build:bridges" (or set FRIDA_MCP_BRIDGES_DIR to a directory containing ${name}.js).`
    );
  }
  const source = readFileSync(file, 'utf8');
  sourceCache.set(name, source);
  return source;
}

/** Test hook: forget cached sources (e.g. after pointing FRIDA_MCP_BRIDGES_DIR elsewhere). */
export function clearBridgeCache(): void {
  sourceCache.clear();
}
