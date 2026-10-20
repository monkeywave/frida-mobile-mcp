import { describe, it, expect, afterEach } from 'vitest';
import { createRequire } from 'node:module';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import {
  BRIDGE_NAMES,
  areBridgesBuilt,
  bridgeBundlePath,
  clearBridgeCache,
  loadBridgeManifest,
  loadBridgeSource,
  type BridgeName,
} from '../../src/agent/bridges.js';

const require = createRequire(import.meta.url);

const MAX_BUNDLE_BYTES = 600 * 1024;

const EXPECTED_PACKAGES: Record<BridgeName, { pkg: string; global: string }> = {
  java: { pkg: 'frida-java-bridge', global: 'Java' },
  objc: { pkg: 'frida-objc-bridge', global: 'ObjC' },
};

function installedVersion(pkg: string): string {
  return (require(`${pkg}/package.json`) as { version: string }).version;
}

function globalInstallPattern(globalName: string): RegExp {
  // Minified form is `defineProperty(globalThis,"Java"`; match loosely around whitespace/quotes.
  return new RegExp(`defineProperty\\(\\s*globalThis\\s*,\\s*["']${globalName}["']`);
}

describe('bridge bundles (dist/bridges)', () => {
  it('bundles are built (run `npm run build:bridges` otherwise)', () => {
    expect(areBridgesBuilt()).toBe(true);
  });

  describe('manifest', () => {
    const manifest = loadBridgeManifest();

    it('exists and lists java + objc', () => {
      expect(manifest).not.toBeNull();
      const names = manifest!.bridges.map((b) => b.name).sort();
      expect(names).toEqual(['java', 'objc']);
    });

    for (const name of BRIDGE_NAMES) {
      it(`${name}: version matches the installed ${EXPECTED_PACKAGES[name].pkg}`, () => {
        const entry = manifest!.bridges.find((b) => b.name === name)!;
        expect(entry.package).toBe(EXPECTED_PACKAGES[name].pkg);
        expect(entry.version).toBe(installedVersion(EXPECTED_PACKAGES[name].pkg));
        expect(entry.file).toBe(`${name}.js`);
      });
    }
  });

  for (const name of BRIDGE_NAMES) {
    describe(`${name}.js`, () => {
      const source = readFileSync(bridgeBundlePath(name), 'utf8');

      it('compiles as a classic script', () => {
        expect(() => new vm.Script(source, { filename: `${name}.js` })).not.toThrow();
      });

      it(`is smaller than ${MAX_BUNDLE_BYTES / 1024} KiB`, () => {
        expect(Buffer.byteLength(source, 'utf8')).toBeLessThan(MAX_BUNDLE_BYTES);
      });

      it(`installs the ${EXPECTED_PACKAGES[name].global} global on globalThis`, () => {
        expect(source).toMatch(globalInstallPattern(EXPECTED_PACKAGES[name].global));
      });

      it('carries the package banner', () => {
        expect(source.startsWith(`/*! ${EXPECTED_PACKAGES[name].pkg} `)).toBe(true);
      });
    });
  }
});

describe('loadBridgeSource', () => {
  afterEach(() => {
    delete process.env.FRIDA_MCP_BRIDGES_DIR;
    clearBridgeCache();
  });

  it('caches the source (same string identity on repeated calls)', () => {
    clearBridgeCache();
    const first = loadBridgeSource('java');
    const second = loadBridgeSource('java');
    expect(second).toBe(first);
  });

  it('throws a helpful error when the bundle is missing', () => {
    const emptyDir = mkdtempSync(path.join(tmpdir(), 'frida-mcp-bridges-'));
    try {
      process.env.FRIDA_MCP_BRIDGES_DIR = emptyDir;
      clearBridgeCache();
      expect(areBridgesBuilt()).toBe(false);
      expect(loadBridgeManifest()).toBeNull();
      expect(() => loadBridgeSource('objc')).toThrow(/npm run build:bridges/);
      expect(() => loadBridgeSource('objc')).toThrow(/objc\.js/);
    } finally {
      rmSync(emptyDir, { recursive: true, force: true });
    }
  });
});

describe('java bundle: multi-script unload workaround', () => {
  it('neutralises the bridge runtime-level Script.bindWeak during module evaluation', () => {
    // See build/bundle-bridges.mjs: frida-java-bridge 7.0.13 detaches the JS thread from the VM
    // when the first script that attached it unloads, crashing sibling scripts on DeleteGlobalRef.
    const source = loadBridgeSource('java');
    expect(source).toContain('Script.bindWeak=function(){return 0}');
    expect(source.trimEnd().endsWith('Script.bindWeak=e}();') || /Script\.bindWeak=[A-Za-z_$]+\}\(\);\s*$/.test(source)).toBe(true);
  });
});
